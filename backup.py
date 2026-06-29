import os
import json
import shutil
import sqlite3
import tempfile
import secrets
import platform
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from tkinter import messagebox, filedialog, simpledialog

from config import DB_FILE, APP_NAME, BACKUP_VERSION
from crypto_utils import derive_backup_key, encrypt_bytes, decrypt_bytes
from security import validate_master_password
from device_secret import load_or_create_device_secret
from database import meta_get_text
from rollback import read_signed_state, verify_signed_state


REQUIRED_TABLES = {
    "vault_meta",
    "audit_log",
    "vault_items",
    "password_entries",
    "totp_entries",
}


REQUIRED_META_KEYS = {
    "kdf_salt",
    "dek_nonce",
    "encrypted_dek",
    "vault_uuid",
    "vault_created_at",
    "vault_version",
    "vault_fingerprint",
    "vault_counter",
    "integrity_hmac",
}



def read_meta_from_sqlite(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT key, value FROM vault_meta")
    rows = dict(cur.fetchall())
    conn.close()
    return rows


def decode_meta_value(value):
    if value is None:
        return ""
    try:
        return value.decode()
    except Exception:
        return ""


def get_current_vault_identity():
    """
    Return the current active vault identity from the live database and signed rollback state.
    If no current vault exists, returns None.
    """
    if not os.path.exists(DB_FILE):
        return None

    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT value FROM vault_meta WHERE key='vault_uuid'")
        uuid_row = cur.fetchone()
        cur.execute("SELECT value FROM vault_meta WHERE key='vault_counter'")
        counter_row = cur.fetchone()
        conn.close()

        if not uuid_row or not counter_row:
            return None

        current_uuid = decode_meta_value(uuid_row[0])
        current_counter = int(decode_meta_value(counter_row[0]))

        state = read_signed_state()
        state_ok, state_message = verify_signed_state(state)

        if not state_ok:
            raise ValueError(
                "Current trusted rollback state is invalid. "
                "Restore is blocked to avoid replacing the vault from an untrusted state. "
                + state_message
            )

        return {
            "vault_uuid": current_uuid,
            "vault_counter": current_counter,
            "signed_counter": int(state.get("counter", -1)),
            "signed_uuid": state.get("vault_uuid", "")
        }

    except Exception as error:
        raise ValueError(f"Could not verify current vault identity before restore: {error}")


def verify_restore_is_authorized(temp_db_path):
    """
    Prevent backup-interface database replacement attacks.

    If an active vault exists, the restored database must:
    - have the same vault_uuid as the current vault
    - have a counter equal to or newer than the signed trusted rollback state
    - not belong to a different vault

    First-time restore with no current database is allowed.
    """

    current = get_current_vault_identity()

    if current is None:
        return True

    restored_meta = read_meta_from_sqlite(temp_db_path)

    restored_uuid = decode_meta_value(restored_meta.get("vault_uuid"))
    restored_counter_text = decode_meta_value(restored_meta.get("vault_counter"))

    if not restored_uuid:
        raise ValueError("Restored database does not contain a readable vault UUID.")

    try:
        restored_counter = int(restored_counter_text)
    except Exception:
        raise ValueError("Restored database contains an invalid vault counter.")

    if current["signed_uuid"] != current["vault_uuid"]:
        raise ValueError("Current signed rollback state does not match the active vault UUID.")

    if restored_uuid != current["vault_uuid"]:
        raise ValueError(
            "Restore blocked. Backup belongs to a different vault UUID than the current vault."
        )

    if restored_counter < current["signed_counter"]:
        raise ValueError(
            "Restore blocked. Backup is older than the trusted current rollback state."
        )

    if restored_counter > current["signed_counter"]:
        raise ValueError(
            "Restore blocked. Backup counter is newer than the trusted current rollback state. "
            "NxTPass will not trust a backup-provided counter automatically."
        )

    return True



APP_DIR_NAME = "NxTPass"
RECOVERY_DIR_NAME = "recovery"


def get_app_support_dir():
    system = platform.system()

    if system == "Darwin":
        base = Path.home() / "Library" / "Application Support" / APP_DIR_NAME
    elif system == "Windows":
        base = Path(os.environ.get("APPDATA", str(Path.home()))) / APP_DIR_NAME
    else:
        base = Path.home() / ".config" / APP_DIR_NAME

    base.mkdir(parents=True, exist_ok=True)

    try:
        os.chmod(base, 0o700)
    except Exception:
        pass

    return base


def get_recovery_dir():
    recovery_dir = get_app_support_dir() / RECOVERY_DIR_NAME
    recovery_dir.mkdir(parents=True, exist_ok=True)

    try:
        os.chmod(recovery_dir, 0o700)
    except Exception:
        pass

    return recovery_dir


def derive_local_recovery_key():
    return hashlib.sha256(
        load_or_create_device_secret() + b"NxTPass encrypted local recovery copy v1"
    ).digest()


def create_encrypted_pre_restore_copy():
    """
    Create an encrypted local safety copy before restore.

    v20 change:
    - No raw authenticator.db.pre_restore*.bak copy is left beside the live DB.
    - The safety copy is encrypted using the local device secret.
    - Filename is random, not predictable.
    """

    if not os.path.exists(DB_FILE):
        return None

    with open(DB_FILE, "rb") as f:
        db_bytes = f.read()

    key = derive_local_recovery_key()
    nonce, ciphertext = encrypt_bytes(
        key,
        db_bytes,
        aad=b"NxTPass pre-restore recovery copy v1"
    )

    recovery_data = {
        "app": APP_NAME,
        "type": "encrypted_pre_restore_recovery",
        "version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex()
    }

    random_name = f"recovery_{secrets.token_hex(16)}.nxtrecovery"
    recovery_path = get_recovery_dir() / random_name

    recovery_path.write_text(json.dumps(recovery_data, indent=2))

    try:
        os.chmod(recovery_path, 0o600)
    except Exception:
        pass

    return str(recovery_path)


def export_encrypted_backup():
    backup_password = simpledialog.askstring(
        "Backup Password",
        (
            "Enter a strong password to encrypt the backup:\n\n"
            "Password requirements:\n"
            "• At least 12 characters\n"
            "• At least one uppercase letter\n"
            "• At least one lowercase letter\n"
            "• At least one number\n"
            "• At least one special character"
        ),
        show="*"
    )

    if not backup_password:
        return

    valid, message = validate_master_password(backup_password)

    if not valid:
        messagebox.showerror("Weak Backup Password", message)
        return

    file_path = filedialog.asksaveasfilename(
        title="Save Encrypted Backup",
        defaultextension=".vaultbak",
        filetypes=[("Vault Backup", "*.vaultbak")]
    )

    if not file_path:
        return

    try:
        with open(DB_FILE, "rb") as f:
            db_bytes = f.read()

        salt = os.urandom(16)
        key = derive_backup_key(backup_password, salt)
        nonce, ciphertext = encrypt_bytes(key, db_bytes)

        backup_data = {
            "app": APP_NAME,
            "version": BACKUP_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        }

        with open(file_path, "w") as f:
            json.dump(backup_data, f)

        messagebox.showinfo("Backup Saved", "Encrypted backup created successfully.")

    except Exception as error:
        messagebox.showerror("Backup Error", f"Could not create backup: {error}")


def decrypt_backup_file(file_path, backup_password):
    with open(file_path, "r") as f:
        backup_data = json.load(f)

    if backup_data.get("app") not in (None, APP_NAME):
        raise ValueError("This does not appear to be a valid NxTPass backup.")

    if "salt" not in backup_data or "nonce" not in backup_data or "ciphertext" not in backup_data:
        raise ValueError("Backup file is missing required encryption fields.")

    salt = bytes.fromhex(backup_data["salt"])
    nonce = bytes.fromhex(backup_data["nonce"])
    ciphertext = bytes.fromhex(backup_data["ciphertext"])

    key = derive_backup_key(backup_password, salt)
    return decrypt_bytes(key, nonce, ciphertext)


def validate_restored_database_file(temp_db_path):
    conn = sqlite3.connect(temp_db_path)
    cur = conn.cursor()

    cur.execute("PRAGMA integrity_check")
    result = cur.fetchone()

    if not result or result[0] != "ok":
        conn.close()
        raise ValueError("SQLite integrity_check failed.")

    cur.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
    """)
    found_tables = {row[0] for row in cur.fetchall()}

    missing_tables = REQUIRED_TABLES - found_tables

    if missing_tables:
        conn.close()
        raise ValueError(
            "Restored database is missing required tables: "
            + ", ".join(sorted(missing_tables))
        )

    cur.execute("SELECT key FROM vault_meta")
    found_meta = {row[0] for row in cur.fetchall()}

    missing_meta = REQUIRED_META_KEYS - found_meta

    if missing_meta:
        conn.close()
        raise ValueError(
            "Restored database is missing required vault metadata: "
            + ", ".join(sorted(missing_meta))
        )

    has_v9_verifier = (
        "protected_verifier_nonce" in found_meta
        and "protected_verifier" in found_meta
    )
    has_legacy_hash = "master_hash" in found_meta

    if not has_v9_verifier and not has_legacy_hash:
        conn.close()
        raise ValueError("Restored database is missing password verifier metadata.")

    has_external_2fa = "twofa_external_enabled" in found_meta
    has_legacy_2fa = (
        "twofa_nonce" in found_meta
        and "encrypted_twofa_secret" in found_meta
    )

    if not has_external_2fa and not has_legacy_2fa:
        conn.close()
        raise ValueError("Restored database is missing vault-login 2FA metadata.")

    conn.close()
    return True


def import_encrypted_backup():
    confirm = messagebox.askyesno(
        "Restore Backup",
        (
            "Restoring a backup will replace the current vault database.\n\n"
            "NxTPass will verify the backup first and create an encrypted local "
            "recovery copy of your current database before replacing it.\n\n"
            "Continue?"
        )
    )

    if not confirm:
        return

    file_path = filedialog.askopenfilename(
        title="Open Encrypted Backup",
        filetypes=[("Vault Backup", "*.vaultbak")]
    )

    if not file_path:
        return

    backup_password = simpledialog.askstring(
        "Backup Password",
        "Enter the backup password:",
        show="*"
    )

    if not backup_password:
        return

    temp_db_path = None

    try:
        db_bytes = decrypt_backup_file(file_path, backup_password)

        fd, temp_db_path = tempfile.mkstemp(prefix="nxtpass_restore_", suffix=".db")
        os.close(fd)

        with open(temp_db_path, "wb") as f:
            f.write(db_bytes)

        validate_restored_database_file(temp_db_path)
        verify_restore_is_authorized(temp_db_path)

        recovery_copy = create_encrypted_pre_restore_copy()

        shutil.copy2(temp_db_path, DB_FILE)

        if recovery_copy:
            message = (
                "Backup restored successfully.\n\n"
                "An encrypted local recovery copy of your previous database was saved as:\n"
                f"{recovery_copy}\n\n"
                "Restart the app before unlocking."
            )
        else:
            message = (
                "Backup restored successfully.\n\n"
                "Restart the app before unlocking."
            )

        messagebox.showinfo("Backup Restored", message)

    except Exception as error:
        messagebox.showerror(
            "Restore Blocked",
            (
                "The backup was not restored.\n\n"
                "Possible causes:\n"
                "• Wrong backup password\n"
                "• Corrupted backup file\n"
                "• Invalid SQLite database\n"
                "• Missing vault tables or metadata\n• Backup does not match the currently authorized vault state\n• Backup is older/newer than the trusted rollback state\n\n"
                f"Details: {error}"
            )
        )

    finally:
        if temp_db_path and os.path.exists(temp_db_path):
            try:
                os.remove(temp_db_path)
            except Exception:
                pass
