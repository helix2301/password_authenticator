import os
import json
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from tkinter import messagebox, filedialog, simpledialog

from config import DB_FILE, APP_NAME, BACKUP_VERSION
from crypto_utils import derive_backup_key, encrypt_bytes, decrypt_bytes
from security import validate_master_password


REQUIRED_TABLES = {
    "vault_meta",
    "audit_log",
    "vault_items",
    "password_entries",
    "totp_entries",
}


REQUIRED_META_KEYS = {
    "master_hash",
    "kdf_salt",
    "dek_nonce",
    "encrypted_dek",
    "twofa_nonce",
    "encrypted_twofa_secret",
    "vault_uuid",
    "vault_created_at",
    "vault_version",
    "vault_fingerprint",
    "vault_counter",
    "integrity_hmac",
}


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
    """
    Validate backup before replacing the real database.

    This checks:
    - SQLite can open the database
    - PRAGMA integrity_check passes
    - Required tables exist
    - Required vault metadata keys exist
    """

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

    conn.close()
    return True


def make_pre_restore_safety_copy():
    if not os.path.exists(DB_FILE):
        return None

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safety_copy = f"{DB_FILE}.pre_restore_{timestamp}.bak"
    shutil.copy2(DB_FILE, safety_copy)
    return safety_copy


def import_encrypted_backup():
    confirm = messagebox.askyesno(
        "Restore Backup",
        (
            "Restoring a backup will replace the current vault database.\n\n"
            "NxTPass will verify the backup first and create a safety copy "
            "of your current database before replacing it.\n\n"
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

        safety_copy = make_pre_restore_safety_copy()

        shutil.copy2(temp_db_path, DB_FILE)

        if safety_copy:
            message = (
                "Backup restored successfully.\n\n"
                f"A safety copy of your previous database was saved as:\n{safety_copy}\n\n"
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
                "• Missing vault tables or metadata\n\n"
                f"Details: {error}"
            )
        )

    finally:
        if temp_db_path and os.path.exists(temp_db_path):
            try:
                os.remove(temp_db_path)
            except Exception:
                pass
