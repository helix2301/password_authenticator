import os
import uuid
import pyotp
from datetime import datetime, timezone
from tkinter import messagebox

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

from config import *
from database import db_connect, meta_get, meta_set
from crypto_utils import derive_key, derive_device_bound_key, encrypt_bytes, decrypt_bytes, encrypt_record, decrypt_record
from security import validate_master_password, reset_failed_logins, is_login_locked
from lockout_state import initialize_lockout_state, get_lockout_state_error
from integrity import (
    compute_vault_fingerprint,
    save_database_hmac,
    verify_database_hmac,
    verify_vault_fingerprint,
    run_database_repair_check,
)
from audit import add_audit_event, verify_audit_chain
from rollback import set_vault_counter, increment_vault_counter, verify_rollback_counter, initialize_trusted_rollback_state
from tamper import handle_confirmed_tamper
from external_2fa import save_external_twofa_secret, load_external_twofa_secret

ph = PasswordHasher()


def aad_for(table_name, item_id):
    return f"NxTPass:v15:{table_name}:item:{item_id}".encode()



def _get_last_audit_hmac_cur(cur):
    cur.execute("SELECT event_hmac FROM audit_log ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    return row[0] if row else "GENESIS"


def _add_audit_event_cur(cur, dek, action, details):
    import json
    import hmac
    import hashlib
    from datetime import datetime, timezone
    from crypto_utils import derive_audit_key, encrypt_bytes

    audit_key = derive_audit_key(dek)
    timestamp = datetime.now(timezone.utc).isoformat()
    previous_hmac = _get_last_audit_hmac_cur(cur)

    details_json = json.dumps(details, sort_keys=True, separators=(",", ":")).encode()
    nonce, ciphertext = encrypt_bytes(
        audit_key,
        details_json,
        aad=f"NxTPass:audit:{action}".encode()
    )
    protected_details = json.dumps(
        {
            "protected": True,
            "version": 1,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        },
        sort_keys=True,
        separators=(",", ":")
    )

    message = json.dumps({
        "timestamp": timestamp,
        "action": action,
        "details": protected_details,
        "previous_hmac": previous_hmac
    }, sort_keys=True, separators=(",", ":")).encode()

    event_hmac = hmac.new(audit_key, message, hashlib.sha256).hexdigest()

    cur.execute("""
        INSERT INTO audit_log
        (timestamp, action, details, previous_hmac, event_hmac)
        VALUES (?, ?, ?, ?, ?)
    """, (timestamp, action, protected_details, previous_hmac, event_hmac))


def _compute_database_hmac_cur(cur, dek):
    import json
    import hmac
    import hashlib
    from crypto_utils import derive_integrity_key

    cur.execute("""
        SELECT key, hex(value)
        FROM vault_meta
        WHERE key NOT IN ('integrity_hmac', 'failed_attempts', 'lockout_until')
        ORDER BY key
    """)
    meta_rows = cur.fetchall()

    cur.execute("SELECT id, hex(nonce), hex(ciphertext) FROM vault_entries ORDER BY id")
    legacy_entry_rows = cur.fetchall()

    cur.execute("SELECT id, hex(item_nonce), hex(item_ciphertext) FROM vault_items ORDER BY id")
    item_rows = cur.fetchall()

    cur.execute("SELECT id, item_id, hex(nonce), hex(ciphertext) FROM password_entries ORDER BY id")
    password_rows = cur.fetchall()

    cur.execute("SELECT id, item_id, hex(nonce), hex(ciphertext) FROM totp_entries ORDER BY id")
    totp_rows = cur.fetchall()

    cur.execute("SELECT id, timestamp, action, details, previous_hmac, event_hmac FROM audit_log ORDER BY id")
    audit_rows = cur.fetchall()

    payload = {
        "meta": meta_rows,
        "legacy_entries": legacy_entry_rows,
        "items": item_rows,
        "password_entries": password_rows,
        "totp_entries": totp_rows,
        "audit": audit_rows
    }

    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(derive_integrity_key(dek), data, hashlib.sha256).hexdigest()


def _set_meta_cur(cur, key, value):
    cur.execute("INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)", (key, value))


def _update_security_state_cur(cur, dek, action, details):
    from rollback import write_signed_state, get_vault_uuid

    cur.execute("SELECT value FROM vault_meta WHERE key = ?", (VAULT_COUNTER_KEY,))
    row = cur.fetchone()
    counter = int(row[0].decode()) if row and row[0] is not None else 0
    counter += 1

    _set_meta_cur(cur, VAULT_COUNTER_KEY, str(counter).encode())

    details = dict(details)
    details["vault_counter"] = counter

    _add_audit_event_cur(cur, dek, action, details)

    digest = _compute_database_hmac_cur(cur, dek)
    _set_meta_cur(cur, INTEGRITY_HMAC_KEY, digest.encode())

    # External rollback state is updated only after DB transaction commits by caller.
    return counter



def decrypt_record_bound_or_legacy(dek, nonce, ciphertext, table_name, item_id):
    """
    v15 decrypts with AES-GCM associated data binding ciphertext to table/item_id.

    Legacy rows from older versions may not have AAD. We allow legacy fallback for
    display/migration compatibility, but new writes always use AAD.
    """
    try:
        return decrypt_record(dek, nonce, ciphertext, aad=aad_for(table_name, item_id))
    except Exception:
        return decrypt_record(dek, nonce, ciphertext)


def initialize_vault_identity(dek):
    vault_uuid = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    fingerprint = compute_vault_fingerprint(vault_uuid, created_at)

    meta_set(VAULT_UUID_KEY, vault_uuid.encode())
    meta_set(VAULT_CREATED_AT_KEY, created_at.encode())
    meta_set(VAULT_VERSION_KEY, b"2")
    meta_set(VAULT_FINGERPRINT_KEY, fingerprint.encode())

    set_vault_counter(1)
    initialize_trusted_rollback_state()
    initialize_lockout_state()

    add_audit_event(dek, "VAULT_CREATED", {
        "vault_uuid": vault_uuid,
        "vault_version": 2,
        "storage": "separated_tables"
    })

    save_database_hmac(dek)

def create_vault(master_password, twofa_secret):
    valid, message = validate_master_password(master_password)

    if not valid:
        raise ValueError(message)

    kdf_salt = os.urandom(16)

    # v9: device-bound KEK.
    # No standalone master_hash is stored for new vaults.
    # This prevents testing guesses against a copied database alone.
    kek = derive_device_bound_key(master_password, kdf_salt)
    dek = os.urandom(32)

    dek_nonce, encrypted_dek = encrypt_bytes(kek, dek)
    verifier_nonce, protected_verifier = encrypt_bytes(
        kek,
        b"NxTPass protected verifier v9"
    )

    meta_set("kdf_salt", kdf_salt)
    meta_set("dek_nonce", dek_nonce)
    meta_set("encrypted_dek", encrypted_dek)
    meta_set("protected_verifier_nonce", verifier_nonce)
    meta_set("protected_verifier", protected_verifier)
    meta_set("twofa_external_enabled", b"1")

    reset_failed_logins()
    initialize_vault_identity(dek)
    save_external_twofa_secret(twofa_secret)
    save_database_hmac(dek)

def unlock_vault(master_password, twofa_code):
    lockout_error = get_lockout_state_error()
    if lockout_error:
        messagebox.showerror("Lockout Protection Failed", lockout_error)
        return None

    if is_login_locked():
        return None

    kdf_salt = meta_get("kdf_salt")
    dek_nonce = meta_get("dek_nonce")
    encrypted_dek = meta_get("encrypted_dek")

    if not kdf_salt or not dek_nonce or not encrypted_dek:
        return None

    verifier_nonce = meta_get("protected_verifier_nonce")
    protected_verifier = meta_get("protected_verifier")

    if verifier_nonce and protected_verifier:
        # v9 protected verifier path.
        # Requires the master password AND local device secret.
        kek = derive_device_bound_key(master_password, kdf_salt)

        try:
            verifier_plaintext = decrypt_bytes(kek, verifier_nonce, protected_verifier)
            if verifier_plaintext != b"NxTPass protected verifier v9":
                return None
        except Exception:
            return None

    else:
        # Legacy compatibility path.
        # Old vaults with master_hash are still unlockable, but they remain
        # vulnerable to offline testing if authenticator.db is stolen.
        master_hash = meta_get("master_hash")

        if not master_hash:
            return None

        try:
            decoded_hash = master_hash.decode("utf-8")
            ph.verify(decoded_hash, master_password)
        except (UnicodeDecodeError, VerifyMismatchError, VerificationError, Exception):
            messagebox.showerror(
                "Vault Metadata Error",
                (
                    "The legacy master password verifier is damaged or malformed.\n\n"
                    "This may indicate database tampering or corruption."
                )
            )
            return None

        kek = derive_key(master_password, kdf_salt)

    try:
        dek = decrypt_bytes(kek, dek_nonce, encrypted_dek)
    except Exception:
        return None

    checks = [
        (*run_database_repair_check(), "Database Repair Check Failed"),
        (*verify_vault_fingerprint(), "Vault Fingerprint Failed"),
        (*verify_rollback_counter(), "Rollback Detected"),
        (*verify_audit_chain(dek), "Tamper Detected"),
        (*verify_database_hmac(dek), "Tamper Detected"),
    ]

    for ok, msg, title in checks:
        if not ok:
            alert_title, alert_message = handle_confirmed_tamper(
                f"{title}: {msg}",
                title="Tamper Detected"
            )
            messagebox.showerror(alert_title, alert_message)
            return None

    try:
        if meta_get("twofa_external_enabled") == b"1":
            # v10 path: vault-login TOTP seed is stored outside authenticator.db.
            twofa_secret = load_external_twofa_secret()
        else:
            # Legacy compatibility path.
            # Old vaults may still store the login 2FA seed encrypted inside the DB.
            twofa_nonce = meta_get("twofa_nonce")
            encrypted_twofa_secret = meta_get("encrypted_twofa_secret")

            if not twofa_nonce or not encrypted_twofa_secret:
                return None

            twofa_secret = decrypt_bytes(dek, twofa_nonce, encrypted_twofa_secret).decode()

    except Exception as error:
        messagebox.showerror(
            "2FA Protection Failed",
            (
                "Vault-login 2FA state could not be loaded.\n\n"
                "Possible causes:\n"
                "• External 2FA state was deleted\n"
                "• External 2FA state was modified\n"
                "• This database was moved to another device\n\n"
                f"Details: {error}"
            )
        )
        return None

    if not pyotp.TOTP(twofa_secret).verify(twofa_code, valid_window=1):
        return None

    # Unlock-only events are security-relevant.
    # Advance the rollback counter so an attacker cannot restore an older
    # database snapshot with the same counter and erase later unlock events.
    update_security_state(dek, "VAULT_UNLOCKED", {
        "result": "success",
        "counter_advanced": True
    })

    return dek

def update_security_state(dek, action, details):
    increment_vault_counter()
    add_audit_event(dek, action, details)
    save_database_hmac(dek)

def _upsert_password_cur(cur, item_id, password, dek):
    if password:
        nonce, ciphertext = encrypt_record(
            dek,
            {"password": password},
            aad=aad_for("password_entries", item_id)
        )
        cur.execute("SELECT id FROM password_entries WHERE item_id = ?", (item_id,))
        row = cur.fetchone()

        if row:
            cur.execute(
                "UPDATE password_entries SET nonce = ?, ciphertext = ? WHERE item_id = ?",
                (nonce, ciphertext, item_id)
            )
        else:
            cur.execute(
                "INSERT INTO password_entries (item_id, nonce, ciphertext) VALUES (?, ?, ?)",
                (item_id, nonce, ciphertext)
            )
    else:
        cur.execute("DELETE FROM password_entries WHERE item_id = ?", (item_id,))


def _upsert_totp_cur(cur, item_id, secret, dek):
    if secret:
        nonce, ciphertext = encrypt_record(
            dek,
            {"secret": secret},
            aad=aad_for("totp_entries", item_id)
        )
        cur.execute("SELECT id FROM totp_entries WHERE item_id = ?", (item_id,))
        row = cur.fetchone()

        if row:
            cur.execute(
                "UPDATE totp_entries SET nonce = ?, ciphertext = ? WHERE item_id = ?",
                (nonce, ciphertext, item_id)
            )
        else:
            cur.execute(
                "INSERT INTO totp_entries (item_id, nonce, ciphertext) VALUES (?, ?, ?)",
                (item_id, nonce, ciphertext)
            )
    else:
        cur.execute("DELETE FROM totp_entries WHERE item_id = ?", (item_id,))

def add_vault_entry(service, username, password, secret, dek):
    from rollback import write_signed_state, get_vault_uuid

    identity = {
        "service": service,
        "username": username
    }

    conn = db_connect()
    cur = conn.cursor()
    new_counter = None

    try:
        cur.execute("BEGIN IMMEDIATE")

        placeholder_nonce, placeholder_ciphertext = encrypt_record(dek, {"pending": True})

        cur.execute(
            "INSERT INTO vault_items (item_nonce, item_ciphertext) VALUES (?, ?)",
            (placeholder_nonce, placeholder_ciphertext)
        )
        item_id = cur.lastrowid

        item_nonce, item_ciphertext = encrypt_record(
            dek,
            identity,
            aad=aad_for("vault_items", item_id)
        )

        cur.execute(
            "UPDATE vault_items SET item_nonce = ?, item_ciphertext = ? WHERE id = ?",
            (item_nonce, item_ciphertext, item_id)
        )

        _upsert_password_cur(cur, item_id, password, dek)
        _upsert_totp_cur(cur, item_id, secret, dek)

        new_counter = _update_security_state_cur(cur, dek, "ENTRY_ADDED", {
            "item_id": item_id,
            "service": service,
            "storage": "separated_tables",
            "atomic": True
        })

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    if new_counter is not None:
        write_signed_state(get_vault_uuid(), new_counter)


def update_vault_entry(item_id, service, username, password, secret, dek):
    from rollback import write_signed_state, get_vault_uuid

    identity = {
        "service": service,
        "username": username
    }

    conn = db_connect()
    cur = conn.cursor()
    new_counter = None

    try:
        cur.execute("BEGIN IMMEDIATE")

        item_nonce, item_ciphertext = encrypt_record(
            dek,
            identity,
            aad=aad_for("vault_items", item_id)
        )

        cur.execute(
            "UPDATE vault_items SET item_nonce = ?, item_ciphertext = ? WHERE id = ?",
            (item_nonce, item_ciphertext, item_id)
        )

        _upsert_password_cur(cur, item_id, password, dek)
        _upsert_totp_cur(cur, item_id, secret, dek)

        new_counter = _update_security_state_cur(cur, dek, "ENTRY_EDITED", {
            "item_id": str(item_id),
            "service": service,
            "storage": "separated_tables",
            "atomic": True
        })

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    if new_counter is not None:
        write_signed_state(get_vault_uuid(), new_counter)



def change_master_password(current_session_dek, old_password, new_password, confirm_password, twofa_code):
    """
    Change the master password and rotate the DEK.

    This performs a best-effort full re-encryption of current separated-table
    vault records using a newly generated DEK.

    Security behavior:
    - verifies old password + 2FA
    - validates new password policy
    - generates a new DEK
    - creates a new device-bound protected verifier
    - re-encrypts vault_items, password_entries, and totp_entries
    - clears old audit log and starts a new audit chain under the new DEK
    - advances vault_counter
    - recalculates database HMAC
    - updates signed rollback state after DB commit

    Legacy all-in-one vault_entries are not migrated here. If present, they are
    left untouched and may become unreadable after DEK rotation. Users should
    recreate legacy entries before rotating the master password.
    """
    from rollback import write_signed_state, get_vault_uuid
    from integrity import verify_database_hmac, verify_vault_fingerprint
    import os

    if new_password != confirm_password:
        return False, "New passwords do not match."

    valid, message = validate_master_password(new_password)
    if not valid:
        return False, message

    # Verify current integrity before making irreversible changes.
    ok, msg = verify_vault_fingerprint()
    if not ok:
        return False, msg

    ok, msg = verify_database_hmac(current_session_dek)
    if not ok:
        return False, msg

    verified_dek = unlock_vault(old_password, twofa_code)
    if not verified_dek:
        return False, "Current master password or 2FA code is incorrect."

    if verified_dek != current_session_dek:
        return False, "Current session key does not match verified vault key."

    # Refuse rotation if legacy rows exist; rotating would orphan them unless migrated.
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM vault_entries")
    legacy_count = cur.fetchone()[0]
    conn.close()

    if legacy_count:
        return False, (
            "Master password rotation is blocked because legacy all-in-one entries exist. "
            "Create new separated-table entries for those records and delete the legacy rows first."
        )

    # Decrypt all current records before starting the write transaction.
    current_items = get_vault_items(current_session_dek)
    clean_items = []

    for item in current_items:
        if str(item.get("id", "")).startswith("legacy-"):
            continue

        clean_items.append({
            "id": int(item["id"]),
            "service": item.get("service", ""),
            "username": item.get("username", ""),
            "password": item.get("password", ""),
            "secret": item.get("secret", ""),
        })

    new_dek = os.urandom(32)
    new_salt = os.urandom(16)
    new_kek = derive_device_bound_key(new_password, new_salt)

    new_dek_nonce, new_encrypted_dek = encrypt_bytes(new_kek, new_dek)
    new_verifier_nonce, new_protected_verifier = encrypt_bytes(
        new_kek,
        b"NxTPass protected verifier v9"
    )

    conn = db_connect()
    cur = conn.cursor()
    new_counter = None

    try:
        cur.execute("BEGIN IMMEDIATE")

        # Replace key-encryption metadata.
        _set_meta_cur(cur, "kdf_salt", new_salt)
        _set_meta_cur(cur, "dek_nonce", new_dek_nonce)
        _set_meta_cur(cur, "encrypted_dek", new_encrypted_dek)
        _set_meta_cur(cur, "protected_verifier_nonce", new_verifier_nonce)
        _set_meta_cur(cur, "protected_verifier", new_protected_verifier)

        # Remove legacy standalone verifier if present so the old password is invalidated.
        cur.execute("DELETE FROM vault_meta WHERE key = 'master_hash'")

        # Re-encrypt all separated-table records under the new DEK.
        for item in clean_items:
            item_id = item["id"]

            identity_nonce, identity_ciphertext = encrypt_record(
                new_dek,
                {
                    "service": item["service"],
                    "username": item["username"]
                },
                aad=aad_for("vault_items", item_id)
            )

            cur.execute(
                "UPDATE vault_items SET item_nonce = ?, item_ciphertext = ? WHERE id = ?",
                (identity_nonce, identity_ciphertext, item_id)
            )

            _upsert_password_cur(cur, item_id, item["password"], new_dek)
            _upsert_totp_cur(cur, item_id, item["secret"], new_dek)

        # Old audit log was authenticated with the old DEK-derived audit key.
        # Start a fresh audit chain under the new DEK after password rotation.
        cur.execute("DELETE FROM audit_log")

        new_counter = _update_security_state_cur(cur, new_dek, "MASTER_PASSWORD_CHANGED", {
            "dek_rotated": True,
            "records_reencrypted": len(clean_items),
            "old_master_password_invalidated": True,
            "atomic": True
        })

        conn.commit()

    except Exception as error:
        conn.rollback()
        return False, f"Master password change failed: {error}"

    finally:
        conn.close()

    if new_counter is not None:
        write_signed_state(get_vault_uuid(), new_counter)

    # Best effort wipe of old/new DEK locals that are mutable? bytes cannot be guaranteed.
    return True, "Master password changed. The vault will now lock. Reopen it with the new password."



def get_vault_items(dek):
    """
    Returns decrypted item dictionaries assembled from separate encrypted tables.
    This function decrypts only while the vault is open.
    """

    conn = db_connect()
    cur = conn.cursor()

    cur.execute("SELECT id, item_nonce, item_ciphertext FROM vault_items ORDER BY id")
    item_rows = cur.fetchall()

    cur.execute("SELECT item_id, nonce, ciphertext FROM password_entries")
    password_rows = cur.fetchall()

    cur.execute("SELECT item_id, nonce, ciphertext FROM totp_entries")
    totp_rows = cur.fetchall()

    # Legacy support: read older all-in-one encrypted rows if they exist.
    cur.execute("SELECT id, nonce, ciphertext FROM vault_entries ORDER BY id")
    legacy_rows = cur.fetchall()

    conn.close()

    password_map = {}
    for item_id, nonce, ciphertext in password_rows:
        try:
            password_map[item_id] = decrypt_record_bound_or_legacy(
                dek,
                nonce,
                ciphertext,
                "password_entries",
                item_id
            ).get("password", "")
        except Exception:
            password_map[item_id] = ""

    totp_map = {}
    for item_id, nonce, ciphertext in totp_rows:
        try:
            totp_map[item_id] = decrypt_record_bound_or_legacy(
                dek,
                nonce,
                ciphertext,
                "totp_entries",
                item_id
            ).get("secret", "")
        except Exception:
            totp_map[item_id] = ""

    items = []

    for item_id, nonce, ciphertext in item_rows:
        try:
            identity = decrypt_record_bound_or_legacy(
                dek,
                nonce,
                ciphertext,
                "vault_items",
                item_id
            )
            items.append({
                "id": str(item_id),
                "service": identity.get("service", ""),
                "username": identity.get("username", ""),
                "password": password_map.get(item_id, ""),
                "secret": totp_map.get(item_id, ""),
                "legacy": False
            })
        except Exception:
            items.append({
                "id": str(item_id),
                "service": "Unable to decrypt",
                "username": "",
                "password": "",
                "secret": "",
                "legacy": False
            })

    for legacy_id, nonce, ciphertext in legacy_rows:
        try:
            data = decrypt_record(dek, nonce, ciphertext)
            items.append({
                "id": f"legacy-{legacy_id}",
                "service": data.get("service", ""),
                "username": data.get("username", ""),
                "password": data.get("password", ""),
                "secret": data.get("secret", ""),
                "legacy": True
            })
        except Exception:
            items.append({
                "id": f"legacy-{legacy_id}",
                "service": "Unable to decrypt legacy row",
                "username": "",
                "password": "",
                "secret": "",
                "legacy": True
            })

    return items

def delete_vault_entry(item_id, dek):
    from rollback import write_signed_state, get_vault_uuid

    conn = db_connect()
    cur = conn.cursor()
    new_counter = None

    try:
        cur.execute("BEGIN IMMEDIATE")

        if str(item_id).startswith("legacy-"):
            legacy_id = str(item_id).replace("legacy-", "", 1)
            cur.execute("DELETE FROM vault_entries WHERE id = ?", (legacy_id,))

            new_counter = _update_security_state_cur(cur, dek, "LEGACY_ENTRY_DELETED", {
                "legacy_id": str(legacy_id),
                "atomic": True
            })
        else:
            cur.execute("DELETE FROM password_entries WHERE item_id = ?", (item_id,))
            cur.execute("DELETE FROM totp_entries WHERE item_id = ?", (item_id,))
            cur.execute("DELETE FROM vault_items WHERE id = ?", (item_id,))

            new_counter = _update_security_state_cur(cur, dek, "ENTRY_DELETED", {
                "item_id": str(item_id),
                "storage": "separated_tables",
                "atomic": True
            })

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    if new_counter is not None:
        write_signed_state(get_vault_uuid(), new_counter)

