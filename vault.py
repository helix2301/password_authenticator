import os
import uuid
import pyotp
from datetime import datetime, timezone
from tkinter import messagebox

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

from config import *
from database import db_connect, meta_get, meta_set
from crypto_utils import derive_key, encrypt_bytes, decrypt_bytes, encrypt_record, decrypt_record
from security import validate_master_password, reset_failed_logins, is_login_locked
from integrity import (
    compute_vault_fingerprint,
    save_database_hmac,
    verify_database_hmac,
    verify_vault_fingerprint,
    run_database_repair_check,
)
from audit import add_audit_event, verify_audit_chain
from rollback import set_vault_counter, increment_vault_counter, verify_rollback_counter
from tamper import record_tamper_event, reset_tamper_count, should_emergency_wipe, emergency_protect_database

ph = PasswordHasher()

def initialize_vault_identity(dek):
    vault_uuid = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    fingerprint = compute_vault_fingerprint(vault_uuid, created_at)

    meta_set(VAULT_UUID_KEY, vault_uuid.encode())
    meta_set(VAULT_CREATED_AT_KEY, created_at.encode())
    meta_set(VAULT_VERSION_KEY, b"2")
    meta_set(VAULT_FINGERPRINT_KEY, fingerprint.encode())

    set_vault_counter(1)

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

    master_hash = ph.hash(master_password)
    kdf_salt = os.urandom(16)

    kek = derive_key(master_password, kdf_salt)
    dek = os.urandom(32)

    dek_nonce, encrypted_dek = encrypt_bytes(kek, dek)
    twofa_nonce, encrypted_twofa_secret = encrypt_bytes(dek, twofa_secret.encode())

    meta_set("master_hash", master_hash.encode())
    meta_set("kdf_salt", kdf_salt)
    meta_set("dek_nonce", dek_nonce)
    meta_set("encrypted_dek", encrypted_dek)
    meta_set("twofa_nonce", twofa_nonce)
    meta_set("encrypted_twofa_secret", encrypted_twofa_secret)

    reset_failed_logins()
    initialize_vault_identity(dek)

def unlock_vault(master_password, twofa_code):
    if is_login_locked():
        return None

    master_hash = meta_get("master_hash")

    if not master_hash:
        return None

    try:
        ph.verify(master_hash.decode(), master_password)
    except (VerifyMismatchError, VerificationError):
        return None

    kdf_salt = meta_get("kdf_salt")
    dek_nonce = meta_get("dek_nonce")
    encrypted_dek = meta_get("encrypted_dek")

    if not kdf_salt or not dek_nonce or not encrypted_dek:
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
            count = record_tamper_event()

            if should_emergency_wipe():
                protected_path = emergency_protect_database()
                messagebox.showerror(
                    "Emergency Protection Triggered",
                    (
                        f"{title}: {msg}\n\n"
                        f"Repeated tamper detections: {count}\n"
                        "The suspicious database has been quarantined or removed.\n\n"
                        f"Result: {protected_path}"
                    )
                )
            else:
                messagebox.showerror(
                    title,
                    f"{msg}\n\nTamper warning count: {count}"
                )

            return None

    reset_tamper_count()

    twofa_nonce = meta_get("twofa_nonce")
    encrypted_twofa_secret = meta_get("encrypted_twofa_secret")

    if not twofa_nonce or not encrypted_twofa_secret:
        return None

    try:
        twofa_secret = decrypt_bytes(dek, twofa_nonce, encrypted_twofa_secret).decode()
    except Exception:
        return None

    if not pyotp.TOTP(twofa_secret).verify(twofa_code, valid_window=1):
        return None

    add_audit_event(dek, "VAULT_UNLOCKED", {
        "result": "success"
    })
    save_database_hmac(dek)

    return dek

def update_security_state(dek, action, details):
    increment_vault_counter()
    add_audit_event(dek, action, details)
    save_database_hmac(dek)

def _upsert_password(item_id, password, dek):
    conn = db_connect()
    cur = conn.cursor()

    if password:
        nonce, ciphertext = encrypt_record(dek, {"password": password})
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

    conn.commit()
    conn.close()

def _upsert_totp(item_id, secret, dek):
    conn = db_connect()
    cur = conn.cursor()

    if secret:
        nonce, ciphertext = encrypt_record(dek, {"secret": secret})
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

    conn.commit()
    conn.close()

def add_vault_entry(service, username, password, secret, dek):
    identity = {
        "service": service,
        "username": username
    }

    item_nonce, item_ciphertext = encrypt_record(dek, identity)

    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO vault_items (item_nonce, item_ciphertext) VALUES (?, ?)",
        (item_nonce, item_ciphertext)
    )
    item_id = cur.lastrowid
    conn.commit()
    conn.close()

    _upsert_password(item_id, password, dek)
    _upsert_totp(item_id, secret, dek)

    update_security_state(dek, "ENTRY_ADDED", {
        "item_id": item_id,
        "service": service,
        "storage": "separated_tables"
    })

def update_vault_entry(item_id, service, username, password, secret, dek):
    identity = {
        "service": service,
        "username": username
    }

    item_nonce, item_ciphertext = encrypt_record(dek, identity)

    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "UPDATE vault_items SET item_nonce = ?, item_ciphertext = ? WHERE id = ?",
        (item_nonce, item_ciphertext, item_id)
    )
    conn.commit()
    conn.close()

    _upsert_password(item_id, password, dek)
    _upsert_totp(item_id, secret, dek)

    update_security_state(dek, "ENTRY_EDITED", {
        "item_id": str(item_id),
        "service": service,
        "storage": "separated_tables"
    })

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
            password_map[item_id] = decrypt_record(dek, nonce, ciphertext).get("password", "")
        except Exception:
            password_map[item_id] = ""

    totp_map = {}
    for item_id, nonce, ciphertext in totp_rows:
        try:
            totp_map[item_id] = decrypt_record(dek, nonce, ciphertext).get("secret", "")
        except Exception:
            totp_map[item_id] = ""

    items = []

    for item_id, nonce, ciphertext in item_rows:
        try:
            identity = decrypt_record(dek, nonce, ciphertext)
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
    if str(item_id).startswith("legacy-"):
        legacy_id = str(item_id).replace("legacy-", "", 1)
        conn = db_connect()
        cur = conn.cursor()
        cur.execute("DELETE FROM vault_entries WHERE id = ?", (legacy_id,))
        conn.commit()
        conn.close()

        update_security_state(dek, "LEGACY_ENTRY_DELETED", {
            "legacy_id": str(legacy_id)
        })
        return

    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM password_entries WHERE item_id = ?", (item_id,))
    cur.execute("DELETE FROM totp_entries WHERE item_id = ?", (item_id,))
    cur.execute("DELETE FROM vault_items WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()

    update_security_state(dek, "ENTRY_DELETED", {
        "item_id": str(item_id),
        "storage": "separated_tables"
    })
