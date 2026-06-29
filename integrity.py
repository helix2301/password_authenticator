import hmac
import json
import hashlib
from config import *
from database import db_connect, meta_get, meta_get_text, meta_set
from crypto_utils import derive_integrity_key

def canonical_database_state():
    conn = db_connect()
    cur = conn.cursor()

    cur.execute("""
        SELECT key, hex(value)
        FROM vault_meta
        WHERE key NOT IN ('integrity_hmac', 'failed_attempts', 'lockout_until')
        ORDER BY key
    """)
    meta_rows = cur.fetchall()

    # Legacy table included so any legacy data remains integrity-protected.
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

    conn.close()

    return json.dumps({
        "meta": meta_rows,
        "legacy_entries": legacy_entry_rows,
        "items": item_rows,
        "password_entries": password_rows,
        "totp_entries": totp_rows,
        "audit": audit_rows
    }, sort_keys=True, separators=(",", ":")).encode()

def compute_database_hmac(dek):
    return hmac.new(
        derive_integrity_key(dek),
        canonical_database_state(),
        hashlib.sha256
    ).hexdigest()

def save_database_hmac(dek):
    meta_set(INTEGRITY_HMAC_KEY, compute_database_hmac(dek).encode())

def verify_database_hmac(dek):
    stored = meta_get(INTEGRITY_HMAC_KEY)

    if stored is None:
        return False, "Missing database integrity HMAC."

    expected = compute_database_hmac(dek)
    actual = stored.decode()

    if not hmac.compare_digest(actual, expected):
        return False, "Database integrity verification failed."

    return True, ""

def compute_vault_fingerprint(vault_uuid, created_at):
    return hashlib.sha256(f"NxTPass|{vault_uuid}|{created_at}".encode()).hexdigest()

def get_vault_fingerprint():
    return meta_get_text(VAULT_FINGERPRINT_KEY, "")

def verify_vault_fingerprint():
    vault_uuid = meta_get_text(VAULT_UUID_KEY, "")
    created_at = meta_get_text(VAULT_CREATED_AT_KEY, "")
    stored = meta_get_text(VAULT_FINGERPRINT_KEY, "")

    if not vault_uuid or not created_at or not stored:
        return False, "Vault fingerprint metadata is missing."

    expected = compute_vault_fingerprint(vault_uuid, created_at)

    if not hmac.compare_digest(expected, stored):
        return False, "Vault fingerprint verification failed."

    return True, ""

def run_database_repair_check():
    required = [
        "kdf_salt",
        "dek_nonce",
        "encrypted_dek",
        VAULT_UUID_KEY,
        VAULT_CREATED_AT_KEY,
        VAULT_VERSION_KEY,
        VAULT_FINGERPRINT_KEY,
        VAULT_COUNTER_KEY,
        INTEGRITY_HMAC_KEY
    ]

    missing = [key for key in required if meta_get(key) is None]

    if missing:
        return False, "Missing vault metadata: " + ", ".join(missing)

    has_external_2fa = meta_get("twofa_external_enabled") == b"1"
    has_legacy_2fa = (
        meta_get("twofa_nonce") is not None
        and meta_get("encrypted_twofa_secret") is not None
    )

    if not has_external_2fa and not has_legacy_2fa:
        return False, "Missing vault-login 2FA metadata."

    has_v9_verifier = (
        meta_get("protected_verifier_nonce") is not None
        and meta_get("protected_verifier") is not None
    )
    has_legacy_hash = meta_get("master_hash") is not None

    if not has_v9_verifier and not has_legacy_hash:
        return False, "Missing password verifier metadata."

    return True, ""


def automatic_integrity_check(dek):
    checks = [
        verify_vault_fingerprint(),
        verify_database_hmac(dek),
    ]

    for ok, msg in checks:
        if not ok:
            return False, msg

    return True, ""


def database_self_repair_best_effort():
    """
    Best-effort SQLite maintenance.

    This does not repair cryptographic tampering. It only attempts ordinary
    SQLite maintenance operations when the database is structurally valid.
    """
    conn = db_connect()
    cur = conn.cursor()

    cur.execute("PRAGMA integrity_check")
    result = cur.fetchone()

    if not result or result[0] != "ok":
        conn.close()
        return False, "SQLite integrity_check failed. Manual restore from backup is recommended."

    try:
        cur.execute("PRAGMA foreign_keys = ON")
        cur.execute("PRAGMA optimize")
        cur.execute("VACUUM")
        conn.commit()
    except Exception as error:
        conn.close()
        return False, f"Self-repair maintenance failed: {error}"

    conn.close()
    return True, "Database maintenance completed successfully."
