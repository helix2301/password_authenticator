import sqlite3
import json
import hashlib
from config import DB_FILE

SENSITIVE_META_KEYS = {
    "vault_uuid",
    "vault_created_at",
    "vault_fingerprint",
}


def _derive_meta_privacy_key():
    from device_secret import load_or_create_device_secret
    return hashlib.sha256(
        load_or_create_device_secret() + b"NxTPass metadata privacy v1"
    ).digest()


def _protect_meta_value(key, value):
    if key not in SENSITIVE_META_KEYS:
        return value

    from crypto_utils import encrypt_bytes

    if isinstance(value, str):
        raw = value.encode()
    else:
        raw = value

    nonce, ciphertext = encrypt_bytes(
        _derive_meta_privacy_key(),
        raw,
        aad=f"NxTPass:meta:{key}".encode()
    )

    payload = {
        "protected": True,
        "version": 1,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex()
    }

    return json.dumps(payload, sort_keys=True).encode()


def _unprotect_meta_value(key, value):
    if key not in SENSITIVE_META_KEYS:
        return value

    if value is None:
        return None

    try:
        parsed = json.loads(value.decode())
        if not parsed.get("protected"):
            return value

        from crypto_utils import decrypt_bytes

        plaintext = decrypt_bytes(
            _derive_meta_privacy_key(),
            bytes.fromhex(parsed["nonce"]),
            bytes.fromhex(parsed["ciphertext"]),
            aad=f"NxTPass:meta:{key}".encode()
        )

        return plaintext

    except Exception:
        # Legacy plaintext compatibility.
        return value


def db_connect():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = FULL")
    return conn

def init_db():
    conn = db_connect()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS vault_meta (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        )
    """)

    # Legacy table kept for older vault compatibility, but new entries use separated tables.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vault_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL
        )
    """)

    # New modular storage design:
    # item identity: encrypted service + username
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vault_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_nonce BLOB NOT NULL,
            item_ciphertext BLOB NOT NULL
        )
    """)

    # encrypted passwords live separately
    cur.execute("""
        CREATE TABLE IF NOT EXISTS password_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL UNIQUE,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            FOREIGN KEY(item_id) REFERENCES vault_items(id) ON DELETE CASCADE
        )
    """)

    # encrypted TOTP/authenticator seeds live separately
    cur.execute("""
        CREATE TABLE IF NOT EXISTS totp_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL UNIQUE,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            FOREIGN KEY(item_id) REFERENCES vault_items(id) ON DELETE CASCADE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            previous_hmac TEXT NOT NULL,
            event_hmac TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()

def meta_get(key):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT value FROM vault_meta WHERE key = ?", (key,))
    row = cur.fetchone()
    conn.close()
    return _unprotect_meta_value(key, row[0]) if row else None

def meta_set(key, value):
    value = _protect_meta_value(key, value)

    conn = db_connect()
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

def meta_get_text(key, default=""):
    value = meta_get(key)
    if value is None:
        return default
    try:
        return value.decode()
    except Exception:
        return default

def meta_set_text(key, value):
    meta_set(key, str(value).encode())
