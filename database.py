import sqlite3
from config import DB_FILE

def db_connect():
    return sqlite3.connect(DB_FILE)

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
    return row[0] if row else None

def meta_set(key, value):
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
