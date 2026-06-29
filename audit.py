import hmac
import json
import hashlib
from datetime import datetime, timezone
from database import db_connect
from crypto_utils import derive_audit_key

def get_last_audit_hmac():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT event_hmac FROM audit_log ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row[0] if row else "GENESIS"

def add_audit_event(dek, action, details):
    audit_key = derive_audit_key(dek)
    timestamp = datetime.now(timezone.utc).isoformat()
    previous_hmac = get_last_audit_hmac()
    details_json = json.dumps(details, sort_keys=True, separators=(",", ":"))
    message = json.dumps({
        "timestamp": timestamp,
        "action": action,
        "details": details_json,
        "previous_hmac": previous_hmac
    }, sort_keys=True, separators=(",", ":")).encode()
    event_hmac = hmac.new(audit_key, message, hashlib.sha256).hexdigest()
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO audit_log
        (timestamp, action, details, previous_hmac, event_hmac)
        VALUES (?, ?, ?, ?, ?)
    """, (timestamp, action, details_json, previous_hmac, event_hmac))
    conn.commit()
    conn.close()

def verify_audit_chain(dek):
    audit_key = derive_audit_key(dek)
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT timestamp, action, details, previous_hmac, event_hmac FROM audit_log ORDER BY id")
    rows = cur.fetchall()
    conn.close()

    previous = "GENESIS"

    for timestamp, action, details, previous_hmac, event_hmac in rows:
        if previous_hmac != previous:
            return False, "Audit log chain was broken."

        message = json.dumps({
            "timestamp": timestamp,
            "action": action,
            "details": details,
            "previous_hmac": previous_hmac
        }, sort_keys=True, separators=(",", ":")).encode()

        expected = hmac.new(audit_key, message, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected, event_hmac):
            return False, "Audit log HMAC verification failed."

        previous = event_hmac

    return True, ""
