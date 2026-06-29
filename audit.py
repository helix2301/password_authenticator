import hmac
import json
import hashlib
from datetime import datetime, timezone
from database import db_connect
from crypto_utils import derive_audit_key, encrypt_bytes, decrypt_bytes


def get_last_audit_hmac():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT event_hmac FROM audit_log ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row[0] if row else "GENESIS"


def _protect_audit_details(dek, action, details):
    audit_key = derive_audit_key(dek)
    details_json = json.dumps(details, sort_keys=True, separators=(",", ":")).encode()

    nonce, ciphertext = encrypt_bytes(
        audit_key,
        details_json,
        aad=f"NxTPass:audit:{action}".encode()
    )

    return json.dumps(
        {
            "protected": True,
            "version": 1,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        },
        sort_keys=True,
        separators=(",", ":")
    )


def _unprotect_audit_details(dek, action, details_field):
    try:
        parsed = json.loads(details_field)

        if not parsed.get("protected"):
            return details_field

        audit_key = derive_audit_key(dek)

        plaintext = decrypt_bytes(
            audit_key,
            bytes.fromhex(parsed["nonce"]),
            bytes.fromhex(parsed["ciphertext"]),
            aad=f"NxTPass:audit:{action}".encode()
        )

        return plaintext.decode()

    except Exception:
        # Legacy plaintext audit compatibility.
        return details_field


def add_audit_event(dek, action, details):
    audit_key = derive_audit_key(dek)

    timestamp = datetime.now(timezone.utc).isoformat()
    previous_hmac = get_last_audit_hmac()
    protected_details = _protect_audit_details(dek, action, details)

    message = json.dumps({
        "timestamp": timestamp,
        "action": action,
        "details": protected_details,
        "previous_hmac": previous_hmac
    }, sort_keys=True, separators=(",", ":")).encode()

    event_hmac = hmac.new(audit_key, message, hashlib.sha256).hexdigest()

    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO audit_log
        (timestamp, action, details, previous_hmac, event_hmac)
        VALUES (?, ?, ?, ?, ?)
    """, (timestamp, action, protected_details, previous_hmac, event_hmac))
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

        # If encrypted audit details are malformed, fail closed.
        parsed = None
        try:
            parsed = json.loads(details)
        except Exception:
            parsed = None

        if isinstance(parsed, dict) and parsed.get("protected"):
            try:
                _unprotect_audit_details(dek, action, details)
            except Exception:
                return False, "Encrypted audit details could not be verified."

        previous = event_hmac

    return True, ""
