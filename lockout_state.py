import os
import json
import hmac
import time
import hashlib
import secrets
import platform
from pathlib import Path

from config import MAX_LOGIN_ATTEMPTS, LOGIN_LOCKOUT_SECONDS, VAULT_UUID_KEY
from database import meta_get_text, meta_set_text


APP_DIR_NAME = "NxTPass"
LOCKOUT_STATE_FILE = "lockout_state.json"
LOCKOUT_KEY_FILE = "lockout_state.key"


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


def get_state_path():
    return get_app_support_dir() / LOCKOUT_STATE_FILE


def get_key_path():
    return get_app_support_dir() / LOCKOUT_KEY_FILE


def load_or_create_lockout_key():
    key_path = get_key_path()

    if key_path.exists():
        try:
            raw = key_path.read_bytes()
            if len(raw) >= 32:
                return raw
        except Exception:
            pass

    key = secrets.token_bytes(32)
    key_path.write_bytes(key)

    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass

    return key


def get_vault_uuid():
    return meta_get_text(VAULT_UUID_KEY, "")


def compute_state_hmac(key, vault_uuid, failed_attempts, lockout_until):
    message = json.dumps(
        {
            "vault_uuid": vault_uuid,
            "failed_attempts": int(failed_attempts),
            "lockout_until": int(lockout_until),
            "purpose": "NxTPass lockout protection v1"
        },
        sort_keys=True,
        separators=(",", ":")
    ).encode()

    return hmac.new(key, message, hashlib.sha256).hexdigest()


def read_signed_state():
    state_path = get_state_path()

    if not state_path.exists():
        return None

    try:
        return json.loads(state_path.read_text())
    except Exception:
        return None


def write_signed_state(failed_attempts, lockout_until):
    vault_uuid = get_vault_uuid()
    key = load_or_create_lockout_key()
    state_path = get_state_path()

    state = {
        "version": 1,
        "vault_uuid": vault_uuid,
        "failed_attempts": int(failed_attempts),
        "lockout_until": int(lockout_until),
        "hmac": compute_state_hmac(key, vault_uuid, int(failed_attempts), int(lockout_until))
    }

    state_path.write_text(json.dumps(state, indent=2))

    try:
        os.chmod(state_path, 0o600)
    except Exception:
        pass

    # Keep DB values only as display/migration hints. They are no longer trusted.
    meta_set_text("failed_attempts", int(failed_attempts))
    meta_set_text("lockout_until", int(lockout_until))


def verify_signed_state(state):
    if not state:
        return False, "Trusted lockout state is missing."

    key = load_or_create_lockout_key()

    try:
        vault_uuid = state["vault_uuid"]
        failed_attempts = int(state["failed_attempts"])
        lockout_until = int(state["lockout_until"])
        stored_hmac = state["hmac"]
    except Exception:
        return False, "Trusted lockout state is damaged."

    expected = compute_state_hmac(key, vault_uuid, failed_attempts, lockout_until)

    if not hmac.compare_digest(expected, stored_hmac):
        return False, "Trusted lockout state HMAC verification failed."

    current_vault_uuid = get_vault_uuid()

    if current_vault_uuid and vault_uuid != current_vault_uuid:
        return False, "Trusted lockout state belongs to a different vault."

    return True, ""


def initialize_lockout_state():
    write_signed_state(0, 0)


def require_valid_lockout_state():
    """
    Fail closed if the signed lockout state is missing or tampered.

    This prevents an attacker from editing failed_attempts/lockout_until in SQLite
    or deleting the lockout state to bypass the lockout.
    """
    if not get_vault_uuid():
        # Vault creation path.
        return True, ""

    state = read_signed_state()
    ok, message = verify_signed_state(state)

    if not ok:
        return False, message + " Login is blocked to prevent lockout bypass."

    return True, ""


def get_failed_attempts():
    ok, _ = require_valid_lockout_state()

    if not ok:
        return MAX_LOGIN_ATTEMPTS

    state = read_signed_state()
    return int(state.get("failed_attempts", 0))


def get_lockout_until():
    ok, _ = require_valid_lockout_state()

    if not ok:
        return int(time.time()) + LOGIN_LOCKOUT_SECONDS

    state = read_signed_state()
    return int(state.get("lockout_until", 0))


def is_login_locked():
    ok, _ = require_valid_lockout_state()

    if not ok:
        return True

    return int(time.time()) < get_lockout_until()


def login_lock_remaining():
    return max(0, get_lockout_until() - int(time.time()))


def record_failed_login():
    ok, _ = require_valid_lockout_state()

    if not ok:
        # Already fail-closed.
        return

    attempts = get_failed_attempts() + 1

    if attempts >= MAX_LOGIN_ATTEMPTS:
        write_signed_state(0, int(time.time()) + LOGIN_LOCKOUT_SECONDS)
    else:
        write_signed_state(attempts, 0)


def reset_failed_logins():
    write_signed_state(0, 0)


def get_lockout_state_error():
    ok, message = require_valid_lockout_state()
    return "" if ok else message
