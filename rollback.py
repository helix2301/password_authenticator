import os
import json
import hmac
import hashlib
import secrets
import platform
from pathlib import Path

from config import VAULT_COUNTER_KEY, VAULT_UUID_KEY
from database import meta_get_text, meta_set_text


APP_DIR_NAME = "NxTPass"
ROLLBACK_STATE_FILE = "rollback_state.json"
ROLLBACK_KEY_FILE = "rollback_state.key"


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
    return get_app_support_dir() / ROLLBACK_STATE_FILE


def get_key_path():
    return get_app_support_dir() / ROLLBACK_KEY_FILE


def load_or_create_rollback_key():
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


def get_vault_counter():
    try:
        return int(meta_get_text(VAULT_COUNTER_KEY, "0"))
    except ValueError:
        return 0


def get_vault_uuid():
    return meta_get_text(VAULT_UUID_KEY, "")


def compute_state_hmac(key, vault_uuid, counter):
    message = json.dumps(
        {
            "vault_uuid": vault_uuid,
            "counter": int(counter),
            "purpose": "NxTPass rollback protection v2"
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


def write_signed_state(vault_uuid, counter):
    key = load_or_create_rollback_key()
    state_path = get_state_path()

    state = {
        "version": 2,
        "vault_uuid": vault_uuid,
        "counter": int(counter),
        "hmac": compute_state_hmac(key, vault_uuid, int(counter))
    }

    state_path.write_text(json.dumps(state, indent=2))

    try:
        os.chmod(state_path, 0o600)
    except Exception:
        pass


def verify_signed_state(state):
    if not state:
        return False, "Trusted rollback state is missing."

    key = load_or_create_rollback_key()

    try:
        vault_uuid = state["vault_uuid"]
        counter = int(state["counter"])
        stored_hmac = state["hmac"]
    except Exception:
        return False, "Trusted rollback state is damaged."

    expected = compute_state_hmac(key, vault_uuid, counter)

    if not hmac.compare_digest(expected, stored_hmac):
        return False, "Trusted rollback state HMAC verification failed."

    return True, ""


def set_vault_counter(counter):
    vault_uuid = get_vault_uuid()
    meta_set_text(VAULT_COUNTER_KEY, counter)

    if vault_uuid:
        write_signed_state(vault_uuid, counter)


def increment_vault_counter():
    counter = get_vault_counter() + 1
    set_vault_counter(counter)
    return counter


def initialize_trusted_rollback_state():
    vault_uuid = get_vault_uuid()
    counter = get_vault_counter()

    if not vault_uuid:
        return False, "Cannot initialize rollback state because vault UUID is missing."

    write_signed_state(vault_uuid, counter)
    return True, ""


def verify_rollback_counter():
    """
    Anti-rollback policy.

    This version no longer trusts a plain .nxtpass_counter file next to the database.
    It stores HMAC-signed rollback state outside the vault folder and fails closed if
    that trusted state is missing, invalid, damaged, belongs to another vault, or does not exactly match the database counter.

    Limitation:
    No purely local app can fully stop rollback if an attacker can copy the database,
    the external rollback state, and the rollback key together. Full rollback resistance
    requires a trusted monotonic counter outside attacker control, such as a server,
    TPM, Secure Enclave, or OS-backed non-exportable key.
    """
    db_counter = get_vault_counter()
    vault_uuid = get_vault_uuid()

    if not vault_uuid:
        return False, "Vault UUID is missing."

    state = read_signed_state()
    state_ok, state_message = verify_signed_state(state)

    if not state_ok:
        return False, state_message + " Possible rollback or state deletion detected."

    state_vault_uuid = state.get("vault_uuid")
    state_counter = int(state.get("counter", -1))

    if state_vault_uuid != vault_uuid:
        return False, "Trusted rollback state belongs to a different vault."

    if db_counter < state_counter:
        return False, (
            "Rollback detected. The database counter is older than the trusted rollback state."
        )

    if db_counter > state_counter:
        return False, (
            "Rollback state poisoning detected. The database counter is newer than "
            "the trusted signed rollback state. NxTPass will not trust this database "
            "counter automatically."
        )

    return True, ""
