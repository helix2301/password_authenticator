import re
from database import meta_get
from lockout_state import (
    get_lockout_until,
    get_failed_attempts,
    is_login_locked,
    login_lock_remaining,
    record_failed_login,
    reset_failed_logins,
    initialize_lockout_state,
    get_lockout_state_error,
)


def validate_master_password(password):
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must contain at least one special character."
    return True, ""


def vault_exists():
    return meta_get("protected_verifier_nonce") is not None or meta_get("master_hash") is not None
