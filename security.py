import re
import time
from config import MAX_LOGIN_ATTEMPTS, LOGIN_LOCKOUT_SECONDS
from database import meta_get, meta_get_text, meta_set_text

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
    return meta_get("master_hash") is not None

def get_lockout_until():
    try:
        return int(meta_get_text("lockout_until", "0"))
    except ValueError:
        return 0

def get_failed_attempts():
    try:
        return int(meta_get_text("failed_attempts", "0"))
    except ValueError:
        return 0

def is_login_locked():
    return int(time.time()) < get_lockout_until()

def login_lock_remaining():
    return max(0, get_lockout_until() - int(time.time()))

def record_failed_login():
    attempts = get_failed_attempts() + 1
    if attempts >= MAX_LOGIN_ATTEMPTS:
        meta_set_text("failed_attempts", 0)
        meta_set_text("lockout_until", int(time.time()) + LOGIN_LOCKOUT_SECONDS)
    else:
        meta_set_text("failed_attempts", attempts)

def reset_failed_logins():
    meta_set_text("failed_attempts", 0)
    meta_set_text("lockout_until", 0)
