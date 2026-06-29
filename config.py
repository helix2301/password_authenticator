DB_FILE = "authenticator.db"
LOGO_FILE = "NxTPass-Logo.png"
ROLLBACK_COUNTER_FILE = ".nxtpass_counter"

LOCK_TIMEOUT_MS = 15 * 60 * 1000
CLIPBOARD_CLEAR_MS = 30 * 1000

MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 10 * 60

APP_NAME = "NxTPass"
BACKUP_VERSION = 1

INTEGRITY_HMAC_KEY = "integrity_hmac"
VAULT_VERSION_KEY = "vault_version"
VAULT_UUID_KEY = "vault_uuid"
VAULT_FINGERPRINT_KEY = "vault_fingerprint"
VAULT_CREATED_AT_KEY = "vault_created_at"
VAULT_COUNTER_KEY = "vault_counter"


# Session and hardening
SESSION_CHECK_MS = 60 * 1000
INTEGRITY_CHECK_MS = 2 * 60 * 1000
MAX_TAMPER_EVENTS = 3
TAMPER_COUNTER_FILE = ".nxtpass_tamper_counter"
EMERGENCY_WIPE_MODE = "quarantine"  # quarantine is safer than permanent delete
