import os
import hmac
import hashlib
import secrets
import platform
from pathlib import Path


APP_DIR_NAME = "NxTPass"
DEVICE_SECRET_FILE = "device_secret.key"


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


def get_device_secret_path():
    return get_app_support_dir() / DEVICE_SECRET_FILE


def load_or_create_device_secret():
    """
    Local device-bound pepper.

    This is intentionally stored outside authenticator.db. A copied database
    alone is not enough to test guesses against the protected verifier or
    encrypted DEK.

    Limitation:
    If an attacker copies the database AND this device secret, offline attacks
    are possible again. Stronger protection requires TPM/Secure Enclave/Keychain
    non-exportable keys or server-side rate limiting.
    """
    path = get_device_secret_path()

    if path.exists():
        try:
            raw = path.read_bytes()
            if len(raw) >= 32:
                return raw
        except Exception:
            pass

    secret = secrets.token_bytes(32)
    path.write_bytes(secret)

    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

    return secret


def device_harden_password(master_password):
    """
    Convert the user's password into a device-bound secret before Argon2id.

    This prevents testing the password against the copied database alone
    because the attacker also needs the local device secret.
    """
    device_secret = load_or_create_device_secret()
    return hmac.new(
        device_secret,
        master_password.encode(),
        hashlib.sha256
    ).hexdigest()
