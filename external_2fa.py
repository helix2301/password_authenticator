import os
import json
import hmac
import hashlib
import platform
from pathlib import Path

from config import VAULT_UUID_KEY
from database import meta_get_text
from crypto_utils import encrypt_bytes, decrypt_bytes
from device_secret import load_or_create_device_secret


APP_DIR_NAME = "NxTPass"
EXTERNAL_2FA_FILE = "vault_2fa_state.json"


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


def get_2fa_state_path():
    return get_app_support_dir() / EXTERNAL_2FA_FILE


def get_vault_uuid():
    return meta_get_text(VAULT_UUID_KEY, "")


def derive_external_2fa_key():
    return hashlib.sha256(
        load_or_create_device_secret() + b"NxTPass external vault 2FA v1"
    ).digest()


def compute_state_hmac(key, vault_uuid, nonce_hex, ciphertext_hex):
    message = json.dumps(
        {
            "vault_uuid": vault_uuid,
            "nonce": nonce_hex,
            "ciphertext": ciphertext_hex,
            "purpose": "NxTPass external vault login 2FA v1"
        },
        sort_keys=True,
        separators=(",", ":")
    ).encode()

    return hmac.new(key, message, hashlib.sha256).hexdigest()


def save_external_twofa_secret(twofa_secret):
    """
    Store the vault-login TOTP seed outside authenticator.db.

    This prevents a copied database plus master password from exposing the same
    TOTP seed stored in the user's authenticator app.
    """
    vault_uuid = get_vault_uuid()

    if not vault_uuid:
        raise ValueError("Cannot save external 2FA state because vault UUID is missing.")

    key = derive_external_2fa_key()
    nonce, ciphertext = encrypt_bytes(key, twofa_secret.encode())

    nonce_hex = nonce.hex()
    ciphertext_hex = ciphertext.hex()

    state = {
        "version": 1,
        "vault_uuid": vault_uuid,
        "nonce": nonce_hex,
        "ciphertext": ciphertext_hex,
        "hmac": compute_state_hmac(key, vault_uuid, nonce_hex, ciphertext_hex)
    }

    path = get_2fa_state_path()
    path.write_text(json.dumps(state, indent=2))

    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def load_external_twofa_secret():
    path = get_2fa_state_path()

    if not path.exists():
        raise ValueError("External vault 2FA state is missing.")

    state = json.loads(path.read_text())

    key = derive_external_2fa_key()

    vault_uuid = state.get("vault_uuid", "")
    current_vault_uuid = get_vault_uuid()

    if current_vault_uuid and vault_uuid != current_vault_uuid:
        raise ValueError("External vault 2FA state belongs to a different vault.")

    nonce_hex = state["nonce"]
    ciphertext_hex = state["ciphertext"]
    stored_hmac = state["hmac"]

    expected_hmac = compute_state_hmac(key, vault_uuid, nonce_hex, ciphertext_hex)

    if not hmac.compare_digest(expected_hmac, stored_hmac):
        raise ValueError("External vault 2FA state HMAC verification failed.")

    plaintext = decrypt_bytes(
        key,
        bytes.fromhex(nonce_hex),
        bytes.fromhex(ciphertext_hex)
    )

    return plaintext.decode()


def external_twofa_exists():
    return get_2fa_state_path().exists()
