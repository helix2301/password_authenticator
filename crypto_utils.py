import os
import json
import hashlib
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(password, salt):
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=Type.ID
    )

def derive_backup_key(password, salt):
    return derive_key(password, salt)

def _normalize_aad(aad):
    if aad is None:
        return None
    if isinstance(aad, bytes):
        return aad
    return str(aad).encode()

def encrypt_bytes(key, plaintext_bytes, aad=None):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, _normalize_aad(aad))
    return nonce, ciphertext

def decrypt_bytes(key, nonce, ciphertext, aad=None):
    return AESGCM(key).decrypt(nonce, ciphertext, _normalize_aad(aad))

def encrypt_record(dek, data, aad=None):
    return encrypt_bytes(dek, json.dumps(data, sort_keys=True).encode(), aad=aad)

def decrypt_record(dek, nonce, ciphertext, aad=None):
    return json.loads(decrypt_bytes(dek, nonce, ciphertext, aad=aad).decode())

def derive_integrity_key(dek):
    return hashlib.sha256(dek + b"NxTPass-integrity-key-v1").digest()

def derive_audit_key(dek):
    return hashlib.sha256(dek + b"NxTPass-audit-key-v1").digest()


def derive_device_bound_key(master_password, salt):
    from device_secret import device_harden_password
    return derive_key(device_harden_password(master_password), salt)
