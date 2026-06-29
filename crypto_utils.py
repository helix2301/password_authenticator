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

def encrypt_bytes(key, plaintext_bytes):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return nonce, ciphertext

def decrypt_bytes(key, nonce, ciphertext):
    return AESGCM(key).decrypt(nonce, ciphertext, None)

def encrypt_record(dek, data):
    return encrypt_bytes(dek, json.dumps(data, sort_keys=True).encode())

def decrypt_record(dek, nonce, ciphertext):
    return json.loads(decrypt_bytes(dek, nonce, ciphertext).decode())

def derive_integrity_key(dek):
    return hashlib.sha256(dek + b"NxTPass-integrity-key-v1").digest()

def derive_audit_key(dek):
    return hashlib.sha256(dek + b"NxTPass-audit-key-v1").digest()
