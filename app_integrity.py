import os
import sys
import json
import hmac
import hashlib
from pathlib import Path
from tkinter import messagebox


APP_INTEGRITY_MANIFEST = "app_manifest.json"
APP_INTEGRITY_KEY_FILE = "app_manifest.key"

PROTECTED_FILES = [
    "app_integrity.py",
    "main.py",
    "audit.py",
    "backup.py",
    "config.py",
    "crypto_utils.py",
    "database.py",
    "device_secret.py",
    "external_2fa.py",
    "integrity.py",
    "lockout_state.py",
    "rollback.py",
    "secure_runtime.py",
    "security.py",
    "session.py",
    "tamper.py",
    "ui_helpers.py",
    "ui_login.py",
    "ui_vault.py",
    "vault.py",
]


def app_base_dir():
    return Path(__file__).resolve().parent


def file_sha256(path):
    h = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


def load_manifest_key():
    key_path = app_base_dir() / APP_INTEGRITY_KEY_FILE

    if not key_path.exists():
        return None

    try:
        key = key_path.read_bytes()
        if len(key) >= 32:
            return key
    except Exception:
        return None

    return None


def compute_manifest_hmac(key, files):
    payload = json.dumps(
        {
            "version": 1,
            "files": files
        },
        sort_keys=True,
        separators=(",", ":")
    ).encode()

    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def load_manifest():
    manifest_path = app_base_dir() / APP_INTEGRITY_MANIFEST

    if not manifest_path.exists():
        return None

    try:
        return json.loads(manifest_path.read_text())
    except Exception:
        return None


def verify_application_integrity(show_success=False):
    """
    Best-effort source integrity verification.

    This detects accidental or casual modification of NxTPass Python files.

    Important limitation:
    If an attacker can edit the Python files and also edit/replace the
    manifest and manifest key, they can bypass this check. Strong protection requires distributing NxTPass as a code-signed
    executable and verifying signatures outside the editable source tree.
    """

    key = load_manifest_key()

    if key is None:
        messagebox.showerror(
            "Application Integrity Failed",
            (
                "Missing application integrity key.\n\n"
                "NxTPass will not start because app code integrity cannot be verified."
            )
        )
        return False

    manifest = load_manifest()

    if manifest is None:
        messagebox.showerror(
            "Application Integrity Failed",
            (
                "Missing or unreadable application integrity manifest.\n\n"
                "NxTPass will not start because app code integrity cannot be verified."
            )
        )
        return False

    expected_files = manifest.get("files", {})
    expected_hmac = manifest.get("hmac", "")

    actual_files = {}

    for filename in PROTECTED_FILES:
        path = app_base_dir() / filename

        if not path.exists():
            messagebox.showerror(
                "Application Integrity Failed",
                f"Protected application file is missing:\n{filename}"
            )
            return False

        actual_files[filename] = file_sha256(path)

    actual_hmac = compute_manifest_hmac(key, actual_files)

    if not hmac.compare_digest(actual_hmac, expected_hmac):
        changed = []

        for name, digest in actual_files.items():
            if expected_files.get(name) != digest:
                changed.append(name)

        if not changed:
            changed = ["manifest or manifest signature"]

        messagebox.showerror(
            "Application Integrity Failed",
            (
                "NxTPass application files appear to have been modified.\n\n"
                "Changed or suspicious files:\n"
                + "\n".join(f"• {name}" for name in changed)
                + "\n\nNxTPass will not start."
            )
        )
        return False

    if show_success:
        messagebox.showinfo(
            "Application Integrity",
            "NxTPass application integrity verified successfully."
        )

    return True
