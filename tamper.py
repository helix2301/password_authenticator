import os
import shutil
from datetime import datetime, timezone
from config import DB_FILE, EMERGENCY_WIPE_MODE


def emergency_protect_database():
    """
    Immediate fail-closed tamper response.

    Default mode is quarantine, not permanent delete.
    """
    if not os.path.exists(DB_FILE):
        return None

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if EMERGENCY_WIPE_MODE == "delete":
        os.remove(DB_FILE)
        return "deleted"

    quarantine_name = f"{DB_FILE}.TAMPER_QUARANTINED_{timestamp}"
    shutil.move(DB_FILE, quarantine_name)
    return quarantine_name


def handle_confirmed_tamper(reason, title="Tamper Detected"):
    protected_path = emergency_protect_database()

    return (
        title,
        (
            f"{reason}\n\n"
            "NxTPass has failed closed immediately.\n"
            "The suspicious database has been quarantined or removed.\n\n"
            f"Result: {protected_path}\n\n"
            "Restore from a verified backup."
        )
    )


# Backward-compatible stubs for older imports.
def read_tamper_count():
    return 0


def write_tamper_count(count):
    return None


def reset_tamper_count():
    return None


def record_tamper_event():
    return 1


def should_emergency_wipe():
    return True
