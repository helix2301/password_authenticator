import os
import shutil
from datetime import datetime, timezone
from config import DB_FILE, TAMPER_COUNTER_FILE, MAX_TAMPER_EVENTS, EMERGENCY_WIPE_MODE


def read_tamper_count():
    try:
        if not os.path.exists(TAMPER_COUNTER_FILE):
            return 0
        with open(TAMPER_COUNTER_FILE, "r") as f:
            return int(f.read().strip())
    except Exception:
        return 0


def write_tamper_count(count):
    try:
        with open(TAMPER_COUNTER_FILE, "w") as f:
            f.write(str(count))
    except Exception:
        pass


def reset_tamper_count():
    write_tamper_count(0)


def record_tamper_event():
    count = read_tamper_count() + 1
    write_tamper_count(count)
    return count


def emergency_protect_database():
    """
    Emergency protection after repeated tamper detections.

    Default mode is quarantine, not permanent delete. This protects the user
    from accidental data loss while still preventing normal app use of the
    suspicious database.
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


def should_emergency_wipe():
    return read_tamper_count() >= MAX_TAMPER_EVENTS
