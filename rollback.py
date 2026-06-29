import os
from config import ROLLBACK_COUNTER_FILE, VAULT_COUNTER_KEY
from database import meta_get_text, meta_set_text

def read_external_counter():
    if not os.path.exists(ROLLBACK_COUNTER_FILE):
        return None

    try:
        with open(ROLLBACK_COUNTER_FILE, "r") as f:
            return int(f.read().strip())
    except Exception:
        return None

def write_external_counter(counter):
    try:
        with open(ROLLBACK_COUNTER_FILE, "w") as f:
            f.write(str(counter))
    except Exception:
        pass

def get_vault_counter():
    try:
        return int(meta_get_text(VAULT_COUNTER_KEY, "0"))
    except ValueError:
        return 0

def set_vault_counter(counter):
    meta_set_text(VAULT_COUNTER_KEY, counter)
    write_external_counter(counter)

def increment_vault_counter():
    counter = get_vault_counter() + 1
    set_vault_counter(counter)
    return counter

def verify_rollback_counter():
    db_counter = get_vault_counter()
    external_counter = read_external_counter()

    if external_counter is None:
        write_external_counter(db_counter)
        return True, ""

    if db_counter < external_counter:
        return False, "Older database detected. Possible rollback attack."

    if db_counter > external_counter:
        write_external_counter(db_counter)

    return True, ""
