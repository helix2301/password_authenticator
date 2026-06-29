from app_integrity import verify_application_integrity


def main():
    if not verify_application_integrity():
        return

    # Import sensitive application modules only after source integrity passes.
    from secure_runtime import harden_process_best_effort
    from database import init_db
    from ui_login import start_login_window

    harden_process_best_effort()
    init_db()
    start_login_window()


if __name__ == "__main__":
    main()
