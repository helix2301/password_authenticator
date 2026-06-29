import time
import tkinter as tk
from tkinter import messagebox, ttk
import pyotp

from config import LOCK_TIMEOUT_MS, CLIPBOARD_CLEAR_MS, SESSION_CHECK_MS, INTEGRITY_CHECK_MS
from ui_helpers import load_logo
from vault import get_vault_items, add_vault_entry, update_vault_entry, delete_vault_entry
from backup import export_encrypted_backup, import_encrypted_backup
from integrity import get_vault_fingerprint, verify_database_hmac, verify_vault_fingerprint, automatic_integrity_check, database_self_repair_best_effort
from audit import verify_audit_chain
from rollback import verify_rollback_counter
from tamper import record_tamper_event, reset_tamper_count, should_emergency_wipe, emergency_protect_database
from secure_runtime import secure_window_shutdown, clear_clipboard_securely, force_garbage_collection

def open_main_window(session):
    main = tk.Tk()
    main.title("NxTPass Secure Password and Authenticator Vault")
    main.geometry("1050x660")

    lock_timer = None
    clipboard_timer = None
    refresh_timer = None
    decrypted_cache = {}

    def dek():
        return session.get_dek()

    logo_photo = load_logo(80)
    if logo_photo:
        main.logo_photo = logo_photo
        tk.Label(main, image=logo_photo).pack(pady=5)

    def cleanup_and_close():
        try:
            session.wipe()
        except Exception:
            pass

        secure_window_shutdown(
            main,
            timers=[lock_timer, clipboard_timer, refresh_timer],
            decrypted_cache=decrypted_cache
        )

    def lock_app():
        clear_clipboard_securely(main)
        messagebox.showinfo("Locked", "Vault locked due to inactivity.")
        cleanup_and_close()

    def reset_lock_timer(event=None):
        nonlocal lock_timer

        if lock_timer:
            try:
                main.after_cancel(lock_timer)
            except tk.TclError:
                pass

        lock_timer = main.after(LOCK_TIMEOUT_MS, lock_app)

    def clear_clipboard():
        clear_clipboard_securely(main)
        try:
            status_label.config(text="Clipboard cleared.")
        except tk.TclError:
            pass

    def copy_to_clipboard(value, message):
        nonlocal clipboard_timer

        clear_clipboard_securely(main, passes=1)
        main.clipboard_append(value)
        main.update()

        if clipboard_timer:
            try:
                main.after_cancel(clipboard_timer)
            except tk.TclError:
                pass

        clipboard_timer = main.after(CLIPBOARD_CLEAR_MS, clear_clipboard)
        status_label.config(text=message + " Clipboard will clear in 30 seconds.")

    main.protocol("WM_DELETE_WINDOW", cleanup_and_close)
    main.bind_all("<Key>", reset_lock_timer)
    main.bind_all("<Button>", reset_lock_timer)

    tk.Label(main, text="NxTPass Secure Password and Authenticator Vault", font=("Arial", 18)).pack(pady=10)

    fingerprint = get_vault_fingerprint()
    short_fingerprint = fingerprint[:16] + "..." if fingerprint else "Unknown"
    tk.Label(main, text=f"Vault Fingerprint: {short_fingerprint}", font=("Arial", 9), fg="gray").pack(pady=(0, 2))
    tk.Label(main, text="Storage: separated encrypted identity, password, and TOTP tables", font=("Arial", 9), fg="gray").pack(pady=(0, 5))

    tree = ttk.Treeview(main, columns=("service", "username", "password", "code", "expires"), show="headings", height=15)

    columns = [
        ("service", "Service", 220, "w"),
        ("username", "Username", 270, "w"),
        ("password", "Password", 120, "center"),
        ("code", "Authenticator Code", 160, "center"),
        ("expires", "Expires", 80, "center"),
    ]

    for col, label, width, anchor in columns:
        tree.heading(col, text=label)
        tree.column(col, width=width, anchor=anchor)

    tree.pack(fill="both", expand=True, padx=10, pady=10)

    status_label = tk.Label(main, text="Ready", anchor="w")
    status_label.pack(fill="x", padx=10, pady=5)

    def refresh_codes():
        nonlocal refresh_timer

        try:
            remaining = 30 - (int(time.time()) % 30)
            current_ids = set()
            entries = []

            for data in get_vault_items(dek()):
                item_id = str(data.get("id", ""))
                current_ids.add(item_id)
                decrypted_cache[item_id] = data

                service = data.get("service", "")
                username = data.get("username", "")
                password = data.get("password", "")
                secret = data.get("secret", "")

                code = "------"

                if secret:
                    try:
                        raw_code = pyotp.TOTP(secret).now()
                        code = f"{raw_code[:3]} {raw_code[3:]}"
                    except Exception:
                        code = "Invalid"

                entries.append((item_id, (
                    service,
                    username,
                    "Saved" if password else "None",
                    code,
                    f"{remaining}s"
                )))

            entries.sort(key=lambda item: str(item[1][0]).lower())
            existing_ids = set(tree.get_children())

            for item_id, values in entries:
                if tree.exists(item_id):
                    tree.item(item_id, values=values)
                else:
                    tree.insert("", "end", iid=item_id, values=values)

            for item_id in existing_ids:
                if item_id not in current_ids:
                    tree.delete(item_id)
                    decrypted_cache.pop(item_id, None)

            refresh_timer = main.after(1000, refresh_codes)

        except tk.TclError:
            return

    def get_selected_item():
        selected = tree.selection()

        if not selected:
            messagebox.showerror("Error", "Please select an entry.")
            return None

        return selected[0]

    def copy_selected_username():
        item_id = get_selected_item()
        if not item_id:
            return

        data = decrypted_cache.get(item_id)
        username = data.get("username", "") if data else ""

        if not username:
            messagebox.showerror("Error", "No username saved for this entry.")
            return

        copy_to_clipboard(username, f"Copied username: {username}")

    def copy_selected_password():
        item_id = get_selected_item()
        if not item_id:
            return

        data = decrypted_cache.get(item_id)
        password = data.get("password", "") if data else ""

        if not password:
            messagebox.showerror("Error", "No password saved for this entry.")
            return

        copy_to_clipboard(password, "Copied password.")

    def copy_selected_code():
        item_id = get_selected_item()
        if not item_id:
            return

        data = decrypted_cache.get(item_id)
        secret = data.get("secret", "") if data else ""

        if not secret:
            messagebox.showerror("Error", "No authenticator secret saved for this entry.")
            return

        try:
            code = pyotp.TOTP(secret).now()
        except Exception:
            messagebox.showerror("Error", "Invalid authenticator secret.")
            return

        copy_to_clipboard(code, f"Copied code: {code}")

    tree.bind("<Double-1>", lambda event: copy_selected_code())

    def entry_window(mode="add"):
        editing = mode == "edit"
        item_id = None
        existing = {}

        if editing:
            item_id = get_selected_item()
            if not item_id:
                return

            if str(item_id).startswith("legacy-"):
                messagebox.showerror(
                    "Legacy Entry",
                    "Legacy all-in-one entries can be deleted, but not edited. "
                    "Create a new entry to store it using separated password/TOTP tables."
                )
                return

            existing = decrypted_cache.get(item_id)

            if not existing:
                messagebox.showerror("Error", "Could not decrypt selected entry.")
                return

        win = tk.Toplevel(main)
        win.title("Edit Vault Entry" if editing else "Add Vault Entry")
        win.geometry("420x400")
        win.resizable(False, False)

        tk.Label(win, text="Service").pack(pady=5)
        service_entry = tk.Entry(win, width=42)
        service_entry.pack()

        tk.Label(win, text="Username / Email").pack(pady=5)
        username_entry = tk.Entry(win, width=42)
        username_entry.pack()

        tk.Label(win, text="Password").pack(pady=5)
        password_entry = tk.Entry(win, show="*", width=42)
        password_entry.pack()

        tk.Label(win, text="Authenticator Secret Key").pack(pady=5)
        secret_entry = tk.Entry(win, show="*", width=42)
        secret_entry.pack()

        if editing:
            service_entry.insert(0, existing.get("service", ""))
            username_entry.insert(0, existing.get("username", ""))
            password_entry.insert(0, existing.get("password", ""))
            secret_entry.insert(0, existing.get("secret", ""))

        def save():
            service = service_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get()
            secret = secret_entry.get().replace(" ", "").strip()

            if not service:
                messagebox.showerror("Error", "Service is required.")
                return

            if not username:
                messagebox.showerror("Error", "Username is required.")
                return

            if not password and not secret:
                messagebox.showerror("Error", "Enter a password, an authenticator secret, or both.")
                return

            if secret:
                try:
                    pyotp.TOTP(secret).now()
                except Exception:
                    messagebox.showerror("Error", "Invalid authenticator secret.")
                    return

            if editing:
                update_vault_entry(item_id, service, username, password, secret, dek())
                status_label.config(text="Entry updated and re-encrypted.")
            else:
                add_vault_entry(service, username, password, secret, dek())
                status_label.config(text="Entry encrypted and saved.")

            win.destroy()
            force_garbage_collection()
            refresh_codes()

        tk.Button(win, text="Save Changes" if editing else "Save", width=15, command=save).pack(pady=20)

    def delete_selected():
        item_id = get_selected_item()

        if not item_id:
            return

        confirm = messagebox.askyesno("Confirm Delete", "Delete the selected entry?")

        if not confirm:
            return

        delete_vault_entry(item_id, dek())
        decrypted_cache.pop(item_id, None)
        status_label.config(text="Entry deleted.")
        force_garbage_collection()
        refresh_codes()

    def verify_integrity_now():
        checks = [
            verify_audit_chain(dek()),
            verify_database_hmac(dek()),
            verify_vault_fingerprint(),
            verify_rollback_counter(),
        ]

        if all(ok for ok, _ in checks):
            messagebox.showinfo("Integrity Check", "Vault integrity verified successfully.")
        else:
            messagebox.showerror(
                "Integrity Check Failed",
                "\\n".join(msg for ok, msg in checks if not ok)
            )


    def session_health_check():
        try:
            if not session.is_active:
                cleanup_and_close()
                return
            session.touch()
            main.after(SESSION_CHECK_MS, session_health_check)
        except tk.TclError:
            return

    def periodic_integrity_check():
        try:
            ok, msg = automatic_integrity_check(dek())

            if not ok:
                count = record_tamper_event()

                if should_emergency_wipe():
                    protected_path = emergency_protect_database()
                    messagebox.showerror(
                        "Emergency Protection Triggered",
                        (
                            f"{msg}\n\n"
                            f"Repeated tamper detections: {count}\n"
                            "The suspicious database has been quarantined or removed.\n\n"
                            f"Result: {protected_path}"
                        )
                    )
                    cleanup_and_close()
                    return

                messagebox.showerror(
                    "Automatic Integrity Check Failed",
                    f"{msg}\n\nTamper warning count: {count}"
                )
                cleanup_and_close()
                return

            reset_tamper_count()
            main.after(INTEGRITY_CHECK_MS, periodic_integrity_check)

        except tk.TclError:
            return
        except Exception as error:
            messagebox.showerror("Integrity Check Error", str(error))
            cleanup_and_close()

    def run_self_repair():
        ok, msg = database_self_repair_best_effort()
        if ok:
            messagebox.showinfo("Database Self-Repair", msg)
        else:
            messagebox.showerror("Database Self-Repair Failed", msg)

    button_frame = tk.Frame(main)
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="Copy Username", width=16, command=copy_selected_username).grid(row=0, column=0, padx=5, pady=5)
    tk.Button(button_frame, text="Copy Password", width=16, command=copy_selected_password).grid(row=0, column=1, padx=5, pady=5)
    tk.Button(button_frame, text="Copy Code", width=16, command=copy_selected_code).grid(row=0, column=2, padx=5, pady=5)
    tk.Button(button_frame, text="Lock Vault", width=16, command=cleanup_and_close).grid(row=0, column=3, padx=5, pady=5)

    tk.Button(button_frame, text="Add", width=16, command=lambda: entry_window("add")).grid(row=1, column=0, padx=5, pady=5)
    tk.Button(button_frame, text="Edit", width=16, command=lambda: entry_window("edit")).grid(row=1, column=1, padx=5, pady=5)
    tk.Button(button_frame, text="Delete", width=16, command=delete_selected).grid(row=1, column=2, padx=5, pady=5)
    tk.Button(button_frame, text="Backup Vault", width=16, command=export_encrypted_backup).grid(row=1, column=3, padx=5, pady=5)
    tk.Button(button_frame, text="Restore Vault", width=16, command=import_encrypted_backup).grid(row=1, column=4, padx=5, pady=5)

    tk.Button(button_frame, text="Verify Integrity", width=16, command=verify_integrity_now).grid(row=2, column=0, padx=5, pady=5)
    tk.Button(button_frame, text="Self-Repair", width=16, command=run_self_repair).grid(row=2, column=1, padx=5, pady=5)

    refresh_codes()
    reset_lock_timer()
    session_health_check()
    periodic_integrity_check()
    main.mainloop()
