import tkinter as tk
from tkinter import messagebox
import pyotp
import qrcode
from PIL import ImageTk

from config import MAX_LOGIN_ATTEMPTS
from security import (
    vault_exists,
    is_login_locked,
    login_lock_remaining,
    get_failed_attempts,
    record_failed_login,
    reset_failed_logins,
)
from ui_helpers import load_logo
from vault import create_vault, unlock_vault
from backup import import_encrypted_backup
from ui_vault import open_main_window
from session import SecureSession

def start_login_window():
    root = tk.Tk()
    root.title("NxTPass Vault Login")
    root.resizable(False, False)

    login_window_active = True
    lockout_timer = None

    def close_login_window():
        nonlocal login_window_active, lockout_timer

        login_window_active = False

        if lockout_timer is not None:
            try:
                root.after_cancel(lockout_timer)
            except tk.TclError:
                pass

        root.destroy()

    root.protocol("WM_DELETE_WINDOW", close_login_window)

    if not vault_exists():
        root.geometry("470x900")

        twofa_secret = pyotp.random_base32()

        setup_uri = pyotp.TOTP(twofa_secret).provisioning_uri(
            name="NxTPass Vault Login",
            issuer_name="NxTPass Password Vault"
        )

        qr_image = qrcode.make(setup_uri)
        qr_image = qr_image.resize((190, 190))
        qr_photo = ImageTk.PhotoImage(qr_image)

        tk.Label(root, text="Create NxTPass Master Vault", font=("Arial", 14)).pack(pady=10)

        tk.Label(
            root,
            text=(
                "Password requirements:\\n"
                "• At least 12 characters\\n"
                "• At least one uppercase letter\\n"
                "• At least one lowercase letter\\n"
                "• At least one number\\n"
                "• At least one special character"
            ),
            justify="left",
            fg="darkgreen"
        ).pack(pady=5)

        tk.Label(root, text="Password").pack()
        password_entry = tk.Entry(root, show="*", width=35)
        password_entry.pack(pady=5)

        tk.Label(root, text="Confirm Password").pack()
        confirm_entry = tk.Entry(root, show="*", width=35)
        confirm_entry.pack(pady=5)

        tk.Label(
            root,
            text=(
                "Required 2FA Setup:\\n"
                "Scan this QR code with your authenticator app."
            ),
            justify="center"
        ).pack(pady=10)

        qr_label = tk.Label(root, image=qr_photo)
        qr_label.image = qr_photo
        qr_label.pack(pady=5)

        tk.Label(root, text="Manual setup key:").pack(pady=(10, 0))

        secret_text = tk.Text(root, height=2, width=45)
        secret_text.insert("1.0", twofa_secret)
        secret_text.config(state="disabled")
        secret_text.pack(pady=5)

        tk.Label(root, text="Enter 6-digit 2FA code").pack()
        twofa_entry = tk.Entry(root, width=20)
        twofa_entry.pack(pady=5)

        def create():
            password = password_entry.get()
            confirm = confirm_entry.get()
            twofa_code = twofa_entry.get().strip()

            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match.")
                return

            if not pyotp.TOTP(twofa_secret).verify(twofa_code, valid_window=1):
                messagebox.showerror("Error", "Invalid 2FA code.")
                return

            try:
                create_vault(password, twofa_secret)
                dek = unlock_vault(password, twofa_code)

                if not dek:
                    messagebox.showerror("Error", "Vault created, but unlock failed.")
                    return

                messagebox.showinfo("Success", "Vault created with 2FA and integrity protection enabled.")
                close_login_window()
                open_main_window(SecureSession(dek))

            except ValueError as error:
                messagebox.showerror("Weak Password", str(error))

        tk.Button(root, text="Create Vault", width=22, height=2, command=create).pack(pady=(20, 10))

        logo_photo = load_logo(85)

        if logo_photo:
            root.logo_photo = logo_photo
            tk.Label(root, image=logo_photo, borderwidth=0, highlightthickness=0).pack(pady=(5, 15))

    else:
        root.geometry("370x560")

        tk.Label(root, text="Enter Master Password", font=("Arial", 14, "bold")).pack(pady=(20, 10))

        logo_photo = load_logo(100)

        if logo_photo:
            root.logo_photo = logo_photo
            tk.Label(root, image=logo_photo, borderwidth=0).pack(pady=(0, 15))

        lockout_status = tk.Label(root, text="", fg="red")
        lockout_status.pack(pady=5)

        tk.Label(root, text="Password").pack()
        password_entry = tk.Entry(root, show="*", width=35)
        password_entry.pack(pady=5)

        tk.Label(root, text="2FA Code").pack()
        twofa_entry = tk.Entry(root, width=20)
        twofa_entry.pack(pady=5)

        def update_lockout_label():
            nonlocal lockout_timer, login_window_active

            if not login_window_active:
                return

            try:
                if not root.winfo_exists():
                    return

                if is_login_locked():
                    seconds = login_lock_remaining()
                    lockout_status.config(text=f"Locked. Try again in {seconds // 60}:{seconds % 60:02d}")
                else:
                    attempts = get_failed_attempts()
                    lockout_status.config(text=f"Failed attempts: {attempts}/{MAX_LOGIN_ATTEMPTS}" if attempts else "")

                lockout_timer = root.after(1000, update_lockout_label)

            except tk.TclError:
                return

        def login():
            if is_login_locked():
                messagebox.showerror(
                    "Locked",
                    f"Too many failed attempts. Try again in {login_lock_remaining()} seconds."
                )
                return

            password = password_entry.get()
            twofa_code = twofa_entry.get().strip()

            dek = unlock_vault(password, twofa_code)

            if dek:
                reset_failed_logins()
                messagebox.showinfo("Success", "Vault unlocked. Integrity verified.")
                close_login_window()
                open_main_window(SecureSession(dek))
            else:
                record_failed_login()

                if is_login_locked():
                    messagebox.showerror("Locked", "Too many failed attempts. Login locked for 10 minutes.")
                else:
                    messagebox.showerror("Error", "Wrong master password, 2FA code, or vault integrity failure.")

        tk.Button(root, text="Unlock Vault", command=login).pack(pady=15)
        tk.Button(root, text="Import Backup", command=import_encrypted_backup).pack(pady=5)

        update_lockout_label()

    root.mainloop()
