import os
import sqlite3
import tkinter as tk
from tkinter import messagebox
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
import pyotp

MASTER_FILE = "master.hash"
DB_FILE = "authenticator.db"

ph = PasswordHasher()


# ---------- AUTH ----------

def master_exists():
    return os.path.exists(MASTER_FILE)


def create_master_password(password):
    if not password:
        raise ValueError("Master password cannot be empty")

    with open(MASTER_FILE, "w") as file:
        file.write(ph.hash(password))


def verify_master_password(password):
    if not master_exists():
        return False

    with open(MASTER_FILE, "r") as file:
        stored_hash = file.read()

    try:
        return ph.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError):
        return False


# ---------- DATABASE ----------

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS authenticator_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            secret TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def add_authenticator_code(service, username, secret):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO authenticator_codes (service, username, secret)
        VALUES (?, ?, ?)
    """, (service, username, secret))

    conn.commit()
    conn.close()


def get_authenticator_codes():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        SELECT id, service, username, secret
        FROM authenticator_codes
        ORDER BY service
    """)

    rows = cur.fetchall()
    conn.close()
    return rows


def delete_authenticator_code(code_id):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("DELETE FROM authenticator_codes WHERE id = ?", (code_id,))

    conn.commit()
    conn.close()


# ---------- MAIN APP ----------

def open_main_window():
    init_db()

    main = tk.Tk()
    main.title("Authenticator Vault")
    main.geometry("600x500")

    def refresh_codes():
        listbox.delete(0, tk.END)

        for code_id, service, username, secret in get_authenticator_codes():
            try:
                totp = pyotp.TOTP(secret)
                current_code = totp.now()
                listbox.insert(
                    tk.END,
                    f"{code_id} | {service} | {username} | Code: {current_code}"
                )
            except Exception:
                listbox.insert(
                    tk.END,
                    f"{code_id} | {service} | {username} | Invalid secret"
                )

        main.after(30000, refresh_codes)

    def add_code_window():
        add_window = tk.Toplevel(main)
        add_window.title("Add Authenticator Code")
        add_window.geometry("400x300")

        tk.Label(add_window, text="Service").pack(pady=5)
        service_entry = tk.Entry(add_window, width=40)
        service_entry.pack()

        tk.Label(add_window, text="Username / Email").pack(pady=5)
        username_entry = tk.Entry(add_window, width=40)
        username_entry.pack()

        tk.Label(add_window, text="Secret Key").pack(pady=5)
        secret_entry = tk.Entry(add_window, width=40)
        secret_entry.pack()

        def save_code():
            service = service_entry.get().strip()
            username = username_entry.get().strip()
            secret = secret_entry.get().replace(" ", "").strip()

            if not service or not username or not secret:
                messagebox.showerror("Error", "All fields are required")
                return

            try:
                pyotp.TOTP(secret).now()
            except Exception:
                messagebox.showerror("Error", "Invalid authenticator secret key")
                return

            add_authenticator_code(service, username, secret)
            messagebox.showinfo("Success", "Authenticator code added")
            add_window.destroy()
            refresh_codes()

        tk.Button(add_window, text="Save", command=save_code).pack(pady=20)

    def delete_selected():
        selected = listbox.curselection()

        if not selected:
            messagebox.showerror("Error", "Select an item to delete")
            return

        item = listbox.get(selected[0])
        code_id = item.split("|")[0].strip()

        delete_authenticator_code(code_id)
        refresh_codes()

    tk.Label(
        main,
        text="Authenticator Codes",
        font=("Arial", 18)
    ).pack(pady=15)

    listbox = tk.Listbox(main, width=80, height=15)
    listbox.pack(pady=10)

    tk.Button(main, text="Refresh Codes", command=refresh_codes).pack(pady=5)
    tk.Button(main, text="Add Authenticator Code", command=add_code_window).pack(pady=5)
    tk.Button(main, text="Delete Selected", command=delete_selected).pack(pady=5)
    tk.Button(main, text="Exit", command=main.destroy).pack(pady=20)

    refresh_codes()
    main.mainloop()


# ---------- LOGIN ----------

def login():
    password = password_entry.get()

    if verify_master_password(password):
        messagebox.showinfo("Success", "Login successful")
        root.destroy()
        open_main_window()
    else:
        messagebox.showerror("Error", "Wrong master password")


def create_master():
    password = password_entry.get()
    confirm = confirm_entry.get()

    if password != confirm:
        messagebox.showerror("Error", "Passwords do not match")
        return

    try:
        create_master_password(password)
        messagebox.showinfo("Success", "Master password created")
        root.destroy()
        open_main_window()
    except ValueError as error:
        messagebox.showerror("Error", str(error))


# ---------- START UI ----------

root = tk.Tk()
root.title("Password Authenticator")
root.geometry("350x250")
root.resizable(False, False)

if not master_exists():
    tk.Label(root, text="Create Master Password", font=("Arial", 14)).pack(pady=15)

    tk.Label(root, text="Password").pack()
    password_entry = tk.Entry(root, show="*", width=30)
    password_entry.pack(pady=5)

    tk.Label(root, text="Confirm Password").pack()
    confirm_entry = tk.Entry(root, show="*", width=30)
    confirm_entry.pack(pady=5)

    tk.Button(root, text="Create Password", command=create_master).pack(pady=20)

else:
    tk.Label(root, text="Enter Master Password", font=("Arial", 14)).pack(pady=20)

    tk.Label(root, text="Password").pack()
    password_entry = tk.Entry(root, show="*", width=30)
    password_entry.pack(pady=5)

    tk.Button(root, text="Login", command=login).pack(pady=20)

root.mainloop()
