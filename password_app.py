import os
import json
import sqlite3
import tkinter as tk
from tkinter import messagebox

import pyotp
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type
from argon2.exceptions import VerifyMismatchError, VerificationError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DB_FILE = "authenticator.db"
LOCK_TIMEOUT_MS = 5 * 60 * 1000

ph = PasswordHasher()


# ---------- DATABASE ----------

def db_connect():
    return sqlite3.connect(DB_FILE)


def init_db():
    conn = db_connect()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS vault_meta (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS authenticator_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def meta_get(key):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT value FROM vault_meta WHERE key = ?", (key,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None


def meta_set(key, value):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT OR REPLACE INTO vault_meta (key, value)
        VALUES (?, ?)
    """, (key, value))
    conn.commit()
    conn.close()


# ---------- CRYPTO ----------

def derive_key(master_password, salt):
    return hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=Type.ID
    )


def encrypt_bytes(key, plaintext_bytes):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return nonce, ciphertext


def decrypt_bytes(key, nonce, ciphertext):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_record(dek, data):
    plaintext = json.dumps(data).encode()
    return encrypt_bytes(dek, plaintext)


def decrypt_record(dek, nonce, ciphertext):
    plaintext = decrypt_bytes(dek, nonce, ciphertext)
    return json.loads(plaintext.decode())


# ---------- VAULT SETUP / LOGIN ----------

def vault_exists():
    return meta_get("master_hash") is not None


def create_vault(master_password):
    if not master_password:
        raise ValueError("Master password cannot be empty")

    master_hash = ph.hash(master_password)
    kdf_salt = os.urandom(16)

    kek = derive_key(master_password, kdf_salt)
    dek = os.urandom(32)

    dek_nonce, encrypted_dek = encrypt_bytes(kek, dek)

    meta_set("master_hash", master_hash.encode())
    meta_set("kdf_salt", kdf_salt)
    meta_set("dek_nonce", dek_nonce)
    meta_set("encrypted_dek", encrypted_dek)


def unlock_vault(master_password):
    master_hash = meta_get("master_hash")

    if not master_hash:
        return None

    try:
        ph.verify(master_hash.decode(), master_password)
    except (VerifyMismatchError, VerificationError):
        return None

    kdf_salt = meta_get("kdf_salt")
    dek_nonce = meta_get("dek_nonce")
    encrypted_dek = meta_get("encrypted_dek")

    kek = derive_key(master_password, kdf_salt)

    try:
        dek = decrypt_bytes(kek, dek_nonce, encrypted_dek)
        return dek
    except Exception:
        return None


# ---------- AUTHENTICATOR STORAGE ----------

def add_authenticator(service, username, secret, dek):
    data = {
        "username": username,
        "secret": secret
    }

    nonce, ciphertext = encrypt_record(dek, data)

    conn = db_connect()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO authenticator_codes
        (service, nonce, ciphertext)
        VALUES (?, ?, ?)
    """, (service, nonce, ciphertext))

    conn.commit()
    conn.close()


def get_authenticators():
    conn = db_connect()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, service, nonce, ciphertext
        FROM authenticator_codes
        ORDER BY service
    """)

    rows = cur.fetchall()
    conn.close()
    return rows


def delete_authenticator(code_id):
    conn = db_connect()
    cur = conn.cursor()

    cur.execute("DELETE FROM authenticator_codes WHERE id = ?", (code_id,))

    conn.commit()
    conn.close()


# ---------- MAIN WINDOW ----------

def open_main_window(dek):
    main = tk.Tk()
    main.title("Secure Authenticator Vault")
    main.geometry("700x500")

    lock_timer = None

    def lock_app():
        messagebox.showinfo("Locked", "Vault locked due to inactivity")
        main.destroy()

    def reset_lock_timer(event=None):
        nonlocal lock_timer

        if lock_timer:
            main.after_cancel(lock_timer)

        lock_timer = main.after(LOCK_TIMEOUT_MS, lock_app)

    main.bind_all("<Key>", reset_lock_timer)
    main.bind_all("<Button>", reset_lock_timer)

    def refresh_codes():
        listbox.delete(0, tk.END)

        for code_id, service, nonce, ciphertext in get_authenticators():
            try:
                data = decrypt_record(dek, nonce, ciphertext)
                username = data["username"]
                secret = data["secret"]

                code = pyotp.TOTP(secret).now()

                listbox.insert(
                    tk.END,
                    f"{code_id} | {service} | {username} | Code: {code}"
                )

            except Exception:
                listbox.insert(
                    tk.END,
                    f"{code_id} | {service} | Unable to decrypt"
                )

        main.after(30000, refresh_codes)

    def add_code_window():
        win = tk.Toplevel(main)
        win.title("Add Authenticator")
        win.geometry("400x320")

        tk.Label(win, text="Service").pack(pady=5)
        service_entry = tk.Entry(win, width=40)
        service_entry.pack()

        tk.Label(win, text="Username / Email").pack(pady=5)
        username_entry = tk.Entry(win, width=40)
        username_entry.pack()

        tk.Label(win, text="Authenticator Secret Key").pack(pady=5)
        secret_entry = tk.Entry(win, show="*", width=40)
        secret_entry.pack()

        def save():
            service = service_entry.get().strip()
            username = username_entry.get().strip()
            secret = secret_entry.get().replace(" ", "").strip()

            if not service or not username or not secret:
                messagebox.showerror("Error", "All fields are required")
                return

            try:
                pyotp.TOTP(secret).now()
            except Exception:
                messagebox.showerror("Error", "Invalid authenticator secret")
                return

            add_authenticator(service, username, secret, dek)

            messagebox.showinfo("Saved", "Authenticator encrypted and saved")
            win.destroy()
            refresh_codes()

        tk.Button(win, text="Save", command=save).pack(pady=20)

    def delete_selected():
        selected = listbox.curselection()

        if not selected:
            messagebox.showerror("Error", "Select an item first")
            return

        item = listbox.get(selected[0])
        code_id = item.split("|")[0].strip()

        delete_authenticator(code_id)
        refresh_codes()

    tk.Label(
        main,
        text="Secure Authenticator Vault",
        font=("Arial", 18)
    ).pack(pady=15)

    listbox = tk.Listbox(main, width=95, height=15)
    listbox.pack(pady=10)

    tk.Button(main, text="Add Authenticator", command=add_code_window).pack(pady=5)
    tk.Button(main, text="Refresh Codes", command=refresh_codes).pack(pady=5)
    tk.Button(main, text="Delete Selected", command=delete_selected).pack(pady=5)
    tk.Button(main, text="Lock / Exit", command=main.destroy).pack(pady=20)

    reset_lock_timer()
    refresh_codes()
    main.mainloop()


# ---------- LOGIN WINDOW ----------

def start_login_window():
    root = tk.Tk()
    root.title("Vault Login")
    root.geometry("350x260")
    root.resizable(False, False)

    if not vault_exists():
        tk.Label(root, text="Create Master Password", font=("Arial", 14)).pack(pady=15)

        tk.Label(root, text="Password").pack()
        password_entry = tk.Entry(root, show="*", width=30)
        password_entry.pack(pady=5)

        tk.Label(root, text="Confirm Password").pack()
        confirm_entry = tk.Entry(root, show="*", width=30)
        confirm_entry.pack(pady=5)

        def create():
            password = password_entry.get()
            confirm = confirm_entry.get()

            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match")
                return

            try:
                create_vault(password)
                dek = unlock_vault(password)

                messagebox.showinfo("Success", "Vault created")
                root.destroy()
                open_main_window(dek)

            except ValueError as error:
                messagebox.showerror("Error", str(error))

        tk.Button(root, text="Create Vault", command=create).pack(pady=20)

    else:
        tk.Label(root, text="Enter Master Password", font=("Arial", 14)).pack(pady=20)

        tk.Label(root, text="Password").pack()
        password_entry = tk.Entry(root, show="*", width=30)
        password_entry.pack(pady=5)

        def login():
            password = password_entry.get()
            dek = unlock_vault(password)

            if dek:
                messagebox.showinfo("Success", "Vault unlocked")
                root.destroy()
                open_main_window(dek)
            else:
                messagebox.showerror("Error", "Wrong master password")

        tk.Button(root, text="Unlock Vault", command=login).pack(pady=20)

    root.mainloop()


# ---------- START ----------

init_db()
start_login_window()
