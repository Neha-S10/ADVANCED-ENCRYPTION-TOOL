import os
import base64
from tkinter import *
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# Derive a 32-byte AES key from password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_path, password):
    try:
        salt = os.urandom(16)
        key = derive_key(password, salt)
        fernet = Fernet(key)

        with open(file_path, 'rb') as f:
            data = f.read()
        encrypted = fernet.encrypt(data)

        new_file = file_path + ".enc"
        with open(new_file, 'wb') as f:
            f.write(salt + encrypted)

        return new_file
    except Exception as e:
        return str(e)

def decrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            encrypted_data = f.read()

        key = derive_key(password, salt)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_data)

        original_file = file_path.replace('.enc', '') + '.dec'
        with open(original_file, 'wb') as f:
            f.write(decrypted)

        return original_file
    except Exception as e:
        return str(e)

# ---------------- UI ----------------
def browse_file():
    filename = filedialog.askopenfilename()
    file_path.set(filename)

def do_encrypt():
    f = file_path.get()
    pwd = password.get()
    if not f or not pwd:
        messagebox.showwarning("Input Missing", "Please select a file and enter password.")
        return
    result = encrypt_file(f, pwd)
    messagebox.showinfo("Encryption Done", f"File encrypted to:\n{result}")

def do_decrypt():
    f = file_path.get()
    pwd = password.get()
    if not f or not pwd:
        messagebox.showwarning("Input Missing", "Please select a file and enter password.")
        return
    result = decrypt_file(f, pwd)
    messagebox.showinfo("Decryption Done", f"File decrypted to:\n{result}")

# Tkinter GUI
root = Tk()
root.title("AES-256 Encryption Tool")
root.geometry("400x250")
root.resizable(False, False)

Label(root, text="Advanced AES-256 File Encryptor", font=("Arial", 14, "bold")).pack(pady=10)

file_path = StringVar()
password = StringVar()

Entry(root, textvariable=file_path, width=40).pack(pady=5)
Button(root, text="Browse File", command=browse_file).pack()

Entry(root, textvariable=password, show="*", width=30).pack(pady=10)
Label(root, text="Enter Password").pack()

Button(root, text="Encrypt File", command=do_encrypt, bg="green", fg="white").pack(pady=5)
Button(root, text="Decrypt File", command=do_decrypt, bg="blue", fg="white").pack(pady=5)

root.mainloop()
