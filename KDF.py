import os
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import padding

# Constants
AES_BLOCK_SIZE = 16  # Block size for AES encryption
SALT_SIZE = 16  # Length of the salt used for key derivation

# Use Argon2id for KDF (Password hashing)
def derive_key(password: str, salt: bytes) -> bytes:
    ph = PasswordHasher(time_cost=2, memory_cost=2**16, parallelism=1)
    return ph.hash(password + salt.hex())  # Derive key using the password and salt

# AES-GCM Encryption (for confidentiality and integrity)
def encrypt_file(file_path: str, password: str):
    salt = os.urandom(SALT_SIZE)  # Generate a random salt for key derivation
    key = derive_key(password, salt)

    with open(file_path, 'rb') as f:
        data = f.read()

    # AES-GCM encryption setup
    nonce = os.urandom(12)  # Random nonce
    cipher = Cipher(algorithms.AES(key.encode()), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    # Store metadata (salt + nonce + tag) for later use
    with open(f"{file_path}.enc", 'wb') as enc_file:
        enc_file.write(salt + nonce + encryptor.tag + encrypted_data)

# AES-GCM Decryption
def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        metadata = f.read(28)  # First 28 bytes contain salt, nonce, and tag
        encrypted_data = f.read()

    salt = metadata[:SALT_SIZE]
    nonce = metadata[SALT_SIZE:SALT_SIZE+12]
    tag = metadata[SALT_SIZE+12:SALT_SIZE+28]

    key = derive_key(password, salt)

    # AES-GCM decryption setup
    cipher = Cipher(algorithms.AES(key.encode()), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    with open(f"{file_path}.dec", 'wb') as dec_file:
        dec_file.write(decrypted_data)

# HMAC for Integrity Protection
def generate_mac(file_path: str, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)  # Random salt for MAC
    key = derive_key(password, salt)
    hmac = HMAC(key.encode(), hashes.SHA256(), backend=default_backend())

    with open(file_path, 'rb') as f:
        data = f.read()
        hmac.update(data)

    return hmac.finalize()

def verify_mac(file_path: str, password: str, expected_mac: bytes) -> bool:
    generated_mac = generate_mac(file_path, password)
    return generated_mac == expected_mac

# Key Rotation
def rotate_key(salt: bytes, password: str) -> bytes:
    # You can alter salt or use a timestamp to change the key periodically
    return derive_key(password, salt)

 
import tkinter as tk
from tkinter import filedialog

root = tk.Tk()
root.withdraw()  # Hide the main window

fileToEncrypt = filedialog.askopenfile(
    parent=root,
    initialdir="/",
    title='Please select file to be encrypted'
)

