import tkinter as tk
from tkinter import filedialog
import os
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import padding
from argon2.low_level import hash_secret_raw, Type

# Constants
AES_BLOCK_SIZE = 16  # Block size for AES encryption
SALT_SIZE = 16  # Length of the salt used for key derivation

# Use Argon2id for KDF (Password hashing)

def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=2,
        memory_cost=2**16,
        parallelism=1,
        hash_len=32,  # AES-256
        type=Type.ID
    )
# AES-GCM Encryption (for confidentiality and integrity)
def encrypt_file(file_path: str, password: str):
    salt = os.urandom(SALT_SIZE)  # Generate a random salt for key derivation
    key = derive_key(password, salt)

    with open(file_path, 'rb') as f:
        data = f.read()

    # AES-GCM encryption setup
    nonce = os.urandom(12)  # Random nonce
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    # Store metadata (salt + nonce + tag) for later use
    with open(file_path, 'wb') as f:
        f.write(salt + nonce + encryptor.tag + encrypted_data)

# AES-GCM Decryption
def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        metadata = f.read(44)  # 16 (salt) + 12 (nonce) + 16 (tag)
        encrypted_data = f.read()

    salt = metadata[:SALT_SIZE]
    nonce = metadata[SALT_SIZE:SALT_SIZE+12]
    tag = metadata[SALT_SIZE+12:SALT_SIZE+28]

    key = derive_key(password, salt)

    # AES-GCM decryption setup
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    with open(file_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)

# HMAC for Integrity Protection
def generate_mac(file_path: str, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)  # Random salt for MAC
    key = derive_key(password, salt)
    hmac = HMAC(key, hashes.SHA256(), backend=default_backend())

    with open(file_path, 'rb') as f:
        data = f.read()
        hmac.update(data)
        
    return hmac.finalize() , salt

def protect_file_integrity(file_path: str, password: str):
    mac, salt = generate_mac(file_path, password)

    with open(file_path + ".mac", 'wb') as f:
        f.write(salt + mac)

    print(f"Integrity tag stored in {file_path}.mac")

def verify_file_integrity(file_path: str, password: str):
    with open(file_path + ".mac", 'rb') as f:
        data = f.read()
        salt = data[:SALT_SIZE]
        expected_mac = data[SALT_SIZE:]

    key = derive_key(password, salt)
    h = HMAC(key, hashes.SHA256(), backend=default_backend())

    with open(file_path, 'rb') as f:
        h.update(f.read())

    try:
        h.verify(expected_mac)
        print("[✓] File integrity: VALID")
        return True
    except Exception:
        print("[✗] File integrity: INVALID or wrong password")
        return False

def fileSelector():
    root = tk.Tk()
    root.withdraw()  # Hide the main window

    chosenFIle = filedialog.askopenfile(
        parent=root,
        initialdir="/",
        title='Please select file to be encrypted')
    return chosenFIle.name    

while True:
    Uinput = input("Do you want:\n"+
                    "1. Encrypt file\n"+
                    "2. Decrypt file\n"+
                    "3. Protect file integrity\n"+
                    "4. Verify file integrity\n"+
                    "5. Change Password for file\n"
                    "0. Exit\n")
    
    if Uinput == '0':
        break

    chosenFIle = fileSelector()
    password = input("Please provide the passwordfor the file:\n")


    match Uinput:
        case '1':
            encrypt_file(chosenFIle,password)
        
        case '2':
            decrypt_file(chosenFIle,password)

        case '3':
            protect_file_integrity(chosenFIle,password)

        case '4':
            verify_file_integrity(chosenFIle,password)

        case '5':
            decrypt_file(chosenFIle,password)
            new_pass = input("Enter new Password:\n")
            encrypt_file(chosenFIle,new_pass)

        case _:
            print("Please input a number between 0 - 5")        

