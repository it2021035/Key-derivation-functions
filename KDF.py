import tkinter as tk
from tkinter import filedialog
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from argon2.low_level import hash_secret_raw, Type

# Constants
SALT_SIZE   = 16  
NONCE_SIZE  = 12  
TAG_SIZE    = 16   
LEVEL_BYTES = 2    

def choose_security_level():
    print("Select security level (bits):")
    print("1. 128")
    print("2. 256")
    choice = input("> ")
    mapping = {'1': '128', '2': '256'}
    bits = mapping.get(choice, '256')
    return int(bits)

# Use Argon2id for KDF (Password hashing)
def derive_key(password: str, salt: bytes, security_level: int) -> bytes:
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=2,
        memory_cost=2**16,
        parallelism=1,
        hash_len=security_level//8,  
        type=Type.ID
    )
# AES-GCM Encryption (for confidentiality and integrity)
def encrypt_file(file_path: str, password: str , security_level: int):
    salt = os.urandom(SALT_SIZE)  # Generate a random salt for key derivation
    key = derive_key(password, salt ,security_level)

    with open(file_path, 'rb') as f:
        data = f.read()

    # AES-GCM encryption setup
    nonce = os.urandom(NONCE_SIZE)  # Random nonce
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    level_bytes = security_level.to_bytes(2, byteorder='big')

    # Store metadata (salt + nonce + tag) for later use
    with open(file_path, 'wb') as f:
        f.write(salt + nonce + encryptor.tag + level_bytes + encrypted_data)

# AES-GCM Decryption
def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        salt       = f.read(SALT_SIZE)
        nonce      = f.read(NONCE_SIZE)
        tag        = f.read(TAG_SIZE)
        level_bytes= f.read(LEVEL_BYTES)
        ciphertext = f.read()

    security_level = int.from_bytes(level_bytes, byteorder='big')

    key = derive_key(password, salt, security_level)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    dec    = cipher.decryptor()
    plaintext = dec.update(ciphertext) + dec.finalize()

    with open(file_path, 'wb') as f:
        f.write(plaintext)

# HMAC for Integrity Protection
def generate_mac(file_path: str, password: str,security_level: int) -> bytes:
    salt = os.urandom(SALT_SIZE)  # Random salt for MAC
    key = derive_key(password, salt, security_level)
    hmac = HMAC(key, hashes.SHA256(), backend=default_backend())

    with open(file_path, 'rb') as f:
        data = f.read()
        hmac.update(data)
        
    return hmac.finalize() , salt

def protect_file_integrity(file_path: str, password: str,security_level: int):
    mac, salt = generate_mac(file_path, password, security_level)
    level_bytes = security_level.to_bytes(2, byteorder='big')

    with open(file_path + ".mac", 'wb') as f:
        f.write(salt + mac + level_bytes)
    print(f"Integrity tag stored in {file_path}.mac")

def verify_file_integrity(file_path: str, password: str):
    with open(file_path + ".mac", 'rb') as f:
        data = f.read()
        salt = data[:SALT_SIZE]
        mac = data[SALT_SIZE:SALT_SIZE + 32]  # ακριβώς 32 bytes για SHA256
        level_bytes = data[-2:]
        security_level = int.from_bytes(level_bytes, byteorder='big')

    key = derive_key(password, salt, security_level)
    h = HMAC(key, hashes.SHA256(), backend=default_backend())

    with open(file_path, 'rb') as f:
        h.update(f.read())

    try:
        h.verify(mac)
        print("File integrity: VALID")
        return True
    except Exception:
        print("File integrity: INVALID or wrong password")
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
                    "0. Exit\n>")
    
    if Uinput == '0':
        break

    chosenFIle = fileSelector()
    password = input("Please provide the passwordfor the file:\n")


    match Uinput:
        case '1':
            security_level = choose_security_level()
            encrypt_file(chosenFIle, password, security_level)
        
        case '2':
            decrypt_file(chosenFIle,password)

        case '3':
            security_level = choose_security_level()
            protect_file_integrity(chosenFIle,password,security_level)

        case '4':
            verify_file_integrity(chosenFIle,password)

        case '5':
            decrypt_file(chosenFIle,password)
            new_pass = input("Enter new Password:\n")
            security_level = choose_security_level()
            encrypt_file(chosenFIle, password, security_level)
        case _:
            print("Please input a number between 0 - 5")        

