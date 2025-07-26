from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def encrypt_file(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data)

def decrypt_file(encrypted_data, key):
    return Fernet(key).decrypt(encrypted_data)