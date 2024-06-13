# initialize_app.py
import os
from cryptography.fernet import Fernet

key_path = '/home/myuser/myquantumproject/secret.key'

def load_or_generate_key():
    if os.path.exists(key_path):
        with open(key_path, 'rb') as key_file:
            key = key_file.read()
    else:
        key = Fernet.generate_key()
        with open(key_path, 'wb') as key_file:
            key_file.write(key)
    return key

encryption_key = load_or_generate_key()
