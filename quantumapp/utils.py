# quantumapp/utils.py
from .models import Shard

def create_default_shard():
    if not Shard.objects.exists():
        Shard.objects.create(name='Default Shard', description='This is the default shard')
import os
from cryptography.fernet import Fernet

def load_key():
    try:
        return open('secret.key', 'rb').read()
    except FileNotFoundError:
        # If no key found, we generate one (should ideally be done separately and securely stored)
        key = Fernet.generate_key()
        with open('secret.key', 'wb') as key_file:
            key_file.write(key)
        return key

def encrypt_message(message):
    key = load_key()
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message):
    key = load_key()
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message
