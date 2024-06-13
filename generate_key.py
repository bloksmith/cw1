# generate_key.py
from cryptography.fernet import Fernet

def generate_and_save_key():
    key = Fernet.generate_key()
    with open('/home/myuser/myquantumproject/secret.key', 'wb') as key_file:
        key_file.write(key)
    print("Key generated and saved to /home/myuser/myquantumproject/secret.key")

if __name__ == "__main__":
    generate_and_save_key()
