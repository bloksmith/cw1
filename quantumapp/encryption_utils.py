from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import json
import requests
from django.http import JsonResponse
from .models import Transaction
from .network_utils import propagate_transaction
from django.conf import settings
from cryptography.fernet import Fernet
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)
# Create a Fernet instance using the encryption key from settings
f = Fernet(settings.ENCRYPTION_KEY)
def encrypt_message(public_key, message):
    public_key = serialization.load_pem_public_key(public_key.encode('utf-8'))
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

def decrypt_message(private_key, encrypted_message):
    private_key = serialization.load_pem_private_key(private_key.encode('utf-8'), password=None)
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode('utf-8')

def send_secure_transaction(node, transaction, private_key):
    message = json.dumps(transaction)
    encrypted_message = encrypt_message(node.public_key, message)
    try:
        response = requests.post(f"{node.address}/receive_transaction/", json={
            'transaction': encrypted_message
        })
        if response.status_code == 200:
            print(f"Secure transaction propagated to {node.address}")
        else:
            print(f"Failed to propagate secure transaction to {node.address}")
    except Exception as e:
        print(f"Error propagating secure transaction to {node.address}: {e}")

def receive_secure_transaction(request):
    if request.method == 'POST':
        encrypted_transaction = request.POST.get('transaction')
        decrypted_transaction = decrypt_message(request.user.wallet.private_key, encrypted_transaction)
        transaction_data = json.loads(decrypted_transaction)
        transaction = Transaction.objects.create(**transaction_data)
        propagate_transaction(transaction)
        return JsonResponse({'status': 'Transaction received, decrypted, and propagated'})
    return JsonResponse({'error': 'Only POST method allowed'}, status=400)
# encryption_utils.py
import os
from cryptography.fernet import Fernet, InvalidToken
import logging

# Initialize logger
logger = logging.getLogger(__name__)

import os
from cryptography.fernet import Fernet, InvalidToken
import logging

# Initialize logger
logger = logging.getLogger(__name__)
import os
from cryptography.fernet import Fernet, InvalidToken
import logging

# Initialize logger
logger = logging.getLogger(__name__)
import os
from cryptography.fernet import Fernet, InvalidToken
import logging

# Initialize logger
logger = logging.getLogger(__name__)
import os
from cryptography.fernet import Fernet, InvalidToken
import logging

# Initialize logger
logger = logging.getLogger(__name__)

import os
from cryptography.fernet import Fernet, InvalidToken
import logging

# Initialize logger
logger = logging.getLogger(__name__)

def load_key():
    key_path = '/home/myuser/myquantumproject/secret.key'
    if os.path.exists(key_path):
        with open(key_path, 'rb') as key_file:
            key = key_file.read()
            logger.debug(f"Loaded encryption key from {key_path}: {key}")
            return key
    else:
        key = Fernet.generate_key()
        with open(key_path, 'wb') as key_file:
            key_file.write(key)
        logger.debug(f"Generated and saved new encryption key to {key_path}: {key}")
        return key

# Load encryption key from secret.key file
encryption_key = load_key()
f = Fernet(encryption_key)

def encrypt_message(message):
    try:
        logger.debug(f"Encrypting message: {message}")
        encrypted_message = f.encrypt(message.encode())
        logger.debug(f"Encrypted message: {encrypted_message}")
        return encrypted_message.decode()
    except Exception as e:
        logger.error(f"Error during encryption: {e}")
        raise Exception("Error during encryption")

def decrypt_message(encrypted_message):
    try:
        logger.debug(f"Attempting to decrypt message: {encrypted_message}")

        if not encrypted_message:
            logger.error("Encrypted message is empty")
            raise ValueError("Encrypted message is empty")

        # Ensure the encrypted message is a proper base64 encoded string
        if len(encrypted_message) % 4 != 0:
            logger.warning("Encrypted message length is not a multiple of 4. Padding with '='.")
            encrypted_message += '=' * (4 - len(encrypted_message) % 4)

        logger.debug(f"Encrypted message after padding: {encrypted_message}")
        decrypted_message = f.decrypt(encrypted_message.encode()).decode()
        logger.debug("Decryption successful")
        return decrypted_message
    except InvalidToken as e:
        logger.error(f"InvalidToken error during decryption. Possible causes: incorrect key, corrupted message, or invalid format. Error: {e}")
        logger.debug("Debug Info: Check if the key used for encryption matches the key used for decryption.")
        raise InvalidToken("Invalid token during decryption")
    except ValueError as e:
        logger.error(f"ValueError during decryption. Ensure the message is properly formatted. Error: {e}")
        logger.debug("Debug Info: Verify if the encrypted message is not empty and properly encoded.")
        raise ValueError("Value error during decryption")
    except TypeError as e:
        logger.error(f"TypeError during decryption. Message might not be encoded correctly. Error: {e}")
        logger.debug("Debug Info: Confirm the encrypted message is a valid string and properly encoded.")
        raise TypeError("Type error during decryption")
    except Exception as e:
        logger.error(f"General error during decryption. This might be due to unexpected issues. Error: {e}")
        raise Exception("General error during decryption")
