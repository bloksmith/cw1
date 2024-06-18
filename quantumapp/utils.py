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
# utils.py
from .models import Transaction

def validate_transaction(transaction):
    # Check for missing signature
    if not transaction.signature:
        print(f"[ERROR] Transaction {transaction.hash} invalid: missing signature")
        return False

    # Check for insufficient balance
    if transaction.sender.balance < (transaction.amount + transaction.fee):
        print(f"[ERROR] Transaction {transaction.hash} invalid: insufficient balance. Sender balance: {transaction.sender.balance}, Transaction amount: {transaction.amount}, Fee: {transaction.fee}")
        return False

    # Check for duplicate transaction
    if Transaction.objects.filter(hash=transaction.hash, is_approved=True).exists():
        print(f"[ERROR] Transaction {transaction.hash} invalid: duplicate transaction")
        return False

    # Additional validation checks (if any)
    # For example, you might check if the transaction format is correct or if the receiver address is valid

    print(f"[DEBUG] Transaction {transaction.hash} is valid")
    return True


def approve_transaction(transaction):
    # Approve the transaction by updating the balance and setting is_approved to True
    transaction.sender.balance -= (transaction.amount + transaction.fee)
    transaction.receiver.balance += transaction.amount
    transaction.is_approved = True
    transaction.save()
    transaction.sender.save()
    transaction.receiver.save()
