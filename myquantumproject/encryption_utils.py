# yourapp/encryption_utils.py

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import json
import requests
from .models import Transaction
from .network_utils import propagate_transaction

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
