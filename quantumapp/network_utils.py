import random
import requests
from django.utils import timezone
from .models import Node, Transaction

def select_random_peers(node, num_peers=3):
    nodes = Node.objects.exclude(address=node.address)
    return random.sample(list(nodes), min(len(nodes), num_peers))

def propagate_transaction(transaction):
    nodes = Node.objects.all()
    for node in nodes:
        peers = select_random_peers(node)
        for peer in peers:
            send_transaction(peer, transaction)

def send_transaction(node, transaction):
    try:
        response = requests.post(f"{node.address}/receive_transaction/", json={
            'transaction': transaction
        })
        if response.status_code == 200:
            print(f"Transaction propagated to {node.address}")
        else:
            print(f"Failed to propagate transaction to {node.address}")
    except Exception as e:
        print(f"Error propagating transaction to {node.address}: {e}")

def receive_transaction(request):
    if request.method == 'POST':
        transaction_data = request.POST.get('transaction')
        transaction = Transaction.objects.create(**transaction_data)
        propagate_transaction(transaction)
        return JsonResponse({'status': 'Transaction received and propagated'})
    return JsonResponse({'error': 'Only POST method allowed'}, status=400)
