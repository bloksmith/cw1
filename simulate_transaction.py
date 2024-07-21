import json
import time
import requests

# Example transaction data
transaction_data = {
    "hash": "tx1",
    "sender": "Alice",
    "receiver": "Bob",
    "amount": 100.0,
    "fee": 0.1,
    "timestamp": str(time.time()),
    "shard": "shard1",
    "is_approved": True
}

# Convert transaction to JSON
transaction_json = json.dumps(transaction_data)

# Broadcast the transaction
def broadcast_transaction(node_url, transaction_json):
    response = requests.post(node_url, data=transaction_json, headers={'Content-Type': 'application/json'})
    if response.status_code == 200:
        print("Transaction broadcasted successfully")
    else:
        print("Failed to broadcast transaction")

# URL of the node to broadcast the transaction to
node_url = "http://127.0.0.1:9001/transactions"  # Adjust the port to 9001

# Broadcast the transaction to the master node
broadcast_transaction(node_url, transaction_json)
