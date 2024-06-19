# quantumapp/utils.py
import json
import requests
import logging

logger = logging.getLogger(__name__)

def broadcast_transactions(transactions):
    global known_nodes  # Ensure we use the updated list of known nodes
    for transaction in transactions:
        transaction_data = {
            'transaction_hash': transaction.hash,
            'sender': transaction.sender.address,
            'receiver': transaction.receiver.address,
            'amount': str(transaction.amount),
            'fee': str(transaction.fee),
            'timestamp': transaction.timestamp.isoformat(),
            'is_approved': transaction.is_approved
        }
        for node in known_nodes:
            try:
                response = requests.post(f"{node}/api/receive_transaction/", json=transaction_data)
                if response.status_code == 200:
                    logger.info(f"Transaction {transaction.hash} broadcasted to {node}")
                else:
                    logger.error(f"Failed to broadcast transaction {transaction.hash} to {node}: {response.text}")
            except Exception as e:
                logger.error(f"Error broadcasting transaction {transaction.hash} to {node}: {e}")

def broadcast_transaction(transaction_data):
    global known_nodes  # Ensure we use the updated list of known nodes
    for node in known_nodes:
        try:
            response = requests.post(f"{node}/api/receive_transaction/", json=transaction_data)
            if response.status_code == 200:
                logger.info(f"Transaction {transaction_data['transaction_hash']} broadcasted to {node}")
            else:
                logger.error(f"Failed to broadcast transaction {transaction_data['transaction_hash']} to {node}: {response.text}")
        except Exception as e:
            logger.error(f"Error broadcasting transaction {transaction_data['transaction_hash']} to {node}: {e}")
