import asyncio
import requests
import logging
from django.utils import timezone
from asgiref.sync import sync_to_async
from .models import Transaction, Wallet, Shard

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define node URLs
NODE_URLS = [
    "http://161.35.219.10:1010",  # Node 1 URL
    "http://161.35.219.10:2020"   # Node 2 URL (example URL, replace with actual)
]

def fetch_transactions_from_node(node_url):
    try:
        response = requests.get(f"{node_url}/api/transaction_pool/")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Error fetching transactions from {node_url}: {e}")
        return None

def send_test_message(node_url, message):
    try:
        response = requests.post(f"{node_url}/api/test_message/", json={'message': message})
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Error sending test message to {node_url}: {e}")
        return None

async def sync_transactions():
    while True:
        logger.info("Starting transaction sync...")
        for node_url in NODE_URLS:
            transactions = fetch_transactions_from_node(node_url)
            if transactions:
                await sync_to_async(process_transactions)(transactions)
            
            # Send test message
            test_message_response = send_test_message(node_url, "Hello, World!")
            if test_message_response:
                logger.info(f"Test message response from {node_url}: {test_message_response}")
            
        await asyncio.sleep(60)  # Wait 60 seconds before the next sync

def process_transactions(transactions):
    for tx_data in transactions:
        try:
            sender_wallet = Wallet.objects.get(address=tx_data['sender'])
            receiver_wallet = Wallet.objects.get(address=tx_data['receiver'])
            shard = Shard.objects.get(name=tx_data['shard'])
            
            transaction, created = Transaction.objects.update_or_create(
                hash=tx_data['hash'],
                defaults={
                    'sender': sender_wallet,
                    'receiver': receiver_wallet,
                    'amount': tx_data['amount'],
                    'fee': tx_data['fee'],
                    'timestamp': timezone.datetime.fromisoformat(tx_data['timestamp']),
                    'is_approved': tx_data['is_approved'],
                    'shard': shard
                }
            )
            if created:
                logger.info(f"Transaction {tx_data['hash']} added.")
            else:
                logger.info(f"Transaction {tx_data['hash']} updated.")
        except Exception as e:
            logger.error(f"Error processing transaction {tx_data['hash']}: {e}")

if __name__ == "__main__":
    logger.info("Starting transaction sync script...")
    asyncio.run(sync_transactions())
