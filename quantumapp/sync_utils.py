import requests

def get_node_status(node_url):
    try:
        latest_transaction = requests.get(f"{node_url}/get_latest_transaction/").json()
        transaction_pool = requests.get(f"{node_url}/get_transaction_pool/").json()['transaction_pool']
        return latest_transaction, transaction_pool
    except Exception as e:
        print(f"Error getting status from {node_url}: {e}")
        return None, None

def check_sync(node1_url, node2_url):
    latest_tx_node1, tx_pool_node1 = get_node_status(node1_url)
    latest_tx_node2, tx_pool_node2 = get_node_status(node2_url)

    if latest_tx_node1 == latest_tx_node2 and tx_pool_node1 == tx_pool_node2:
        return True
    return False
# quantumapp/sync_utils.py

from .models import Node

MASTER_NODE_URL = "http://161.35.219.10:1010"

def get_active_nodes():
    # Fetch active nodes from the database
    nodes = list(Node.objects.values_list('address', flat=True))
    if MASTER_NODE_URL not in nodes:
        nodes.insert(0, MASTER_NODE_URL)  # Ensure the master node URL is always included
    return nodes

def get_node_latest_transaction(node_url):
    try:
        response = requests.get(f"{node_url}/api/latest_transaction/")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching latest transaction from {node_url}: {e}")
        return None

def get_node_transaction_pool(node_url):
    try:
        response = requests.get(f"{node_url}/api/transaction_pool/")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching transaction pool from {node_url}: {e}")
        return None

def check_node_synchronization():
    node_urls = get_active_nodes()
    if len(node_urls) < 2:
        return {
            "is_synchronized": False,
            "message": "Not enough nodes to check synchronization",
            "nodes": node_urls,
        }

    node1_url = node_urls[0]
    node2_url = node_urls[1]

    node1_latest_tx = get_node_latest_transaction(node1_url)
    node1_tx_pool = get_node_transaction_pool(node1_url)
    node2_latest_tx = get_node_latest_transaction(node2_url)
    node2_tx_pool = get_node_transaction_pool(node2_url)

    is_synchronized = node1_latest_tx == node2_latest_tx

    return {
        "is_synchronized": is_synchronized,
        "node1_latest_transaction": node1_latest_tx,
        "node1_transaction_pool": node1_tx_pool,
        "node2_latest_transaction": node2_latest_tx,
        "node2_transaction_pool": node2_tx_pool,
    }

def synchronize_nodes():
    node_urls = get_active_nodes()
    node1_url = node_urls[0]
    node2_url = node_urls[1]

    node1_tx_pool = get_node_transaction_pool(node1_url)
    node2_tx_pool = get_node_transaction_pool(node2_url)

    if node1_tx_pool and node2_tx_pool:
        node1_txs = set(tx['hash'] for tx in node1_tx_pool['transaction_pool'])
        node2_txs = set(tx['hash'] for tx in node2_tx_pool['transaction_pool'])

        missing_in_node1 = node2_txs - node1_txs
        missing_in_node2 = node1_txs - node2_txs

        for tx_hash in missing_in_node1:
            tx = next(tx for tx in node2_tx_pool['transaction_pool'] if tx['hash'] == tx_hash)
            requests.post(f"{node1_url}/api/receive_transaction/", json=tx)

        for tx_hash in missing_in_node2:
            tx = next(tx for tx in node1_tx_pool['transaction_pool'] if tx['hash'] == tx_hash)
            requests.post(f"{node2_url}/api/receive_transaction/", json=tx)

        print("Nodes synchronized.")
    else:
        print("Failed to fetch transaction pools for synchronization.")
