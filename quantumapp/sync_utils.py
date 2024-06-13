import requests
import os
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
# quantumapp/sync_utils.py

import requests
import logging

logger = logging.getLogger(__name__)

def get_active_nodes(master_node_url):
    try:
        response = requests.get(f"{master_node_url}/api/nodes/")
        response.raise_for_status()
        nodes = response.json()
        return nodes
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching nodes from master node: {e}")
        return []

def get_node_latest_transaction(node_url):
    try:
        response = requests.get(f"{node_url}/api/latest_transaction/")
        response.raise_for_status()
        latest_transaction = response.json()
        return latest_transaction
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching latest transaction from {node_url}: {e}")
        return None

def fetch_node_data(node_url):
    return {
        "url": node_url,
        "latest_transaction": get_node_latest_transaction(node_url)
    }

def check_node_synchronization():
    master_node_url = os.getenv('MASTER_NODE_URL')
    if not master_node_url:
        return {
            "is_synchronized": False,
            "message": "MASTER_NODE_URL environment variable is not set",
        }

    nodes = get_active_nodes(master_node_url)

    if len(nodes) < 2:
        return {
            "is_synchronized": False,
            "message": "Not enough nodes to check synchronization",
            "nodes": nodes,
        }

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(fetch_node_data, node['url']) for node in nodes[:2]]
        results = {future.result()['url']: future.result() for future in as_completed(futures)}

    node1_url, node2_url = list(results.keys())[:2]
    node1_data = results[node1_url]
    node2_data = results[node2_url]

    is_synchronized = node1_data['latest_transaction'] == node2_data['latest_transaction']
    return {
        "is_synchronized": is_synchronized,
        "node1_latest_transaction": node1_data['latest_transaction'],
        "node2_latest_transaction": node2_data['latest_transaction'],
    }

def synchronize_nodes():
    logger.info("Synchronizing nodes...")
    # Add logic to synchronize nodes here
    pass
