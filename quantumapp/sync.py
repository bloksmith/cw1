def broadcast_transactions_to_nodes(transaction_data):
    node_urls = settings.NODE_URLS
    for node_url in node_urls:
        try:
            response = requests.post(f"{node_url}/api/receive_transaction/", json=transaction_data)
            if response.status_code == 200:
                logger.info(f"Transaction broadcasted to {node_url}")
            else:
                logger.error(f"Failed to broadcast transaction to {node_url}. Status code: {response.status_code}")
        except Exception as e:
            logger.error(f"Error broadcasting transaction to {node_url}: {e}")
