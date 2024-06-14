# quantumapp/node_registration.py

import requests
import os
import logging

logger = logging.getLogger(__name__)

def register_with_master_node():
    master_node_url = os.getenv('MASTER_NODE_URL')
    node_url = os.getenv('NODE_URL')
    
    if not master_node_url or not node_url:
        logger.error("MASTER_NODE_URL or NODE_URL environment variables are not set")
        return

    try:
        response = requests.post(f"{master_node_url}/api/register_node/", json={"url": node_url})
        response.raise_for_status()
        logger.info(f"Node registered successfully with master node: {node_url}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error registering node with master node: {e}")
