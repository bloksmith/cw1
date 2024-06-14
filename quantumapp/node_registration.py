# quantumapp/node_registration.py

import requests
import logging
from django.conf import settings
import socket

logger = logging.getLogger(__name__)

def get_node_url():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    port = settings.NODE_PORT
    return f"http://{local_ip}:{port}"

def register_with_master_node():
    master_node_url = settings.MASTER_NODE_URL
    node_url = get_node_url()
    
    if not master_node_url:
        logger.error("MASTER_NODE_URL is not set in settings")
        return

    try:
        response = requests.post(f"{master_node_url}/api/register_node/", json={"url": node_url})
        response.raise_for_status()
        logger.info(f"Node registered successfully with master node: {node_url}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error registering node with master node: {e}")
