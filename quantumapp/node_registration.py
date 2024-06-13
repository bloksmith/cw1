# quantumapp/node_registration.py

import requests
from django.conf import settings

def register_with_master_node():
    master_node_url = settings.MASTER_NODE_URL
    node_url = settings.CURRENT_NODE_URL
    try:
        response = requests.post(f"{master_node_url}/api/register_node/", json={"url": node_url})
        response.raise_for_status()
        print(f"Node registered successfully with master node: {node_url}")
    except requests.exceptions.RequestException as e:
        print(f"Error registering node with master node: {e}")
