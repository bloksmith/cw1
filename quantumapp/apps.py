# quantumapp/apps.py

from django.apps import AppConfig
import threading
import time
import requests
import logging

logger = logging.getLogger(__name__)

def start_scheduler_in_thread():
    from .scheduler import start_scheduler
    start_scheduler()

def register_with_master_node():
    master_node_url = os.getenv('MASTER_NODE_URL')
    current_node_url = os.getenv('CURRENT_NODE_URL')
    retry_attempts = 5  # Number of times to retry registration
    retry_delay = 5  # Delay between retries in seconds

    if master_node_url and current_node_url:
        for attempt in range(retry_attempts):
            try:
                response = requests.post(f"{master_node_url}/api/register_node/", json={'url': current_node_url})
                if response.status_code == 200:
                    logger.info("Successfully registered with master node.")
                    return
                else:
                    logger.error(f"Failed to register with master node. Status code: {response.status_code}")
            except Exception as e:
                logger.error(f"Error registering with master node: {e}")
            
            # Wait before retrying
            time.sleep(retry_delay)
        
        logger.error("Max retry attempts reached. Could not register with master node.")
    else:
        logger.error("MASTER_NODE_URL or CURRENT_NODE_URL is not set.")

class QuantumappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'quantumapp'

    def ready(self):
        # Start the scheduler in a separate thread
        threading.Thread(target=start_scheduler_in_thread).start()
        
        # Register with the master node in a separate thread
        threading.Thread(target=register_with_master_node).start()
