# quantumapp/apps.py
from django.apps import AppConfig
import threading
import time
import json
import logging
import asyncio
import websockets
from django.conf import settings

logger = logging.getLogger(__name__)

def start_scheduler_in_thread():
    from .scheduler import start_scheduler
    start_scheduler()

async def register_with_master_node_async():
    master_node_url = settings.MASTER_NODE_URL
    current_node_url = settings.CURRENT_NODE_URL
    retry_attempts = 5  # Number of times to retry registration
    retry_delay = 5  # Delay between retries in seconds

    if master_node_url and current_node_url:
        for attempt in range(retry_attempts):
            try:
                async with websockets.connect(master_node_url) as websocket:
                    await websocket.send(json.dumps({'url': current_node_url}))
                    response = await websocket.recv()
                    response_data = json.loads(response)
                    if response_data.get("status") == "success":
                        logger.info("Successfully registered with master node.")
                        return
                    else:
                        logger.error(f"Failed to register with master node. Response: {response_data}")
                        if response_data.get("message") == "Node already registered or invalid URL":
                            logger.warning("Attempting to re-register with a unique URL.")
                            current_node_url = f"{current_node_url}?attempt={attempt}"
            except Exception as e:
                logger.error(f"Error registering with master node: {e}")

            # Wait before retrying
            await asyncio.sleep(retry_delay)

        logger.error("Max retry attempts reached. Could not register with master node.")
    else:
        logger.error("MASTER_NODE_URL or CURRENT_NODE_URL is not set.")

def register_with_master_node():
    asyncio.run(register_with_master_node_async())

class QuantumappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'quantumapp'

    def ready(self):
        # Start the scheduler in a separate thread
        threading.Thread(target=start_scheduler_in_thread).start()

        # Register with the master node in a separate thread
        threading.Thread(target=register_with_master_node).start()
