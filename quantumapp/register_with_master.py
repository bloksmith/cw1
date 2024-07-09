import asyncio
import websockets
import json
import logging
import traceback
from django.conf import settings
import django
import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'quantumapp.settings')



logger = logging.getLogger(__name__)

async def register_with_master_node_async():
    master_node_url = settings.MASTER_NODE_URL + '/ws/register_node/'
    current_node_url = settings.CURRENT_NODE_URL
    retry_attempts = 1
    retry_delay = 1

    logger.debug(f"MASTER_NODE_URL: {settings.MASTER_NODE_URL}")
    logger.debug(f"CURRENT_NODE_URL: {settings.CURRENT_NODE_URL}")

    if master_node_url and current_node_url:
        for attempt in range(retry_attempts):
            try:
                logger.info(f"Attempting to connect to master node (attempt {attempt + 1}/{retry_attempts})")
                logger.debug(f"Connecting to {master_node_url} with current node URL {current_node_url}")
                async with websockets.connect(master_node_url, timeout=10) as websocket:
                    logger.info(f"Connected to master node: {master_node_url}")
                    await websocket.send(json.dumps({'url': current_node_url, 'public_key': 'your_public_key_here'}))
                    response = await websocket.recv()
                    response_data = json.loads(response)
                    logger.debug(f"Response from master node: {response_data}")
                    if response_data.get("status") == "success":
                        logger.info("Successfully registered with master node.")
                        return
                    else:
                        logger.error(f"Failed to register with master node. Response: {response_data}")
                        if response_data.get("message") == "Node already registered or invalid URL":
                            logger.warning("Attempting to re-register with a unique URL.")
                            current_node_url = f"{current_node_url}?attempt={attempt}"
            except (websockets.exceptions.InvalidStatusCode, websockets.exceptions.WebSocketException, asyncio.TimeoutError) as e:
                logger.error(f"Error registering with master node: {e}\n{traceback.format_exc()}")
            except Exception as e:
                logger.error(f"Unexpected error: {e}\n{traceback.format_exc()}")

            logger.info(f"Retrying in {retry_delay} seconds...")
            await asyncio.sleep(retry_delay)

        logger.error("Max retry attempts reached. Could not register with master node.")
    else:
        logger.error("MASTER_NODE_URL or CURRENT_NODE_URL is not set.")

if __name__ == "__main__":
    asyncio.run(register_with_master_node_async())
