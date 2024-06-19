# quantumapp/node_registration.py
import websockets
import asyncio
import json
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

async def register_with_master_node():
    master_node_url = settings.MASTER_NODE_URL
    current_node_url = settings.CURRENT_NODE_URL
    public_key = 'your_public_key_here'  # Replace with the actual public key

    async with websockets.connect(master_node_url) as websocket:
        await websocket.send(json.dumps({"url": current_node_url, "public_key": public_key}))
        response = await websocket.recv()
        logger.info(f"Response from master node: {response}")

def start_registration():
    asyncio.run(register_with_master_node())
