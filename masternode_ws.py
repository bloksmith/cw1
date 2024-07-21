import asyncio
import websockets
import json
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

connected_clients = set()
current_multiaddress = None

async def multiaddress_handler(websocket, path):
    global connected_clients, current_multiaddress
    connected_clients.add(websocket)
    logger.debug(f"New client connected: {websocket.remote_address}")
    try:
        if current_multiaddress is not None:
            await websocket.send(json.dumps({"multiaddress": current_multiaddress}))
        else:
            await websocket.send(json.dumps({"error": "No multiaddress available"}))
        
        async for message in websocket:
            logger.debug(f"Message received from {websocket.remote_address}: {message}")
            data = json.loads(message)
            if "multiaddress" in data:
                await broadcast_multiaddress(data["multiaddress"])
            elif data.get("action") == "get_all_multiaddresses":
                await websocket.send(json.dumps({"multiaddresses": [current_multiaddress] if current_multiaddress else []}))
    except websockets.ConnectionClosed:
        pass
    finally:
        connected_clients.remove(websocket)
        logger.debug(f"Client removed: {websocket.remote_address}")

async def broadcast_multiaddress(new_multiaddress):
    global connected_clients, current_multiaddress
    current_multiaddress = new_multiaddress
    if connected_clients:
        message = json.dumps({"multiaddress": new_multiaddress})
        logger.debug(f"Broadcasting new multiaddress: {new_multiaddress}")
        await asyncio.wait([client.send(message) for client in connected_clients])

async def start_websocket_server(port):
    server = await websockets.serve(multiaddress_handler, "0.0.0.0", port)
    logger.info(f"WebSocket server started on port {port}")
    await server.wait_closed()

if __name__ == "__main__":
    ws_port = 8765  # Define your WebSocket port
    asyncio.run(start_websocket_server(ws_port))
