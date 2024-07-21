import asyncio
import websockets

async def hello():
    uri = "ws://localhost:8765"
    try:
        async with websockets.connect(uri) as websocket:
            print("Connected to WebSocket server")
            greeting = await websocket.recv()
            print(f"Received: {greeting}")
    except Exception as e:
        print(f"Failed to connect to WebSocket server: {e}")

asyncio.get_event_loop().run_until_complete(hello())
