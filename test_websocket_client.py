import asyncio
import logging
import sys
print(sys.executable)
import websockets

logging.basicConfig(level=logging.DEBUG)

async def test_websocket():
    url = 'ws://app.cashewstable.com/ws/transactions/'
    try:
        async with websockets.connect(url) as websocket:
            logging.debug("Connected")

            # Sending a message
            await websocket.send("Hello, WebSocket!")
            logging.debug("Message sent: Hello, WebSocket!")

            # Receiving a message
            response = await websocket.recv()
            logging.debug(f"Received: {response}")

    except websockets.exceptions.ConnectionClosedError as e:
        logging.error(f"WebSocket connection closed with error: {e}")
    except Exception as e:
        logging.error(f"WebSocket connection error: {e}")

asyncio.run(test_websocket())
