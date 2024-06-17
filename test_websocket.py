# test_websocket.py

import websocket
import json

def on_message(ws, message):
    print(f"Message from server: {message}")

def on_open(ws):
    test_transaction = {
        "type": "new_transaction",
        "transaction": {
            "hash": "test_hash_123",
            "sender": "test_sender",
            "receiver": "test_receiver",
            "amount": 100,
            "fee": 1,
            "timestamp": "2024-06-17T00:00:00Z"
        }
    }
    ws.send(json.dumps(test_transaction))

if __name__ == "__main__":
    ws = websocket.WebSocketApp("ws://localhost:8000/ws/transactions/",
                                on_message=on_message,
                                on_open=on_open)
    ws.run_forever()
