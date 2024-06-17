# tests.py

from channels.testing import WebsocketCommunicator
from django.test import TestCase
from myquantumproject.asgi import application
import json
import logging

logger = logging.getLogger(__name__)

class WebSocketTests(TestCase):

    async def test_transaction_sync(self):
        logger.debug("Starting WebSocket connection test")
        communicator = WebsocketCommunicator(application, "/ws/transactions/")
        connected, subprotocol = await communicator.connect()
        logger.debug(f"WebSocket connected: {connected}, subprotocol: {subprotocol}")
        self.assertTrue(connected, "WebSocket connection failed")

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

        logger.debug("Sending test transaction")
        await communicator.send_json_to(test_transaction)
        response = await communicator.receive_json_from()
        logger.debug(f"Response received: {response}")
        self.assertEqual(response["type"], "new_transaction")
        self.assertEqual(response["transaction"]["hash"], "test_hash_123")

        await communicator.disconnect()
        logger.debug("WebSocket connection test completed")
