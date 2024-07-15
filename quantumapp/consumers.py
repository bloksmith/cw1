import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.layers import get_channel_layer
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import hashlib
# quantumapp/consumers.py

logger = logging.getLogger(__name__)

class TokenConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add("broadcast_group", self.channel_name)
        await self.accept()
        logger.info(f"TokenConsumer connected: {self.channel_name}")

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("broadcast_group", self.channel_name)
        logger.info(f"TokenConsumer disconnected: {self.channel_name}")

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json['message']
        logger.info(f"TokenConsumer received message: {message}")

        # Broadcast message to group
        await self.channel_layer.group_send(
            "broadcast_group",
            {
                'type': 'broadcast_message',
                'message': message
            }
        )

    async def broadcast_message(self, event):
        message = event['message']
        logger.info(f"TokenConsumer broadcasting message: {message}")

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message
        }))


class PoolConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add("pools", self.channel_name)
        await self.accept()
        logger.info(f"PoolConsumer connected: {self.channel_name}")

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("pools", self.channel_name)
        logger.info(f"PoolConsumer disconnected: {self.channel_name}")

    async def receive(self, text_data):
        data = json.loads(text_data)
        logger.info(f"PoolConsumer received data: {data}")
        if data['type'] == 'update_pools':
            await self.update_pools()

    async def update_pools(self):
        from .models import Pool  # Deferred import
        from django.db.models import Count

        top_pools = Pool.objects.annotate(
            num_users=Count('poolmember')
        ).order_by('-num_users', '-hashrate', '-rewards')[:10]

        pools_data = [{
            'name': pool.name,
            'num_users': pool.num_users,
            'hashrate': pool.hashrate,
            'rewards': pool.rewards
        } for pool in top_pools]

        logger.info(f"PoolConsumer sending pools data: {pools_data}")

        await self.channel_layer.group_send(
            "pools",
            {
                'type': 'broadcast_pools',
                'pools': pools_data
            }
        )

    async def broadcast_pools(self, event):
        pools = event['pools']
        logger.info(f"PoolConsumer broadcasting pools data: {pools}")

        await self.send(text_data=json.dumps({
            'type': 'pools_update',
            'pools': pools
        }))


class BlockchainConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add("blockchain", self.channel_name)
        await self.accept()
        logger.info(f"BlockchainConsumer connected: {self.channel_name}")

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("blockchain", self.channel_name)
        logger.info(f"BlockchainConsumer disconnected: {self.channel_name}")

    async def new_block(self, event):
        block = event['block']
        logger.info(f"BlockchainConsumer new block received: {block}")
        await self.send(text_data=json.dumps({
            'type': 'new_block',
            'block': block
        }))

    async def receive(self, text_data):
        from .models import Wallet  # Deferred import
        data = json.loads(text_data)
        logger.info(f"BlockchainConsumer received data: {data}")
        if data['type'] == 'new_block':
            block = data['block']
            if self.verify_block(block):
                await self.add_block(block)
                await self.channel_layer.group_send(
                    "blockchain",
                    {
                        "type": "new_block",
                        "block": block,
                    }
                )

    def verify_block(self, block):
        last_hash = block['previous_hash']
        proof = block['proof']
        if not self.valid_proof(last_hash, proof):
            return False

        for transaction in block['transactions']:
            if not self.validate_transaction(transaction):
                return False

        return True

    def valid_proof(self, last_hash, proof, difficulty=4):
        guess = f'{last_hash}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == "0" * difficulty

    def validate_transaction(self, transaction):
        from .models import Wallet  # Deferred import
        try:
            sender_public_key_pem = transaction['sender_public_key']
            signature = transaction['signature']
            transaction_data = f"{transaction['sender']}{transaction['receiver']}{transaction['amount']}{transaction['timestamp']}"

            sender_public_key = serialization.load_pem_public_key(
                sender_public_key_pem.encode('utf-8'),
                backend=default_backend()
            )

            sender_public_key.verify(
                signature.encode('utf-8'),
                transaction_data.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            sender_wallet = Wallet.objects.get(public_key=transaction['sender_public_key'])
            if sender_wallet.balance < transaction['amount']:
                logger.warning(f"Transaction from {transaction['sender']} to {transaction['receiver']} for {transaction['amount']} failed due to insufficient balance.")
                return False

            logger.info(f"Transaction from {transaction['sender']} to {transaction['receiver']} for {transaction['amount']} is valid.")
            return True

        except Exception as e:
            logger.error(f"Transaction validation failed: {e}")
            return False

    async def add_block(self, block):
        global blockchain
        blockchain.append(block)
        await self.save_blockchain()
        logger.info(f"BlockchainConsumer added block: {block}")

    async def save_blockchain(self):
        with open('blockchain.json', 'w') as file:
            json.dump(blockchain, file)
        logger.info("BlockchainConsumer saved blockchain")


class TransactionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add("transactions", self.channel_name)
        await self.accept()
        logger.info(f"TransactionConsumer connected: {self.channel_name}")

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("transactions", self.channel_name)
        logger.info(f"TransactionConsumer disconnected: {self.channel_name}")

    async def receive(self, text_data):
        data = json.loads(text_data)
        logger.info(f"TransactionConsumer received data: {data}")
        await self.channel_layer.group_send(
            "transactions",
            {
                "type": "transaction_message",
                "message": data
            }
        )

    async def transaction_message(self, event):
        message = event['message']
        logger.info(f"TransactionConsumer broadcasting message: {message}")
        await self.send(text_data=json.dumps({
            'type': 'transaction_update',
            'message': message
        }))


class SyncConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add("sync_group", self.channel_name)
        await self.accept()
        logger.info(f"SyncConsumer connected: {self.channel_name}")

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("sync_group", self.channel_name)
        logger.info(f"SyncConsumer disconnected: {self.channel_name}")

    async def new_transaction(self, event):
        transaction = event['transaction']
        logger.info(f"SyncConsumer new transaction: {transaction}")
        await self.send(text_data=json.dumps({
            'type': 'new_transaction',
            'transaction': transaction
        }))

    async def receive(self, text_data):
        data = json.loads(text_data)
        logger.info(f"SyncConsumer received data: {data}")
        if data['type'] == 'new_transaction':
            await self.channel_layer.group_send("sync_group", {
                "type": "new_transaction",
                "transaction": data['transaction']
            })


class SyncStatusConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add("sync_status", self.channel_name)
        await self.accept()
        logger.info(f"SyncStatusConsumer connected: {self.channel_name}")

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("sync_status", self.channel_name)
        logger.info(f"SyncStatusConsumer disconnected: {self.channel_name}")

    async def receive(self, text_data):
        pass  # No messages expected from client in this case

    async def sync_status_update(self, event):
        logger.info(f"SyncStatusConsumer sync status update: {event['message']}")
        await self.send(text_data=json.dumps({
            'type': 'sync_status',
            'message': event["message"]
        }))


class NodeConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.node_group_name = "nodes"
        await self.channel_layer.group_add(self.node_group_name, self.channel_name)
        await self.accept()
        logger.info(f"NodeConsumer connected: {self.channel_name}")

        # Notify master node of the connection
        await self.channel_layer.group_send(
            "master_node",
            {
                "type": "node.connect",
                "node_address": self.scope["client"][0]
            }
        )

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.node_group_name, self.channel_name)
        logger.info(f"NodeConsumer disconnected: {self.channel_name}")

    async def receive(self, text_data):
        data = json.loads(text_data)
        logger.info(f"NodeConsumer received data: {data}")
        await self.channel_layer.group_send(
            self.node_group_name,
            {
                "type": "transaction.message",
                "message": data
            }
        )

    async def transaction_message(self, event):
        message = event["message"]
        logger.info(f"NodeConsumer broadcasting message: {message}")
        await self.send(text_data=json.dumps({
            'type': 'node_update',
            'message': message
        }))

from channels.generic.websocket import WebsocketConsumer
import json
class DAGConsumer(WebsocketConsumer):
    def connect(self):
        self.accept()
        async_to_sync(self.channel_layer.group_add)('dag_updates', self.channel_name)
        logger.debug("WebSocket connected and added to dag_updates group")

    def disconnect(self, close_code):
        async_to_sync(self.channel_layer.group_discard)('dag_updates', self.channel_name)
        logger.debug(f"WebSocket disconnected: {close_code}")

    def dag_update(self, event):
        logger.debug(f"Received DAG update: {event}")
        dag = event['dag']
        self.send(text_data=json.dumps({
            'type': 'dag.update',
            'dag': dag
        }))

import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer

logger = logging.getLogger(__name__)

class TransactionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        logger.debug(f"Attempting WebSocket connection: {self.scope['path']} with headers {self.scope['headers']}")
        await self.channel_layer.group_add("transactions", self.channel_name)
        await self.accept()
        logger.info(f"WebSocket connected: {self.channel_name}")

    async def disconnect(self, close_code):
        logger.info(f"WebSocket disconnected: {self.channel_name}, code: {close_code}")
        await self.channel_layer.group_discard("transactions", self.channel_name)

    async def new_transaction(self, event):
        transaction = event['transaction']
        logger.debug(f"New transaction event received: {transaction}")
        await self.send(text_data=json.dumps({
            'type': 'new_transaction',
            'transaction': transaction
        }))
# consumers.py
# consumers.py
from channels.generic.websocket import AsyncWebsocketConsumer
import json
import logging

logger = logging.getLogger(__name__)

class TransactionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        self.room_name = 'transactions'
        self.room_group_name = 'transactions_group'
        logger.debug("WebSocket connected")

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.send(text_data=json.dumps({
            'message': 'WebSocket connected!'
        }))

    async def disconnect(self, close_code):
        logger.debug("WebSocket disconnected with code: %s", close_code)
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        logger.debug("Received message: %s", text_data)
        if text_data:
            try:
                text_data_json = json.loads(text_data)
                message = text_data_json.get('message', '')

                # Send message to WebSocket
                await self.send(text_data=json.dumps({
                    'message': f"Received: {message}"
                }))
                logger.debug("Sent response message: %s", message)

                # Broadcast message to group
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'chat_message',
                        'message': message
                    }
                )
            except json.JSONDecodeError:
                logger.error("Failed to decode JSON: %s", text_data)
                await self.send(text_data=json.dumps({
                    'error': 'Invalid JSON received'
                }))
        else:
            logger.warning("Received empty message")

    async def chat_message(self, event):
        message = event['message']
        logger.debug("Broadcasting message: %s", message)

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message
        }))
# consumers.py
from channels.generic.websocket import AsyncWebsocketConsumer
import json
import logging

logger = logging.getLogger(__name__)

class TransactionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        self.room_name = 'transactions'
        self.room_group_name = 'transactions_group'
        logger.debug("WebSocket connected")

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.send(text_data=json.dumps({
            'message': 'WebSocket connected!'
        }))

    async def disconnect(self, close_code):
        logger.debug("WebSocket disconnected with code: %s", close_code)
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        logger.debug("Received message: %s", text_data)
        if text_data:
            try:
                text_data_json = json.loads(text_data)
                message = text_data_json.get('message', '')

                # Send message to WebSocket
                await self.send(text_data=json.dumps({
                    'message': f"Received: {message}"
                }))
                logger.debug("Sent response message: %s", message)

                # Broadcast message to group
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'chat_message',
                        'message': message
                    }
                )
            except json.JSONDecodeError:
                logger.warning("Message is not valid JSON, treating as plain text")
                message = text_data

                # Send message to WebSocket
                await self.send(text_data=json.dumps({
                    'message': f"Received: {message}"
                }))
                logger.debug("Sent response message: %s", message)

                # Broadcast message to group
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'chat_message',
                        'message': message
                    }
                )
        else:
            logger.warning("Received empty message")

    async def chat_message(self, event):
        message = event['message']
        logger.debug("Broadcasting message: %s", message)

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message
        }))
from channels.generic.websocket import AsyncWebsocketConsumer
import json
import logging

logger = logging.getLogger(__name__)

class TransactionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = 'transactions'
        self.room_group_name = 'transactions_group'
        
        await self.accept()
        logger.debug("WebSocket connected")

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.send(text_data=json.dumps({
            'message': 'WebSocket connected!'
        }))

    async def disconnect(self, close_code):
        logger.debug("WebSocket disconnected with code: %s", close_code)
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        logger.debug("Received message: %s", text_data)
        if text_data:
            try:
                text_data_json = json.loads(text_data)
                message = text_data_json.get('message', '')

                # Send message to WebSocket
                await self.send(text_data=json.dumps({
                    'message': f"Received: {message}"
                }))
                logger.debug("Sent response message: %s", message)

                # Broadcast message to group
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'chat_message',
                        'message': message
                    }
                )
            except json.JSONDecodeError:
                logger.warning("Message is not valid JSON, treating as plain text")
                message = text_data

                # Send message to WebSocket
                await self.send(text_data=json.dumps({
                    'message': f"Received: {message}"
                }))
                logger.debug("Sent response message: %s", message)

                # Broadcast message to group
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'chat_message',
                        'message': message
                    }
                )
        else:
            logger.warning("Received empty message")

    async def chat_message(self, event):
        message = event['message']
        logger.debug("Broadcasting message: %s", message)

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message
        }))
from channels.generic.websocket import AsyncWebsocketConsumer
import json
import logging

logger = logging.getLogger(__name__)

class TransactionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        self.room_name = 'transactions'
        self.room_group_name = 'transactions_group'
        logger.debug("WebSocket connected")

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.send(text_data=json.dumps({
            'message': 'WebSocket connected!'
        }))

    async def disconnect(self, close_code):
        logger.debug("WebSocket disconnected with code: %s", close_code)
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        logger.debug("Received message: %s", text_data)
        if text_data:
            try:
                text_data_json = json.loads(text_data)
                message = text_data_json.get('message', '')

                # Send message to WebSocket
                await self.send(text_data=json.dumps({
                    'message': f"Received: {message}"
                }))
                logger.debug("Sent response message: %s", message)

                # Broadcast message to group
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'chat_message',
                        'message': message
                    }
                )
            except json.JSONDecodeError:
                logger.warning("Message is not valid JSON, treating as plain text")
                message = text_data

                # Send message to WebSocket
                await self.send(text_data=json.dumps({
                    'message': f"Received: {message}"
                }))
                logger.debug("Sent response message: %s", message)

                # Broadcast message to group
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'chat_message',
                        'message': message
                    }
                )
        else:
            logger.warning("Received empty message")

    async def chat_message(self, event):
        message = event['message']
        logger.debug("Broadcasting message: %s", message)

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message
        }))
# quantumapp/consumers.py
import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer

logger = logging.getLogger(__name__)

class TransactionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        self.room_name = 'transactions'
        self.room_group_name = 'transactions_group'
        logger.debug("WebSocket connected")

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.send(text_data=json.dumps({
            'message': 'WebSocket connected!'
        }))

    async def disconnect(self, close_code):
        logger.debug("WebSocket disconnected with code: %s", close_code)
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        logger.debug("Received message: %s", text_data)
        if text_data:
            try:
                text_data_json = json.loads(text_data)
                message = text_data_json.get('message', '')

                # Send message to WebSocket
                await self.send(text_data=json.dumps({
                    'message': f"Received: {message}"
                }))
                logger.debug("Sent response message: %s", message)

                # Broadcast message to group
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'chat_message',
                        'message': message
                    }
                )
            except json.JSONDecodeError:
                logger.warning("Message is not valid JSON, treating as plain text")
                message = text_data

                # Send message to WebSocket
                await self.send(text_data=json.dumps({
                    'message': f"Received: {message}"
                }))
                logger.debug("Sent response message: %s", message)

                # Broadcast message to group
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'chat_message',
                        'message': message
                    }
                )
        else:
            logger.warning("Received empty message")

    async def chat_message(self, event):
        message = event['message']
        logger.debug("Broadcasting message: %s", message)

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message
        }))
# consumers.py

import json
from channels.generic.websocket import AsyncWebsocketConsumer

class TransactionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add(
            "transactions_group",
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            "transactions_group",
            self.channel_name
        )

    async def receive(self, text_data):
        message = json.loads(text_data)
        await self.channel_layer.group_send(
            "transactions_group",
            {
                "type": "chat_message",
                "message": message
            }
        )

    async def chat_message(self, event):
        message = event['message']
        await self.send(text_data=json.dumps(message))

class WalletUpdateConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add(
            "wallet_updates_group",
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            "wallet_updates_group",
            self.channel_name
        )

    async def receive(self, text_data):
        message = json.loads(text_data)
        await self.channel_layer.group_send(
            "wallet_updates_group",
            {
                "type": "chat_message",
                "message": message
            }
        )

    async def chat_message(self, event):
        message = event['message']
        await self.send(text_data=json.dumps(message))
# quantumapp/consumers.py
import json
from channels.generic.websocket import AsyncWebsocketConsumer

class TransactionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add("transactions_group", self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("transactions_group", self.channel_name)

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json['message']
        
        # Broadcast message to group
        await self.channel_layer.group_send(
            "transactions_group",
            {
                'type': 'transaction_message',
                'message': message
            }
        )

    async def transaction_message(self, event):
        message = event['message']

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message
        }))

class WalletConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add("wallet_updates_group", self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("wallet_updates_group", self.channel_name)

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json['message']
        
        # Broadcast message to group
        await self.channel_layer.group_send(
            "wallet_updates_group",
            {
                'type': 'wallet_message',
                'message': message
            }
        )

    async def wallet_message(self, event):
        message = event['message']

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message
        }))
# consumers.py
import json
from channels.generic.websocket import AsyncWebsocketConsumer

class P2PConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.peer_group = "peer_group"
        await self.channel_layer.group_add(self.peer_group, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.peer_group, self.channel_name)

    async def receive(self, text_data):
        message = json.loads(text_data)
        await self.channel_layer.group_send(
            self.peer_group,
            {
                'type': 'peer_message',
                'message': message
            }
        )

    async def peer_message(self, event):
        message = event['message']
        await self.send(text_data=json.dumps(message))
# consumers.py
import json
from channels.generic.websocket import AsyncWebsocketConsumer

class NodeConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.node_group_name = "nodes"
        await self.channel_layer.group_add(self.node_group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.node_group_name, self.channel_name)

    async def receive(self, text_data):
        data = json.loads(text_data)
        await self.channel_layer.group_send(
            self.node_group_name, 
            {
                "type": "node_message",
                "message": data['message']
            }
        )

    async def node_message(self, event):
        message = event['message']
        await self.send(text_data=json.dumps({"message": message}))
from channels.generic.websocket import AsyncWebsocketConsumer
import json

class RegisterNodeConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            node_url = data.get('url')
            public_key = data.get('public_key')

            if node_url and public_key:
                # Save the node to the database
                node, created = Node.objects.get_or_create(address=node_url, defaults={'public_key': public_key})
                if created:
                    await self.send(json.dumps({"status": "success", "message": "Node registered"}))
                else:
                    await self.send(json.dumps({"status": "error", "message": "Node already registered"}))
            else:
                await self.send(json.dumps({"status": "error", "message": "Invalid data"}))
        except Exception as e:
            await self.send(json.dumps({"status": "error", "message": str(e)}))
import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async

logger = logging.getLogger(__name__)

class NodeRegisterConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        logger.debug(f"WebSocket connection attempt: {self.scope['path']} with headers {self.scope['headers']}")
        await self.accept()
        logger.info("NodeRegisterConsumer connected")

    async def disconnect(self, close_code):
        logger.info(f"NodeRegisterConsumer disconnected: {close_code}")

    async def receive(self, text_data):
        from .models import Node  # Ensure this import is within the method

        logger.debug(f"Received data: {text_data}")
        try:
            data = json.loads(text_data)
            logger.debug(f"Parsed data: {data}")
            node_url = data.get('url')
            public_key = data.get('public_key')
            logger.debug(f"Extracted node_url: {node_url}, public_key: {public_key}")

            if node_url and public_key:
                node, created = await sync_to_async(Node.objects.get_or_create)(
                    address=node_url, defaults={'public_key': public_key}
                )
                if created:
                    await self.send(json.dumps({"status": "success", "message": "Node registered"}))
                    logger.info(f"Node registered: {node_url}")
                else:
                    await self.send(json.dumps({"status": "error", "message": "Node already registered"}))
                    logger.info(f"Node already registered: {node_url}")
            else:
                await self.send(json.dumps({"status": "error", "message": "Invalid data"}))
                logger.error("Invalid data received")
        except Exception as e:
            logger.error(f"Error in receive method: {e}")
            await self.send(json.dumps({"status": "error", "message": str(e)}))

# quantumapp/consumers.py
import json
from channels.generic.websocket import AsyncWebsocketConsumer

class TransactionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add("transactions", self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("transactions", self.channel_name)

    async def receive(self, text_data):
        data = json.loads(text_data)
        # Broadcast the received transaction to the group
        await self.channel_layer.group_send(
            "transactions",
            {
                "type": "transaction_message",
                "message": data
            }
        )

    async def transaction_message(self, event):
        message = event["message"]
        await self.send(text_data=json.dumps(message))
# quantumapp/consumers.py

import json
from channels.generic.websocket import AsyncWebsocketConsumer
import logging

logger = logging.getLogger(__name__)
class TransactionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add("transactions_group", self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("transactions_group", self.channel_name)

    async def receive(self, text_data):
        data = json.loads(text_data)
        # Broadcast the received transaction to the group
        await self.channel_layer.group_send(
            "transactions_group",
            {
                "type": "transaction_message",
                "message": data
            }
        )

    async def transaction_message(self, event):
        message = event["message"]
        await self.send(text_data=json.dumps(message))

        # Forward the transaction to the HTTP endpoint
        response = requests.post(
            'https://app.cashestable.com/receive_transaction/',  # Adjust the URL to match your setup
            headers={'Content-Type': 'application/json'},
            data=json.dumps(message)
        )
        if response.status_code == 200:
            print("Transaction forwarded successfully")
        else:
            print("Failed to forward transaction")
class TransactionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add("transactions_group", self.channel_name)
        await self.accept()
        logger.debug("WebSocket connected")

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("transactions_group", self.channel_name)
        logger.debug("WebSocket disconnected with code: %s", close_code)

    async def receive(self, text_data):
        data = json.loads(text_data)
        logger.debug(f"Received data: {data}")

        # Broadcast the received transaction to the group
        await self.channel_layer.group_send(
            "transactions_group",
            {
                "type": "transaction_message",
                "message": data
            }
        )

        # Forward the transaction to the HTTP endpoint
        response = requests.post(
            'https://app.cashewstable.com/receive_transaction/',  # Adjust the URL to match your setup
            headers={'Content-Type': 'application/json'},
            data=json.dumps(data)
        )
        if response.status_code == 200:
            logger.info("Transaction forwarded successfully")
        else:
            logger.error("Failed to forward transaction")

    async def transaction_message(self, event):
        message = event["message"]
        logger.debug(f"Broadcasting message: {message}")
        await self.send(text_data=json.dumps(message))
# quantumapp/consumers.py
class SyncConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        logger.info(f"Node connected: {self.channel_name}")

        # Register with master node if this is a slave node
        if settings.CURRENT_NODE_URL != settings.MASTER_NODE_URL:
            await self.register_with_master_node()

    async def disconnect(self, close_code):
        logger.info(f"Node disconnected: {self.channel_name}")

    async def receive(self, text_data):
        data = json.loads(text_data)
        logger.debug(f"Received data: {data}")

        if data.get('type') == 'transaction':
            await self.handle_transaction(data['transaction'])
        elif data.get('type') == 'block':
            await self.handle_block(data['block'])
    
    async def handle_transaction(self, transaction_data):
        from .models import Transaction  # Importing inside the method
        logger.debug(f"Handling transaction: {transaction_data}")
        transaction, created = await sync_to_async(Transaction.objects.get_or_create)(
            hash=transaction_data['transaction_hash'],
            defaults={
                'sender': transaction_data['sender'],
                'receiver': transaction_data['receiver'],
                'amount': transaction_data['amount'],
                'fee': transaction_data['fee'],
                'timestamp': transaction_data['timestamp'],
                'is_approved': transaction_data['is_approved'],
            }
        )
        if created:
            logger.info(f"Transaction {transaction.hash} synchronized successfully")
        else:
            logger.info(f"Transaction {transaction.hash} already exists")

    async def handle_block(self, block_data):
        logger.debug(f"Handling block: {block_data}")

        # Create the block object
        block = Block(
            hash=block_data['hash'],
            previous_hash=block_data['previous_hash'],
            timestamp=datetime.fromisoformat(block_data['timestamp'])
        )

        # Add block to the DAG
        if block.hash not in dag:
            dag[block.hash] = block
            if block.previous_hash in dag:
                dag[block.previous_hash].children.append(block)

        # Ensure the block is valid
        if await self.validate_block(block):
            logger.info(f"Block {block.hash} synchronized successfully")
        else:
            logger.error(f"Invalid block: {block_data['hash']}")

    async def validate_block(self, block):
        # Example validation: Check if the previous hash exists in the DAG
        if block.previous_hash and block.previous_hash not in dag:
            logger.error(f"Invalid previous hash for block {block.hash}")
            return False
        return True

    async def register_with_master_node(self):
        from .models import Node  # Importing inside the method                                                 
        try:
            async with websockets.connect(settings.MASTER_NODE_URL + '/ws/register_node/') as websocket:
                await websocket.send(json.dumps({'url': settings.CURRENT_NODE_URL, 'public_key': 'your_public_key_here'}))
                response = await websocket.recv()
                response_data = json.loads(response)
                if response_data.get("status") == "success":
                    logger.info("Successfully registered with master node.")
                else:
                    logger.error(f"Failed to register with master node. Response: {response_data}")
        except Exception as e:
            logger.error(f"Error registering with master node: {e}")

# For master node to handle new node registration
class NodeRegisterConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        logger.info(f"NodeRegisterConsumer connected")

    async def disconnect(self, close_code):
        logger.info(f"NodeRegisterConsumer disconnected: {close_code}")

    async def receive(self, text_data):
        data = json.loads(text_data)
        node_url = data.get('url')
        public_key = data.get('public_key')

        if node_url and public_key:
            node, created = await sync_to_async(Node.objects.get_or_create)(
                address=node_url, defaults={'public_key': public_key}
            )
            if created:
                await self.send(json.dumps({"status": "success", "message": "Node registered"}))
                logger.info(f"Node registered: {node_url}")
            else:
                await self.send(json.dumps({"status": "error", "message": "Node already registered"}))
                logger.info(f"Node already registered: {node_url}")
        else:
            await self.send(json.dumps({"status": "error", "message": "Invalid data"}))
            logger.error("Invalid data received")
        
class SyncConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        logger.info(f"Node connected: {self.channel_name}")

        # Register with master node if this is a slave node
        if settings.CURRENT_NODE_URL != settings.MASTER_NODE_URL:
            await self.register_with_master_node()

    async def disconnect(self, close_code):
        logger.info(f"Node disconnected: {self.channel_name}")

    async def receive(self, text_data):
        data = json.loads(text_data)
        logger.debug(f"Received data: {data}")

        if data.get('type') == 'transaction':
            await self.handle_transaction(data['transaction'])
        elif data.get('type') == 'block':
            await self.handle_block(data['block'])
    
    async def handle_transaction(self, transaction_data):
        from .models import Transaction  # Importing inside the method
        logger.debug(f"Handling transaction: {transaction_data}")
        transaction, created = await sync_to_async(Transaction.objects.get_or_create)(
            hash=transaction_data['transaction_hash'],
            defaults={
                'sender': transaction_data['sender'],
                'receiver': transaction_data['receiver'],
                'amount': transaction_data['amount'],
                'fee': transaction_data['fee'],
                'timestamp': transaction_data['timestamp'],
                'is_approved': transaction_data['is_approved'],
            }
        )
        if created:
            logger.info(f"Transaction {transaction.hash} synchronized successfully")
        else:
            logger.info(f"Transaction {transaction.hash} already exists")

    async def handle_block(self, block_data):
        logger.debug(f"Handling block: {block_data}")

        # Create the block object
        block = Block(
            hash=block_data['hash'],
            previous_hash=block_data['previous_hash'],
            timestamp=datetime.fromisoformat(block_data['timestamp'])
        )

        # Add block to the DAG
        if block.hash not in dag:
            dag[block.hash] = block
            if block.previous_hash in dag:
                dag[block.previous_hash].children.append(block)

        # Ensure the block is valid
        if await self.validate_block(block):
            logger.info(f"Block {block.hash} synchronized successfully")
        else:
            logger.error(f"Invalid block: {block_data['hash']}")

    async def validate_block(self, block):
        # Example validation: Check if the previous hash exists in the DAG
        if block.previous_hash and block.previous_hash not in dag:
            logger.error(f"Invalid previous hash for block {block.hash}")
            return False
        return True

    async def register_with_master_node(self):
        from .models import Node  # Importing inside the method
        try:
            async with websockets.connect(settings.MASTER_NODE_URL + '/ws/register_node/') as websocket:
                await websocket.send(json.dumps({'url': settings.CURRENT_NODE_URL, 'public_key': 'your_public_key_here'}))
                response = await websocket.recv()
                response_data = json.loads(response)
                if response_data.get("status") == "success":
                    logger.info("Successfully registered with master node.")
                else:
                    logger.error(f"Failed to register with master node. Response: {response_data}")
        except Exception as e:
            logger.error(f"Error registering with master node: {e}")
import json
import logging
from datetime import datetime
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from django.conf import settings

logger = logging.getLogger(__name__)

class SyncConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        logger.info(f"Node connected: {self.channel_name}")

        # Register with master node if this is a slave node
        if settings.CURRENT_NODE_URL != settings.MASTER_NODE_URL:
            await self.register_with_master_node()

    async def disconnect(self, close_code):
        logger.info(f"Node disconnected: {self.channel_name}")

    async def receive(self, text_data):
        data = json.loads(text_data)
        logger.debug(f"Received data: {data}")

        if data.get('type') == 'transaction':
            await self.handle_transaction(data['transaction'])
        elif data.get('type') == 'block':
            await self.handle_block(data['block'])
    
    async def handle_transaction(self, transaction_data):
        from .models import Transaction  # Importing inside the method
        logger.debug(f"Handling transaction: {transaction_data}")
        transaction, created = await sync_to_async(Transaction.objects.get_or_create)(
            hash=transaction_data['transaction_hash'],
            defaults={
                'sender': transaction_data['sender'],
                'receiver': transaction_data['receiver'],
                'amount': transaction_data['amount'],
                'fee': transaction_data['fee'],
                'timestamp': transaction_data['timestamp'],
                'is_approved': transaction_data['is_approved'],
            }
        )
        if created:
            logger.info(f"Transaction {transaction.hash} synchronized successfully")
        else:
            logger.info(f"Transaction {transaction.hash} already exists")

    async def handle_block(self, block_data):
        logger.debug(f"Handling block: {block_data}")

        # Create the block object
        block = Block(
            hash=block_data['hash'],
            previous_hash=block_data['previous_hash'],
            timestamp=datetime.fromisoformat(block_data['timestamp'])
        )

        # Add block to the DAG
        if block.hash not in dag:
            dag[block.hash] = block
            if block.previous_hash in dag:
                dag[block.previous_hash].children.append(block)

        # Ensure the block is valid
        if await self.validate_block(block):
            logger.info(f"Block {block.hash} synchronized successfully")
        else:
            logger.error(f"Invalid block: {block_data['hash']}")

    async def validate_block(self, block):
        # Example validation: Check if the previous hash exists in the DAG
        if block.previous_hash and block.previous_hash not in dag:
            logger.error(f"Invalid previous hash for block {block.hash}")
            return False
        return True

    async def register_with_master_node(self):
        from .models import Node  # Importing inside the method                                                 
        try:
            async with websockets.connect(settings.MASTER_NODE_URL + '/ws/register_node/') as websocket:
                await websocket.send(json.dumps({'url': settings.CURRENT_NODE_URL, 'public_key': 'your_public_key_here'}))
                response = await websocket.recv()
                response_data = json.loads(response)
                if response_data.get("status") == "success":
                    logger.info("Successfully registered with master node.")
                else:
                    logger.error(f"Failed to register with master node. Response: {response_data}")
        except Exception as e:
            logger.error(f"Error registering with master node: {e}")
class SyncConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        logger.info(f"Node connected: {self.channel_name}")

        # Register with master node if this is a slave node
        if settings.CURRENT_NODE_URL != settings.MASTER_NODE_URL:
            await self.register_with_master_node()

    async def disconnect(self, close_code):
        logger.info(f"Node disconnected: {self.channel_name}")

    async def receive(self, text_data):
        data = json.loads(text_data)
        logger.debug(f"Received data: {data}")

        if data.get('type') == 'transaction':
            await self.handle_transaction(data['transaction'])
        elif data.get('type') == 'block':
            await self.handle_block(data['block'])
    
    async def handle_transaction(self, transaction_data):
        from .models import Transaction  # Importing inside the method
        logger.debug(f"Handling transaction: {transaction_data}")
        transaction, created = await sync_to_async(Transaction.objects.get_or_create)(
            hash=transaction_data['transaction_hash'],
            defaults={
                'sender': transaction_data['sender'],
                'receiver': transaction_data['receiver'],
                'amount': transaction_data['amount'],
                'fee': transaction_data['fee'],
                'timestamp': transaction_data['timestamp'],
                'is_approved': transaction_data['is_approved'],
            }
        )
        if created:
            logger.info(f"Transaction {transaction.hash} synchronized successfully")
        else:
            logger.info(f"Transaction {transaction.hash} already exists")

    async def handle_block(self, block_data):
        logger.debug(f"Handling block: {block_data}")

        # Create the block object
        block = Block(
            hash=block_data['hash'],
            previous_hash=block_data['previous_hash'],
            timestamp=datetime.fromisoformat(block_data['timestamp'])
        )

        # Add block to the DAG
        if block.hash not in dag:
            dag[block.hash] = block
            if block.previous_hash in dag:
                dag[block.previous_hash].children.append(block)

        # Ensure the block is valid
        if await self.validate_block(block):
            logger.info(f"Block {block.hash} synchronized successfully")
        else:
            logger.error(f"Invalid block: {block_data['hash']}")

    async def validate_block(self, block):
        # Example validation: Check if the previous hash exists in the DAG
        if block.previous_hash and block.previous_hash not in dag:
            logger.error(f"Invalid previous hash for block {block.hash}")
            return False
        return True

    async def register_with_master_node(self):
        from .models import Node  # Importing inside the method                                                 
        try:
            async with websockets.connect(settings.MASTER_NODE_URL + '/ws/register_node/', timeout=10) as websocket:
                await websocket.send(json.dumps({'url': settings.CURRENT_NODE_URL, 'public_key': 'your_public_key_here'}))
                response = await websocket.recv()
                response_data = json.loads(response)
                if response_data.get("status") == "success":
                    logger.info("Successfully registered with master node.")
                else:
                    logger.error(f"Failed to register with master node. Response: {response_data}")
        except (websockets.exceptions.InvalidStatusCode, websockets.exceptions.WebSocketException, asyncio.TimeoutError) as e:
            logger.error(f"Error registering with master node: {e}\n{traceback.format_exc()}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}\n{traceback.format_exc()}")
            
class SyncConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        logger.info(f"Node connected: {self.channel_name}")

        # Register with master node if this is a slave node
        if settings.CURRENT_NODE_URL != settings.MASTER_NODE_URL:
            await self.register_with_master_node()

    async def disconnect(self, close_code):
        logger.info(f"Node disconnected: {self.channel_name}")

    async def receive(self, text_data):
        data = json.loads(text_data)
        logger.debug(f"Received data: {data}")

        if data.get('type') == 'transaction':
            await self.handle_transaction(data['transaction'])
        elif data.get('type') == 'block':
            await self.handle_block(data['block'])
        elif data.get('type') == 'node_registration':
            await self.handle_node_registration(data['node_info'])

    async def handle_transaction(self, transaction_data):
        from .models import Transaction  # Importing inside the method
        logger.debug(f"Handling transaction: {transaction_data}")
        try:
            transaction, created = await sync_to_async(Transaction.objects.get_or_create)(
                hash=transaction_data['transaction_hash'],
                defaults={
                    'sender': transaction_data['sender'],
                    'receiver': transaction_data['receiver'],
                    'amount': transaction_data['amount'],
                    'fee': transaction_data['fee'],
                    'timestamp': transaction_data['timestamp'],
                    'is_approved': transaction_data['is_approved'],
                }
            )
            if created:
                logger.info(f"Transaction {transaction.hash} synchronized successfully")
            else:
                logger.info(f"Transaction {transaction.hash} already exists")
        except Exception as e:
            logger.error(f"Error handling transaction: {e}\n{traceback.format_exc()}")

    async def handle_block(self, block_data):
        logger.debug(f"Handling block: {block_data}")
        try:
            # Create the block object
            block = Block(
                hash=block_data['hash'],
                previous_hash=block_data['previous_hash'],
                timestamp=datetime.fromisoformat(block_data['timestamp'])
            )

            # Add block to the DAG
            if block.hash not in dag:
                dag[block.hash] = block
                if block.previous_hash in dag:
                    dag[block.previous_hash].children.append(block)

            # Ensure the block is valid
            if await self.validate_block(block):
                logger.info(f"Block {block.hash} synchronized successfully")
            else:
                logger.error(f"Invalid block: {block_data['hash']}")
        except Exception as e:
            logger.error(f"Error handling block: {e}\n{traceback.format_exc()}")

    async def validate_block(self, block):
        try:
            # Example validation: Check if the previous hash exists in the DAG
            if block.previous_hash and block.previous_hash not in dag:
                logger.error(f"Invalid previous hash for block {block.hash}")
                return False
            return True
        except Exception as e:
            logger.error(f"Error validating block: {e}\n{traceback.format_exc()}")
            return False

    async def register_with_master_node(self):
        from .models import Node  # Importing inside the method
        try:
            logger.info(f"Attempting to connect to master node at {settings.MASTER_NODE_URL}")
            async with websockets.connect(settings.MASTER_NODE_URL + '/ws/register_node/', timeout=10) as websocket:
                logger.info(f"Connected to master node: {settings.MASTER_NODE_URL}")
                await websocket.send(json.dumps({'url': settings.CURRENT_NODE_URL, 'public_key': 'your_public_key_here'}))
                response = await websocket.recv()
                response_data = json.loads(response)
                logger.debug(f"Response from master node: {response_data}")
                if response_data.get("status") == "success":
                    logger.info("Successfully registered with master node.")
                else:
                    logger.error(f"Failed to register with master node. Response: {response_data}")
        except (websockets.exceptions.InvalidStatusCode, websockets.exceptions.WebSocketException, asyncio.TimeoutError) as e:
            logger.error(f"Error registering with master node: {e}\n{traceback.format_exc()}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}\n{traceback.format_exc()}")

    async def handle_node_registration(self, node_info):
        from .models import Node  # Importing inside the method
        logger.debug(f"Handling node registration: {node_info}")
        try:
            node, created = await sync_to_async(Node.objects.get_or_create)(
                url=node_info['url'],
                defaults={
                    'public_key': node_info['public_key'],
                    'is_master': node_info['is_master'],
                }
            )
            if created:
                logger.info(f"Node {node.url} registered successfully")
            else:
                logger.info(f"Node {node.url} already exists")
        except Exception as e:
            logger.error(f"Error handling node registration: {e}\n{traceback.format_exc()}")
class NodeRegisterConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        logger.info("NodeRegisterConsumer connected")

    async def disconnect(self, close_code):
        logger.info(f"NodeRegisterConsumer disconnected with close code {close_code}")

    async def receive(self, text_data):
        logger.debug(f"Received message: {text_data}")
        message = json.loads(text_data)
        
        try:
            from quantumapp.models import Node  # Import within the method
            node, created = await sync_to_async(Node.objects.get_or_create)(
                url=message["url"]
            )
            if created:
                logger.info(f"Node created: {node}")
            else:
                logger.info(f"Node already exists: {node}")
        except Exception as e:
            logger.error(f"Error in receive method: {e}\n{traceback.format_exc()}")
            await self.close()

    async def send_message(self, message):
        await self.send(text_data=json.dumps(message))
import json
import logging
import traceback
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async

logger = logging.getLogger(__name__)

class NodeRegisterConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        self.peer_id = None
        logger.info("NodeRegisterConsumer connected")
        await self.send(text_data=json.dumps({
            'message': 'Connected to the Node Registration WebSocket'
        }))

    async def disconnect(self, close_code):
        if self.peer_id:
            from quantumapp.models import Node  # Importing within the method
            await sync_to_async(Node.objects.filter(id=self.peer_id).delete)()
        logger.info(f"NodeRegisterConsumer disconnected with close code {close_code}")

    async def receive(self, text_data):
        logger.debug(f"Received message: {text_data}")
        message = json.loads(text_data)
        
        url = message.get('url')
        public_key = message.get('public_key')

        if not url or not public_key:
            await self.send(text_data=json.dumps({'error': 'URL and public key are required'}))
            return

        try:
            from quantumapp.models import Node  # Importing within the method
            node, created = await sync_to_async(Node.objects.get_or_create)(
                address=url,
                defaults={'public_key': public_key}
            )
            if not created:
                node.public_key = public_key
                await sync_to_async(node.save)()

            self.peer_id = node.id

            # Generate the multiaddress using libp2p
            multiaddress = f"/ip4/{self.scope['client'][0]}/tcp/{self.scope['client'][1]}/p2p/{node.public_key}"

            await self.send(text_data=json.dumps({
                'message': 'Node registered successfully',
                'multiaddress': multiaddress
            }))
            logger.info(f"Node {node} registered with multiaddress: {multiaddress}")

        except Exception as e:
            logger.error(f"Error in receive method: {e}\n{traceback.format_exc()}")
            await self.close()

    async def send_message(self, message):
        await self.send(text_data=json.dumps(message))

import asyncio
import json
from channels.generic.websocket import AsyncWebsocketConsumer

class LogConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()

        # Simulate streaming logs (you should replace this with your actual log streaming logic)
        async def stream_logs():
            for i in range(100):
                log_message = f"Log entry {i}"
                await self.send(text_data=json.dumps({
                    'message': log_message
                }))
                await asyncio.sleep(1)

        asyncio.create_task(stream_logs())

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        pass
# consumers.py
# consumers.py
# consumers.py
# consumers.py
import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
import websockets

logger = logging.getLogger(__name__)

class QuantumSyncConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User
        from .libp2p_node import start_node
        from django.conf import settings

        await self.channel_layer.group_add("node_sync_group", self.channel_name)
        await self.accept()
        logger.info("QuantumSyncConsumer connected")

    async def disconnect(self, close_code):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User
        from .libp2p_node import start_node
        from django.conf import settings

        await self.channel_layer.group_discard("node_sync_group", self.channel_name)
        logger.info(f"QuantumSyncConsumer disconnected with close code {close_code}")

    async def sync_wallet(self, event):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User
        from .libp2p_node import start_node
        from django.conf import settings

        wallet_data = event['wallet_data']
        logger.debug(f"Received wallet data for sync: {wallet_data}")
        await self.create_wallet(wallet_data)

        # Send sync status update to the frontend
        await self.send(text_data=json.dumps({
            'type': 'sync_status',
            'status': 'Wallet synced',
            'wallet_data': wallet_data
        }))

        # Broadcast using libp2p
        await self.broadcast_wallet_libp2p(wallet_data)

    @sync_to_async
    def create_wallet(self, wallet_data):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User
        from .libp2p_node import start_node
        from django.conf import settings

        try:
            user, created = User.objects.get_or_create(username=wallet_data['public_key'])
            if created:
                Wallet.objects.create(
                    user=user,
                    public_key=wallet_data['public_key'],
                    address=wallet_data['address'],
                    alias=wallet_data['alias'],
                    balance=wallet_data['balance']
                )
                logger.info(f"Wallet synchronized: {wallet_data['public_key']}")
            else:
                logger.info(f"Wallet already exists: {wallet_data['public_key']}")
        except Exception as e:
            logger.error(f"Error creating wallet: {str(e)}")

    async def broadcast_wallet_libp2p(self, wallet_data):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User
        from .libp2p_node import start_node
        from django.conf import settings

        node = await start_node()
        for peer_id in node.peerstore.peer_ids():
            if peer_id != node.get_id():
                try:
                    stream = await node.new_stream(peer_id, ["/echo/1.0.0"])
                    await stream.write(json.dumps(wallet_data).encode("utf-8"))
                    logger.info(f"Broadcasted wallet data to peer {peer_id.pretty()}")

                    # Send libp2p status update to the frontend
                    await self.send(text_data=json.dumps({
                        'type': 'libp2p_status',
                        'status': 'Broadcasted wallet data',
                        'peer_id': peer_id.pretty()
                    }))
                except Exception as e:
                    logger.error(f"Error broadcasting wallet data to peer {peer_id.pretty()}: {str(e)}")
                    await self.send(text_data=json.dumps({
                        'type': 'libp2p_status',
                        'status': 'Error broadcasting wallet data',
                        'peer_id': peer_id.pretty(),
                        'error': str(e)
                    }))
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from django.conf import settings

logger = logging.getLogger(__name__)

class QuantumSyncConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User
        from .libp2p_node import start_node
        from django.conf import settings

        await self.channel_layer.group_add("node_sync_group", self.channel_name)
        await self.accept()
        logger.info("QuantumSyncConsumer connected")

    async def disconnect(self, close_code):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User
        from .libp2p_node import start_node
        from django.conf import settings

        await self.channel_layer.group_discard("node_sync_group", self.channel_name)
        logger.info(f"QuantumSyncConsumer disconnected with close code {close_code}")
    async def register_peer(self, peer_info):
        try:
            await self.save_peer_info(peer_info)
            logger.info(f"Registering peer: {peer_info}")
            await self.send(text_data=json.dumps({
                'type': 'registration_status',
                'status': 'Peer registered successfully',
                'peer_info': peer_info
            }))
        except Exception as e:
            logger.error(f"Error registering peer: {str(e)}")
            await self.send(text_data=json.dumps({
                'type': 'registration_status',
                'status': 'Error registering peer',
                'error': str(e)
            }))

    @sync_to_async
    def save_peer_info(self, peer_info):
        try:
            peer, created = Peer.objects.get_or_create(
                peer_id=peer_info['peer_id'],
                defaults={'address': peer_info['address']}
            )
            if not created:
                peer.address = peer_info['address']
                peer.save()
        except Exception as e:
            logger.error(f"Error saving peer info: {str(e)}")
            raise e



    async def sync_wallet(self, event):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User
        from .libp2p_node import start_node
        from django.conf import settings

        wallet_data = event['wallet_data']
        logger.debug(f"Received wallet data for sync: {wallet_data}")
        await self.create_wallet(wallet_data)

        # Send sync status update to the frontend
        await self.send(text_data=json.dumps({
            'type': 'sync_status',
            'status': 'Wallet synced',
            'wallet_data': wallet_data
        }))

        # Broadcast using libp2p
        await self.broadcast_wallet_libp2p(wallet_data)

    @sync_to_async
    def create_wallet(self, wallet_data):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User
        from .libp2p_node import start_node
        from django.conf import settings

        try:
            user, created = User.objects.get_or_create(username=wallet_data['public_key'])
            if created:
                Wallet.objects.create(
                    user=user,
                    public_key=wallet_data['public_key'],
                    address=wallet_data['address'],
                    alias=wallet_data['alias'],
                    balance=wallet_data['balance']
                )
                logger.info(f"Wallet synchronized: {wallet_data['public_key']}")
            else:
                logger.info(f"Wallet already exists: {wallet_data['public_key']}")
        except Exception as e:
            logger.error(f"Error creating wallet: {str(e)}")

    async def broadcast_wallet_libp2p(self, wallet_data):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User
        from .libp2p_node import start_node
        from django.conf import settings

        node = await start_node()
        for peer_id in node.peerstore.peer_ids():
            if peer_id != node.get_id():
                try:
                    stream = await node.new_stream(peer_id, ["/echo/1.0.0"])
                    await stream.write(json.dumps(wallet_data).encode("utf-8"))
                    logger.info(f"Broadcasted wallet data to peer {peer_id.pretty()}")

                    # Send libp2p status update to the frontend
                    await self.send(text_data=json.dumps({
                        'type': 'libp2p_status',
                        'status': 'Broadcasted wallet data',
                        'peer_id': peer_id.pretty()
                    }))
                except Exception as e:
                    logger.error(f"Error broadcasting wallet data to peer {peer_id.pretty()}: {str(e)}")
                    await self.send(text_data=json.dumps({
                        'type': 'libp2p_status',
                        'status': 'Error broadcasting wallet data',
                        'peer_id': peer_id.pretty(),
                        'error': str(e)
                    }))

    async def receive(self, text_data):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User
        from .libp2p_node import start_node
        from django.conf import settings

        logger.debug(f"Received raw text data: {text_data}")
        try:
            data = json.loads(text_data)
            if 'type' in data and data['type'] == 'sync_wallet':
                await self.sync_wallet(data)
        except json.JSONDecodeError as e:
            logger.error(f"JSONDecodeError: {str(e)}")
            logger.error(f"Received invalid JSON: {text_data}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid JSON format'
            }))
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Unexpected error occurred'
            }))
# consumers.py
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from django.conf import settings

logger = logging.getLogger(__name__)

class QuantumSyncConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add("node_sync_group", self.channel_name)
        await self.accept()
        logger.info("QuantumSyncConsumer connected")
        await self.sync_wallets_from_master()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("node_sync_group", self.channel_name)
        logger.info(f"QuantumSyncConsumer disconnected with close code {close_code}")

    async def sync_wallet(self, event):
        import json
        wallet_data = event['wallet_data']
        logger.debug(f"Received wallet data for sync: {wallet_data}")
        await self.create_wallet(wallet_data)

        # Send sync status update to the frontend
        await self.send(text_data=json.dumps({
            'type': 'sync_status',
            'status': 'Wallet synced',
            'wallet_data': wallet_data
        }))

        # Broadcast using libp2p
        await self.broadcast_wallet_libp2p(wallet_data)

    @sync_to_async
    def create_wallet(self, wallet_data):
        import logging
        from .models import Wallet, User
        logger = logging.getLogger(__name__)
        try:
            user, created = User.objects.get_or_create(username=wallet_data['public_key'])
            if created:
                Wallet.objects.create(
                    user=user,
                    public_key=wallet_data['public_key'],
                    address=wallet_data['address'],
                    alias=wallet_data['alias'],
                    balance=wallet_data['balance']
                )
                logger.info(f"Wallet synchronized: {wallet_data['public_key']}")
            else:
                logger.info(f"Wallet already exists: {wallet_data['public_key']}")
        except Exception as e:
            logger.error(f"Error creating wallet: {str(e)}")

    async def broadcast_wallet_libp2p(self, wallet_data):
        import json
        from .libp2p_node import start_node
        node = await start_node()
        for peer_id in node.peerstore.peer_ids():
            if peer_id != node.get_id():
                try:
                    stream = await node.new_stream(peer_id, ["/echo/1.0.0"])
                    await stream.write(json.dumps(wallet_data).encode("utf-8"))
                    logger.info(f"Broadcasted wallet data to peer {peer_id.pretty()}")

                    # Send libp2p status update to the frontend
                    await self.send(text_data=json.dumps({
                        'type': 'libp2p_status',
                        'status': 'Broadcasted wallet data',
                        'peer_id': peer_id.pretty()
                    }))
                except Exception as e:
                    logger.error(f"Error broadcasting wallet data to peer {peer_id.pretty()}: {str(e)}")
                    await self.send(text_data=json.dumps({
                        'type': 'libp2p_status',
                        'status': 'Error broadcasting wallet data',
                        'peer_id': peer_id.pretty(),
                        'error': str(e)
                    }))

    async def receive(self, text_data):
        import json
        logger.debug(f"Received raw text data: {text_data}")
        try:
            data = json.loads(text_data)
            if 'type' in data and data['type'] == 'sync_wallet':
                await self.sync_wallet(data)
            elif 'action' in data and data['action'] == 'register_peer':
                await self.register_peer(data['peer_info'])
        except json.JSONDecodeError as e:
            logger.error(f"JSONDecodeError: {str(e)}")
            logger.error(f"Received invalid JSON: {text_data}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid JSON format'
            }))
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Unexpected error occurred'
            }))

    @sync_to_async
    def register_peer(self, peer_info):
        from .models import Peer
        logger = logging.getLogger(__name__)
        try:
            peer, created = Peer.objects.get_or_create(
                address=peer_info['address'],
                peer_id=peer_info['peer_id']
            )
            if created:
                logger.info(f"Registered new peer: {peer_info}")
            else:
                logger.info(f"Peer already exists: {peer_info}")
        except Exception as e:
            logger.error(f"Error registering peer: {str(e)}")

    async def sync_wallets_from_master(self):
        import json
        import websockets
        logger = logging.getLogger(__name__)
        try:
            async with websockets.connect(settings.MASTER_NODE_URL + '/ws/sync_wallets/', timeout=10) as websocket:
                await websocket.send(json.dumps({'action': 'fetch_wallets'}))
                response = await websocket.recv()
                wallet_list = json.loads(response)
                for wallet_data in wallet_list:
                    await self.create_wallet(wallet_data)
                logger.info("Successfully synced wallets from master node")
        except Exception as e:
            logger.error(f"Error syncing wallets from master node: {str(e)}")
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from django.conf import settings

logger = logging.getLogger(__name__)

class QuantumSyncConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add("node_sync_group", self.channel_name)
        await self.accept()
        logger.info("QuantumSyncConsumer connected")
        await self.register_and_sync_from_master()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("node_sync_group", self.channel_name)
        logger.info(f"QuantumSyncConsumer disconnected with close code {close_code}")

    async def sync_wallet(self, event):
        import json
        wallet_data = event['wallet_data']
        logger.debug(f"Received wallet data for sync: {wallet_data}")
        await self.create_wallet(wallet_data)

        # Send sync status update to the frontend
        await self.send(text_data=json.dumps({
            'type': 'sync_status',
            'status': 'Wallet synced',
            'wallet_data': wallet_data
        }))

        # Broadcast using libp2p
        await self.broadcast_wallet_libp2p(wallet_data)

    @sync_to_async
    def create_wallet(self, wallet_data):
        from .models import Wallet, User
        try:
            user, created = User.objects.get_or_create(username=wallet_data['public_key'])
            if created:
                Wallet.objects.create(
                    user=user,
                    public_key=wallet_data['public_key'],
                    address=wallet_data['address'],
                    alias=wallet_data['alias'],
                    balance=wallet_data['balance']
                )
                logger.info(f"Wallet synchronized: {wallet_data['public_key']}")
            else:
                logger.info(f"Wallet already exists: {wallet_data['public_key']}")
        except Exception as e:
            logger.error(f"Error creating wallet: {str(e)}")

    async def broadcast_wallet_libp2p(self, wallet_data):
        import json
        from .libp2p_node import start_node
        node = await start_node()
        for peer_id in node.peerstore.peer_ids():
            if peer_id != node.get_id():
                try:
                    stream = await node.new_stream(peer_id, ["/echo/1.0.0"])
                    await stream.write(json.dumps(wallet_data).encode("utf-8"))
                    logger.info(f"Broadcasted wallet data to peer {peer_id.pretty()}")

                    # Send libp2p status update to the frontend
                    await self.send(text_data=json.dumps({
                        'type': 'libp2p_status',
                        'status': 'Broadcasted wallet data',
                        'peer_id': peer_id.pretty()
                    }))
                except Exception as e:
                    logger.error(f"Error broadcasting wallet data to peer {peer_id.pretty()}: {str(e)}")
                    await self.send(text_data=json.dumps({
                        'type': 'libp2p_status',
                        'status': 'Error broadcasting wallet data',
                        'peer_id': peer_id.pretty(),
                        'error': str(e)
                    }))

    async def receive(self, text_data):
        import json
        logger.debug(f"Received raw text data: {text_data}")
        try:
            data = json.loads(text_data)
            if 'type' in data and data['type'] == 'sync_wallet':
                await self.sync_wallet(data)
            elif 'action' in data and data['action'] == 'register_peer':
                await self.register_peer(data['peer_info'])
        except json.JSONDecodeError as e:
            logger.error(f"JSONDecodeError: {str(e)}")
            logger.error(f"Received invalid JSON: {text_data}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid JSON format'
            }))
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Unexpected error occurred'
            }))

    @sync_to_async
    def register_peer(self, peer_info):
        from .models import Peer
        try:
            peer, created = Peer.objects.get_or_create(
                address=peer_info['address'],
                peer_id=peer_info['peer_id']
            )
            if created:
                logger.info(f"Registered new peer: {peer_info}")
            else:
                logger.info(f"Peer already exists: {peer_info}")
        except Exception as e:
            logger.error(f"Error registering peer: {str(e)}")

    async def register_and_sync_from_master(self):
        from .register_with_master import register_with_master_node_async
        try:
            multiaddress = await register_with_master_node_async()
            if multiaddress:
                # Use multiaddress for further operations, like syncing wallets
                await self.sync_wallets_from_master(multiaddress)
        except Exception as e:
            logger.error(f"Error during registration and syncing: {str(e)}")

    async def sync_wallets_from_master(self, multiaddress):
        import json
        import websockets
        try:
            async with websockets.connect(multiaddress + '/ws/sync_wallets/', timeout=10) as websocket:
                await websocket.send(json.dumps({'action': 'fetch_wallets'}))
                response = await websocket.recv()
                wallet_list = json.loads(response)
                for wallet_data in wallet_list:
                    await self.create_wallet(wallet_data)
                logger.info("Successfully synced wallets from master node")
        except Exception as e:
            logger.error(f"Error syncing wallets from master node: {str(e)}")
class QuantumSyncConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User, Peer
        from .libp2p_node import start_node
        from django.conf import settings
        import websockets

        await self.channel_layer.group_add("node_sync_group", self.channel_name)
        await self.accept()
        logger.info("QuantumSyncConsumer connected")
        await self.register_and_sync_from_master()

    async def disconnect(self, close_code):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User, Peer
        from .libp2p_node import start_node
        from django.conf import settings
        import websockets

        await self.channel_layer.group_discard("node_sync_group", self.channel_name)
        logger.info(f"QuantumSyncConsumer disconnected with close code {close_code}")

    async def sync_wallet(self, event):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User, Peer
        from .libp2p_node import start_node
        from django.conf import settings
        import websockets

        wallet_data = event['wallet_data']
        logger.debug(f"Received wallet data for sync: {wallet_data}")
        await self.create_wallet(wallet_data)

        # Send sync status update to the frontend
        await self.send(text_data=json.dumps({
            'type': 'sync_status',
            'status': 'Wallet synced',
            'wallet_data': wallet_data
        }))

        # Broadcast using libp2p
        await self.broadcast_wallet_libp2p(wallet_data)

    @sync_to_async
    def create_wallet(self, wallet_data):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User, Peer
        from .libp2p_node import start_node
        from django.conf import settings
        import websockets

        try:
            user, created = User.objects.get_or_create(username=wallet_data['public_key'])
            if created:
                Wallet.objects.create(
                    user=user,
                    public_key=wallet_data['public_key'],
                    address=wallet_data['address'],
                    alias=wallet_data['alias'],
                    balance=wallet_data['balance']
                )
                logger.info(f"Wallet synchronized: {wallet_data['public_key']}")
            else:
                logger.info(f"Wallet already exists: {wallet_data['public_key']}")
        except Exception as e:
            logger.error(f"Error creating wallet: {str(e)}")

    async def broadcast_wallet_libp2p(self, wallet_data):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User, Peer
        from .libp2p_node import start_node
        from django.conf import settings
        import websockets

        node = await start_node()
        for peer_id in node.peerstore.peer_ids():
            if peer_id != node.get_id():
                try:
                    stream = await node.new_stream(peer_id, ["/echo/1.0.0"])
                    await stream.write(json.dumps(wallet_data).encode("utf-8"))
                    logger.info(f"Broadcasted wallet data to peer {peer_id.pretty()}")

                    # Send libp2p status update to the frontend
                    await self.send(text_data=json.dumps({
                        'type': 'libp2p_status',
                        'status': 'Broadcasted wallet data',
                        'peer_id': peer_id.pretty()
                    }))
                except Exception as e:
                    logger.error(f"Error broadcasting wallet data to peer {peer_id.pretty()}: {str(e)}")
                    await self.send(text_data=json.dumps({
                        'type': 'libp2p_status',
                        'status': 'Error broadcasting wallet data',
                        'peer_id': peer_id.pretty(),
                        'error': str(e)
                    }))

    async def receive(self, text_data):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User, Peer
        from .libp2p_node import start_node
        from django.conf import settings
        import websockets

        logger.debug(f"Received raw text data: {text_data}")
        try:
            data = json.loads(text_data)
            if 'type' in data and data['type'] == 'sync_wallet':
                await self.sync_wallet(data)
            elif 'action' in data and data['action'] == 'register_peer':
                await self.register_peer(data['peer_info'])
        except json.JSONDecodeError as e:
            logger.error(f"JSONDecodeError: {str(e)}")
            logger.error(f"Received invalid JSON: {text_data}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid JSON format'
            }))
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Unexpected error occurred'
            }))

    @sync_to_async
    def register_peer(self, peer_info):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User, Peer
        from .libp2p_node import start_node
        from django.conf import settings
        import websockets

        try:
            peer, created = Peer.objects.get_or_create(
                address=peer_info['address'],
                peer_id=peer_info['peer_id']
            )
            if created:
                logger.info(f"Registered new peer: {peer_info}")
            else:
                logger.info(f"Peer already exists: {peer_info}")
        except Exception as e:
            logger.error(f"Error registering peer: {str(e)}")

    async def register_and_sync_from_master(self):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User, Peer
        from .libp2p_node import start_node
        from django.conf import settings
        import websockets
        from .register_with_master import register_with_master_node_async

        try:
            multiaddress = await register_with_master_node_async()
            if multiaddress:
                # Use multiaddress for further operations, like syncing wallets
                logger.info(f"Using multiaddress {multiaddress} for syncing wallets")
                await self.sync_wallets_from_master(multiaddress)
        except Exception as e:
            logger.error(f"Error during registration and syncing: {str(e)}")

    async def sync_wallets_from_master(self, multiaddress):
        import json
        import logging
        from channels.generic.websocket import AsyncWebsocketConsumer
        from asgiref.sync import sync_to_async
        from .models import Wallet, User, Peer
        from .libp2p_node import start_node
        from django.conf import settings
        import websockets

        try:
            async with websockets.connect(multiaddress + '/ws/sync_wallets/', timeout=10) as websocket:
                await websocket.send(json.dumps({'action': 'fetch_wallets'}))
                response = await websocket.recv()
                wallet_list = json.loads(response)
                for wallet_data in wallet_list:
                    await self.create_wallet(wallet_data)
                logger.info("Successfully synced wallets from master node")
        except Exception as e:
            logger.error(f"Error syncing wallets from master node: {str(e)}")
