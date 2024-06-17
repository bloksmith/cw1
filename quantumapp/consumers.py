import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.layers import get_channel_layer
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import hashlib

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

