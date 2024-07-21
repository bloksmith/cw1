# quantumapp/utils.py
from .models import Shard

def create_default_shard():
    if not Shard.objects.exists():
        Shard.objects.create(name='Default Shard', description='This is the default shard')
import os
from cryptography.fernet import Fernet

def load_key():
    try:
        return open('secret.key', 'rb').read()
    except FileNotFoundError:
        # If no key found, we generate one (should ideally be done separately and securely stored)
        key = Fernet.generate_key()
        with open('secret.key', 'wb') as key_file:
            key_file.write(key)
        return key

def encrypt_message(message):
    key = load_key()
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message):
    key = load_key()
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message
# utils.py
from .models import Transaction

def validate_transaction(transaction):
    # Check for missing signature
    if not transaction.signature:
        print(f"[ERROR] Transaction {transaction.hash} invalid: missing signature")
        return False

    # Check for insufficient balance
    if transaction.sender.balance < (transaction.amount + transaction.fee):
        print(f"[ERROR] Transaction {transaction.hash} invalid: insufficient balance. Sender balance: {transaction.sender.balance}, Transaction amount: {transaction.amount}, Fee: {transaction.fee}")
        return False

    # Check for duplicate transaction
    if Transaction.objects.filter(hash=transaction.hash, is_approved=True).exists():
        print(f"[ERROR] Transaction {transaction.hash} invalid: duplicate transaction")
        return False

    # Additional validation checks (if any)
    # For example, you might check if the transaction format is correct or if the receiver address is valid

    print(f"[DEBUG] Transaction {transaction.hash} is valid")
    return True


def approve_transaction(transaction):
    # Approve the transaction by updating the balance and setting is_approved to True
    transaction.sender.balance -= (transaction.amount + transaction.fee)
    transaction.receiver.balance += transaction.amount
    transaction.is_approved = True
    transaction.save()
    transaction.sender.save()
    transaction.receiver.save()
# quantumapp/utils.py
import json
import requests
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def broadcast_transactions(transactions):
    nodes = settings.KNOWN_NODES  # List of known nodes
    for transaction in transactions:
        transaction_data = {
            'transaction_hash': transaction.hash,
            'sender': transaction.sender.address,
            'receiver': transaction.receiver.address,
            'amount': str(transaction.amount),
            'fee': str(transaction.fee),
            'timestamp': transaction.timestamp.isoformat(),
            'is_approved': transaction.is_approved
        }
        for node in nodes:
            try:
                response = requests.post(f"{node}/api/receive_transaction/", json=transaction_data)
                if response.status_code == 200:
                    logger.info(f"Transaction {transaction.hash} broadcasted to {node}")
                else:
                    logger.error(f"Failed to broadcast transaction {transaction.hash} to {node}")
            except Exception as e:
                logger.error(f"Error broadcasting transaction {transaction.hash} to {node}: {e}")

def broadcast_transaction(transaction_data):
    nodes = settings.KNOWN_NODES  # List of known nodes
    for node in nodes:
        try:
            response = requests.post(f"{node}/api/receive_transaction/", json=transaction_data)
            if response.status_code == 200:
                logger.info(f"Transaction {transaction_data['transaction_hash']} broadcasted to {node}")
            else:
                logger.error(f"Failed to broadcast transaction {transaction_data['transaction_hash']} to {node}")
        except Exception as e:
            logger.error(f"Error broadcasting transaction {transaction_data['transaction_hash']} to {node}: {e}")
def mine_single_block(user, shard_id):
    global mining_statistics
    try:
        shard = Shard.objects.get(id=shard_id)
    except Shard.DoesNotExist:
        logger.error("Shard not found")
        return JsonResponse({'error': 'Shard not found'}, status=404)

    transactions = Transaction.objects.filter(is_approved=False, shard=shard)
    previous_block_hash = '0000000000000000000000000000000000000000000000000000000000000000'
    proof = proof_of_work(previous_block_hash)
    miner_wallet = Wallet.objects.get(user=user)
    system_wallet = ensure_system_wallet()

    total_fees = Decimal(0)
    approved_transactions = []

    for transaction in transactions:
        logger.info(f"Validating transaction {transaction.hash}")
        if validate_transaction(transaction):
            transaction.is_approved = True
            transaction.save()
            total_fees += Decimal(transaction.fee)
            approved_transactions.append(transaction)
        else:
            logger.info(f"Transaction {transaction.hash} was not approved")

    current_time = timezone.now()
    block_reward, _ = adjust_difficulty_and_reward()
    total_reward = block_reward + total_fees

    current_supply = Wallet.objects.exclude(user=system_wallet.user).aggregate(Sum('balance'))['balance__sum'] or Decimal(0)
    if current_supply + total_reward > TOTAL_SUPPLY_CAP:
        total_reward = TOTAL_SUPPLY_CAP - current_supply
        block_reward = total_reward - total_fees

    if total_reward <= 0:
        return JsonResponse({
            'message': 'No reward due to supply cap. Skipping block mining.',
            'proof': proof,
            'reward': 0,
            'fees': total_fees,
            'total_reward': 0
        })

    miner_wallet.balance += total_reward
    miner_wallet.save()

    new_block_hash = generate_unique_hash()
    new_block = Block(hash=new_block_hash, previous_hash=previous_block_hash, timestamp=current_time)
    dag[new_block_hash] = new_block
    if previous_block_hash in dag:
        dag[previous_block_hash].children.append(new_block)

    reward_transaction = Transaction(
        hash=generate_unique_hash(),
        sender=system_wallet,
        receiver=miner_wallet,
        amount=block_reward,
        fee=Decimal(0),
        signature="reward_signature",
        timestamp=current_time,
        is_approved=True,
        shard=shard
    )
    reward_transaction.save()

    # Broadcast the approved transactions
    broadcast_transactions(approved_transactions)

    # Broadcast the reward transaction
    broadcast_transaction({
        'transaction_hash': reward_transaction.hash,
        'sender': reward_transaction.sender.address,
        'receiver': reward_transaction.receiver.address,
        'amount': str(reward_transaction.amount),
        'fee': str(reward_transaction.fee),
        'timestamp': reward_transaction.timestamp.isoformat(),
        'is_approved': reward_transaction.is_approved
    })

    mining_statistics["blocks_mined"] += 1
    mining_statistics["total_rewards"] += float(total_reward)

    ordered_blocks = order_blocks(dag)
    well_connected_subset = select_well_connected_subset(dag)

    record_miner_contribution(miner_wallet, reward_transaction)
    distribute_rewards(get_miners(), total_reward)

    return JsonResponse({
        'message': f'Block mined successfully in shard {shard.name}',
        'proof': proof,
        'reward': block_reward,
        'fees': total_fees,
        'total_reward': total_reward
    })
# quantumapp/views.py
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from .models import Node

known_nodes = []

@csrf_exempt
def register_node(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            node_url = data.get("url")
            if node_url and node_url not in known_nodes:
                known_nodes.append(node_url)
                Node.objects.get_or_create(url=node_url)  # Save the node to the database
                return JsonResponse({"status": "success", "nodes": known_nodes})
            return JsonResponse({"status": "error", "message": "Node already registered or invalid URL"})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=500)
    return JsonResponse({"status": "error", "message": "Only POST method allowed"}, status=400)
# quantumapp/utils.py
import websockets
import asyncio
import json
from django.conf import settings
from .models import Transaction

async def broadcast_transaction(transaction_data):
    nodes = Node.objects.all()
    for node in nodes:
        try:
            async with websockets.connect(f"{node.address}/ws/transactions/") as websocket:
                await websocket.send(json.dumps(transaction_data))
        except Exception as e:
            logger.error(f"Failed to broadcast to {node.address}: {e}")

def sync_transaction(transaction_data):
    asyncio.run(broadcast_transaction(transaction_data))
# utils.py
import re
import multiaddr
from libp2p import new_host
import trio

def get_libp2p_peer_info(url):
    match = re.match(r'ws://([\d\.]+|\w+)(?::(\d+))?', url)
    if match:
        ip = match.group(1)
        port = match.group(2) or '4001'  # Replace '4001' with your desired default port

        # Generate a new host and extract the peer ID
        async def generate_peer_id():
            host = new_host()
            return host.get_id().pretty()

        # Run the trio event loop to generate the peer ID
        peer_id = trio.run(generate_peer_id)

        multiaddress = f"/ip4/{ip}/tcp/{port}/p2p/{peer_id}"
        return multiaddress
    else:
        raise ValueError("Invalid URL format")
# quantumapp/utils.py

import trio
import multiaddr
from libp2p import new_host
from libp2p.network.stream.net_stream_interface import INetStream
from libp2p.typing import TProtocol
import websockets

PROTOCOL_ID = TProtocol("/transaction/1.0.0")
MAX_READ_LEN = 2**32 - 1

async def read_data(stream: INetStream) -> None:
    while True:
        read_bytes = await stream.read(MAX_READ_LEN)
        if read_bytes:
            read_string = read_bytes.decode()
            if read_string != "\n":
                print(f"Received: {read_string}")

async def write_data(stream: INetStream, transaction_data: str) -> None:
    await stream.write(transaction_data.encode())
    print(f"Sent: {transaction_data}")

async def run_masternode(port: int) -> str:
    listen_addr = multiaddr.Multiaddr(f"/ip4/0.0.0.0/tcp/{port}")
    host = new_host()  # Synchronous call

    async def host_service(nursery):
        async with host.run(listen_addrs=[listen_addr]):
            async def stream_handler(stream: INetStream) -> None:
                nursery.start_soon(read_data, stream)
            host.set_stream_handler(PROTOCOL_ID, stream_handler)
            master_node_url = f"/ip4/0.0.0.0/tcp/{port}/p2p/{host.get_id().pretty()}"
            print(f"Master node multiaddress: {master_node_url}")
            await trio.sleep_forever()
    
    async with trio.open_nursery() as nursery:
        nursery.start_soon(host_service, nursery)
        master_node_url = f"/ip4/0.0.0.0/tcp/{port}/p2p/{host.get_id().pretty()}"
        return master_node_url

async def websocket_handler(websocket, path, master_node_url):
    await websocket.send(master_node_url)
    print(f"Sent multiaddress: {master_node_url}")

async def run_websocket_server(master_node_url, ws_port=8765):
    async with websockets.serve(lambda ws, path: websocket_handler(ws, path, master_node_url), "localhost", ws_port):
        print(f"WebSocket server listening on ws://localhost:{ws_port}")
        await trio.sleep_forever()

async def fetch_masternode_address(ws_url: str) -> str:
    async with websockets.connect(ws_url) as websocket:
        master_node_url = await websocket.recv()
        print(f"Received multiaddress: {master_node_url}")
        return master_node_url

async def join_network(multiaddr_str: str) -> None:
    host = new_host()  # Synchronous call

    maddr = multiaddr.Multiaddr(multiaddr_str)
    info = info_from_p2p_addr(maddr)
    await host.connect(info)
    stream = await host.new_stream(info.peer_id, [PROTOCOL_ID])
    
    async with trio.open_nursery() as nursery:
        nursery.start_soon(read_data, stream)
        nursery.start_soon(write_data, stream)
