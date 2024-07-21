import argparse
import sys
import multiaddr
import trio
import trio_asyncio
import json
import os
import django
from decimal import Decimal
from django.core.management.base import BaseCommand
from typing import Dict, Any
from libp2p import new_host
from libp2p.network.stream.net_stream_interface import INetStream
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.typing import TProtocol
import logging
from trio_websocket import open_websocket_url, ConnectionClosed
import traceback

# Set up Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myquantumproject.settings')
django.setup()

from quantumapp.models import Transaction, Wallet, Shard

PROTOCOL_ID = TProtocol("/transaction/1.0.0")
MAX_READ_LEN = 2**32 - 1
transaction_pool = []
known_peer_addresses = {}

current_multiaddress = None

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

async def get_masternode_multiaddress(ws_url):
    try:
        async with open_websocket_url(ws_url) as websocket:
            await websocket.send_message(json.dumps({"action": "get_all_multiaddresses"}))
            response = await websocket.get_message()
            data = json.loads(response)
            multiaddresses = data.get("multiaddresses", [])
            logger.debug(f"Retrieved multiaddresses: {multiaddresses}")
            if not multiaddresses:
                logger.error("No multiaddress available from WebSocket server.")
            return multiaddresses[0] if multiaddresses else None
    except ConnectionClosed as e:
        logger.error(f"Connection closed while retrieving multiaddress: {e}")
        logger.error(traceback.format_exc())
        return None
    except Exception as e:
        logger.error(f"Failed to retrieve multiaddress from WebSocket server: {e}")
        logger.error(traceback.format_exc())
        return None

async def broadcast_multiaddress(new_multiaddress):
    global current_multiaddress
    current_multiaddress = new_multiaddress
    ws_url = "ws://app.cashewstable.com:8765"

    try:
        async with open_websocket_url(ws_url) as websocket:
            await websocket.send_message(json.dumps({"multiaddress": new_multiaddress}))
            logger.debug(f"Broadcasting multiaddress: {new_multiaddress}")
    except ConnectionClosed as e:
        logger.error(f"Connection closed while broadcasting multiaddress: {e}")
        logger.error(traceback.format_exc())
    except Exception as e:
        logger.error(f"Failed to broadcast multiaddress to WebSocket server: {e}")
        logger.error(traceback.format_exc())

def create_transaction(sender: str, receiver: str, amount: Decimal, fee: Decimal, hash: str, timestamp: str, shard: str) -> Dict[str, Any]:
    return {
        'hash': hash,
        'sender': sender,
        'receiver': receiver,
        'amount': float(amount),
        'fee': float(fee),
        'timestamp': timestamp,
        'is_approved': True,
        'shard': shard
    }

def transaction_to_json(transaction: Dict[str, Any]) -> str:
    try:
        return json.dumps(transaction)
    except Exception as e:
        logger.error(f"Failed to convert transaction to JSON: {e}")
        logger.error(traceback.format_exc())
        return ""

def json_to_transaction(json_str: str) -> Dict[str, Any]:
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON transaction: {e}")
        logger.error(traceback.format_exc())
        return {}

def validate_transaction(transaction: Dict[str, Any]) -> bool:
    try:
        # Implement your validation logic here (e.g., check balances, signatures, etc.)
        return True
    except Exception as e:
        logger.error(f"Failed to validate transaction: {e}")
        logger.error(traceback.format_exc())
        return False

async def read_data(stream: INetStream) -> None:
    try:
        buffer = ""
        while True:
            read_bytes = await stream.read(MAX_READ_LEN)
            if read_bytes:
                read_string = read_bytes.decode()
                buffer += read_string
                if buffer.endswith("\n"):
                    messages = buffer.split('\n')
                    for message in messages[:-1]:
                        if message:
                            print(f"\x1b[32m{message}\x1b[0m")
                    buffer = messages[-1]
            else:
                print("No data read, stream may have been closed.")
                break
    except Exception as e:
        logger.error(f"Exception in read_data: {e}")
        logger.error(traceback.format_exc())

async def write_data(stream: INetStream) -> None:
    try:
        async_f = trio.wrap_file(sys.stdin)
        buffer = ""
        while True:
            line = await async_f.readline()
            buffer += line
            if buffer.endswith('\n'):
                await stream.write(buffer.encode())
                print(f"Sent: {buffer}")
                buffer = ""
    except Exception as e:
        logger.error(f"Exception in write_data: {e}")
        logger.error(traceback.format_exc())

def add_addrs(peer_id, addrs, host):
    try:
        for addr in addrs:
            if addr not in known_peer_addresses.get(peer_id, []):
                host.get_peerstore().add_addr(peer_id, multiaddr.Multiaddr(addr), 100)
                if peer_id not in known_peer_addresses:
                    known_peer_addresses[peer_id] = []
                known_peer_addresses[peer_id].append(addr)
                logger.debug(f"Added address {addr} for peer {peer_id}")
    except Exception as e:
        logger.error(f"Exception in add_addrs: {e}")
        logger.error(traceback.format_exc())

async def broadcast_transaction(host, transaction: Dict[str, Any]):
    try:
        peers = host.get_peerstore().peer_ids()
        for peer_id in peers:
            peer_id_str = str(peer_id)
            if peer_id_str in known_peer_addresses:
                add_addrs(peer_id_str, known_peer_addresses[peer_id_str], host)
            try:
                stream = await host.new_stream(peer_id, [PROTOCOL_ID])
                await stream.write(transaction_to_json(transaction).encode())
                await stream.close()
                logger.debug(f"Broadcasted transaction to {peer_id}")
            except Exception as e:
                logger.error(f"Failed to broadcast to {peer_id}: {e}")
                logger.error(traceback.format_exc())
    except Exception as e:
        logger.error(f"Exception in broadcast_transaction: {e}")
        logger.error(traceback.format_exc())

async def sync_transaction_pool(host):
    try:
        while True:
            peers = host.get_peerstore().peer_ids()
            for peer_id in peers:
                peer_id_str = str(peer_id)
                if peer_id_str in known_peer_addresses:
                    add_addrs(peer_id_str, known_peer_addresses[peer_id_str], host)
                try:
                    stream = await host.new_stream(peer_id, [PROTOCOL_ID])
                    await stream.write(b'GET_TRANSACTIONS')
                    response = await stream.read(MAX_READ_LEN)
                    if response:
                        response_str = response.decode()
                        if response_str.strip():  # Ensure response is not empty
                            try:
                                new_transactions = json.loads(response_str)
                                if isinstance(new_transactions, list):
                                    for transaction in new_transactions:
                                        if validate_transaction(transaction):
                                            transaction_pool.append(transaction)
                                            logger.debug(f"Synced transaction: {transaction}")
                                else:
                                    logger.error("Invalid transactions format")
                            except json.JSONDecodeError as e:
                                logger.error(f"Failed to decode JSON response: {e}")
                                logger.error(f"Response content: {response_str}")
                                logger.error(traceback.format_exc())
                    await stream.close()
                except Exception as e:
                    logger.error(f"Failed to sync with {peer_id}: {e}")
                    logger.error(traceback.format_exc())
            await trio.sleep(30)  # sync every 30 seconds
    except Exception as e:
        logger.error(f"Exception in sync_transaction_pool: {e}")
        logger.error(traceback.format_exc())

async def stream_handler(stream: INetStream) -> None:
    try:
        buffer = ""
        while True:
            try:
                read_bytes = await stream.read(MAX_READ_LEN)
                if not read_bytes:
                    break
                message_str = read_bytes.decode()
                buffer += message_str
                if buffer.endswith("\n"):
                    if buffer.strip() == 'GET_TRANSACTIONS':
                        transactions_json = json.dumps(transaction_pool)
                        await stream.write(transactions_json.encode())
                    elif buffer.strip() == 'GET_ADDRESSES':
                        addresses_json = json.dumps({str(k): v for k, v in known_peer_addresses.items()})
                        await stream.write(addresses_json.encode())
                    else:
                        try:
                            transaction = json.loads(buffer)
                            if validate_transaction(transaction):
                                transaction_pool.append(transaction)
                                await broadcast_transaction(stream.host, transaction)
                                logger.debug(f"Received and broadcasted transaction: {transaction}")
                        except json.JSONDecodeError as e:
                            logger.error(f"Failed to decode JSON message: {e}")
                            logger.error(f"Message content: {buffer}")
                            logger.error(traceback.format_exc())
                    buffer = ""
            except Exception as e:
                logger.error(f"Exception in stream_handler inner loop: {e}")
                logger.error(traceback.format_exc())
                break
    except Exception as e:
        logger.error(f"Exception in stream_handler: {e}")
        logger.error(traceback.format_exc())

async def share_addresses_with_peers(host):
    try:
        peers = host.get_peerstore().peer_ids()
        for peer_id in peers:
            peer_id_str = str(peer_id)
            if peer_id_str in known_peer_addresses:
                add_addrs(peer_id_str, known_peer_addresses[peer_id_str], host)
                try:
                    stream = await host.new_stream(peer_id, [PROTOCOL_ID])
                    # Convert keys to string
                    addresses_str = {str(k): v for k, v in known_peer_addresses.items()}
                    await stream.write(json.dumps(addresses_str).encode())
                    await stream.close()
                    logger.debug(f"Shared addresses with peer {peer_id}")
                except Exception as e:
                    logger.error(f"Failed to share addresses with {peer_id}: {e}")
                    logger.error(traceback.format_exc())
    except Exception as e:
        logger.error(f"Exception in share_addresses_with_peers: {e}")
        logger.error(traceback.format_exc())

async def request_peer_addresses(host):
    try:
        peers = host.get_peerstore().peer_ids()
        for peer_id in peers:
            peer_id_str = str(peer_id)
            if peer_id_str not in known_peer_addresses:
                logger.debug(f"No known addresses for peer {peer_id_str}, requesting addresses...")
                try:
                    stream = await host.new_stream(peer_id, [PROTOCOL_ID])
                    await stream.write(b'GET_ADDRESSES')
                    response = await stream.read(MAX_READ_LEN)
                    if response:
                        try:
                            addresses_str = response.decode()
                            addresses_dict = json.loads(addresses_str)
                            known_peer_addresses.update(addresses_dict)
                            for pid, addrs in addresses_dict.items():
                                add_addrs(pid, addrs, host)
                            logger.debug(f"Received addresses from peer {peer_id_str}: {addresses_dict}")
                        except json.JSONDecodeError as e:
                            logger.error(f"Failed to decode JSON addresses response: {e}")
                            logger.error(traceback.format_exc())
                    await stream.close()
                except Exception as e:
                    logger.error(f"Failed to request addresses from {peer_id}: {e}")
                    logger.error(traceback.format_exc())
    except Exception as e:
        logger.error(f"Exception in request_peer_addresses: {e}")
        logger.error(traceback.format_exc())

async def log_connected_peers(host):
    try:
        while True:
            peers = host.get_peerstore().peer_ids()
            logger.debug(f"Connected peers: {peers}")
            await trio.sleep(30)
    except Exception as e:
        logger.error(f"Exception in log_connected_peers: {e}")
        logger.error(traceback.format_exc())

async def run(port: int, transaction_data: str = None) -> None:
    try:
        global current_multiaddress
        listen_addr = multiaddr.Multiaddr(f"/ip4/0.0.0.0/tcp/{port}")
        host = new_host()
        ws_url = "ws://app.cashewstable.com:8765"  # Replace with the actual WebSocket server URL
        destination = await get_masternode_multiaddress(ws_url)

        if not destination:
            # No destination means this is the first node, so it should broadcast its address
            async with host.run(listen_addrs=[listen_addr]), trio.open_nursery() as nursery:
                async def stream_handler_inner(stream: INetStream) -> None:
                    nursery.start_soon(read_data, stream)
                    nursery.start_soon(write_data, stream)

                host.set_stream_handler(PROTOCOL_ID, stream_handler_inner)
                logger.info(
                    "Run this from the same folder in another console:\n\n"
                    f"python manage.py run_p2p_node -p {int(port) + 1}\n"
                )
                logger.info("Waiting for incoming connection...")

                current_multiaddress = f"/ip4/0.0.0.0/tcp/{port}/p2p/{host.get_id().pretty()}"
                await broadcast_multiaddress(current_multiaddress)
                logger.info(f"Master node multiaddress: {current_multiaddress}")

                if transaction_data:
                    await broadcast_transaction(host, json.loads(transaction_data))

                # Periodically synchronize the transaction pool
                nursery.start_soon(sync_transaction_pool, host)

                # Periodically share known addresses with peers
                nursery.start_soon(share_addresses_with_peers, host)

                # Periodically request addresses from peers
                nursery.start_soon(request_peer_addresses, host)

                # Periodically log connected peers
                nursery.start_soon(log_connected_peers, host)

                await trio.sleep_forever()
        else:
            async with host.run(listen_addrs=[listen_addr]), trio.open_nursery() as nursery:
                current_multiaddress = f"/ip4/0.0.0.0/tcp/{port}/p2p/{host.get_id().pretty()}"
                logger.info(f"Current multiaddress: {current_multiaddress}")
                logger.info(f"Destination multiaddress: {destination}")

                if destination == current_multiaddress:
                    logger.info(f"Skipping connection to self: {destination}")
                    return

                try:
                    maddr = multiaddr.Multiaddr(destination)
                except TypeError as e:
                    logger.error(f"Invalid multiaddress format: {e}")
                    logger.error(traceback.format_exc())
                    return

                info = info_from_p2p_addr(maddr)
                if info.peer_id.pretty() == host.get_id().pretty():
                    logger.info(f"Skipping connection to self: {info.peer_id.pretty()}")
                    return

                logger.info(f"Connecting to peer {info.peer_id} at addresses {info.addrs}")
                await host.connect(info)
                stream = await host.new_stream(info.peer_id, [PROTOCOL_ID])

                # Store known addresses of the peer
                peer_id_str = str(info.peer_id)
                if peer_id_str not in known_peer_addresses:
                    known_peer_addresses[peer_id_str] = []
                for addr in info.addrs:
                    addr_str = str(addr)
                    if addr_str not in known_peer_addresses[peer_id_str]:
                        known_peer_addresses[peer_id_str].append(addr_str)
                        host.get_peerstore().add_addr(info.peer_id, addr, 100)
                        logger.debug(f"Added address {addr_str} for peer {info.peer_id}")

                nursery.start_soon(read_data, stream)
                nursery.start_soon(write_data, stream)
                logger.info(f"Connected to peer {info.addrs[0]}")

                if transaction_data:
                    await broadcast_transaction(host, json.loads(transaction_data))

                # Periodically synchronize the transaction pool
                nursery.start_soon(sync_transaction_pool, host)

                # Periodically share known addresses with peers
                nursery.start_soon(share_addresses_with_peers, host)

                # Periodically request addresses from peers
                nursery.start_soon(request_peer_addresses, host)

                # Periodically log connected peers
                nursery.start_soon(log_connected_peers, host)

                await trio.sleep_forever()
    except Exception as e:
        logger.error(f"Exception in run: {e}")
        logger.error(traceback.format_exc())

class Command(BaseCommand):
    help = 'Run the P2P node'

    def add_arguments(self, parser):
        parser.add_argument('-p', '--port', type=int, help='source port number')
        parser.add_argument('-t', '--transaction', type=str, help='transaction data in JSON format')

    def handle(self, *args, **options):
        port = options['port']
        transaction = options['transaction']

        try:
            trio_asyncio.run(run, port, transaction)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.error(f"Exception in handle: {e}")
            logger.error(traceback.format_exc())
