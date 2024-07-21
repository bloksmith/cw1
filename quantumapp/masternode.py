import argparse
import sys
import multiaddr
import trio
import json
from decimal import Decimal
from typing import Dict, Any
from libp2p import new_host
from libp2p.network.stream.net_stream_interface import INetStream
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.typing import TProtocol

PROTOCOL_ID = TProtocol("/transaction/1.0.0")
MAX_READ_LEN = 2**32 - 1
master_node_url_storage = []
transaction_pool = []
known_peer_addresses = {}

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
    return json.dumps(transaction)

def json_to_transaction(json_str: str) -> Dict[str, Any]:
    return json.loads(json_str)

def validate_transaction(transaction: Dict[str, Any]) -> bool:
    # Implement your validation logic here (e.g., check balances, signatures, etc.)
    return True

async def read_data(stream: INetStream) -> None:
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

async def write_data(stream: INetStream) -> None:
    async_f = trio.wrap_file(sys.stdin)
    buffer = ""
    while True:
        line = await async_f.readline()
        buffer += line
        if buffer.endswith('\n'):
            await stream.write(buffer.encode())
            print(f"Sent: {buffer}")
            buffer = ""

async def broadcast_transaction(host, transaction: Dict[str, Any]):
    peers = host.get_peerstore().peer_ids()
    for peer_id in peers:
        if peer_id in known_peer_addresses:
            for addr in known_peer_addresses[peer_id]:
                host.get_peerstore().add_addr(peer_id, multiaddr.Multiaddr(addr), 100)
        try:
            stream = await host.new_stream(peer_id, [PROTOCOL_ID])
            await stream.write(transaction_to_json(transaction).encode())
            await stream.close()
        except Exception as e:
            print(f"Failed to broadcast to {peer_id}: {e}")

async def sync_transaction_pool(host):
    while True:
        peers = host.get_peerstore().peer_ids()
        for peer_id in peers:
            if peer_id in known_peer_addresses:
                for addr in known_peer_addresses[peer_id]:
                    host.get_peerstore().add_addr(peer_id, multiaddr.Multiaddr(addr), 100)
            try:
                stream = await host.new_stream(peer_id, [PROTOCOL_ID])
                await stream.write(b'GET_TRANSACTIONS')
                response = await stream.read(MAX_READ_LEN)
                if response:
                    try:
                        new_transactions = json.loads(response.decode())
                        if isinstance(new_transactions, list):
                            for transaction in new_transactions:
                                if validate_transaction(transaction):
                                    transaction_pool.append(transaction)
                        else:
                            print("Invalid transactions format")
                    except json.JSONDecodeError as e:
                        print(f"Failed to decode JSON response: {e}")
                        print(f"Response content: {response.decode()}")
                await stream.close()
            except Exception as e:
                print(f"Failed to sync with {peer_id}: {e}")
        await trio.sleep(30)  # sync every 30 seconds

async def stream_handler(stream: INetStream) -> None:
    buffer = ""
    while True:
        read_bytes = await stream.read(MAX_READ_LEN)
        if not read_bytes:
            break
        message_str = read_bytes.decode()
        buffer += message_str
        if buffer.endswith('\n'):
            if buffer.strip() == 'GET_TRANSACTIONS':
                transactions_json = json.dumps(transaction_pool)
                await stream.write(transactions_json.encode())
            else:
                try:
                    transaction = json.loads(buffer)
                    if validate_transaction(transaction):
                        transaction_pool.append(transaction)
                        await broadcast_transaction(stream.host, transaction)
                except json.JSONDecodeError as e:
                    print(f"Failed to decode JSON message: {e}")
                    print(f"Message content: {buffer}")
            buffer = ""

async def run(port: int, destination: str, transaction_data: str = None) -> None:
    localhost_ip = "127.0.0.1"
    listen_addr = multiaddr.Multiaddr(f"/ip4/0.0.0.0/tcp/{port}")
    host = new_host()
    async with host.run(listen_addrs=[listen_addr]), trio.open_nursery() as nursery:
        if not destination:  # it's the server

            async def stream_handler_inner(stream: INetStream) -> None:
                nursery.start_soon(read_data, stream)
                nursery.start_soon(write_data, stream)

            host.set_stream_handler(PROTOCOL_ID, stream_handler_inner)
            print(
                "Run this from the same folder in another console:\n\n"
                f"python masternode.py -p {int(port) + 1} "
                f"-d /ip4/{localhost_ip}/tcp/{port}/p2p/{host.get_id().pretty()}\n"
            )
            print("Waiting for incoming connection...")

            master_node_url = f"/ip4/0.0.0.0/tcp/{port}/p2p/{host.get_id().pretty()}"
            print(f"Master node multiaddress: {master_node_url}")
            master_node_url_storage.append(master_node_url)

            if transaction_data:
                await broadcast_transaction(host, json.loads(transaction_data))

        else:  # it's the client
            maddr = multiaddr.Multiaddr(destination)
            info = info_from_p2p_addr(maddr)
            await host.connect(info)
            stream = await host.new_stream(info.peer_id, [PROTOCOL_ID])

            # Store known addresses of the peer
            if info.peer_id not in known_peer_addresses:
                known_peer_addresses[info.peer_id] = []
            for addr in info.addrs:
                if str(addr) not in known_peer_addresses[info.peer_id]:
                    known_peer_addresses[info.peer_id].append(str(addr))

            nursery.start_soon(read_data, stream)
            nursery.start_soon(write_data, stream)
            print(f"Connected to peer {info.addrs[0]}")

            if transaction_data:
                await broadcast_transaction(host, json.loads(transaction_data))

        # Periodically synchronize the transaction pool
        nursery.start_soon(sync_transaction_pool, host)

        await trio.sleep_forever()

def main() -> None:
    description = """
    This program demonstrates a simple p2p transaction synchronization using libp2p.
    To use it, first run 'python ./masternode.py -p <PORT>', where <PORT> is the port number.
    Then, run another host with 'python ./masternode.py -p <ANOTHER_PORT> -d <DESTINATION>',
    where <DESTINATION> is the multiaddress of the previous listener host.
    """
    example_maddr = (
        "/ip4/127.0.0.1/tcp/8000/p2p/QmQn4SwGkDZKkUEpBRBvTmheQycxAHJUNmVEnjA2v1qe8Q"
    )
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "-p", "--port", default=8000, type=int, help="source port number"
    )
    parser.add_argument(
        "-d",
        "--destination",
        type=str,
        help=f"destination multiaddr string, e.g. {example_maddr}",
    )
    parser.add_argument(
        "-t",
        "--transaction",
        type=str,
        help="transaction data in JSON format",
    )
    args = parser.parse_args()

    if not args.port:
        raise RuntimeError("was not able to determine a local port")

    try:
        trio.run(run, *(args.port, args.destination, args.transaction))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
