import subprocess
import sys
import trio
import multiaddr
import pytest
import json
from django.test import TransactionTestCase
from channels.testing import WebsocketCommunicator
from quantumapp.routing import application
from libp2p import new_host
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.network.stream.net_stream_interface import INetStream
from libp2p.typing import TProtocol
from quantumapp.consumers import QuantumSyncConsumer

PROTOCOL_ID = TProtocol("/chat/1.0.0")
MAX_READ_LEN = 2**32 - 1

async def read_data(stream: INetStream) -> None:
    while True:
        read_bytes = await stream.read(MAX_READ_LEN)
        if read_bytes:
            read_string = read_bytes.decode()
            if read_string != "\n":
                print("\x1b[32m %s\x1b[0m " % read_string, end="")

async def write_data(stream: INetStream) -> None:
    test_message = "Hello, World!"
    await stream.write(test_message.encode())
    print(f"Sent: {test_message}")

    transaction_data = json.dumps({
        "type": "transaction_sync",
        "transactions": [
            {
                "hash": "tx1",
                "sender": "sender1",
                "receiver": "receiver1",
                "amount": 100,
                "fee": 1,
                "timestamp": "2024-07-17T12:00:00Z",
                "is_approved": True,
                "shard": "shard1"
            }
        ]
    })
    await stream.write(transaction_data.encode())
    print(f"Sent transaction data: {transaction_data}")

    wallet_data = json.dumps({
        "type": "wallet_sync",
        "wallets": [
            {
                "public_key": "test_public_key",
                "address": "test_address",
                "alias": "test_alias",
                "balance": 1000
            }
        ]
    })
    await stream.write(wallet_data.encode())
    print(f"Sent wallet data: {wallet_data}")

    async_f = trio.wrap_file(sys.stdin)
    while True:
        line = await async_f.readline()
        await stream.write(line.encode())

async def run_libp2p(port: int, destination: str) -> None:
    localhost_ip = "127.0.0.1"
    listen_addr = multiaddr.Multiaddr(f"/ip4/0.0.0.0/tcp/{port}")
    host = new_host()  # Synchronous call

    async def host_service(nursery):
        async with host.run(listen_addrs=[listen_addr]):
            if not destination:
                async def stream_handler(stream: INetStream) -> None:
                    nursery.start_soon(read_data, stream)
                    nursery.start_soon(write_data, stream)
                host.set_stream_handler(PROTOCOL_ID, stream_handler)
                master_node_url = f"/ip4/{localhost_ip}/tcp/{port}/p2p/{host.get_id().pretty()}"
                print(
                    "Run this from the same folder in another console:\n\n"
                    f"python chat.py -p {int(port) + 1} -d {master_node_url}\n"
                )
                print("Waiting for incoming connection...")
                print(f"Master node libp2p URL: {master_node_url}")
            else:
                maddr = multiaddr.Multiaddr(destination)
                info = info_from_p2p_addr(maddr)
                await host.connect(info)
                stream = await host.new_stream(info.peer_id, [PROTOCOL_ID])
                nursery.start_soon(read_data, stream)
                nursery.start_soon(write_data, stream)
                print(f"Connected to peer {info.addrs[0]}")
            await trio.sleep_forever()
    
    async with trio.open_nursery() as nursery:
        nursery.start_soon(host_service, nursery)

@pytest.mark.trio
async def test_register_node_and_join_libp2p():
    port = 8000
    destination = None  # You can set a destination if needed

    await run_libp2p(port, destination)

@pytest.mark.trio
class NodeRegistrationTest(TransactionTestCase):
    async def test_register_node_2(self):
        communicator = WebsocketCommunicator(application, "/ws/register_node/")
        connected, subprotocol = await communicator.connect()
        self.assertTrue(connected)

        response = await communicator.receive_json_from(timeout=10)
        self.assertEqual(response['message'], 'Connected to the Node Registration WebSocket')

        registration_message = {
            'url': 'ws://127.0.0.1:12345',  # Updated to a valid IP address
            'public_key': 'your_public_key_here'
        }

        await communicator.send_json_to(registration_message)
        try:
            response = await communicator.receive_json_from(timeout=10)  # Increase timeout to 10 seconds
        except trio.TooSlowError:
            self.fail("Did not receive a response in time")

        self.assertEqual(response.get('status'), 'success')
        self.assertIn('multiaddress', response)
        multiaddress = response['multiaddress']
        
        # Validate multiaddress
        try:
            ip_port, peer_id = multiaddress.split('/p2p/')
            self.assertTrue(ip_port.startswith('/ip4/'))
            self.assertTrue(peer_id.isalnum())  # Assuming peer ID is alphanumeric
        except ValueError as e:
            self.fail(f"Invalid multiaddress format: {multiaddress}")
        await communicator.disconnect()

        # Now join the libp2p network using the multiaddress
        port = 8000  # or any available port
        await run_libp2p(port, multiaddress)

    @pytest.mark.trio
    async def test_quantum_sync_consumer(self):
        communicator = WebsocketCommunicator(application, "/ws/unique-sync-url/")
        connected, subprotocol = await communicator.connect()
        self.assertTrue(connected)

        # Send a sync_wallet message
        wallet_data = {
            'public_key': 'test_public_key',
            'address': 'test_address',
            'alias': 'test_alias',
            'balance': '1000'
        }
        sync_message = {
            'type': 'sync_wallet',
            'wallet_data': wallet_data
        }
        await communicator.send_json_to(sync_message)

        response = await communicator.receive_json_from(timeout=10)
        self.assertEqual(response['type'], 'sync_status')
        self.assertEqual(response['status'], 'Wallet synced')
        self.assertEqual(response['wallet_data'], wallet_data)

        await communicator.disconnect()

        # Ensure the libp2p node is running
        node = await QuantumSyncConsumer().start_node()
        self.assertIsNotNone(node)
        # Removed 'is_running' check as it does not exist on BasicHost

        # Start the transaction sync script in a subprocess
        sync_process = subprocess.Popen(["python", "transaction_sync.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Wait for a while to let the sync process run
        await trio.sleep(60)

        # Terminate the sync process
        sync_process.terminate()
        stdout, stderr = sync_process.communicate()
        print(stdout.decode())
        print(stderr.decode())
