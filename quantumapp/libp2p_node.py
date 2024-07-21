import asyncio
import multiaddr
from libp2p import new_host
from libp2p.crypto.ed25519 import create_new_key_pair
from libp2p.network.stream.net_stream import NetStream
from libp2p.network.stream.exceptions import StreamClosed
from libp2p.peer.peerinfo import info_from_p2p_addr
from multiaddr import Multiaddr
import trio
import trio_asyncio

async def create_node():
    try:
        key_pair = create_new_key_pair()
        host = await trio_asyncio.aio_as_trio(new_host)(key_pair)
        return host
    except Exception as e:
        print(f"Failed to create node: {e}")
        return None

async def start_node():
    node = await create_node()
    if node:
        try:
            listen_addr = Multiaddr("/ip4/0.0.0.0/tcp/12345")
            network = node.get_network()
            await trio_asyncio.aio_as_trio(network.listen)(listen_addr)

            async def stream_handler(stream: NetStream) -> None:
                try:
                    async for data in stream:
                        print(f"Received: {data.decode('utf-8')}")
                except StreamClosed:
                    print("Stream closed")

            node.set_stream_handler("/chat/1.0.0", stream_handler)
            print(f"Node started with address: {node.get_addrs()}")
            await trio.sleep_forever()  # Keeps the node running indefinitely
        except Exception as e:
            print(f"Failed to start node: {e}")
            return None
    return node

# Example usage
if __name__ == "__main__":
    try:
        trio_asyncio.run(start_node)
    except KeyboardInterrupt:
        print("Node is shutting down...")
