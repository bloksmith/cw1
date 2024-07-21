# node.py

import multiaddr
import sys
import threading
import time
import websockets
from libp2p import new_host
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.network.stream.net_stream_interface import INetStream
from libp2p.typing import TProtocol

PROTOCOL_ID = TProtocol("/transaction/1.0.0")
MAX_READ_LEN = 2**32 - 1

def read_data(stream: INetStream) -> None:
    while True:
        read_bytes = stream.read(MAX_READ_LEN)
        if read_bytes:
            read_string = read_bytes.decode()
            if read_string != "\n":
                print(f"Received: {read_string}")

def write_data(stream: INetStream) -> None:
    while True:
        line = sys.stdin.readline()
        stream.write(line.encode())

def fetch_masternode_address(ws_url: str) -> str:
    with websockets.connect(ws_url) as websocket:
        master_node_url = websocket.recv()
        print(f"Received multiaddress: {master_node_url}")
        return master_node_url

def join_network(multiaddr_str: str) -> None:
    host = new_host()  # Synchronous call

    maddr = multiaddr.Multiaddr(multiaddr_str)
    info = info_from_p2p_addr(maddr)
    host.connect(info)
    stream = host.new_stream(info.peer_id, [PROTOCOL_ID])
    
    threading.Thread(target=read_data, args=(stream,)).start()
    threading.Thread(target=write_data, args=(stream,)).start()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python node.py <ws_url>")
        sys.exit(1)
    ws_url = sys.argv[1]
    master_node_url = fetch_masternode_address(ws_url)
    join_network(master_node_url)
