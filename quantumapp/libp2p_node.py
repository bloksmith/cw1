from libp2p import new_host
from libp2p.crypto.ed25519 import create_new_key_pair
from multiaddr import Multiaddr

def create_node():
    key_pair = create_new_key_pair()
    node = new_host(key_pair)  # No await here
    return node

def start_node():
    node = create_node()
    node.get_network().listen(Multiaddr("/ip4/0.0.0.0/tcp/0"))  # No await here
    return node
