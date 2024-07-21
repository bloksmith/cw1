import re
from libp2p.peer.id import ID
from libp2p.peer.peerinfo import PeerInfo
from libp2p.crypto.keys import KeyPair, create_new_key_pair

def get_libp2p_peer_info(url):
    # Parse the URL to extract IP and port (assuming the URL format is ws://<ip>:<port>)
    match = re.match(r'ws://([\d\.]+):(\d+)', url)
    if match:
        ip = match.group(1)
        port = match.group(2)
        # Generate a new key pair and peer ID
        key_pair = create_new_key_pair()
        peer_id = ID.from_pubkey(key_pair.public_key)
        multiaddress = f"/ip4/{ip}/tcp/{port}/p2p/{peer_id}"
        return multiaddress
    else:
        raise ValueError("Invalid URL format")
