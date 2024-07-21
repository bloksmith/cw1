# test_libp2p_connection.py
import pytest
import json
from channels.testing import WebsocketCommunicator
from quantumapp.routing import application
from quantumapp.models import Node
from asgiref.sync import sync_to_async

@pytest.mark.asyncio
@pytest.mark.django_db(transaction=True)
async def test_libp2p_node_registration():
    communicator = WebsocketCommunicator(application, "/ws/node/register/")
    connected, _ = await communicator.connect()
    assert connected

    # Simulate sending a registration message
    message = {
        "url": "ws://app3.cashewstable.com",
        "public_key": "your_public_key_here"
    }
    await communicator.send_json_to(message)

    # Receive response from consumer
    response = await communicator.receive_json_from()
    assert response.get('status') == 'success', f"Unexpected response: {response}"

    # Verify the node was registered in the database
    node = await sync_to_async(Node.objects.get)(public_key="your_public_key_here")
    assert node is not None
    assert node.multiaddress is not None
    assert node.multiaddress.startswith("/ip4")

    await communicator.disconnect()
