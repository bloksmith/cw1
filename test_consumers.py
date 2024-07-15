import pytest
import json
import asynctest
from channels.testing import WebsocketCommunicator
from myquantumproject.asgi import application
from myquantumproject.consumers import QuantumSyncConsumer
from unittest.mock import patch

@pytest.mark.asyncio
class TestQuantumSyncConsumer:

    @pytest.fixture
    def mock_node(self):
        mock_node = asynctest.Mock()
        mock_node.get_id.return_value = 'mock_node_id'
        mock_node.peerstore.peer_ids.return_value = ['peer_1', 'peer_2']
        return mock_node

    @pytest.fixture
    def wallet_data(self):
        return {
            'public_key': 'test_public_key',
            'address': 'test_address',
            'alias': 'test_alias',
            'balance': 100
        }

    @pytest.fixture
    async def communicator(self):
        communicator = WebsocketCommunicator(application, "/ws/sync/")
        connected, _ = await communicator.connect()
        assert connected
        yield communicator
        await communicator.disconnect()

    @pytest.mark.asyncio
    @patch('myquantumproject.consumers.start_node')
    async def test_broadcast_wallet_libp2p(self, mock_start_node, communicator, wallet_data, mock_node):
        mock_start_node.return_value = mock_node
        consumer = QuantumSyncConsumer(scope=communicator.scope)
        await consumer.broadcast_wallet_libp2p(wallet_data)

        # Verify the correct methods were called
        mock_start_node.assert_called_once()
        mock_node.new_stream.assert_any_call('peer_1', ["/echo/1.0.0"])
        mock_node.new_stream.assert_any_call('peer_2', ["/echo/1.0.0"])

        # Verify the data was sent correctly
        for call in mock_node.new_stream.return_value.write.call_args_list:
            data_sent = call[0][0].decode("utf-8")
            assert json.loads(data_sent) == wallet_data

        # Verify the log messages
        with asynctest.patch('myquantumproject.consumers.logger.info') as mock_logger_info:
            await consumer.broadcast_wallet_libp2p(wallet_data)
            mock_logger_info.assert_any_call(f"Broadcasted wallet data to peer peer_1")
            mock_logger_info.assert_any_call(f"Broadcasted wallet data to peer peer_2")
