import pytest
import json
import asynctest
from channels.testing import WebsocketCommunicator
from myquantumproject.asgi import application
from quantumapp.consumers import QuantumSyncConsumer
from unittest.mock import patch, AsyncMock
import logging

@pytest.mark.asyncio
class TestQuantumSyncConsumer:

    @pytest.fixture
    def mock_node(self):
        mock_node = asynctest.Mock()
        mock_node.get_id.return_value = 'mock_node_id'
        peer_1 = asynctest.Mock()
        peer_1.pretty.return_value = 'peer_1'
        peer_2 = asynctest.Mock()
        peer_2.pretty.return_value = 'peer_2'
        mock_node.peerstore.peer_ids.return_value = [peer_1, peer_2]
        
        # Mock stream and its write method
        mock_stream = asynctest.Mock()
        mock_stream.write = AsyncMock()
        mock_node.new_stream = AsyncMock(return_value=mock_stream)
        
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
    @patch('quantumapp.libp2p_node.start_node')  # Correctly reference the patch target
    async def test_broadcast_wallet_libp2p(self, mock_start_node, communicator, wallet_data, mock_node, caplog):
        mock_start_node.return_value = mock_node

        # Create a scope for the consumer
        scope = {
            'type': 'websocket',
            'path': '/ws/sync/',
            'headers': [
                (b'host', b'localhost'),
                (b'upgrade', b'websocket'),
                (b'connection', b'Upgrade'),
                (b'sec-websocket-key', b'test_key'),
                (b'sec-websocket-version', b'13'),
            ],
            'query_string': b'',
            'client': ('127.0.0.1', 12345),
                'server': ('127.0.0.1', 8000),
                'subprotocols': [],
            }

        consumer = QuantumSyncConsumer(scope)
        consumer.channel_name = "test_channel"

        # Mock the send method
        consumer.send = AsyncMock()

        with caplog.at_level(logging.INFO):
            await consumer.broadcast_wallet_libp2p(wallet_data)

        # Verify the correct methods were called
        mock_start_node.assert_called_once()
        mock_node.new_stream.assert_any_call(mock_node.peerstore.peer_ids()[0], ["/echo/1.0.0"])
        mock_node.new_stream.assert_any_call(mock_node.peerstore.peer_ids()[1], ["/echo/1.0.0"])

        # Verify the data was sent correctly
        for call in mock_node.new_stream.return_value.write.call_args_list:
            data_sent = call[0][0].decode("utf-8")
            assert json.loads(data_sent) == wallet_data

        # Verify the log messages
        assert "Broadcasted wallet data to peer peer_1" in caplog.text
        assert "Broadcasted wallet data to peer peer_2" in caplog.text

    @pytest.mark.asyncio
    async def test_connect(self, communicator):
        with patch('quantumapp.register_with_master.register_with_master_node_async', new=AsyncMock(return_value='test_multiaddress')) as mock_register:
            # Create a scope for the consumer
            scope = {
                'type': 'websocket',
                'path': '/ws/sync/',
                'headers': [
                    (b'host', b'localhost'),
                    (b'upgrade', b'websocket'),
                    (b'connection', b'Upgrade'),
                    (b'sec-websocket-key', b'test_key'),
                    (b'sec-websocket-version', b'13'),
                ],
                'query_string': b'',
                'client': ('127.0.0.1', 12345),
                'server': ('127.0.0.1', 8000),
                'subprotocols': [],
            }

            consumer = QuantumSyncConsumer(scope)
            consumer.channel_name = "test_channel"

            consumer.channel_layer = AsyncMock()
            consumer.base_send = AsyncMock()  # Patch base_send

            with patch.object(consumer, 'send', new_callable=AsyncMock):
                with patch('quantumapp.consumers.QuantumSyncConsumer.register_and_sync_from_master', new=AsyncMock()):
                    await consumer.connect()
                    assert consumer.channel_name == "test_channel"
                    await consumer.disconnect(1000)

    @pytest.mark.asyncio
    async def test_disconnect(self, communicator):
        # Create a scope for the consumer
        scope = {
            'type': 'websocket',
            'path': '/ws/sync/',
            'headers': [
                (b'host', b'localhost'),
                (b'upgrade', b'websocket'),
                (b'connection', b'Upgrade'),
                (b'sec-websocket-key', b'test_key'),
                (b'sec-websocket-version', b'13'),
            ],
            'query_string': b'',
            'client': ('127.0.0.1', 12345),
            'server': ('127.0.0.1', 8000),
            'subprotocols': [],
        }

        consumer = QuantumSyncConsumer(scope)
        consumer.channel_name = "test_channel"

        consumer.channel_layer = AsyncMock()

        with patch.object(consumer, 'send', new_callable=AsyncMock):
            await consumer.disconnect(1000)
            assert consumer.channel_name == "test_channel"
            
    @pytest.mark.asyncio
    @patch('quantumapp.consumers.QuantumSyncConsumer.create_wallet', new_callable=AsyncMock)
    @patch('quantumapp.consumers.QuantumSyncConsumer.broadcast_wallet_libp2p', new_callable=AsyncMock)
    async def test_sync_wallet(self, mock_broadcast_wallet_libp2p, mock_create_wallet, communicator, wallet_data):
        # Create a scope for the consumer
        scope = {
            'type': 'websocket',
            'path': '/ws/sync/',
            'headers': [
                (b'host', b'localhost'),
                (b'upgrade', b'websocket'),
                (b'connection', b'Upgrade'),
                (b'sec-websocket-key', b'test_key'),
                (b'sec-websocket-version', b'13'),
            ],
            'query_string': b'',
            'client': ('127.0.0.1', 12345),
            'server': ('127.0.0.1', 8000),
            'subprotocols': [],
        }

        consumer = QuantumSyncConsumer(scope)
        consumer.channel_name = "test_channel"

        with patch.object(consumer, 'send', new_callable=AsyncMock):
            event = {
                'wallet_data': wallet_data
            }
            await consumer.sync_wallet(event)

            # Verify the create_wallet and broadcast_wallet_libp2p methods were called
            mock_create_wallet.assert_called_once_with(wallet_data)
            mock_broadcast_wallet_libp2p.assert_called_once_with(wallet_data)

            # Verify the send method was called with the correct data
            expected_message = {
                'type': 'sync_status',
                'status': 'Wallet synced',
                'wallet_data': wallet_data
            }
            consumer.send.assert_called_once_with(text_data=json.dumps(expected_message))
            
    @pytest.mark.asyncio
    async def test_receive(self, communicator, wallet_data, caplog):
        # Create a scope for the consumer
        scope = {
            'type': 'websocket',
            'path': '/ws/sync/',
            'headers': [
                (b'host', b'localhost'),
                (b'upgrade', b'websocket'),
                (b'connection', b'Upgrade'),
                (b'sec-websocket-key', b'test_key'),
                (b'sec-websocket-version', b'13'),
            ],
            'query_string': b'',
            'client': ('127.0.0.1', 12345),
            'server': ('127.0.0.1', 8000),
            'subprotocols': [],
        }

        consumer = QuantumSyncConsumer(scope)
        consumer.channel_name = "test_channel"

        with patch.object(consumer, 'sync_wallet', new_callable=AsyncMock) as mock_sync_wallet:
            with patch.object(consumer, 'register_peer', new_callable=AsyncMock) as mock_register_peer:
                with patch.object(consumer, 'send', new_callable=AsyncMock) as mock_send:
                    # Test sync_wallet
                    sync_wallet_message = {
                        'type': 'sync_wallet',
                        'wallet_data': wallet_data
                    }
                    with caplog.at_level(logging.DEBUG):
                        await consumer.receive(text_data=json.dumps(sync_wallet_message))
                    mock_sync_wallet.assert_called_once_with(sync_wallet_message)
                    assert any("Received raw text data" in message for message in caplog.messages)

                    # Test register_peer
                    register_peer_message = {
                        'action': 'register_peer',
                        'peer_info': {
                            'address': 'test_address',
                            'peer_id': 'test_peer_id'
                        }
                    }
                    with caplog.at_level(logging.DEBUG):
                        await consumer.receive(text_data=json.dumps(register_peer_message))
                    mock_register_peer.assert_called_once_with(register_peer_message['peer_info'])
                    assert any("Received raw text data" in message for message in caplog.messages)

                    # Test invalid JSON
                    invalid_json_message = 'invalid_json'
                    with caplog.at_level(logging.ERROR):
                        await consumer.receive(text_data=invalid_json_message)
                    expected_error_message = {
                        'type': 'error',
                        'message': 'Invalid JSON format'
                    }
                    mock_send.assert_any_call(text_data=json.dumps(expected_error_message))
                    assert any("JSONDecodeError" in message for message in caplog.messages)
                    assert any("Received invalid JSON" in message for message in caplog.messages)

                    # Test unexpected error
                    with patch('json.loads', side_effect=Exception('Unexpected error')):
                        with caplog.at_level(logging.ERROR):
                            await consumer.receive(text_data=json.dumps(sync_wallet_message))
                        expected_unexpected_error_message = {
                            'type': 'error',
                            'message': 'Unexpected error occurred'
                        }
                        mock_send.assert_any_call(text_data=json.dumps(expected_unexpected_error_message))
                        assert any("Unexpected error" in message for message in caplog.messages)

if __name__ == "__main__":
    pytest.main()
