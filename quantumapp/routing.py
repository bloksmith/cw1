from django.urls import re_path, path
from .consumers import TokenConsumer, PoolConsumer, BlockchainConsumer, TransactionConsumer, SyncConsumer, SyncStatusConsumer, DAGConsumer, NodeRegisterConsumer, LogConsumer
from .consumers import QuantumSyncConsumer

websocket_urlpatterns = [
    re_path(r'ws/token/$', TokenConsumer.as_asgi()),
    re_path(r'ws/pool/$', PoolConsumer.as_asgi()),
    re_path(r'ws/blockchain/$', BlockchainConsumer.as_asgi()),
    re_path(r'ws/transactions/$', TransactionConsumer.as_asgi()),
    re_path(r'ws/sync/$', SyncConsumer.as_asgi()),
    re_path(r'ws/sync_status/$', SyncStatusConsumer.as_asgi()),
    re_path(r'ws/dag/$', DAGConsumer.as_asgi()),
    re_path(r'ws/register_node/$', NodeRegisterConsumer.as_asgi()),
    path('ws/veilid/logs/', LogConsumer.as_asgi()),  # Corrected import here
    re_path(r'ws/unique-sync-url/', QuantumSyncConsumer.as_asgi(), name='ws_unique_sync'),  # Added a special name for the path

]
