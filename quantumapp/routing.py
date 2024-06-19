# quantumapp/routing.py
from django.urls import re_path
from .consumers import TokenConsumer, PoolConsumer, BlockchainConsumer, TransactionConsumer, SyncConsumer, SyncStatusConsumer, DAGConsumer, NodeRegisterConsumer

websocket_urlpatterns = [
    re_path(r'ws/token/$', TokenConsumer.as_asgi()),
    re_path(r'ws/pool/$', PoolConsumer.as_asgi()),
    re_path(r'ws/blockchain/$', BlockchainConsumer.as_asgi()),
    re_path(r'ws/transactions/$', TransactionConsumer.as_asgi()),
    re_path(r'ws/sync/$', SyncConsumer.as_asgi()),
    re_path(r'ws/sync_status/$', SyncStatusConsumer.as_asgi()),
    re_path(r'ws/dag/$', DAGConsumer.as_asgi()),
    re_path(r'ws/register_node/$', NodeRegisterConsumer.as_asgi()),
]
