from django.urls import path, re_path
from .consumers import TokenConsumer, PoolConsumer, BlockchainConsumer, TransactionConsumer, SyncConsumer, SyncStatusConsumer

websocket_urlpatterns = [
    path('ws/token/', TokenConsumer.as_asgi()),
    path('ws/pool/<str:pool_name>/', PoolConsumer.as_asgi()),
    re_path(r'ws/blockchain/$', BlockchainConsumer.as_asgi()),
    path('ws/transactions/', TransactionConsumer.as_asgi()),
    path('ws/sync/', SyncConsumer.as_asgi()),
    re_path(r'ws/sync_status/$', SyncStatusConsumer.as_asgi()),
    path('ws/dag/', DAGConsumer.as_asgi()),

]
