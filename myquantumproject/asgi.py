import os
import django
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from channels.security.websocket import AllowedHostsOriginValidator
from django.core.asgi import get_asgi_application
from django.urls import path, re_path
from quantumapp import consumers

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myquantumproject.settings')
django.setup()

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AllowedHostsOriginValidator(
        AuthMiddlewareStack(
            URLRouter(
                [
                    path("ws/transactions/", consumers.TransactionConsumer.as_asgi()),
                    path("ws/nodes/", consumers.NodeConsumer.as_asgi()),
                    path("ws/pools/", consumers.PoolConsumer.as_asgi()),
                    re_path(r'ws/blockchain/$', consumers.BlockchainConsumer.as_asgi()),
                    re_path(r'ws/sync_status/$', consumers.SyncStatusConsumer.as_asgi()),
                    path("ws/dag/", consumers.DAGConsumer.as_asgi()),  # Added DAGConsumer
                ]
            )
        )
    ),
})
