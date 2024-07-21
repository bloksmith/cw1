# quantumapp/management/commands/start_masternode.py

import trio
from django.core.management.base import BaseCommand
from quantumapp.utils import run_masternode, run_websocket_server

class Command(BaseCommand):
    help = 'Start the masternode and websocket server'

    def handle(self, *args, **kwargs):
        async def start_services():
            master_node_url = await run_masternode(8001)
            await run_websocket_server(master_node_url)

        trio.run(start_services)
