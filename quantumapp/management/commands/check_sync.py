from django.core.management.base import BaseCommand
from quantumapp.sync_utils import check_sync

class Command(BaseCommand):
    help = 'Check synchronization status of nodes'

    def handle(self, *args, **options):
        node1_url = "http://localhost:1010"
        node2_url = "http://localhost:2020"
        is_synced = check_sync(node1_url, node2_url)
        if is_synced:
            self.stdout.write(self.style.SUCCESS('Nodes are in sync'))
        else:
            self.stdout.write(self.style.ERROR('Nodes are not in sync'))
