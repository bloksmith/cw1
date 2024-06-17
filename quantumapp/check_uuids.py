# management/commands/check_uuids.py
import uuid
from django.core.management.base import BaseCommand
from quantumapp.models import Pool

class Command(BaseCommand):
    help = 'Check UUIDs in Pool model'

    def handle(self, *args, **kwargs):
        pools = Pool.objects.all()
        for pool in pools:
            try:
                uuid.UUID(str(pool.id))
                print(f"Pool {pool.id} is a valid UUID")
            except ValueError:
                print(f"Pool {pool.id} is not a valid UUID")
