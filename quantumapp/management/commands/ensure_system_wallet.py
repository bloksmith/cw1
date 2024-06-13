from django.core.management.base import BaseCommand
from quantumapp.models import ensure_system_wallet

class Command(BaseCommand):
    help = 'Ensure the system wallet exists with sufficient balance'

    def handle(self, *args, **kwargs):
        ensure_system_wallet()
        self.stdout.write(self.style.SUCCESS('Successfully ensured system wallet exists'))
