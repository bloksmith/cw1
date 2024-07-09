# Custom management command to clear the alias field
from django.core.management.base import BaseCommand
from quantumapp.models import Wallet

class Command(BaseCommand):
    help = 'Clear alias values in Wallet'

    def handle(self, *args, **kwargs):
        Wallet.objects.update(alias=None)
        self.stdout.write(self.style.SUCCESS('Successfully cleared alias values'))
