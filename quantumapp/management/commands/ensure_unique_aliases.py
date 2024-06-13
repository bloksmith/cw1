from django.core.management.base import BaseCommand
from quantumapp.models import Wallet
from django.utils.text import slugify

class Command(BaseCommand):
    help = 'Populate the alias field with unique values'

    def handle(self, *args, **kwargs):
        wallets = Wallet.objects.all()
        seen_aliases = set()
        for wallet in wallets:
            if not wallet.alias:  # Only update if alias is not set
                base_alias = slugify(wallet.user.username)
                alias = base_alias
                counter = 1
                while alias in seen_aliases or Wallet.objects.filter(alias=alias).exists():
                    alias = f"{base_alias}-{counter}"
                    counter += 1
                wallet.alias = alias
                wallet.save()
                seen_aliases.add(alias)
        self.stdout.write(self.style.SUCCESS('Successfully populated wallet aliases with unique values'))
