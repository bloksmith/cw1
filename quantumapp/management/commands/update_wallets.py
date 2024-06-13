# your_app/management/commands/update_wallets.py
from django.core.management.base import BaseCommand
from quantumapp.models import Wallet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

class Command(BaseCommand):
    help = 'Encrypt existing private keys for wallets'

    def handle(self, *args, **kwargs):
        # Load public key
        with open("public_key.pem", "rb") as key_file:
            public_key_pem = key_file.read()
        
        public_key = serialization.load_pem_public_key(public_key_pem)
        
        for wallet in Wallet.objects.all():
            private_key_pem = wallet.private_key.encode()  # Assuming private_key is available as a string
            encrypted_private_key = public_key.encrypt(
                private_key_pem,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            wallet.encrypted_private_key = encrypted_private_key
            wallet.save()
        
        self.stdout.write(self.style.SUCCESS('Successfully updated wallet encrypted private keys'))
