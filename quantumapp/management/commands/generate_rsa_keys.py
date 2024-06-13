from django.core.management.base import BaseCommand
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class Command(BaseCommand):
    help = 'Generate RSA keys and save them to files'

    def handle(self, *args, **kwargs):
        # Generate RSA keys
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        public_key = private_key.public_key()

        # Save the private key
        with open("private_key.pem", "wb") as private_key_file:
            private_key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Save the public key
        with open("public_key.pem", "wb") as public_key_file:
            public_key_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

        # Encrypt the private key in chunks
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        chunk_size = 190  # chunk size is less than 256 bytes
        encrypted_chunks = []

        for i in range(0, len(private_key_bytes), chunk_size):
            chunk = private_key_bytes[i:i + chunk_size]
            encrypted_chunk = public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_chunks.append(encrypted_chunk)

        encrypted_private_key = b"".join(encrypted_chunks)

        # Save the encrypted private key
        with open("encrypted_private_key.pem", "wb") as encrypted_private_key_file:
            encrypted_private_key_file.write(encrypted_private_key)

        self.stdout.write(self.style.SUCCESS('Successfully generated and encrypted RSA keys'))
