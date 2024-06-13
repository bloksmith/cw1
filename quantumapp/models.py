from django.db import models
import hashlib
import json
from django.contrib.auth.models import User
from django.db import models
from django.contrib.auth.models import User
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from django.utils.text import slugify
from django.utils import timezone
import os 
from web3 import Web3  # Ensure Web3 is imported
from django.db import models

class Node(models.Model):
    address = models.CharField(max_length=255, unique=True)
    public_key = models.TextField()
    last_seen = models.DateTimeField(auto_now=True)

def default_address():
    # Generating a random address (this can be any address generation logic)
    return hashlib.sha256(os.urandom(32)).hexdigest()[:32]
from django.db import models
from django.contrib.auth.models import User
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes, padding
from django.utils.text import slugify

class Wallet(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    public_key = models.TextField()
    private_key = models.TextField()
    alias = models.SlugField(max_length=255, unique=True, blank=True)
    address = models.CharField(max_length=42, unique=True)
    balance = models.DecimalField(max_digits=20, decimal_places=8, default=0)
    contribution = models.DecimalField(max_digits=20, decimal_places=8, default=0)
    encrypted_private_key = models.BinaryField(default=b'')

    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        
        self.private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        self.public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        encrypted_private_key = public_key.encrypt(
            self.private_key.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        self.encrypted_private_key = encrypted_private_key
        self.address = self.generate_address(public_key)
        self.save()

    def generate_address(self, public_key):
        public_key_bytes = serialization.load_pem_public_key(
            public_key,
        ).public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        keccak_hash = Web3.keccak(public_key_bytes[1:])
        address = Web3.to_checksum_address(keccak_hash[-20:])
        return address

    def save(self, *args, **kwargs):
        if not self.alias:
            self.alias = slugify(self.user.username)
        super(Wallet, self).save(*args, **kwargs)



class Shard(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)

class Transaction(models.Model):
    hash = models.CharField(max_length=255, unique=True)
    sender = models.ForeignKey(Wallet, related_name='sent_transactions', on_delete=models.CASCADE)
    receiver = models.ForeignKey(Wallet, related_name='received_transactions', on_delete=models.CASCADE)
    amount = models.FloatField()
    fee = models.FloatField(default=0.0)  # Add default value for fee
    signature = models.TextField()  # Placeholder for digital signature
    timestamp = models.DateTimeField(auto_now_add=True)
    is_approved = models.BooleanField(default=False)
    shard = models.ForeignKey(Shard, on_delete=models.CASCADE, related_name='transactions')
    parents = models.ManyToManyField('self', symmetrical=False, related_name='children')
    is_mining_reward = models.BooleanField(default=False)  # Add this field if needed

    def create_hash(self):
        sha = hashlib.sha256()
        sha.update((str(self.sender.public_key) + str(self.receiver.public_key) + str(self.amount) + str(self.timestamp)).encode('utf-8'))
        return sha.hexdigest()


class TransactionMetadata(models.Model):
    transaction = models.ForeignKey(Transaction, on_delete=models.CASCADE, related_name='metadata')
    type = models.CharField(max_length=100)
    status = models.CharField(max_length=100)
    metadata = models.TextField()
from django.db import models
from django.contrib.auth.models import User
import uuid

class Pool(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    host = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    hashrate = models.FloatField(default=0.0)  # Example field for hashrate
    rewards = models.FloatField(default=0.0)   # Example field for rewards

    def __str__(self):
        return self.name


class PoolMember(models.Model):
    pool = models.ForeignKey(Pool, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    joined_at = models.DateTimeField(auto_now_add=True)
from django.db import models
from django.contrib.auth.models import User
class Miner(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    resource_capability = models.IntegerField(default=1)
    contribution = models.FloatField(default=0)
    reward = models.FloatField(default=0)
    tasks_assigned = models.IntegerField(default=0)
    tasks_completed = models.IntegerField(default=0)
    task_completion_times = models.JSONField(default=list)  # Store times as a list of floats

    def __str__(self):
        return f"Miner {self.user.username}"
# models.py

from django.db import models
from django.db import models
class Contract(models.Model):
    address = models.CharField(max_length=42)
    abi = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
from django.db import models

from django.db import models

class CustomToken(models.Model):
    address = models.CharField(max_length=255, unique=True)
    symbol = models.CharField(max_length=10)
    balance = models.DecimalField(max_digits=20, decimal_places=0, default=0)
    wallet = models.ForeignKey('Wallet', on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=255, null=True, blank=True)
    total_supply = models.DecimalField(max_digits=20, decimal_places=0, default=0)

    def __str__(self):
        return f'{self.symbol} - {self.address}'
from django.contrib.auth.models import User
from decimal import Decimal
from django.contrib.auth.models import User
from decimal import Decimal

def ensure_system_wallet():
    system_user, created = User.objects.get_or_create(username='system', defaults={'email': 'system@example.com', 'password': 'systempassword'})
    system_wallet, created = Wallet.objects.get_or_create(user=system_user, defaults={'balance': Decimal('1000000000')})
    if system_wallet.balance < Decimal('1000000000'):
        system_wallet.balance = Decimal('1000000000')
        system_wallet.save()
    return system_wallet
