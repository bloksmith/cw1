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
from django.db import models
from decimal import Decimal
import hashlib

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
    batch_processed = models.BooleanField(default=False)

    def create_hash(self):
        sha = hashlib.sha256()
        sha.update((str(self.sender.public_key) + str(self.receiver.public_key) + str(self.amount) + str(self.timestamp)).encode('utf-8'))
        return sha.hexdigest()

    def estimate_size(self):
        # Estimate the size of the transaction in bytes
        size = len(self.sender.address) + len(self.receiver.address) + len(str(self.amount)) + len(self.signature)
        return size

    @staticmethod
    def estimate_fee(transaction_size, congestion_factor=1.0):
        BASE_FEE_RATE = Decimal('0.00000001')  # Base fee rate per byte
        fee = BASE_FEE_RATE * transaction_size * congestion_factor
        return fee


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

class TokenPair(models.Model):
    NETWORK_CHOICES = [
        ('ETH_MAINNET', 'Ethereum Mainnet'),
        ('ETH_SEPOLIA', 'Ethereum Sepolia'),
        ('ARBITRUM', 'Arbitrum'),
        ('AVALANCHE', 'Avalanche'),
        ('BASE', 'Base'),
        ('BSC', 'Binance Smart Chain'),
        ('CELO', 'Celo'),
        ('FANTOM', 'Fantom'),
        ('OPTIMISM', 'Optimism'),
        ('POLYGON', 'Polygon'),
    ]

    name = models.CharField(max_length=255, default='Default Token Pair Name')
    token1_symbol = models.CharField(max_length=10, default='TKN1')
    token2_symbol = models.CharField(max_length=10, default='TKN2')
    token1_address = models.CharField(max_length=42, default='0x0000000000000000000000000000000000000000')
    token2_address = models.CharField(max_length=42, default='0x0000000000000000000000000000000000000000')
    from_token = models.CharField(max_length=42, help_text="Address of the from token")
    to_token = models.CharField(max_length=42, help_text="Address of the to token")
    active = models.BooleanField(default=True, help_text="Is the token pair actively traded?")
    trading_enabled = models.BooleanField(default=True, help_text="Can actual buy/sell operations be performed?")
    buy_token = models.CharField(max_length=42, help_text="Token address for buying", default='0x0000000000000000000000000000000000000000')
    sell_token = models.CharField(max_length=42, help_text="Token address for selling", default='0x0000000000000000000000000000000000000000')
    sell_to_address = models.CharField(max_length=42, default='0x826c533770B4Bc53aa6dA31747113595e0032567', help_text="Address to send tokens when selling")
    buy_to_address = models.CharField(max_length=42, default='0x826c533770B4Bc53aa6dA31747113595e0032567', help_text="Address to send tokens when buying")
    sell_transaction_data = models.TextField(help_text="Transaction data for selling", blank=True, default='function_data')
    buy_transaction_data = models.TextField(help_text="Transaction data for buying", blank=True, null=True)
    use_deep_learning = models.BooleanField(default=False, help_text="Use deep learning models for this pair?")
    buy_signal = models.BooleanField(default=False, help_text="Indicator for a buy signal")
    sell_signal = models.BooleanField(default=False, help_text="Indicator for a sell signal")
    # New fields for sentiment and risk data
    sentiment_score = models.FloatField(default=0.0, help_text="Sentiment score from analysis")
    sentiment_summary = models.TextField(blank=True, help_text="Summary of the sentiment analysis")
    risk_level = models.CharField(max_length=10, default='UNKNOWN', choices=[('LOW', 'Low'), ('MEDIUM', 'Medium'), ('HIGH', 'High')], help_text="Risk level from the latest analysis")
    last_analyzed = models.DateTimeField(auto_now=True, editable=False)
    buy_small_amount = models.BooleanField(default=False, help_text="Always buy a small amount regardless of other indicators for cStables/DAI")
    token11_network = models.CharField(max_length=20, choices=NETWORK_CHOICES, default='POLYGON', help_text="Blockchain network for token1")
    token22_network = models.CharField(max_length=20, choices=NETWORK_CHOICES, default='POLYGON', help_text="Blockchain network for token2")

    def __str__(self):
        return f"{self.token1_symbol}/{self.token2_symbol} - {self.name}"

class TokenQuote(models.Model):
    from_token = models.CharField(max_length=42)
    to_token = models.CharField(max_length=42)
    price = models.DecimalField(max_digits=20, decimal_places=10)
    gross_price = models.DecimalField(max_digits=20, decimal_places=10, null=True)
    estimated_price_impact = models.CharField(max_length=100, null=True)
    gas_price = models.BigIntegerField(null=True)
    gas_used = models.BigIntegerField(null=True)
    sources = models.JSONField(default=dict)
    created_at = models.DateTimeField()
    amount = models.DecimalField(max_digits=20, decimal_places=10, null=True, default=None)

    # Technical indicators
    upper_band = models.DecimalField(max_digits=20, decimal_places=10, null=True)
    lower_band = models.DecimalField(max_digits=20, decimal_places=10, null=True)
    rsi = models.DecimalField(max_digits=10, decimal_places=4, null=True)
    macd = models.DecimalField(max_digits=20, decimal_places=10, null=True)
    rsi_sma = models.DecimalField(max_digits=10, decimal_places=4, null=True)
    signal_line = models.DecimalField(max_digits=20, decimal_places=10, null=True)
    # Additional technical indicators
    fibonacci_retracement = models.DecimalField(max_digits=20, decimal_places=10, null=True)
    impulse_macd = models.DecimalField(max_digits=20, decimal_places=10, null=True)

    # Trade signals
    buy_signal = models.BooleanField(default=False)
    sell_signal = models.BooleanField(default=False)

    # Sentiment and risk assessment
    sentiment_score = models.FloatField(default=0.0, help_text="Sentiment score from analysis")
    sentiment_summary = models.TextField(blank=True, help_text="Summary of the sentiment analysis")
    risk_level = models.CharField(max_length=10, default='UNKNOWN', choices=[('LOW', 'Low'), ('MEDIUM', 'Medium'), ('HIGH', 'High')], help_text="Risk level from the latest analysis")
    last_analyzed = models.DateTimeField(default=timezone.now, help_text="Timestamp of the last analysis")
    volatility = models.FloatField(default=0.0)  # Added volatility field
    price_difference = models.FloatField(default=0.0)  # Added price difference field
    realized_profit = models.DecimalField(max_digits=20, decimal_places=10, null=True)  # Ensure this field exists

    def save(self, *args, **kwargs):
        print(f"Saving TokenQuote instance: {self}")
        super().save(*args, **kwargs)
        print(f"TokenQuote instance saved: {self}")

    def __str__(self):
        return f"{self.from_token} to {self.to_token} at {self.price} on {self.created_at.strftime('%Y-%m-%d %H:%M:%S')}"
from django.db import models

class Block(models.Model):
    hash = models.CharField(max_length=64, unique=True)
    previous_hash = models.CharField(max_length=64)
    timestamp = models.DateTimeField()
    # Add transient children attribute, not persisted in the database
    children = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.children = []

from django.db import models
from django.utils import timezone

class PendingTransaction(models.Model):
    sender = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='pending_sender')
    receiver = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='pending_receiver')
    amount = models.DecimalField(max_digits=20, decimal_places=8)
    fee = models.DecimalField(max_digits=20, decimal_places=8)
    timestamp = models.DateTimeField(default=timezone.now)
    hash = models.CharField(max_length=64)
    signature = models.CharField(max_length=256)
from django.db import models

class Peer(models.Model):
    address = models.CharField(max_length=255)
    peer_id = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.peer_id} @ {self.address}"
