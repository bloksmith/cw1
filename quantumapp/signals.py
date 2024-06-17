# quantumapp/signals.py
from django.db.models.signals import post_migrate
from django.dispatch import receiver
from .models import Shard
from .utils import create_default_shard

@receiver(post_migrate)
def create_default_shard_after_migration(sender, **kwargs):
    if sender.name == 'quantumapp':
        create_default_shard()
