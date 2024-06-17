from django.contrib import admin
from .models import Node, Wallet, Shard, Transaction, TransactionMetadata, Pool, PoolMember, Miner, Contract, CustomToken

@admin.register(Node)
class NodeAdmin(admin.ModelAdmin):
    list_display = ('address', 'public_key', 'last_seen')
    search_fields = ('address', 'public_key')
    list_filter = ('last_seen',)

@admin.register(Wallet)
class WalletAdmin(admin.ModelAdmin):
    list_display = ('user', 'public_key', 'address', 'balance', 'contribution')
    search_fields = ('user__username', 'public_key', 'address')
    list_filter = ('balance', 'contribution')
    readonly_fields = ('public_key', 'private_key', 'address', 'encrypted_private_key')
    fieldsets = (
        (None, {
            'fields': ('user', 'alias', 'public_key', 'address', 'balance', 'contribution', 'encrypted_private_key')
        }),
        ('Private Key Information', {
            'classes': ('collapse',),
            'fields': ('private_key',),
        }),
    )

@admin.register(Shard)
class ShardAdmin(admin.ModelAdmin):
    list_display = ('name', 'description')
    search_fields = ('name', 'description')

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ('hash', 'sender', 'receiver', 'amount', 'fee', 'timestamp', 'is_approved', 'shard', 'is_mining_reward')
    search_fields = ('hash', 'sender__address', 'receiver__address')
    list_filter = ('is_approved', 'timestamp', 'shard')
    readonly_fields = ('hash', 'signature')
    fieldsets = (
        (None, {
            'fields': ('sender', 'receiver', 'amount', 'fee', 'shard', 'parents', 'is_approved', 'is_mining_reward')
        }),
        ('Advanced options', {
            'classes': ('collapse',),
            'fields': ('hash', 'signature'),
        }),
    )

@admin.register(TransactionMetadata)
class TransactionMetadataAdmin(admin.ModelAdmin):
    list_display = ('transaction', 'type', 'status')
    search_fields = ('transaction__hash', 'type', 'status')
    list_filter = ('type', 'status')

@admin.register(Pool)
class PoolAdmin(admin.ModelAdmin):
    list_display = ('name', 'host', 'created_at', 'hashrate', 'rewards')
    search_fields = ('name', 'host__username')
    list_filter = ('created_at',)

@admin.register(PoolMember)
class PoolMemberAdmin(admin.ModelAdmin):
    list_display = ('pool', 'user', 'joined_at')
    search_fields = ('pool__name', 'user__username')
    list_filter = ('joined_at',)

@admin.register(Miner)
class MinerAdmin(admin.ModelAdmin):
    list_display = ('user', 'resource_capability', 'contribution', 'reward', 'tasks_assigned', 'tasks_completed')
    search_fields = ('user__username',)
    list_filter = ('resource_capability', 'contribution', 'reward')

@admin.register(Contract)
class ContractAdmin(admin.ModelAdmin):
    list_display = ('address', 'created_at', 'updated_at')
    search_fields = ('address',)
    list_filter = ('created_at', 'updated_at')

@admin.register(CustomToken)
class CustomTokenAdmin(admin.ModelAdmin):
    list_display = ('symbol', 'address', 'balance', 'wallet', 'total_supply')
    search_fields = ('symbol', 'address', 'wallet__address')
    list_filter = ('balance', 'total_supply')

# Models are already registered with decorators, no need to register them again
