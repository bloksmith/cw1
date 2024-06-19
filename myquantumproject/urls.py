from django.contrib import admin
from django.urls import path, re_path  # Added re_path import
from quantumapp import views
from django.conf import settings
from django.conf.urls.static import static
from quantumapp.sync_utils import synchronize_nodes
from quantumapp import consumers  # Ensure this import is correct

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('market/', views.market, name='market'),
    path('trading_bot/', views.trading_bot, name='trading_bot'),
    path('admin/', admin.site.urls),
    path('register/', views.register, name='register'),
    path('import_wallet/', views.import_wallet, name='import_wallet'),
    path('create_transaction/', views.create_transaction, name='create_transaction'),
    path('mine/<int:shard_id>/', views.mine_block, name='mine_block'),
    path('start_mining/<int:shard_id>/', views.start_mining, name='start_mining'),
    path('stop_mining/', views.stop_mining, name='stop_mining'),
    path('create_pool/', views.create_pool, name='create_pool'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('get_wallet_aliases/', views.get_wallet_aliases, name='get_wallet_aliases'),
    path('get_wallet_details/', views.get_wallet_details, name='get_wallet_details'),
    path('join_pool/<uuid:pool_id>/', views.join_pool, name='join_pool'),  # UUID pool_id
    path('api/receive_transaction/', views.receive_transaction, name='receive_transaction'),
    path('api/latest_transaction/', views.latest_transaction, name='latest_transaction'),
    path('api/transaction_pool/', views.transaction_pool, name='transaction_pool'),
    path('network_status/', views.get_network_status, name='network_status'),
    path('get_mining_statistics/', views.get_mining_statistics, name='get_mining_statistics'),
    path('search_transaction/', views.search_transaction, name='search_transaction'),
    path('manage-contract/', views.manage_contract, name='manage_contract'),
    path('deploy_contract/', views.deploy_contract, name='deploy_contract'),
    path('get_token_details/', views.get_token_details, name='get_token_details'),
    path('market/', views.market_view, name='market'),
    path('get_transaction_data/', views.get_transaction_data, name='get_transaction_data'),
    path('get_node_data/', views.get_node_data, name='get_node_data'),
    path('fetch_token_details/', views.fetch_token_details, name='fetch_token_details'),
    path('import_token/', views.import_token, name='import_token'),
    path('send_token/', views.send_token, name='send_token'),
    path('burn_token/', views.burn_token, name='burn_token'),
    path('mint_token/', views.mint_token, name='mint_token'),
    path('api/nodes/', views.list_nodes, name='list_nodes'),
    path('api/register_node/', views.register_node, name='register_node'),
    path('api/synchronize_nodes/', synchronize_nodes, name='synchronize_nodes'),
    path('tradingbot/', views.trading_bot_view, name='tradingbot'),
    path('fetch-trending-pairs/', views.fetch_trending_pairs, name='fetch_token_pairs'),
    path('fetch-token-pairs/', views.fetch_token_pairs, name='fetch_token_pairs'),
    path('api/receive_block/', views.receive_block, name='receive_block'),
    path('get_congestion_factor/', views.get_network_congestion_factor_view, name='get_congestion_factor'),
    path('ws/wallet_updates/', consumers.WalletUpdateConsumer.as_asgi()),
    path('ws/peer/', consumers.P2PConsumer.as_asgi()),
    re_path(r'ws/nodes/$', consumers.NodeConsumer.as_asgi()),
    path('recent_transactions/', views.recent_transactions, name='recent_transactions'),
    path('nodes/', views.node_list, name='node_list'),



] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
