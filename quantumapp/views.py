import asyncio
import json
import hashlib
import requests
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from .models import Wallet, Transaction, Shard, Pool, PoolMember
from mnemonic import Mnemonic
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from web3 import Web3
from django.utils import timezone
from django.contrib.auth import authenticate, login
from decimal import Decimal  # Add this import
from .utils import create_default_shard
import base64
import hashlib
import logging
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

# Ensure default shard is created
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)
protocol_parameters = {
    "block_timeout": 10  # Default block timeout in seconds
}
import subprocess

def measure_network_latency():
    try:
        result = subprocess.run(["ping", "-c", "1", "8.8.8.8"], stdout=subprocess.PIPE)
        if result.returncode == 0:
            latency = float(result.stdout.decode().split('time=')[1].split(' ms')[0])
            return latency / 1000.0  # Convert ms to seconds
        else:
            logger.error("Ping command failed")
            return None
    except Exception as e:
        logger.error(f"Error measuring network latency: {e}")
        return None


def get_wallet_balance(public_key_pem):
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        sha256 = hashlib.sha256(public_key_bytes).digest()
        keccak = Web3.keccak(sha256)
        address = Web3.to_checksum_address(keccak[-20:])
        w3 = Web3(Web3.HTTPProvider('http://159.89.106.101:8545'))
        if not w3.is_connected():
            return None
        balance = w3.eth.get_balance(address)
        balance_eth = w3.from_wei(balance, 'ether')
        return balance_eth
    except Exception as e:
        print(f"Error getting wallet balance: {e}")
        return None
def generate_wallet():
    # Generate a mnemonic phrase
    mnemo = Mnemonic("english")
    mnemonic_phrase = mnemo.generate(strength=128)

    # Generate a private key and public key using the mnemonic phrase
    account = Account.from_mnemonic(mnemonic_phrase)
    private_key = account.privateKey
    public_key = account._key_obj.public_key
    address = account.address

    # Serialize the private key and public key
    private_key_serialized = private_key.to_bytes().hex()
    public_key_serialized = public_key.to_bytes().hex()

    return {
        "mnemonic": mnemonic_phrase,
        "private_key": private_key_serialized,
        "public_key": public_key_serialized,
        "address": address
    }

### Updated `register` view:
@csrf_exempt
def register(request):
    if request.method == 'POST':
        try:
            if not request.POST:
                return JsonResponse({'error': 'Empty request body.'}, status=400)

            adapt_to_latency()  # Ensure protocol parameters are adapted during registration
            wallet_data = generate_wallet()
            username = wallet_data['public_key']
            password = None  # Set password if needed
            logger.debug(f"Generated username: {username}")

            user = User.objects.create_user(username=username, password=password)
            alias = generate_unique_alias(wallet_data['public_key'])
            address = wallet_data['address']

            wallet = Wallet(
                user=user,
                public_key=wallet_data['public_key'],
                private_key=wallet_data['private_key'],
                alias=alias,
                address=address
            )
            wallet.save()
            
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)

            balance = get_wallet_balance(wallet_data['public_key'])
                
            return JsonResponse({
                'message': 'User and wallet created',
                'public_key': wallet.public_key,
                'mnemonic': wallet_data['mnemonic'],
                'address': wallet.address,
                'balance': balance
            })
        except IntegrityError as e:
            logger.error(f"Error during registration: {str(e)}")
            return JsonResponse({'error': 'User with this public key already exists or alias conflict'}, status=400)
        except Exception as e:
            logger.error(f"Error during registration: {str(e)}")
            return JsonResponse({'error': 'An unexpected error occurred'}, status=500)
    return JsonResponse({'error': 'Only POST method allowed'}, status=400)


def generate_unique_alias(public_key):
    base_alias = public_key[:8]
    alias = base_alias
    counter = 1
    while Wallet.objects.filter(alias=alias).exists():
        alias = f"{base_alias}-{counter}"
        counter += 1
    return alias

@csrf_exempt
def import_wallet(request):
    if request.method == 'POST':
        mnemonic_phrase = request.POST.get('mnemonic')
        mnemo = Mnemonic("english")
        if mnemo.check(mnemonic_phrase):
            wallet_data = generate_wallet()
            user, created = User.objects.get_or_create(username=wallet_data['public_key'])
            if created:
                alias = generate_unique_alias(wallet_data['public_key'])
                wallet = Wallet(
                    user=user, 
                    public_key=wallet_data['public_key'], 
                    private_key=wallet_data['private_key'], 
                    alias=alias,
                    address=wallet_data['address']
                )
                wallet.save()
            else:
                wallet = Wallet.objects.get(user=user)

            # Auto-login the user
            user = authenticate(username=wallet_data['public_key'], password=None)
            login(request, user)
            
            return JsonResponse({
                'message': 'Wallet imported successfully',
                'public_key': wallet.public_key,
                'address': wallet.address
            })
        else:
            return JsonResponse({'error': 'Invalid mnemonic phrase'}, status=400)
    return JsonResponse({'error': 'Only POST method allowed'}, status=400)

import threading

@csrf_exempt
@login_required

def generate_unique_hash():
    return hashlib.sha256(str(timezone.now()).encode('utf-8')).hexdigest()

def proof_of_work(last_hash):
    proof = 0
    while not valid_proof(last_hash, proof):
        proof += 1
    return proof

def valid_proof(last_hash, proof, difficulty=4):
    guess = f'{last_hash}{proof}'.encode()
    guess_hash = hashlib.sha256(guess).hexdigest()
    return guess_hash[:difficulty] == "0" * difficulty
    import threading
import time
import asyncio
import json
import hashlib
import requests
import threading
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from decimal import Decimal
from .models import Wallet, Transaction, Shard, Pool, PoolMember
from .utils import create_default_shard

mining_active = threading.Event()
mining_statistics = {
    "hashrate": 0,
    "blocks_mined": 0,
    "total_rewards": 0
}

@csrf_exempt
@login_required
def start_mining(request, shard_id):
    adapt_to_latency()  # Ensure protocol parameters are adapted before starting mining
    mining_active.set()  # Set the mining active flag
    threading.Thread(target=mine_blocks_continuously, args=(request.user, shard_id)).start()
    return JsonResponse({'message': 'Mining started'})


@csrf_exempt
@login_required
def stop_mining(request):
    mining_active.clear()  # Clear the mining active flag
    return JsonResponse({'message': 'Mining stopped'})
def mine_blocks_continuously(user, shard_id):
    global mining_statistics
    miners = get_miners()  # Fetch miners
    tasks = generate_tasks()
    efficient_task_allocation(miners, tasks)
    while mining_active.is_set():
        adapt_to_latency()  # Adapt protocol parameters based on latency
        start_time = time.time()
        mine_single_block(user, shard_id)
        end_time = time.time()
        elapsed_time = end_time - start_time
        if elapsed_time > 0:
            hashrate = 1 / elapsed_time
            mining_statistics["hashrate"] = hashrate
        time.sleep(0.0001)
        broadcast_pools()  # Broadcast updated pools after mining each block




from decimal import Decimal  # Ensure this import is at the top of your file





def generate_unique_hash():
    return hashlib.sha256(str(timezone.now()).encode('utf-8')).hexdigest()

def proof_of_work(last_hash):
    proof = 0
    while not valid_proof(last_hash, proof):
        proof += 1
    return proof

def valid_proof(last_hash, proof, difficulty=4):
    guess = f'{last_hash}{proof}'.encode()
    guess_hash = hashlib.sha256(guess).hexdigest()
    return guess_hash[:difficulty] == "0" * difficulty

def validate_transaction(transaction):
    # Check if the transaction has a valid signature
    if not transaction.signature:
        print(f"[ERROR] Transaction {transaction.hash} invalid: missing signature")
        return False

    # Ensure the sender has sufficient balance
    if transaction.sender.balance < (transaction.amount + transaction.fee):
        print(f"[ERROR] Transaction {transaction.hash} invalid: insufficient balance. Sender balance: {transaction.sender.balance}, Transaction amount: {transaction.amount}, Fee: {transaction.fee}")
        return False

    # Prevent double-spending by checking transaction hashes
    if Transaction.objects.filter(hash=transaction.hash, is_approved=True).exists():
        print(f"[ERROR] Transaction {transaction.hash} invalid: duplicate transaction")
        return False

    print(f"[DEBUG] Transaction {transaction.hash} is valid")
    return True


@csrf_exempt
@login_required
def get_mining_statistics(request):
    print("Fetching mining statistics:", mining_statistics)
    return JsonResponse(mining_statistics)

def get_active_nodes(master_node_url):
    try:
        response = requests.get(f"{master_node_url}/api/nodes/")
        response.raise_for_status()
        nodes = response.json()
        return nodes
    except requests.exceptions.RequestException as e:
        print(f"Error fetching nodes from master node: {e}")
        return []

def get_node_latest_transaction(node_url):
    try:
        response = requests.get(f"{node_url}/api/latest_transaction/")
        response.raise_for_status()
        latest_transaction = response.json()
        return latest_transaction
    except requests.exceptions.RequestException as e:
        print(f"Error fetching latest transaction from {node_url}: {e}")
        return None

def check_node_synchronization():
    master_node_url = "http://161.35.219.10:1010"
    nodes = get_active_nodes(master_node_url)

    if len(nodes) < 2:
        return {
            "is_synchronized": False,
            "message": "Not enough nodes to check synchronization",
            "nodes": nodes,
        }

    node1_url = nodes[0]['url']
    node2_url = nodes[1]['url']

    node1_latest_tx = get_node_latest_transaction(node1_url)
    node2_latest_tx = get_node_latest_transaction(node2_url)

    is_synchronized = node1_latest_tx == node2_latest_tx
    return {
        "is_synchronized": is_synchronized,
        "node1_latest_transaction": node1_latest_tx,
        "node2_latest_transaction": node2_latest_tx,
    }

@csrf_exempt
def get_network_status(request):
    sync_status = check_node_synchronization()
    return JsonResponse(sync_status)

@csrf_exempt
def create_transaction(request):
    if request.method == 'POST':
        try:
            sender_address = request.POST.get('sender')
            receiver_address = request.POST.get('receiver')
            amount = Decimal(request.POST.get('amount'))
            fee = Decimal(request.POST.get('fee'))

            if not sender_address or not receiver_address or not amount or not fee:
                return JsonResponse({'error': 'All fields (sender, receiver, amount, fee) are required'}, status=400)

            sender = Wallet.objects.get(address=sender_address)
            receiver = Wallet.objects.get(address=receiver_address)
            shard = Shard.objects.first()  # Assuming you have at least one shard

            if sender.balance < (amount + fee):
                return JsonResponse({'error': 'Insufficient balance'}, status=400)

            transaction = Transaction(
                sender=sender,
                receiver=receiver,
                amount=amount,
                fee=fee,
                timestamp=timezone.now(),
                shard=shard,
                is_approved=False  # Transaction starts as not approved
            )
            transaction.hash = transaction.create_hash()
            transaction.signature = "simulated_signature"  # You should replace this with actual signature logic
            transaction.save()

            # Attempt to approve the transaction immediately
            try:
                if validate_transaction(transaction):
                    approve_transaction(transaction)
                    message = 'Transaction created and approved'
                else:
                    message = 'Transaction created but not approved due to validation failure'
            except Exception as e:
                message = f'Transaction created but approval failed: {str(e)}'

            return JsonResponse({'message': message, 'transaction_hash': transaction.hash})

        except Wallet.DoesNotExist:
            return JsonResponse({'error': 'Wallet not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Only POST method allowed'}, status=400)

def approve_transaction(transaction):
    if transaction.is_approved:
        print(f"[INFO] Transaction {transaction.hash} is already approved")
        return  # If the transaction is already approved, do nothing

    if transaction.sender.balance < (transaction.amount + transaction.fee):
        print(f"[ERROR] Insufficient balance to approve transaction {transaction.hash}. Sender balance: {transaction.sender.balance}, Amount: {transaction.amount}, Fee: {transaction.fee}")
        raise ValueError("Insufficient balance to approve transaction")

    transaction.is_approved = True
    transaction.save()

    # Update balances
    transaction.sender.balance -= (transaction.amount + transaction.fee)
    transaction.sender.save()

    transaction.receiver.balance += transaction.amount
    transaction.receiver.save()

    print(f"[INFO] Transaction {transaction.hash} approved successfully")
    return transaction


def join_pool_api(pool_url, user):
  if not pool_url:
    raise ValidationError("Pool URL cannot be empty.")

  try:
    response = requests.post(pool_url, data={'user_id': user.id})
    response.raise_for_status()  # Raise exception for non-200 status codes
    return True
  except requests.exceptions.RequestException as e:
    print(f"Error connecting to pool server: {e}")
    return False
  except requests.exceptions.HTTPError as e:
    print(f"Pool server responded with error: {e}")
    return False
  except Exception as e:  # Catch unexpected exceptions as last resort
    print(f"Unexpected error joining pool: {e}")
    return False


@csrf_exempt
@login_required
def create_pool(request):
    if request.method == 'POST':
        pool_name = request.POST.get('name')
        if not pool_name:
            return JsonResponse({'error': 'Pool name is required'}, status=400)
        
        print(f"Received pool name: {pool_name}")  # Debugging statement
        host = request.user
        try:
            pool = Pool.objects.create(name=pool_name, host=host)
            print(f"Created pool with ID: {pool.id}")  # Debugging statement
            PoolMember.objects.create(pool=pool, user=host)
            print(f"Host {host} added as a member to the pool")  # Debugging statement
            return JsonResponse({'message': 'Pool created', 'pool_id': str(pool.id)})
        except IntegrityError as e:
            print(f"Error creating pool: {str(e)}")  # Debugging statement
            return JsonResponse({'error': f'Error creating pool: {str(e)}'}, status=500)
        except Exception as e:
            print(f"Unexpected error: {str(e)}")  # Debugging statement
            return JsonResponse({'error': f'Unexpected error: {str(e)}'}, status=500)

    # Query top 10 pools based on number of users, hashrate, and rewards
    top_pools = Pool.objects.annotate(
        num_users=models.Count('poolmember')
    ).order_by('-num_users', '-hashrate', '-rewards')[:10]

    # Render the template with the top pools data
    return render(request, 'index.html', {'top_pools': top_pools})





from django.http import JsonResponse
from django.db import IntegrityError
from quantumapp.models import Pool, PoolMember
@login_required
def join_pool(request, pool_id):
    print("---- join_pool view called ----")
    print(f"Request method: {request.method}")
    print(f"Pool ID: {pool_id}")
    print(f"User authenticated: {request.user.is_authenticated}")
    print(f"Pool ID in URL: {pool_id}")
    print(f"Request POST data: {request.POST}")

    if not request.user.is_authenticated:
        print('User must be logged in to join a pool')
        return JsonResponse({'error': 'User must be logged in to join a pool'}, status=403)

    if request.method == 'POST':
        try:
            pool = Pool.objects.get(id=pool_id)
            print(f"Pool found: {pool}")
            print(f"Creating PoolMember for user {request.user}")
            PoolMember.objects.create(pool=pool, user=request.user)
            print(f"User {request.user} joined pool {pool_id}")
            return JsonResponse({'message': 'Joined pool', 'pool_id': str(pool.id)})
        except Pool.DoesNotExist:
            print(f"Pool with ID {pool_id} not found")
            return JsonResponse({'error': 'Pool not found'}, status=404)
        except IntegrityError as e:
            print(f"IntegrityError while joining pool: {e}")  # Catch potential integrity errors
            return JsonResponse({'error': 'Failed to join pool. Please try again.'}, status=500)
        except Exception as e:
            print(f"Unexpected error: {e}")
            return JsonResponse({'error': 'An unexpected error occurred. Please try again later.'}, status=500)
    else:
        print('Only POST method allowed')
        return JsonResponse({'error': 'Only POST method allowed'}, status=400)


from django.db import models
# views.py
# views.py

from django.shortcuts import render, redirect
from .models import Contract, Wallet, Pool
from .forms import ContractForm
from django.db import models
import os 
from django.conf import settings  # Import the settings module
def home(request):
    contract, created = Contract.objects.get_or_create(
        pk=1, 
        defaults={
            'address': '',  
            'abi': '[]'
        }
    )

    if request.method == 'POST':
        form = ContractForm(request.POST, instance=contract)
        if form.is_valid():
            form.save()
            return redirect('deploy_contract')
    else:
        form = ContractForm(instance=contract)

    # Handle transaction creation if form is submitted
    if request.method == 'POST' and 'create_transaction' in request.POST:
        try:
            sender_address = request.POST.get('sender')
            receiver_address = request.POST.get('receiver')
            amount = Decimal(request.POST.get('amount'))
            fee = Decimal(request.POST.get('fee'))

            if not sender_address or not receiver_address or not amount or not fee:
                return JsonResponse({'error': 'All fields (sender, receiver, amount, fee) are required'}, status=400)

            sender = Wallet.objects.get(address=sender_address)
            receiver = Wallet.objects.get(address=receiver_address)
            shard = Shard.objects.first()  # Assuming you have at least one shard

            if sender.balance < (amount + fee):
                return JsonResponse({'error': 'Insufficient balance'}, status=400)

            transaction = Transaction(
                sender=sender,
                receiver=receiver,
                amount=amount,
                fee=fee,
                timestamp=timezone.now(),
                shard=shard,
                is_approved=False  # Transaction starts as not approved
            )
            transaction.hash = transaction.create_hash()
            transaction.signature = "simulated_signature"  # You should replace this with actual signature logic
            transaction.save()

            # Attempt to approve the transaction immediately
            try:
                if validate_transaction(transaction):
                    approve_transaction(transaction)
                    message = 'Transaction created and approved'
                else:
                    message = 'Transaction created but not approved due to validation failure'
            except Exception as e:
                message = f'Transaction created but approval failed: {str(e)}'

            return JsonResponse({'message': message, 'transaction_hash': transaction.hash})

        except Wallet.DoesNotExist:
            return JsonResponse({'error': 'Wallet not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    wallets = Wallet.objects.all()
    context = {
        'form': form,
        'wallets': wallets,
    }

    return render(request, 'index.html', context)

def deploy_contract(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        token_name = data.get('name')
        token_symbol = data.get('symbol')
        initial_supply = data.get('initialSupply')
        enable_liquidity_pool = data.get('enableLiquidityPool')
        use_native_token = data.get('useNativeToken')
        token_pair1 = data.get('tokenPair1')
        token_pair2 = data.get('tokenPair2')
        token1_amount = data.get('token1Amount')
        token2_amount = data.get('token2Amount')

        if not initial_supply:
            return JsonResponse({'error': 'Initial supply is required.'}, status=400)

        initial_supply = int(initial_supply)

        try:
            abi, bytecode = compile_contract('MyToken.sol', 'MyToken')

            # Connect to local Ethereum node
            w3 = Web3(Web3.HTTPProvider('http://159.89.106.101:8545'))
            if not w3.is_connected():
                logger.error('Could not connect to Ethereum node.')
                return JsonResponse({'error': 'Could not connect to Ethereum node.'}, status=500)

            accounts = w3.eth.accounts
            if not accounts:
                logger.error('No Ethereum accounts available.')
                return JsonResponse({'error': 'No Ethereum accounts available.'}, status=500)

            w3.eth.default_account = accounts[0]

            # Create web3 contract instance
            Web3Contract = w3.eth.contract(abi=abi, bytecode=bytecode)

            # Deploy contract
            initial_owner = w3.eth.default_account  # Set the initial owner to the default account
            tx_hash = Web3Contract.constructor(token_name, token_symbol, initial_supply, initial_owner).transact({'from': w3.eth.default_account})
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            logger.info(f"Contract deployed at address: {tx_receipt.contractAddress}")

            # Save contract details in the database
            Contract.objects.create(
                address=tx_receipt.contractAddress,
                abi=json.dumps(abi)
            )

            response_data = {
                'deployed': True,
                'contract_address': tx_receipt.contractAddress
            }

            if enable_liquidity_pool and token1_amount and token2_amount:
                if use_native_token:
                    token_pair2 = '0x0000000000000000000000000000000000000000'  # Native token address
                # Deploy the liquidity pool smart contract
                liquidity_pool_address = deploy_liquidity_pool(tx_receipt.contractAddress, token_pair1, token_pair2, token1_amount, token2_amount)
                response_data['liquidity_pool_address'] = liquidity_pool_address

            return JsonResponse(response_data)
        except Exception as e:
            logger.error(f"Error deploying contract: {str(e)}")
            return JsonResponse({'error': f'Error deploying contract: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Invalid request method.'}, status=400)

def deploy_erc20_token(token_name, token_symbol, initial_supply):
    # Connect to local Ethereum node
    w3 = Web3(Web3.HTTPProvider('http://159.89.106.101:8545'))

    # Check if connected
    if not w3.is_connected():
        raise Exception('Could not connect to Ethereum node.')

    # Load compiled ERC20 contract
    compiled_contract_path = os.path.join(settings.BASE_DIR, 'my-token-project/artifacts/contracts/MyToken.sol/MyToken.json')
    if not os.path.exists(compiled_contract_path):
        raise Exception('Compiled contract file not found.')

    with open(compiled_contract_path) as f:
        compiled_contract = json.load(f)
    
    abi = compiled_contract['abi']
    bytecode = compiled_contract['bytecode']

    # Get default account for deployment
    w3.eth.default_account = w3.eth.accounts[0]

    # Create web3 contract instance
    Web3Contract = w3.eth.contract(abi=abi, bytecode=bytecode)

    # Deploy contract
    try:
        initial_owner = w3.eth.default_account  # Set the initial owner to the default account
        tx_hash = Web3Contract.constructor(token_name, token_symbol, initial_supply, initial_owner).transact({'from': w3.eth.default_account})
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_receipt.contractAddress
    except Exception as e:
        raise Exception(f"Error deploying ERC20 contract: {str(e)}")
def compile_contract(contract_path, contract_name):
    compile_command = ['npx', 'hardhat', 'compile']
    result = subprocess.run(compile_command, cwd=os.path.join(settings.BASE_DIR, 'my-token-project'), capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f"Compilation failed: {result.stderr}")
        raise Exception(f"Compilation failed: {result.stderr}")

    compiled_contract_path = os.path.join(settings.BASE_DIR, f'my-token-project/artifacts/contracts/{contract_path}/{contract_name}.json')
    if not os.path.exists(compiled_contract_path):
        logger.error('Compiled contract file not found.')
        raise Exception('Compiled contract file not found.')

    with open(compiled_contract_path) as f:
        compiled_contract = json.load(f)
    
    return compiled_contract['abi'], compiled_contract['bytecode']
def deploy_liquidity_pool(token_address, token_pair1, token_pair2, token1_amount, token2_amount):
    # Load and compile the liquidity pool contract
    compile_command = ['npx', 'hardhat', 'compile']
    result = subprocess.run(compile_command, cwd=os.path.join(settings.BASE_DIR, 'my-token-project'), capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f"Compilation failed: {result.stderr}")
        raise Exception(f"Compilation failed: {result.stderr}")

    compiled_contract_path = os.path.join(settings.BASE_DIR, 'my-token-project/artifacts/contracts/LiquidityPool.sol/LiquidityPool.json')
    if not os.path.exists(compiled_contract_path):
        logger.error('Compiled contract file not found.')
        raise Exception('Compiled contract file not found.')

    with open(compiled_contract_path) as f:
        compiled_contract = json.load(f)

    abi = compiled_contract['abi']
    bytecode = compiled_contract['bytecode']

    # Get default account for deployment
    w3 = Web3(Web3.HTTPProvider(GETH_NODE_URL))
    w3.eth.default_account = w3.eth.accounts[0]

    # Create web3 contract instance
    Web3Contract = w3.eth.contract(abi=abi, bytecode=bytecode)

    # Deploy the liquidity pool contract
    try:
        tx_hash = Web3Contract.constructor(token_address, token_pair1, token_pair2).transact({'from': w3.eth.default_account, 'gas': 3000000})
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        logger.info(f"Liquidity Pool Contract deployed at address: {tx_receipt.contractAddress}")
        return tx_receipt.contractAddress
    except Exception as e:
        logger.error(f"Error deploying liquidity pool contract: {str(e)}")
        raise Exception(f"Error deploying liquidity pool contract: {str(e)}")



def get_wallet_aliases(request):
    wallets = Wallet.objects.all()
    aliases = [{'alias': wallet.alias, 'public_key': wallet.public_key} for wallet in wallets]
    return JsonResponse({'aliases': aliases})

def dashboard(request):
    return render(request, 'dashboard.html')
    from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import Wallet, CustomToken
from django.core.paginator import Paginator

@login_required
def get_wallet_details(request):
    try:
        wallet_address = request.user.wallet.address  # Adjust according to how you store the user's wallet
        wallet = Wallet.objects.get(address=wallet_address)

        transactions_sent = Transaction.objects.filter(sender=wallet, is_approved=True)
        transactions_received = Transaction.objects.filter(receiver=wallet, is_approved=True)
        custom_tokens = CustomToken.objects.filter(wallet=wallet)
        liquidity_pools = Contract.objects.filter(wallet=wallet, contract_type='liquidity_pool')  # Assuming you have a contract_type field

        # Calculate balance based on transactions
        balance = sum(tx.amount for tx in transactions_received) - sum(tx.amount + tx.fee for tx in transactions_sent)

        # Pagination parameters
        page_number = request.GET.get('page', 1)
        page_size = 20

        # Combine sent and received transactions
        transactions = transactions_sent.union(transactions_received).order_by('-timestamp')
        paginator = Paginator(transactions, page_size)
        page_obj = paginator.get_page(page_number)

        transactions_data = [{
            'hash': tx.hash,
            'sender': tx.sender.address,
            'receiver': tx.receiver.address,
            'amount': str(tx.amount),
            'fee': str(tx.fee),
            'timestamp': tx.timestamp.isoformat(),
            'is_approved': tx.is_approved,
            'shard': tx.shard.name
        } for tx in page_obj]

        custom_tokens_data = [{
            'address': token.address,
            'name': token.name,
            'symbol': token.symbol,
            'balance': str(token.balance),
        } for token in custom_tokens]

        liquidity_pools_data = [{
            'address': pool.address,
            'abi': pool.abi,
        } for pool in liquidity_pools]

        wallet_data = {
            'alias': wallet.alias or 'N/A',
            'address': wallet.address,
            'public_key': wallet.public_key or 'N/A',
            'balance': str(balance),
            'transactions': transactions_data,
            'custom_tokens': custom_tokens_data,
            'liquidity_pools': liquidity_pools_data,
            'total_pages': paginator.num_pages,
            'current_page': page_obj.number,
        }

        return JsonResponse(wallet_data)

    except Wallet.DoesNotExist:
        return JsonResponse({'error': 'Wallet not found'}, status=404)
    except Exception as e:
        print(f"Error while fetching wallet details: {e}")
        return JsonResponse({'error': 'An error occurred while fetching the wallet details'}, status=500)



from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from .network_utils import receive_transaction  # Import the function

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from .encryption_utils import receive_secure_transaction  # Import the function

@csrf_exempt
@login_required
def receive_transaction_view(request):
    return receive_secure_transaction(request)
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Transaction

@csrf_exempt
def get_latest_transaction(request):
    try:
        latest_transaction = Transaction.objects.latest('timestamp')
        return JsonResponse({
            'hash': latest_transaction.hash,
            'sender': latest_transaction.sender.address,
            'receiver': latest_transaction.receiver.address,
            'amount': latest_transaction.amount,
            'fee': latest_transaction.fee,
            'timestamp': latest_transaction.timestamp,
            'is_approved': latest_transaction.is_approved,
            'shard': latest_transaction.shard.name
        })
    except Transaction.DoesNotExist:
        return JsonResponse({'error': 'No transactions found'}, status=404)

@csrf_exempt
def get_transaction_pool(request):
    transactions = Transaction.objects.filter(is_approved=False)
    transactions_list = [
        {
            'hash': transaction.hash,
            'sender': transaction.sender.address,
            'receiver': transaction.receiver.address,
            'amount': transaction.amount,
            'fee': transaction.fee,
            'timestamp': transaction.timestamp,
            'is_approved': transaction.is_approved,
            'shard': transaction.shard.name
        } for transaction in transactions
    ]
    return JsonResponse({'transaction_pool': transactions_list})
import requests
from django.http import JsonResponse
def get_node_status(node_url):
    try:
        latest_tx_response = requests.get(f"{node_url}/api/latest_transaction/")
        tx_pool_response = requests.get(f"{node_url}/api/transaction_pool/")
        
        latest_tx_response.raise_for_status()
        tx_pool_response.raise_for_status()
        
        latest_tx = latest_tx_response.json()
        tx_pool = tx_pool_response.json()
        
        return latest_tx, tx_pool
    except requests.exceptions.RequestException as e:
        print(f"Error fetching node status: {e}")
        return None, None

def check_node_synchronization():
    node_urls = get_all_nodes()  # Fetch the list of all node URLs from the master node
    if len(node_urls) < 2:
        return {
            "is_synchronized": False,
            "message": "Not enough nodes to check synchronization"
        }

    node1_url, node2_url = node_urls[:2]  # Just compare the first two nodes for simplicity

    node1_latest_tx, node1_tx_pool = get_node_status(node1_url)
    node2_latest_tx, node2_tx_pool = get_node_status(node2_url)

    is_synchronized = node1_latest_tx == node2_latest_tx

    return {
        "is_synchronized": is_synchronized,
        "node1_latest_transaction": node1_latest_tx,
        "node2_latest_transaction": node2_latest_tx,
        "node1_transaction_pool": node1_tx_pool,
        "node2_transaction_pool": node2_tx_pool
    }

def get_network_status(request):
    node1_url = "http://161.35.219.10:1010"
    node2_url = "http://161.35.219.10:1010"

    node1_latest_tx, node1_tx_pool = get_node_status(node1_url)
    node2_latest_tx, node2_tx_pool = get_node_status(node2_url)

    return JsonResponse({
        'node1': {
            'latest_transaction': node1_latest_tx,
            'transaction_pool': node1_tx_pool
        },
        'node2': {
            'latest_transaction': node2_latest_tx,
            'transaction_pool': node2_tx_pool
        }
    })
from django.http import JsonResponse
from .models import Transaction

def latest_transaction(request):
    latest_tx = Transaction.objects.order_by('-timestamp').first()
    if latest_tx:
        latest_tx_data = {
            'hash': latest_tx.hash,
            'sender': latest_tx.sender.address,
            'receiver': latest_tx.receiver.address,
            'amount': latest_tx.amount,
            'fee': latest_tx.fee,
            'timestamp': latest_tx.timestamp.isoformat()
        }
        return JsonResponse(latest_tx_data)
    return JsonResponse({'error': 'No transactions found'}, status=404)

def transaction_pool(request):
    tx_pool = Transaction.objects.filter(is_approved=False)
    tx_pool_data = [
        {
            'hash': tx.hash,
            'sender': tx.sender.address,
            'receiver': tx.receiver.address,
            'amount': tx.amount,
            'fee': tx.fee,
            'timestamp': tx.timestamp.isoformat()
        }
        for tx in tx_pool
    ]
    return JsonResponse(tx_pool_data, safe=False)
def get_node_latest_transaction(node_url):
    try:
        response = requests.get(f"{node_url}/api/latest_transaction/")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching latest transaction from {node_url}: {e}")
        return None

def get_network_synchronization_status(request):
    sync_status = check_node_synchronization()
    return JsonResponse(sync_status)
def get_node_latest_transaction(node_url):
    try:
        response = requests.get(f"{node_url}/api/latest_transaction/")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching latest transaction from {node_url}: {e}")
        return None

def fetch_node_ips(master_node_url):
    try:
        response = requests.get(f"{master_node_url}/api/nodes/")
        response.raise_for_status()
        return response.json().get('nodes', [])
    except requests.RequestException as e:
        print(f"Error fetching nodes from master node: {e}")
        return []

def network_synchronization_status(request):
    sync_status = check_node_synchronization()
    return JsonResponse(sync_status)
import requests
from django.http import JsonResponse
def get_active_nodes(master_node_url):
    try:
        response = requests.get(f"{master_node_url}/api/nodes/")
        response.raise_for_status()
        nodes = response.json().get('nodes', [])
        return nodes
    except requests.exceptions.RequestException as e:
        print(f"Error fetching nodes from master node: {e}")
        return []

def get_node_latest_transaction(node_url):
    try:
        response = requests.get(f"{node_url}/api/latest_transaction/")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching latest transaction from {node_url}: {e}")
        return None


def check_node_synchronization():
    master_node_url = "http://161.35.219.10:1010"
    nodes = get_active_nodes(master_node_url)

    if len(nodes) < 2:
        return {
            "is_synchronized": False,
            "message": "Not enough nodes to check synchronization",
            "nodes": nodes,
        }

    node1_url = nodes[0]['url']
    node2_url = nodes[1]['url']

    node1_latest_tx = get_node_latest_transaction(node1_url)
    node2_latest_tx = get_node_latest_transaction(node2_url)

    is_synchronized = node1_latest_tx == node2_latest_tx
    return {
        "is_synchronized": is_synchronized,
        "node1_latest_transaction": node1_latest_tx,
        "node2_latest_transaction": node2_latest_tx,
    }

def get_network_status(request):
    sync_status = check_node_synchronization()
    return JsonResponse(sync_status)
def get_node_transaction_pool(node_url):
    try:
        response = requests.get(f"{node_url}/api/transaction_pool/")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching transaction pool from {node_url}: {e}")
        return None
def check_node_synchronization():
    master_node_url = "http://161.35.219.10:1010"
    nodes = get_active_nodes(master_node_url)

    if len(nodes) < 2:
        return {
            "is_synchronized": False,
            "message": "Not enough nodes to check synchronization",
            "nodes": nodes,
        }

    node1_url = nodes[0]
    node2_url = nodes[1]

    node1_latest_tx = get_node_latest_transaction(node1_url)
    node1_tx_pool = get_node_transaction_pool(node1_url)
    node2_latest_tx = get_node_latest_transaction(node2_url)
    node2_tx_pool = get_node_transaction_pool(node2_url)

    is_synchronized = node1_latest_tx == node2_latest_tx
    return {
        "is_synchronized": is_synchronized,
        "node1_latest_transaction": node1_latest_tx,
        "node1_transaction_pool": node1_tx_pool,
        "node2_latest_transaction": node2_latest_tx,
        "node2_transaction_pool": node2_tx_pool,
    }

@csrf_exempt
def get_network_status(request):
    sync_status = check_node_synchronization()
    return JsonResponse(sync_status)
import requests
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

def get_active_nodes(master_node_url):
    try:
        response = requests.get(f"{master_node_url}/api/nodes/")
        response.raise_for_status()
        nodes = response.json().get('nodes', [])
        print(f"Active nodes fetched: {nodes}")  # Debug statement
        return nodes
    except requests.exceptions.RequestException as e:
        print(f"Error fetching nodes from master node: {e}")
        return []

def get_node_latest_transaction(node_url):
    try:
        response = requests.get(f"{node_url}/api/latest_transaction/")
        response.raise_for_status()
        latest_transaction = response.json()
        print(f"Latest transaction from {node_url}: {latest_transaction}")  # Debug statement
        return latest_transaction
    except requests.RequestException as e:
        print(f"Error fetching latest transaction from {node_url}: {e}")
        return None

def get_node_transaction_pool(node_url):
    try:
        response = requests.get(f"{node_url}/api/transaction_pool/")
        response.raise_for_status()
        transaction_pool = response.json()
        print(f"Transaction pool from {node_url}: {transaction_pool}")  # Debug statement
        return transaction_pool
    except requests.RequestException as e:
        print(f"Error fetching transaction pool from {node_url}: {e}")
        return None

def check_node_synchronization():
    master_node_url = "http://161.35.219.10:1010"
    nodes = get_active_nodes(master_node_url)

    if len(nodes) < 2:
        return {
            "is_synchronized": False,
            "message": "Not enough nodes to check synchronization",
            "nodes": nodes,
        }

    node1_url = nodes[0]
    node2_url = nodes[1]

    node1_latest_tx = get_node_latest_transaction(node1_url)
    node1_tx_pool = get_node_transaction_pool(node1_url)
    node2_latest_tx = get_node_latest_transaction(node2_url)
    node2_tx_pool = get_node_transaction_pool(node2_url)

    is_synchronized = node1_latest_tx == node2_latest_tx
    return {
        "is_synchronized": is_synchronized,
        "node1_latest_transaction": node1_latest_tx,
        "node1_transaction_pool": node1_tx_pool,
        "node2_latest_transaction": node2_latest_tx,
        "node2_transaction_pool": node2_tx_pool,
    }

@csrf_exempt
def get_network_status(request):
    sync_status = check_node_synchronization()
    print(f"Synchronization status: {sync_status}")  # Debug statement
    return JsonResponse(sync_status)
import requests
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

def get_active_nodes(master_node_url):
    try:
        response = requests.get(f"{master_node_url}/api/nodes/")
        response.raise_for_status()
        nodes = response.json().get('nodes', [])
        print(f"Active nodes fetched: {nodes}")  # Debug statement
        return nodes
    except requests.exceptions.RequestException as e:
        print(f"Error fetching nodes from master node: {e}")
        return []

def get_node_latest_transaction(node_url):
    try:
        response = requests.get(f"{node_url}/api/latest_transaction/")
        response.raise_for_status()
        latest_transaction = response.json()
        print(f"Latest transaction from {node_url}: {latest_transaction}")  # Debug statement
        return latest_transaction
    except requests.RequestException as e:
        print(f"Error fetching latest transaction from {node_url}: {e}")
        return None

def get_node_transaction_pool(node_url):
    try:
        response = requests.get(f"{node_url}/api/transaction_pool/")
        response.raise_for_status()
        transaction_pool = response.json()
        print(f"Transaction pool from {node_url}: {transaction_pool}")  # Debug statement
        return transaction_pool
    except requests.RequestException as e:
        print(f"Error fetching transaction pool from {node_url}: {e}")
        return None

def check_node_synchronization():
    master_node_url = "http://161.35.219.10:1010"
    nodes = get_active_nodes(master_node_url)

    if len(nodes) < 2:
        return {
            "is_synchronized": False,
            "message": "Not enough nodes to check synchronization",
            "nodes": nodes,
        }

    node1_url = nodes[0]
    node2_url = nodes[1]

    node1_latest_tx = get_node_latest_transaction(node1_url)
    node1_tx_pool = get_node_transaction_pool(node1_url)
    node2_latest_tx = get_node_latest_transaction(node2_url)
    node2_tx_pool = get_node_transaction_pool(node2_url)

    is_synchronized = node1_latest_tx == node2_latest_tx
    return {
        "is_synchronized": is_synchronized,
        "node1_latest_transaction": node1_latest_tx,
        "node1_transaction_pool": node1_tx_pool,
        "node2_latest_transaction": node2_latest_tx,
        "node2_transaction_pool": node2_tx_pool,
    }

@csrf_exempt
def get_network_status(request):
    sync_status = check_node_synchronization()
    print(f"Synchronization status: {sync_status}")  # Debug statement
    return JsonResponse(sync_status)
NODE_URLS = [
    "http://161.35.219.10:1010",  # Node 1 URL
    "http://161.35.219.10:2020"   # Node 2 URL (example URL, replace with actual)
]

def get_node_latest_transaction(node_url):
    try:
        response = requests.get(f"{node_url}/api/latest_transaction/")
        response.raise_for_status()
        latest_transaction = response.json()
        print(f"Latest transaction from {node_url}: {latest_transaction}")  # Debug statement
        return latest_transaction
    except requests.RequestException as e:
        print(f"Error fetching latest transaction from {node_url}: {e}")
        return None

def get_node_transaction_pool(node_url):
    try:
        response = requests.get(f"{node_url}/api/transaction_pool/")
        response.raise_for_status()
        transaction_pool = response.json()
        print(f"Transaction pool from {node_url}: {transaction_pool}")  # Debug statement
        return transaction_pool
    except requests.RequestException as e:
        print(f"Error fetching transaction pool from {node_url}: {e}")
        return None

def check_node_synchronization():
    if len(NODE_URLS) < 2:
        return {
            "is_synchronized": False,
            "message": "Not enough nodes to check synchronization",
            "nodes": NODE_URLS,
        }

    node1_url = NODE_URLS[0]
    node2_url = NODE_URLS[1]

    node1_latest_tx = get_node_latest_transaction(node1_url)
    node1_tx_pool = get_node_transaction_pool(node1_url)
    node2_latest_tx = get_node_latest_transaction(node2_url)
    node2_tx_pool = get_node_transaction_pool(node2_url)

    is_synchronized = node1_latest_tx == node2_latest_tx
    return {
        "is_synchronized": is_synchronized,
        "node1_latest_transaction": node1_latest_tx,
        "node1_transaction_pool": node1_tx_pool,
        "node2_latest_transaction": node2_latest_tx,
        "node2_transaction_pool": node2_tx_pool,
    }

@csrf_exempt
def get_network_status(request):
    sync_status = check_node_synchronization()
    print(f"Synchronization status: {sync_status}")  # Debug statement
    return JsonResponse(sync_status)
from django.db.models import Count

def get_top_pools():
    return Pool.objects.annotate(
        num_users=Count('poolmember')
    ).order_by('-num_users', '-hashrate', '-rewards')[:10]
def update_pools():
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        "pools", {
            "type": "broadcast_pools",
        }
    )
def broadcast_pools():
    top_pools = Pool.objects.annotate(
        num_users=models.Count('poolmember')
    ).order_by('-num_users', '-hashrate', '-rewards')[:10]
    
    global mining_statistics  # Use global statistics
    pools_data = [{
        'id': str(pool.id),
        'name': pool.name,
        'num_users': pool.num_users,
        'hashrate': mining_statistics['hashrate'],  # Use the global hashrate here
        'rewards': mining_statistics['total_rewards']  # Use the global total_rewards here
    } for pool in top_pools]
    
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        "pools", {
            "type": "broadcast_pools",
            "pools": pools_data
        }
    )
    print("Broadcasted pools data:", pools_data)


class Block:
    def __init__(self, hash, previous_hash, timestamp):
        self.hash = hash
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.children = []

def order_blocks(dag):
    ordered_blocks = []
    visited = set()

    def dfs(block):
        if block in visited:
            return
        visited.add(block)
        for child in block.children:
            dfs(child)
        ordered_blocks.append(block)

    for block in dag.values():
        if block.previous_hash == '0' * 64:  # Assuming '0'*64 is the genesis block's previous_hash
            dfs(block)

    return ordered_blocks

def select_well_connected_subset(dag):
    max_subset = []
    visited = set()

    def dfs(block, current_subset):
        current_subset.append(block)
        visited.add(block)
        for child in block.children:
            if child not in visited:
                dfs(child, current_subset)

    for block in dag.values():
        if block.previous_hash == '0' * 64:
            current_subset = []
            dfs(block, current_subset)
            if len(current_subset) > len(max_subset):
                max_subset = current_subset

    return max_subset
dag = {}

def initialize_dag():
    # Initialize DAG with genesis block or any pre-existing blocks
    genesis_block = Block(hash='0'*64, previous_hash=None, timestamp=timezone.now())
    dag[genesis_block.hash] = genesis_block
    # Add any other pre-existing blocks if necessary

initialize_dag()
def update_pool_statistics():
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        "pools", {
            "type": "broadcast_pools",
        }
    )
def broadcast_pools():
    top_pools = Pool.objects.annotate(
        num_users=models.Count('poolmember')
    ).order_by('-num_users', '-hashrate', '-rewards')[:10]
    
    global mining_statistics  # Use global statistics
    pools_data = [{
        'id': str(pool.id),
        'name': pool.name,
        'num_users': pool.num_users,
        'hashrate': mining_statistics['hashrate'],  # Use the global hashrate here
        'rewards': mining_statistics['total_rewards']  # Use the global total_rewards here
    } for pool in top_pools]
    
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        "pools", {
            "type": "broadcast_pools",
            "pools": pools_data
        }
    )
    print("Broadcasted pools data:", pools_data)

import random

class Task:
    def __init__(self, task_id, difficulty, resource_requirement):
        self.task_id = task_id
        self.difficulty = difficulty
        self.resource_requirement = resource_requirement

def generate_tasks(num_tasks=10):
    """
    Generate NAS tasks or mining tasks with varying difficulty and resource requirements.
    """
    tasks = []
    for i in range(num_tasks):
        task_id = f"task_{i}"
        difficulty = random.choice(['easy', 'medium', 'hard'])
        resource_requirement = random.randint(1, 10)
        tasks.append(Task(task_id, difficulty, resource_requirement))
    return tasks

def select_task_for_miner(miner, tasks):
    """
    Select appropriate task for a miner based on miner's capabilities.
    """
    suitable_tasks = [task for task in tasks if task.resource_requirement <= miner.resource_capability]
    if suitable_tasks:
        selected_task = random.choice(suitable_tasks)
        tasks.remove(selected_task)
        return selected_task
    else:
        return None

def assign_tasks_to_miners(miners):
    """
    Assign tasks to miners based on their capabilities.
    """
    tasks = generate_tasks()  # Generate NAS tasks or mining tasks
    for miner in miners:
        task = select_task_for_miner(miner, tasks)  # Select appropriate task for the miner
        if task:
            miner.assign_task(task)  # Assign the task to the miner
        else:
            print(f"No suitable tasks available for miner {miner.id}")


 

def adjust_tasks_for_miner(miner, performance):
    """
    Adjust tasks for a miner based on their performance.
    """
    if performance < 0.5:
        task = get_easier_task()
    else:
        task = get_harder_task()
    miner.assign_task(task)

def get_easier_task():
    return Task("easy_task", "easy", 2)

def get_harder_task():
    return Task("hard_task", "hard", 8)
from collections import deque

def efficient_task_allocation(miners, tasks):
    """
    Implement efficient task allocation strategy.
    """
    task_queue = deque(tasks)
    for miner in miners:
        if task_queue:
            task = select_task_for_miner(miner, task_queue)
            if task:
                miner.assign_task(task)
        else:
            break
def record_miner_contribution(miner, task):
    """
    Record miner's contribution.
    """
    contribution = calculate_contribution(miner, task)
    miner.add_contribution(contribution)

def calculate_contribution(miner, task):
    """
    Calculate miner's contribution based on task completion.
    """
    # Implement the logic to calculate the contribution.
    # For simplicity, let's assume the contribution is based on task difficulty.
    difficulty_scores = {"easy": 1, "medium": 2, "hard": 3}
    return difficulty_scores.get(task.difficulty, 0)  # Default to 0 if difficulty not found

def evaluate_miner_performance(miner):
    """
    Evaluate miner's performance based on various metrics.
    """
    # Example metrics for performance evaluation:
    # - Past contributions
    # - Task completion speed
    # - Efficiency (tasks completed vs. tasks assigned)
    
    # For demonstration, let's assume we have these metrics as attributes of the miner
    past_contributions = miner.contribution  # Total past contributions
    task_completion_speed = random.uniform(0.5, 1.5)  # Random value to simulate speed
    efficiency = random.uniform(0.5, 1.0)  # Random value to simulate efficiency
    
    # Combine these metrics into a performance score
    performance_score = (past_contributions * 0.5) + (task_completion_speed * 0.3) + (efficiency * 0.2)
    
    # Normalize the performance score to be between 0 and 1
    max_possible_score = (max_past_contributions * 0.5) + (1.5 * 0.3) + (1.0 * 0.2)
    normalized_performance_score = performance_score / max_possible_score
    
    return normalized_performance_score

# Define a maximum value for past contributions for normalization purposes
max_past_contributions = 100  # This can be adjusted based on the application context

def distribute_rewards(miners, total_reward):
    """
    Distribute rewards among miners based on their contributions.
    """
    total_contribution = sum(miner.contribution for miner in miners)
    for miner in miners:
        miner_reward = (miner.contribution / total_contribution) * total_reward
        miner.add_reward(miner_reward)
def evaluate_miner_performance(miner):
    """
    Evaluate miner's performance based on various metrics.
    """
    # Example metrics for performance evaluation:
    # - Past contributions
    # - Task completion speed
    # - Efficiency (tasks completed vs. tasks assigned)
    
    # Fetch real-world data for the miner
    past_contributions = miner.contribution  # Total past contributions from the miner
    task_completion_times = miner.task_completion_times  # List of task completion times
    tasks_assigned = miner.tasks_assigned  # Total tasks assigned to the miner
    tasks_completed = miner.tasks_completed  # Total tasks completed by the miner

    # Calculate the average task completion speed
    if tasks_completed > 0:
        average_completion_speed = sum(task_completion_times) / len(task_completion_times)
    else:
        average_completion_speed = float('inf')  # Default to a high value if no tasks completed

    # Calculate efficiency
    if tasks_assigned > 0:
        efficiency = tasks_completed / tasks_assigned
    else:
        efficiency = 0

    # Combine these metrics into a performance score
    performance_score = (past_contributions * 0.5) + ((1 / average_completion_speed) * 0.3) + (efficiency * 0.2)

    # Normalize the performance score to be between 0 and 1
    max_possible_score = (max_past_contributions * 0.5) + (1 * 0.3) + (1 * 0.2)
    normalized_performance_score = performance_score / max_possible_score
    
    return normalized_performance_score

# Define a maximum value for past contributions for normalization purposes
max_past_contributions = 100  # This can be adjusted based on the application context

class Miner:
    def __init__(self, miner_id, resource_capability):
        self.id = miner_id
        self.resource_capability = resource_capability
        self.assigned_task = None
        self.contribution = 0
        self.reward = 0
        self.task_completion_times = []  # List to store task completion times
        self.tasks_assigned = 0  # Total tasks assigned to the miner
        self.tasks_completed = 0  # Total tasks completed by the miner
    
    def assign_task(self, task):
        self.assigned_task = task
        self.tasks_assigned += 1
        print(f"Miner {self.id} assigned to {task.task_id} with difficulty {task.difficulty} and resource requirement {task.resource_requirement}")
    
    def add_contribution(self, contribution):
        self.contribution += contribution
    
    def add_reward(self, reward):
        self.reward += reward
        print(f"Miner {self.id} received reward: {reward}")

    def complete_task(self, task, completion_time):
        self.task_completion_times.append(completion_time)
        self.tasks_completed += 1
        self.add_contribution(calculate_contribution(self, task))
def get_miners():
    db_miners = Miner.objects.all()  # Fetch all miners from the database
    miners = []
    for db_miner in db_miners:
        miner = CustomMiner(
            miner_id=db_miner.user.id,
            resource_capability=db_miner.resource_capability
        )
        miner.contribution = db_miner.contribution
        miner.reward = db_miner.reward
        miner.tasks_assigned = db_miner.tasks_assigned
        miner.tasks_completed = db_miner.tasks_completed
        miner.task_completion_times = db_miner.task_completion_times
        miners.append(miner)
    return miners



def adapt_tasks_based_on_performance(miners):
    for miner in miners:
        performance = evaluate_miner_performance(miner)
        adjust_tasks_for_miner(miner, performance)

def evaluate_miner_performance(miner):
    # Example metrics for performance evaluation
    past_contributions = miner.contribution
    task_completion_times = miner.task_completion_times
    tasks_assigned = miner.tasks_assigned
    tasks_completed = miner.tasks_completed

    # Calculate the average task completion speed
    if tasks_completed > 0:
        average_completion_speed = sum(task_completion_times) / len(task_completion_times)
    else:
        average_completion_speed = float('inf')

    # Calculate efficiency
    if tasks_assigned > 0:
        efficiency = tasks_completed / tasks_assigned
    else:
        efficiency = 0

    # Combine these metrics into a performance score
    performance_score = (past_contributions * 0.5) + ((1 / average_completion_speed) * 0.3) + (efficiency * 0.2)

    # Normalize the performance score to be between 0 and 1
    max_possible_score = (max_past_contributions * 0.5) + (1 * 0.3) + (1 * 0.2)
    normalized_performance_score = performance_score / max_possible_score
    
    return normalized_performance_score

def adjust_tasks_for_miner(miner, performance):
    # Adjust tasks for a miner based on their performance
    if performance < 0.5:
        task = get_easier_task()
    else:
        task = get_harder_task()
    miner.assign_task(task)

def get_easier_task():
    return Task("easy_task", "easy", 2)

def get_harder_task():
    return Task("hard_task", "hard", 8)
from collections import deque

def efficient_task_allocation(miners, tasks):
    task_queue = deque(tasks)
    for miner in miners:
        if task_queue:
            task = select_task_for_miner(miner, task_queue)
            if task:
                miner.assign_task(task)
        else:
            break
def record_miner_contribution(miner, task):
    contribution = calculate_contribution(miner, task)
    miner.add_contribution(contribution)

def calculate_contribution(miner, task):
    difficulty_scores = {"easy": 1, "medium": 2, "hard": 3}
    return difficulty_scores.get(task.difficulty, 0)  # Default to 0 if difficulty not found
def distribute_rewards(miners, total_reward):
    total_contribution = sum(miner.contribution for miner in miners)
    for miner in miners:
        miner_reward = (miner.contribution / total_contribution) * total_reward
        miner.add_reward(miner_reward)
def adapt_to_latency():
    current_latency = measure_network_latency()
    if current_latency:
        # Example: Adjust block timeout based on latency
        if current_latency > 1:
            protocol_parameters["block_timeout"] = 20
        else:
            protocol_parameters["block_timeout"] = 10
        logger.debug(f"Adjusted protocol parameters: {protocol_parameters}")
    else:
        logger.error("Failed to measure network latency.")
class CustomMiner:
    def __init__(self, miner_id, resource_capability):
        self.id = miner_id
        self.resource_capability = resource_capability
        self.assigned_task = None
        self.contribution = 0
        self.reward = 0
        self.task_completion_times = []  # List to store task completion times
        self.tasks_assigned = 0  # Total tasks assigned to the miner
        self.tasks_completed = 0  # Total tasks completed by the miner
    
    def assign_task(self, task):
        self.assigned_task = task
        self.tasks_assigned += 1
        print(f"Miner {self.id} assigned to {task.task_id} with difficulty {task.difficulty} and resource requirement {task.resource_requirement}")
    
    def add_contribution(self, contribution):
        self.contribution += contribution
    
    def add_reward(self, reward):
        self.reward += reward
        print(f"Miner {self.id} received reward: {reward}")

    def complete_task(self, task, completion_time):
        self.task_completion_times.append(completion_time)
        self.tasks_completed += 1
        self.add_contribution(calculate_contribution(self, task))
from .models import Miner  # Ensure correct import of Django model

class CustomMiner:
    def __init__(self, miner_id, resource_capability):
        self.id = miner_id
        self.resource_capability = resource_capability
        self.assigned_task = None
        self.contribution = 0
        self.reward = 0
        self.task_completion_times = []  # List to store task completion times
        self.tasks_assigned = 0  # Total tasks assigned to the miner
        self.tasks_completed = 0  # Total tasks completed by the miner
    
    def assign_task(self, task):
        self.assigned_task = task
        self.tasks_assigned += 1
        print(f"Miner {self.id} assigned to {task.task_id} with difficulty {task.difficulty} and resource requirement {task.resource_requirement}")
    
    def add_contribution(self, contribution):
        self.contribution += contribution
    
    def add_reward(self, reward):
        self.reward += reward
        print(f"Miner {self.id} received reward: {reward}")

    def complete_task(self, task, completion_time):
        self.task_completion_times.append(completion_time)
        self.tasks_completed += 1
        self.add_contribution(calculate_contribution(self, task))

def get_miners():
    db_miners = Miner.objects.all()  # Fetch all miners from the database
    miners = []
    for db_miner in db_miners:
        miner = CustomMiner(
            miner_id=db_miner.user.id,
            resource_capability=db_miner.resource_capability
        )
        miner.contribution = db_miner.contribution
        miner.reward = db_miner.reward
        miner.tasks_assigned = db_miner.tasks_assigned
        miner.tasks_completed = db_miner.tasks_completed
        miner.task_completion_times = db_miner.task_completion_times
        miners.append(miner)
    return miners
def record_miner_contribution(miner_wallet, reward_transaction):
    """
    Record miner's contribution.
    """
    contribution = calculate_contribution(miner_wallet, reward_transaction)
    miner_wallet.contribution += contribution
    miner_wallet.save()

def calculate_contribution(miner_wallet, transaction):
    """
    Calculate miner's contribution based on the transaction.
    """
    # Implement the logic to calculate the contribution.
    # For simplicity, let's assume the contribution is based on transaction amount.
    return transaction.amount  # Use transaction amount or another relevant attribute
from decimal import Decimal  # Ensure this import is at the top of your file
def mine_single_block(user, shard_id):
    global mining_statistics
    try:
        shard = Shard.objects.get(id=shard_id)
    except Shard.DoesNotExist:
        print("Shard not found")
        return JsonResponse({'error': 'Shard not found'}, status=404)

    transactions = Transaction.objects.filter(is_approved=False, shard=shard)
    previous_block_hash = '0000000000000000000000000000000000000000000000000000000000000000'
    proof = proof_of_work(previous_block_hash)
    miner_wallet = Wallet.objects.get(user=user)

    total_fees = Decimal(0)
    for transaction in transactions:
        print(f"Validating transaction {transaction.hash}")
        if validate_transaction(transaction):
            transaction.is_approved = True
            transaction.save()
            total_fees += Decimal(transaction.fee)  # Convert fee to Decimal
            print(f"Transaction {transaction.hash} approved")
        else:
            print(f"Transaction {transaction.hash} was not approved")

    current_time = timezone.now()
    genesis_time = timezone.datetime(2020, 1, 1, tzinfo=timezone.utc)
    years_elapsed = (current_time - genesis_time).days / 365.25
    reward_halvings = int(years_elapsed // 4)
    block_reward = Decimal(50) / (2 ** reward_halvings)
    total_reward = block_reward + total_fees

    print(f"Before mining, wallet balance: {miner_wallet.balance}")
    miner_wallet.balance += total_reward
    miner_wallet.save()
    print(f"After mining, wallet balance: {miner_wallet.balance}")

    new_block_hash = generate_unique_hash()
    new_block = Block(hash=new_block_hash, previous_hash=previous_block_hash, timestamp=current_time)
    dag[new_block_hash] = new_block
    if previous_block_hash in dag:
        dag[previous_block_hash].children.append(new_block)

    reward_transaction = Transaction(
        hash=new_block_hash,
        sender=miner_wallet,
        receiver=miner_wallet,
        amount=block_reward,
        fee=Decimal(0),
        signature="reward_signature",
        timestamp=current_time,
        is_approved=True,
        shard=shard
    )
    reward_transaction.save()

    mining_statistics["blocks_mined"] += 1
    mining_statistics["total_rewards"] += float(total_reward)
    print(f"Mined block. Hashrate: {mining_statistics['hashrate']}, Blocks Mined: {mining_statistics['blocks_mined']}, Total Rewards: {mining_statistics['total_rewards']}")

    ordered_blocks = order_blocks(dag)
    well_connected_subset = select_well_connected_subset(dag)

    print(f"Ordered Blocks: {[block.hash for block in ordered_blocks]}")
    print(f"Well Connected Subset: {[block.hash for block in well_connected_subset]}")

    record_miner_contribution(miner_wallet, reward_transaction)
    distribute_rewards(get_miners(), total_reward)


def record_miner_contribution(miner_wallet, transaction):
    """
    Record miner's contribution.
    """
    contribution = calculate_contribution(miner_wallet, transaction)
    miner_wallet.contribution += contribution
    miner_wallet.save()

def calculate_contribution(miner_wallet, transaction):
    """
    Calculate miner's contribution based on the transaction.
    """
    # Implement the logic to calculate the contribution.
    # For simplicity, let's assume the contribution is based on transaction amount.
    return Decimal(transaction.amount)  # Convert transaction amount to 
def search_transaction(request):
    if request.method == 'GET':
        query = request.GET.get('query')

        if not query:
            return JsonResponse({'error': 'Transaction hash, wallet address, or custom token is required'}, status=400)

        # Initialize the response data structure
        response_data = {'results': []}

        # Search for transaction
        try:
            transaction = Transaction.objects.get(hash=query)
            transaction_data = {
                'hash': transaction.hash,
                'sender': transaction.sender.address,
                'receiver': transaction.receiver.address,
                'amount': str(transaction.amount),
                'fee': str(transaction.fee),
                'timestamp': transaction.timestamp.isoformat(),
                'is_approved': transaction.is_approved,
                'shard': transaction.shard.name
            }
            response_data['results'].append(transaction_data)
            return JsonResponse(response_data)
        except Transaction.DoesNotExist:
            pass

        # Search for wallet
        try:
            wallet = Wallet.objects.filter(address=query).first()
            if wallet:
                transactions_sent = Transaction.objects.filter(sender=wallet, is_approved=True)
                transactions_received = Transaction.objects.filter(receiver=wallet, is_approved=True)

                balance = sum(tx.amount for tx in transactions_received) - sum(tx.amount + tx.fee for tx in transactions_sent)

                transactions_sent_data = [{
                    'hash': tx.hash,
                    'receiver': tx.receiver.address,
                    'amount': str(tx.amount),
                    'fee': str(tx.fee),
                    'timestamp': tx.timestamp.isoformat(),
                    'is_approved': tx.is_approved,
                    'shard': tx.shard.name
                } for tx in transactions_sent]

                transactions_received_data = [{
                    'hash': tx.hash,
                    'sender': tx.sender.address,
                    'amount': str(tx.amount),
                    'fee': str(tx.fee),
                    'timestamp': tx.timestamp.isoformat(),
                    'is_approved': tx.is_approved,
                    'shard': tx.shard.name
                } for tx in transactions_received]

                custom_tokens = CustomToken.objects.filter(wallet=wallet)
                custom_tokens_data = [{
                    'address': token.address,
                    'name': token.name,
                    'symbol': token.symbol,
                    'balance': str(token.balance),
                    'total_supply': str(token.total_supply)
                } for token in custom_tokens]

                wallet_data = {
                    'address': wallet.address,
                    'balance': str(balance),
                    'transactions_sent': transactions_sent_data,
                    'transactions_received': transactions_received_data,
                    'custom_tokens': custom_tokens_data
                }
                response_data['results'].append(wallet_data)
                return JsonResponse(response_data)
        except Wallet.DoesNotExist:
            pass

        # Search for custom token
        try:
            custom_token = CustomToken.objects.get(address=query)
            token_data = {
                'address': custom_token.address,
                'name': custom_token.name,
                'symbol': custom_token.symbol,
                'balance': str(custom_token.balance),
                'total_supply': str(custom_token.total_supply)
            }
            response_data['results'].append(token_data)
            return JsonResponse(response_data)
        except CustomToken.DoesNotExist:
            pass

        # Search for contract
        try:
            contract = Contract.objects.filter(address=query).first()
            if contract:
                contract_data = {
                    'address': contract.address,
                    'abi': json.loads(contract.abi),
                    'created_at': contract.created_at.isoformat(),
                    'updated_at': contract.updated_at.isoformat(),
                }
                response_data['results'].append(contract_data)
                return JsonResponse(response_data)
        except Contract.DoesNotExist:
            pass

        return JsonResponse({'error': 'No matching transaction, wallet, contract, or custom token found'}, status=404)

    return JsonResponse({'error': 'Only GET method allowed'}, status=400)


def get_active_nodes(master_node_url):
    try:
        response = requests.get(f"{master_node_url}/api/nodes/")
        response.raise_for_status()
        nodes = response.json().get('nodes', [])
        print(f"Active nodes fetched: {nodes}")
        return nodes
    except requests.exceptions.RequestException as e:
        print(f"Error fetching nodes from master node: {e}")
        return []
def get_node_latest_transaction(node_url):
    try:
        response = requests.get(f"{node_url}/api/latest_transaction/")
        response.raise_for_status()
        latest_transaction = response.json()
        print(f"Latest transaction from {node_url}: {latest_transaction}")
        return latest_transaction
    except requests.RequestException as e:
        print(f"Error fetching latest transaction from {node_url}: {e}")
        return None

def get_node_transaction_pool(node_url):
    try:
        response = requests.get(f"{node_url}/api/transaction_pool/")
        response.raise_for_status()
        transaction_pool = response.json()
        print(f"Transaction pool from {node_url}: {transaction_pool}")
        return transaction_pool
    except requests.RequestException as e:
        print(f"Error fetching transaction pool from {node_url}: {e}")
        return None
def check_node_synchronization():
    master_node_url = "http://161.35.219.10:1010"
    nodes = get_active_nodes(master_node_url)

    if len(nodes) < 2:
        return {
            "is_synchronized": False,
            "message": "Not enough nodes to check synchronization",
            "nodes": nodes,
        }

    node1_url = nodes[0]['url']
    node2_url = nodes[1]['url']

    node1_latest_tx = get_node_latest_transaction(node1_url)
    node1_tx_pool = get_node_transaction_pool(node1_url)
    node2_latest_tx = get_node_latest_transaction(node2_url)
    node2_tx_pool = get_node_transaction_pool(node2_url)

    is_synchronized = (node1_latest_tx == node2_latest_tx) and (node1_tx_pool == node2_tx_pool)
    return {
        "is_synchronized": is_synchronized,
        "node1_latest_transaction": node1_latest_tx,
        "node1_transaction_pool": node1_tx_pool,
        "node2_latest_transaction": node2_latest_tx,
        "node2_transaction_pool": node2_tx_pool,
    }
@csrf_exempt
def get_network_status(request):
    sync_status = check_node_synchronization()
    print(f"Synchronization status: {sync_status}")
    return JsonResponse(sync_status)
import asyncio
import json
import hashlib
import requests
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from .models import Wallet, Transaction, Shard, Pool, PoolMember
from mnemonic import Mnemonic
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from web3 import Web3
from django.utils import timezone
from django.contrib.auth import authenticate, login
from decimal import Decimal
from .utils import create_default_shard
import base64
import hashlib
import logging
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)
protocol_parameters = {
    "block_timeout": 10
}
import subprocess

def measure_network_latency():
    try:
        result = subprocess.run(["ping", "-c", "1", "8.8.8.8"], stdout=subprocess.PIPE)
        if result.returncode == 0:
            latency = float(result.stdout.decode().split('time=')[1].split(' ms')[0])
            return latency / 1000.0
        else:
            logger.error("Ping command failed")
            return None
    except Exception as e:
        logger.error(f"Error measuring network latency: {e}")
        return None

def get_wallet_balance(public_key_pem):
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        sha256 = hashlib.sha256(public_key_bytes).digest()
        keccak = Web3.keccak(sha256)
        address = Web3.to_checksum_address(keccak[-20:])
        w3 = Web3(Web3.HTTPProvider('http://159.89.106.101:8545'))
        if not w3.is_connected():
            return None
        balance = w3.eth.get_balance(address)
        balance_eth = w3.from_wei(balance, 'ether')
        return balance_eth
    except Exception as e:
        print(f"Error getting wallet balance: {e}")
        return None
def generate_wallet():
    mnemo = Mnemonic("english")
    mnemonic_phrase = mnemo.generate(strength=128)
    seed = mnemo.to_seed(mnemonic_phrase)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    private_key_serialized = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_key = private_key.public_key()
    public_key_serialized = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    sha256 = hashlib.sha256(public_key_serialized.encode('utf-8')).digest()
    address = base64.urlsafe_b64encode(sha256).decode('utf-8')[:32]

    return {
        "mnemonic": mnemonic_phrase,
        "private_key": private_key_serialized,
        "public_key": public_key_serialized,
        "address": address
    }


@csrf_exempt
def register(request):
    if request.method == 'POST':
        try:
            adapt_to_latency()

            logger.debug("Starting wallet generation.")
            wallet_data = generate_wallet()
            logger.debug(f"Generated wallet data: {wallet_data}")

            username = wallet_data['public_key']
            password = None
            logger.debug(f"Generated username: {username}")

            user = User.objects.create_user(username=username, password=password)
            logger.debug(f"Created user: {user}")

            alias = generate_unique_alias(wallet_data['public_key'])
            address = wallet_data['address']
            logger.debug(f"Generated alias: {alias}, address: {address}")

            wallet = Wallet(
                user=user,
                public_key=wallet_data['public_key'],
                private_key=wallet_data['private_key'],
                alias=alias,
                address=address
            )
            wallet.save()
            logger.debug(f"Saved wallet: {wallet}")

            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                logger.debug(f"User authenticated and logged in: {user}")

            balance = get_wallet_balance(wallet_data['public_key'])
            logger.debug(f"Retrieved wallet balance: {balance}")

            return JsonResponse({
                'message': 'User and wallet created',
                'public_key': wallet.public_key,
                'mnemonic': wallet_data['mnemonic'],
                'address': wallet.address,
                'balance': balance
            })

        except IntegrityError as e:
            logger.error(f"Integrity error during registration: {str(e)}")
            return JsonResponse({'error': 'User with this public key already exists or alias conflict'}, status=400)
        except Exception as e:
            logger.error(f"Unexpected error during registration: {str(e)}")
            return JsonResponse({'error': 'An unexpected error occurred'}, status=500)
    return JsonResponse({'error': 'Only POST method allowed'}, status=400)


def generate_unique_alias(public_key):
    base_alias = public_key[:8]
    alias = base_alias
    counter = 1
    while Wallet.objects.filter(alias=alias).exists():
        alias = f"{base_alias}-{counter}"
        counter += 1
    return alias

@csrf_exempt
def import_wallet(request):
    if request.method == 'POST':
        mnemonic_phrase = request.POST.get('mnemonic')
        mnemo = Mnemonic("english")
        if mnemo.check(mnemonic_phrase):
            wallet_data = generate_wallet(mnemonic_phrase=mnemonic_phrase)
            user, created = User.objects.get_or_create(username=wallet_data['public_key'])
            if created:
                alias = generate_unique_alias(wallet_data['public_key'])
                wallet = Wallet(
                    user=user, 
                    public_key=wallet_data['public_key'], 
                    private_key=wallet_data['private_key'], 
                    alias=alias,
                    address=wallet_data['address']
                )
                wallet.save()
            else:
                wallet = Wallet.objects.get(user=user)

            user = authenticate(username=wallet_data['public_key'], password=None)
            login(request, user)

            return JsonResponse({
                'message': 'Wallet imported successfully',
                'public_key': wallet.public_key,
                'address': wallet.address
            })
        else:
            return JsonResponse({'error': 'Invalid mnemonic phrase'}, status=400)
    return JsonResponse({'error': 'Only POST method allowed'}, status=400)

import threading


def generate_unique_hash():
    return hashlib.sha256(str(timezone.now()).encode('utf-8')).hexdigest()

def proof_of_work(last_hash):
    proof = 0
    while not valid_proof(last_hash, proof):
        proof += 1
    return proof

def valid_proof(last_hash, proof, difficulty=4):
    guess = f'{last_hash}{proof}'.encode()
    guess_hash = hashlib.sha256(guess).hexdigest()
    return guess_hash[:difficulty] == "0" * difficulty
import asyncio
import json
import hashlib
import requests
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from .models import Wallet, Transaction, Shard, Pool, PoolMember
from mnemonic import Mnemonic
from bip32utils import BIP32Key
from web3 import Web3
from django.utils import timezone
from django.contrib.auth import authenticate, login
from decimal import Decimal
from .utils import create_default_shard
import base64
import hashlib
import logging
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)
protocol_parameters = {
    "block_timeout": 10
}
import subprocess

def measure_network_latency():
    try:
        result = subprocess.run(["ping", "-c", "1", "8.8.8.8"], stdout=subprocess.PIPE)
        if result.returncode == 0:
            latency = float(result.stdout.decode().split('time=')[1].split(' ms')[0])
            return latency / 1000.0
        else:
            logger.error("Ping command failed")
            return None
    except Exception as e:
        logger.error(f"Error measuring network latency: {e}")
        return None

def get_wallet_balance(public_key_pem):
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        sha256 = hashlib.sha256(public_key_bytes).digest()
        keccak = Web3.keccak(sha256)
        address = Web3.to_checksum_address(keccak[-20:])
        w3 = Web3(Web3.HTTPProvider('http://159.89.106.101:8545'))
        if not w3.is_connected():
            return None
        balance = w3.eth.get_balance(address)
        balance_eth = w3.from_wei(balance, 'ether')
        return balance_eth
    except Exception as e:
        print(f"Error getting wallet balance: {e}")
        return None
def generate_wallet():
    # Generate a new mnemonic phrase
    mnemo = Mnemonic("english")
    mnemonic_phrase = mnemo.generate(strength=128)
    seed = mnemo.to_seed(mnemonic_phrase)

    # Generate a private key using the seed
    private_key = binascii.hexlify(seed[:32]).decode('utf-8')

    # Generate an Ethereum account from the private key
    account = Account.from_key(private_key)

    return {
        "mnemonic": mnemonic_phrase,
        "private_key": private_key,
        "public_key": account.key.hex(),
        "address": account.address
    }



@csrf_exempt
def register(request):
    if request.method == 'POST':
        try:
            logger.debug("Starting wallet generation.")
            wallet_data = generate_wallet()
            logger.debug(f"Generated wallet data: {wallet_data}")

            username = wallet_data['public_key']
            password = None
            logger.debug(f"Generated username: {username}")

            user = User.objects.create_user(username=username, password=password)
            logger.debug(f"Created user: {user}")

            alias = generate_unique_alias(wallet_data['public_key'])
            address = wallet_data['address']
            logger.debug(f"Generated alias: {alias}, address: {address}")

            wallet = Wallet(
                user=user,
                public_key=wallet_data['public_key'],
                private_key=wallet_data['private_key'],
                alias=alias,
                address=address
            )
            wallet.save()
            logger.debug(f"Saved wallet: {wallet}")

            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                logger.debug(f"User authenticated and logged in: {user}")

            balance = get_wallet_balance(wallet_data['public_key'])
            logger.debug(f"Retrieved wallet balance: {balance}")

            return JsonResponse({
                'message': 'User and wallet created',
                'public_key': wallet.public_key,
                'mnemonic': wallet_data['mnemonic'],
                'address': wallet.address,
                'balance': balance
            })

        except IntegrityError as e:
            logger.error(f"Integrity error during registration: {str(e)}")
            return JsonResponse({'error': 'User with this public key already exists or alias conflict'}, status=400)
        except Exception as e:
            logger.error(f"Unexpected error during registration: {str(e)}")
            return JsonResponse({'error': 'An unexpected error occurred'}, status=500)
    return JsonResponse({'error': 'Only POST method allowed'}, status=400)


def generate_unique_alias(public_key):
    base_alias = public_key[:8]
    alias = base_alias
    counter = 1
    while Wallet.objects.filter(alias=alias).exists():
        alias = f"{base_alias}-{counter}"
        counter += 1
    return alias


@csrf_exempt
def import_wallet(request):
    if request.method == 'POST':
        mnemonic_phrase = request.POST.get('mnemonic')
        mnemo = Mnemonic("english")
        if mnemo.check(mnemonic_phrase):
            wallet_data = generate_wallet(mnemonic_phrase=mnemonic_phrase)
            user, created = User.objects.get_or_create(username=wallet_data['public_key'])
            if created:
                alias = generate_unique_alias(wallet_data['public_key'])
                wallet = Wallet(
                    user=user, 
                    public_key=wallet_data['public_key'], 
                    private_key=wallet_data['private_key'], 
                    alias=alias,
                    address=wallet_data['address']
                )
                wallet.save()
            else:
                wallet = Wallet.objects.get(user=user)

            user = authenticate(username=wallet_data['public_key'], password=None)
            login(request, user)

            return JsonResponse({
                'message': 'Wallet imported successfully',
                'public_key': wallet.public_key,
                'address': wallet.address
            })
        else:
            return JsonResponse({'error': 'Invalid mnemonic phrase'}, status=400)
    return JsonResponse({'error': 'Only POST method allowed'}, status=400)


def generate_unique_hash():
    return hashlib.sha256(str(timezone.now()).encode('utf-8')).hexdigest()

def proof_of_work(last_hash):
    proof = 0
    while not valid_proof(last_hash, proof):
        proof += 1
    return proof

def valid_proof(last_hash, proof, difficulty=4):
    guess = f'{last_hash}{proof}'.encode()
    guess_hash = hashlib.sha256(guess).hexdigest()
    return guess_hash[:difficulty] == "0" * difficulty
def broadcast_transaction_update(transaction):
    channel_layer = get_channel_layer()
    transaction_data = {
        'hash': transaction.hash,
        'sender': transaction.sender.address,
        'receiver': transaction.receiver.address,
        'amount': str(transaction.amount),
        'fee': str(transaction.fee),
        'timestamp': transaction.timestamp.isoformat(),
        'is_approved': transaction.is_approved,
        'shard': transaction.shard.name
    }
    async_to_sync(channel_layer.group_send)(
        "transactions", {
            "type": "transaction_message",
            "message": transaction_data
        }
    )

# views.py

from django.shortcuts import render, redirect
from .models import Contract
from .forms import ContractForm

def manage_contract(request):
    contract = Contract.objects.first()
    if request.method == 'POST':
        form = ContractForm(request.POST, instance=contract)
        if form.is_valid():
            form.save()
            return redirect('index')
    else:
        form = ContractForm(instance=contract)
    return render(request, 'index.html', {'form': form})
@csrf_exempt
def import_token(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            token_address = data.get('token_address')
            token_symbol = data.get('token_symbol')

            custom_token, created = CustomToken.objects.update_or_create(
                address=token_address,
                defaults={
                    'symbol': token_symbol,
                    'balance': 0  # Assuming a default balance of 0
                }
            )

            token_details = {
                'address': custom_token.address,
                'name': custom_token.name,
                'symbol': custom_token.symbol,
                'balance': str(custom_token.balance),
                'total_supply': str(custom_token.total_supply)
            }

            return JsonResponse({'success': True, 'token_details': token_details})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Only POST method is allowed'}, status=400)



from web3 import Web3
from django.conf import settings
web3 = Web3(Web3.HTTPProvider(settings.GETH_NODE_URL))
def get_token_details(request):
    token_address = request.GET.get('token_address')

    if not token_address:
        return JsonResponse({'success': False, 'error': 'Token address is required'})

    try:
        # Call the function to fetch token details
        token_details = fetch_token_details(token_address)
        if token_details:
            return JsonResponse({'success': True, 'token_symbol': token_details['symbol']})
        else:
            return JsonResponse({'success': False, 'error': 'Token details not found'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

def fetch_token_details(token_address):
    ERC20_ABI = [
        {
            "constant": True,
            "inputs": [],
            "name": "name",
            "outputs": [{"name": "", "type": "string"}],
            "payable": False,
            "stateMutability": "view",
            "type": "function",
        },
        {
            "constant": True,
            "inputs": [],
            "name": "symbol",
            "outputs": [{"name": "", "type": "string"}],
            "payable": False,
            "stateMutability": "view",
            "type": "function",
        },
        {
            "constant": True,
            "inputs": [{"name": "_owner", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "balance", "type": "uint256"}],
            "payable": False,
            "stateMutability": "view",
            "type": "function",
        },
        {
            "constant": True,
            "inputs": [],
            "name": "totalSupply",
            "outputs": [{"name": "supply", "type": "uint256"}],
            "payable": False,
            "stateMutability": "view",
            "type": "function",
        },
    ]

    token_address = web3.to_checksum_address(token_address)

    contract = web3.eth.contract(address=token_address, abi=ERC20_ABI)

    try:
        name = contract.functions.name().call()
        symbol = contract.functions.symbol().call()
        total_supply = contract.functions.totalSupply().call()
        return {
            'name': name,
            'symbol': symbol,
            'total_supply': total_supply
        }
    except Exception as e:
        print(f"Error fetching token details: {e}")
        return None
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import CustomToken, Wallet
from web3 import Web3

# Initialize web3
web3 = Web3(Web3.HTTPProvider('http://159.89.106.101:8545'))

def get_token_details(token_address, wallet_address=None):
    ERC20_ABI = [
        {
            "constant": True,
            "inputs": [],
            "name": "name",
            "outputs": [{"name": "", "type": "string"}],
            "payable": False,
            "stateMutability": "view",
            "type": "function",
        },
        {
            "constant": True,
            "inputs": [],
            "name": "symbol",
            "outputs": [{"name": "", "type": "string"}],
            "payable": False,
            "stateMutability": "view",
            "type": "function",
        },
        {
            "constant": True,
            "inputs": [{"name": "_owner", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "balance", "type": "uint256"}],
            "payable": False,
            "stateMutability": "view",
            "type": "function",
        },
        {
            "constant": True,
            "inputs": [],
            "name": "totalSupply",
            "outputs": [{"name": "supply", "type": "uint256"}],
            "payable": False,
            "stateMutability": "view",
            "type": "function",
        },
    ]

    token_address = web3.to_checksum_address(token_address)

    contract = web3.eth.contract(address=token_address, abi=ERC20_ABI)

    try:
        name = contract.functions.name().call()
        symbol = contract.functions.symbol().call()
        total_supply = contract.functions.totalSupply().call()

        balance = 0
        if wallet_address:
            wallet_address = web3.to_checksum_address(wallet_address)
            balance = contract.functions.balanceOf(wallet_address).call()

        return {
            'name': name,
            'symbol': symbol,
            'balance': balance,
            'total_supply': total_supply
        }
    except Exception as e:
        print(f"Error fetching token details: {e}")
        return None
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Wallet, CustomToken
import json
import logging

logger = logging.getLogger(__name__)
node_url = 'https://polygon-rpc.com'
web3 = Web3(Web3.HTTPProvider(node_url))
from web3 import Web3
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Wallet, CustomToken
import logging

logger = logging.getLogger(__name__)
from web3 import Web3
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Wallet, CustomToken
import logging

logger = logging.getLogger(__name__)

# Connect to an Ethereum node using a public URL
node_url = 'https://polygon-rpc.com'
web3 = Web3(Web3.HTTPProvider(node_url))

def get_token_details(token_address):
    try:
        # ERC20 Token ABI
        token_abi = [
            {
                "constant": True,
                "inputs": [],
                "name": "name",
                "outputs": [{"name": "", "type": "string"}],
                "payable": False,
                "stateMutability": "view",
                "type": "function",
            },
            {
                "constant": True,
                "inputs": [],
                "name": "symbol",
                "outputs": [{"name": "", "type": "string"}],
                "payable": False,
                "stateMutability": "view",
                "type": "function",
            },
            {
                "constant": True,
                "inputs": [],
                "name": "totalSupply",
                "outputs": [{"name": "", "type": "uint256"}],
                "payable": False,
                "stateMutability": "view",
                "type": "function",
            },
        ]
        
        # Initialize contract
        token_contract = web3.eth.contract(address=web3.to_checksum_address(token_address), abi=token_abi)

        # Fetch token details
        name = token_contract.functions.name().call()
        symbol = token_contract.functions.symbol().call()
        total_supply = token_contract.functions.totalSupply().call()

        return {
            'name': name,
            'symbol': symbol,
            'initial_supply': total_supply
        }
    except Exception as e:
        logger.error(f"Exception occurred while fetching token details: {e}")
        return None

@csrf_exempt
def fetch_token_details(request):
    if request.method == 'GET':
        token_address = request.GET.get('address')
        if not token_address:
            return JsonResponse({'error': 'Token address is required'}, status=400)
        
        token_details = get_token_details(token_address)
        if token_details:
            return JsonResponse(token_details)
        else:
            return JsonResponse({'error': 'Failed to fetch token details'}, status=500)
    else:
        return JsonResponse({'error': 'Only GET method is allowed'}, status=400)

@csrf_exempt
def import_token(request):
    if request.method == 'POST':
        try:
            data = request.POST
            logger.info(f"Received data: {data}")

            token_address = data.get('tokenAddress')
            token_symbol = data.get('tokenSymbol')
            token_name = data.get('tokenName')
            initial_supply = data.get('initialSupply')

            # Fetch token details if not provided
            if not all([token_symbol, token_name, initial_supply]):
                token_details = get_token_details(token_address)
                if token_details:
                    token_name = token_name or token_details['name']
                    token_symbol = token_symbol or token_details['symbol']
                    initial_supply = initial_supply or token_details['initial_supply']
                else:
                    return JsonResponse({'error': 'Failed to fetch token details'}, status=400)

            if not all([token_address, token_symbol, token_name, initial_supply]):
                logger.error("Missing required fields: tokenAddress, tokenSymbol, tokenName, or initialSupply")
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            # Assuming a default wallet for all imported tokens
            default_wallet = Wallet.objects.get(user=request.user)

            custom_token, created = CustomToken.objects.update_or_create(
                address=token_address,
                wallet=default_wallet,
                defaults={
                    'name': token_name,
                    'symbol': token_symbol,
                    'balance': initial_supply
                }
            )

            token_details = {
                'name': custom_token.name,
                'address': custom_token.address,
                'symbol': custom_token.symbol,
                'balance': str(custom_token.balance),
            }

            return JsonResponse({'success': True, 'token_details': token_details})
        except Wallet.DoesNotExist:
            logger.error("Wallet not found")
            return JsonResponse({'error': 'Wallet not found'}, status=404)
        except Exception as e:
            logger.error(f"Error importing token: {e}")
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Only POST method is allowed'}, status=400)

from django.shortcuts import render

def market_view(request):
    return render(request, 'market.html')

def trading_bot_view(request):
    return render(request, 'tradingbot.html')
    
    
from cryptography.fernet import Fernet
import os

# Generate and store this key securely
# key = Fernet.generate_key()
# store this key securely, e.g., in an environment variable
encryption_key = os.environ.get('ENCRYPTION_KEY')
f = Fernet(encryption_key)

def encrypt_private_key(private_key):
    return f.encrypt(private_key.encode()).decode()

def decrypt_private_key(encrypted_private_key):
    return f.decrypt(encrypted_private_key.encode()).decode()
    
def get_wallet_details(request):
    try:
        wallet_address = request.user.wallet.address  # Adjust according to how you store the user's wallet
        wallet = Wallet.objects.get(address=wallet_address)

        transactions_sent = Transaction.objects.filter(sender=wallet, is_approved=True)
        transactions_received = Transaction.objects.filter(receiver=wallet, is_approved=True)
        custom_tokens = CustomToken.objects.filter(wallet=wallet)

        # Calculate balance based on transactions
        balance = sum(tx.amount for tx in transactions_received) - sum(tx.amount + tx.fee for tx in transactions_sent)

        # Pagination parameters
        page_number = request.GET.get('page', 1)
        page_size = 20

        # Combine sent and received transactions
        transactions = transactions_sent.union(transactions_received).order_by('-timestamp')
        paginator = Paginator(transactions, page_size)
        page_obj = paginator.get_page(page_number)

        transactions_data = [{
            'hash': tx.hash,
            'sender': tx.sender.address,
            'receiver': tx.receiver.address,
            'amount': str(tx.amount),
            'fee': str(tx.fee),
            'timestamp': tx.timestamp.isoformat(),
            'is_approved': tx.is_approved,
            'shard': tx.shard.name
        } for tx in page_obj]

        custom_tokens_data = [{
            'address': token.address,
            'name': token.name,
            'symbol': token.symbol,
            'balance': str(token.balance),
        } for token in custom_tokens]

        wallet_data = {
            'alias': wallet.alias or 'N/A',
            'address': wallet.address,
            'public_key': wallet.public_key or 'N/A',
            'balance': str(balance),
            'transactions': transactions_data,
            'custom_tokens': custom_tokens_data,
            'total_pages': paginator.num_pages,
            'current_page': page_obj.number,
        }

        return JsonResponse(wallet_data)

    except Wallet.DoesNotExist:
        return JsonResponse({'error': 'Wallet not found'}, status=404)
    except Exception as e:
        print(f"Error while fetching wallet details: {e}")
        return JsonResponse({'error': 'An error occurred while fetching the wallet details'}, status=500)
def deploy_contract(request):
    if request.method == 'POST':
        try:
            if not request.POST:
                return JsonResponse({'error': 'Empty request body.'}, status=400)

            logger.info(f"Request body: {request.POST}")

            token_name = request.POST.get('name')
            token_symbol = request.POST.get('symbol')
            initial_supply = request.POST.get('initialSupply')
            enable_liquidity_pool = request.POST.get('enableLiquidityPool')
            use_native_token = request.POST.get('useNativeToken')
            token_pair1 = request.POST.get('tokenPair1')
            token_pair2 = request.POST.get('tokenPair2')
            token1_amount = request.POST.get('token1Amount')
            token2_amount = request.POST.get('token2Amount')

            if not initial_supply:
                return JsonResponse({'error': 'Initial supply is required.'}, status=400)

            initial_supply = int(initial_supply)

            # Compile the contract using Hardhat
            compile_command = ['npx', 'hardhat', 'compile']
            result = subprocess.run(compile_command, cwd=os.path.join(settings.BASE_DIR, 'my-token-project'), capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Compilation failed: {result.stderr}")
                return JsonResponse({'error': f'Compilation failed: {result.stderr}'}, status=500)

            # Connect to local Ethereum node
            w3 = Web3(Web3.HTTPProvider('http://159.89.106.101:8545'))

            # Check if connected
            if not w3.is_connected():
                logger.error('Could not connect to Ethereum node.')
                return JsonResponse({'error': 'Could not connect to Ethereum node.'}, status=500)

            # Check for available accounts
            if not w3.eth.accounts:
                logger.error('No Ethereum accounts found.')
                return JsonResponse({'error': 'No Ethereum accounts found.'}, status=500)

            # Get default account for deployment
            w3.eth.default_account = w3.eth.accounts[0]

            # Load compiled contract
            compiled_contract_path = os.path.join(settings.BASE_DIR, 'my-token-project/artifacts/contracts/MyToken.sol/MyToken.json')
            if not os.path.exists(compiled_contract_path):
                logger.error('Compiled contract file not found.')
                return JsonResponse({'error': 'Compiled contract file not found.'}, status=500)

            with open(compiled_contract_path) as f:
                compiled_contract = json.load(f)
            
            abi = compiled_contract['abi']
            bytecode = compiled_contract['bytecode']

            # Create web3 contract instance
            Web3Contract = w3.eth.contract(abi=abi, bytecode=bytecode)

            # Deploy contract
            try:
                initial_owner = w3.eth.default_account
                estimated_gas = Web3Contract.constructor(token_name, token_symbol, initial_supply, initial_owner).estimate_gas({'from': w3.eth.default_account})

                # Log estimated gas
                logger.info(f"Estimated gas: {estimated_gas}")

                # Setting gas limit higher to avoid the "exceeds allowance" issue
                gas_limit = estimated_gas + 300000  # Increase this if needed

                tx_hash = Web3Contract.constructor(token_name, token_symbol, initial_supply, initial_owner).transact({'from': w3.eth.default_account, 'gas': gas_limit})
                tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
                logger.info(f"Contract deployed at address: {tx_receipt.contractAddress}")

                # Save contract details in the database
                Contract.objects.create(
                    address=tx_receipt.contractAddress,
                    abi=json.dumps(abi)
                )

                response_data = {
                    'deployed': True,
                    'contract_address': tx_receipt.contractAddress
                }

                if enable_liquidity_pool and token1_amount and token2_amount:
                    if use_native_token:
                        token_pair2 = '0x0000000000000000000000000000000000000000'
                    liquidity_pool_address = deploy_liquidity_pool(tx_receipt.contractAddress, token_pair1, token_pair2, token1_amount, token2_amount)
                    response_data['liquidity_pool_address'] = liquidity_pool_address

                return JsonResponse(response_data)
            except ValueError as e:
                logger.error(f"Error deploying contract: {e}")
                if 'exceeds block gas limit' in str(e):
                    return JsonResponse({'error': 'Gas required exceeds block gas limit. Please increase the gas limit.'}, status=500)
                else:
                    return JsonResponse({'error': f'Error deploying contract: {str(e)}'}, status=500)
            except Exception as e:
                logger.error(f"Error deploying contract: {str(e)}")
                return JsonResponse({'error': f'Error deploying contract: {str(e)}'}, status=500)

        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'An unexpected error occurred.'}, status=500)

    return JsonResponse({'error': 'Invalid request method.'}, status=400)

from django.http import JsonResponse
from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required
from .models import Wallet, Transaction, CustomToken
from .encryption_utils import decrypt_message
from cryptography.fernet import InvalidToken
import logging

# Initialize logger
logger = logging.getLogger(__name__)

from django.http import JsonResponse
from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required
from .models import Wallet, Transaction, CustomToken
from .encryption_utils import decrypt_message
from cryptography.fernet import InvalidToken
import logging

# Initialize logger
logger = logging.getLogger(__name__)

from django.http import JsonResponse
from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required
from .models import Wallet, Transaction, CustomToken
from .encryption_utils import decrypt_message
from cryptography.fernet import InvalidToken
import logging

# Initialize logger
logger = logging.getLogger(__name__)

from django.http import JsonResponse
from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required
from .models import Wallet, Transaction, CustomToken
from .encryption_utils import decrypt_message
from cryptography.fernet import InvalidToken
import logging

# Initialize logger
logger = logging.getLogger(__name__)

from django.http import JsonResponse
from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required
from .models import Wallet, Transaction, CustomToken
from .encryption_utils import decrypt_message
from cryptography.fernet import InvalidToken
import logging

# Initialize logger
logger = logging.getLogger(__name__)

from django.http import JsonResponse
from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required
from .models import Wallet, Transaction, CustomToken
from .encryption_utils import decrypt_message
from cryptography.fernet import InvalidToken
import logging

# Initialize logger
logger = logging.getLogger(__name__)

# views.py
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required
from .models import Wallet, Transaction, CustomToken
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import logging

# Initialize logger
logger = logging.getLogger(__name__)
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required
from .models import Wallet, Transaction, CustomToken
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import logging

# Initialize logger
logger = logging.getLogger(__name__)
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def decrypt_private_key(private_key_pem, encrypted_private_key):
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    chunk_size = 256  # decryption chunk size (same as the key size)
    decrypted_chunks = []

    for i in range(0, len(encrypted_private_key), chunk_size):
        encrypted_chunk = encrypted_private_key[i:i + chunk_size]
        decrypted_chunk = private_key.decrypt(
            encrypted_chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_chunks.append(decrypted_chunk)

    decrypted_private_key = b"".join(decrypted_chunks)
    return decrypted_private_key

@login_required
def get_wallet_details(request):
    try:
        logger.debug("Fetching wallet address for user: %s", request.user)
        wallet_address = request.user.wallet.address
        logger.debug("Wallet address: %s", wallet_address)

        wallet = Wallet.objects.get(address=wallet_address)
        logger.debug("Wallet found: %s", wallet)

        transactions_sent = Transaction.objects.filter(sender=wallet, is_approved=True)
        transactions_received = Transaction.objects.filter(receiver=wallet, is_approved=True)
        mining_rewards = Transaction.objects.filter(receiver=wallet, is_mining_reward=True, is_approved=True)
        custom_tokens = CustomToken.objects.filter(wallet=wallet)  # Define custom_tokens here

        logger.debug("Transactions sent: %s, Transactions received: %s, Mining rewards: %s, Custom tokens: %s",
                     transactions_sent.count(), transactions_received.count(), mining_rewards.count(), custom_tokens.count())

        # Calculate balance
        received_amount = sum(tx.amount for tx in transactions_received)
        sent_amount = sum(tx.amount + tx.fee for tx in transactions_sent)
        mining_rewards_amount = sum(tx.amount for tx in mining_rewards)

        balance = received_amount - sent_amount + mining_rewards_amount
        logger.debug("Calculated balance: %s", balance)

        page_number = request.GET.get('page', 1)
        page_size = 20

        transactions = transactions_sent.union(transactions_received).order_by('-timestamp')
        paginator = Paginator(transactions, page_size)
        page_obj = paginator.get_page(page_number)

        transactions_data = [{
            'hash': tx.hash,
            'sender': tx.sender.address,
            'receiver': tx.receiver.address,
            'amount': str(tx.amount),
            'fee': str(tx.fee),
            'timestamp': tx.timestamp.isoformat(),
            'is_approved': tx.is_approved,
            'shard': tx.shard.name
        } for tx in page_obj]

        custom_tokens_data = [{
            'address': token.address,
            'name': token.name,
            'symbol': token.symbol,
            'balance': str(token.balance),
        } for token in custom_tokens]

        try:
            with open("private_key.pem", "rb") as key_file:
                private_key_pem = key_file.read()
            decrypted_private_key = decrypt_private_key(private_key_pem, wallet.encrypted_private_key)
            logger.debug("Decrypted private key for wallet: %s", wallet_address)
        except ValueError as e:
            logger.error("ValueError decrypting private key: %s", e)
            return JsonResponse({'error': 'Value error, decryption failed'}, status=500)
        except Exception as e:
            logger.error("General error decrypting private key: %s", e)
            return JsonResponse({'error': 'An error occurred during decryption'}, status=500)

        wallet_data = {
            'alias': wallet.alias or 'N/A',
            'address': wallet.address,
            'public_key': wallet.public_key or 'N/A',
            'private_key': decrypted_private_key.decode('utf-8'),
            'balance': str(balance),
            'transactions': transactions_data,
            'custom_tokens': custom_tokens_data,
            'total_pages': paginator.num_pages,
            'current_page': page_obj.number,
        }

        logger.debug("Returning wallet data: %s", wallet_data)
        return JsonResponse(wallet_data)

    except Wallet.DoesNotExist:
        logger.error("Wallet not found for address: %s", wallet_address)
        return JsonResponse({'error': 'Wallet not found'}, status=404)
    except Exception as e:
        logger.error("Error fetching wallet details: %s", str(e))
        return JsonResponse({'error': 'An error occurred while fetching the wallet details'}, status=500)

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Contract
from web3 import Web3
import json
import os
import subprocess
import logging

logger = logging.getLogger(__name__)

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import subprocess
import os
import json
import logging
from web3 import Web3
from django.conf import settings
from .models import Contract

logger = logging.getLogger(__name__)

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import subprocess
import os
import json
import logging
from web3 import Web3
from django.conf import settings
from .models import Contract

logger = logging.getLogger(__name__)

@csrf_exempt
def deploy_contract(request):
    if request.method == 'POST':
        try:
            if not request.POST:
                return JsonResponse({'error': 'Empty request body.'}, status=400)

            logger.info(f"Request body: {request.POST}")

            token_name = request.POST.get('name')
            token_symbol = request.POST.get('symbol')
            initial_supply = request.POST.get('initialSupply')

            if not initial_supply:
                return JsonResponse({'error': 'Initial supply is required.'}, status=400)

            initial_supply = int(initial_supply)

            contract_path = '/home/myuser/myquantumproject/solc/MyToken.sol'
            openzeppelin_path = '/home/myuser/myquantumproject/node_modules/@openzeppelin/contracts'
            chainlink_path = '/home/myuser/myquantumproject/node_modules/@chainlink/contracts'
            combined_json_path = '/home/myuser/myquantumproject/solc/combined.json/combined.json'

            # Compile the contract using solc with OpenZeppelin and Chainlink imports
            compile_command = [
                'solc', '--combined-json', 'abi,bin', '--optimize', '--overwrite',
                '--include-path', openzeppelin_path, '--include-path', chainlink_path,
                '--base-path', '/home/myuser/myquantumproject/solc', contract_path,
                '-o', '/home/myuser/myquantumproject/solc/combined.json'
            ]
            result = subprocess.run(compile_command, capture_output=True, text=True, cwd='/home/myuser/myquantumproject/solc')
            if result.returncode != 0:
                logger.error(f"Compilation failed: {result.stderr}")
                return JsonResponse({'error': f'Compilation failed: {result.stderr}'}, status=500)

            # Load compiled contract
            if not os.path.exists(combined_json_path):
                logger.error(f"Compiled contract file not found: {combined_json_path}")
                return JsonResponse({'error': f'Compiled contract file not found: {combined_json_path}'}, status=500)

            try:
                with open(combined_json_path, 'r') as f:
                    compiled_contracts = json.load(f)
                    logger.info(f"Compiled contracts keys: {compiled_contracts['contracts'].keys()}")

                    # Identify the correct contract key
                    contract_key = None
                    for key in compiled_contracts['contracts'].keys():
                        if key.endswith(':MyToken'):
                            contract_key = key
                            break

                    if not contract_key:
                        logger.error(f"Contract key not found in compiled contracts")
                        return JsonResponse({'error': 'Contract key not found in compiled contracts'}, status=500)
                    
                    contract_data = compiled_contracts['contracts'][contract_key]
            except json.JSONDecodeError as e:
                logger.error(f"Error parsing JSON from compiled contract: {e}")
                return JsonResponse({'error': 'Error parsing JSON from compiled contract'}, status=500)

            abi = json.loads(contract_data['abi'])
            bytecode = contract_data['bin']

            # Connect to local Ethereum node
            w3 = Web3(Web3.HTTPProvider('http://159.89.106.101:8545'))

            # Check if connected
            if not w3.is_connected():
                logger.error('Could not connect to Ethereum node.')
                return JsonResponse({'error': 'Could not connect to Ethereum node.'}, status=500)

            # Check for available accounts
            if not w3.eth.accounts:
                logger.error('No Ethereum accounts found.')
                return JsonResponse({'error': 'No Ethereum accounts found.'}, status=500)

            # Get default account for deployment
            w3.eth.default_account = w3.eth.accounts[0]

            # Create web3 contract instance
            Web3Contract = w3.eth.contract(abi=abi, bytecode=bytecode)

            # Deploy contract
            try:
                initial_owner = w3.eth.default_account
                estimated_gas = Web3Contract.constructor(token_name, token_symbol, initial_supply).estimate_gas({'from': w3.eth.default_account})

                # Log estimated gas
                logger.info(f"Estimated gas: {estimated_gas}")

                # Setting a higher gas limit to avoid "exceeds allowance" issue
                gas_limit = estimated_gas + 500000  # Increased gas limit

                tx_hash = Web3Contract.constructor(token_name, token_symbol, initial_supply).transact({'from': w3.eth.default_account, 'gas': gas_limit})
                tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
                logger.info(f"Contract deployed at address: {tx_receipt.contractAddress}")

                # Save contract details in the database
                Contract.objects.create(
                    address=tx_receipt.contractAddress,
                    abi=json.dumps(abi)
                )

                response_data = {
                    'deployed': True,
                    'contract_address': tx_receipt.contractAddress
                }

                return JsonResponse(response_data)
            except ValueError as e:
                logger.error(f"Error deploying contract: {e}")
                if 'exceeds block gas limit' in str(e):
                    return JsonResponse({'error': 'Gas required exceeds block gas limit. Please increase the gas limit.'}, status=500)
                else:
                    return JsonResponse({'error': f'Error deploying contract: {str(e)}'}, status=500)
            except Exception as e:
                logger.error(f"Error deploying contract: {str(e)}")
                return JsonResponse({'error': f'Error deploying contract: {str(e)}'}, status=500)

        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'An unexpected error occurred.'}, status=500)

    return JsonResponse({'error': 'Invalid request method.'}, status=400)
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .models import Transaction

@csrf_exempt
def receive_transaction(request):
    if request.method == 'POST':
        transaction_data = json.loads(request.body)
        # Save transaction and broadcast
        transaction = Transaction.objects.create(**transaction_data)
        broadcast_transaction_update(transaction)
        return JsonResponse({'status': 'Transaction received and broadcasted'})
    return JsonResponse({'error': 'Invalid request method'}, status=400)
import requests

def get_node_status(node_url):
    try:
        response = requests.get(f"{node_url}/api/latest_transaction/")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching node status: {e}")
        return None

def check_node_synchronization():
    node_urls = ["http://node1.url", "http://node2.url"]  # Add your node URLs
    latest_transactions = [get_node_status(url) for url in node_urls]
    
    is_synchronized = all(tx == latest_transactions[0] for tx in latest_transactions)
    return {
        "is_synchronized": is_synchronized,
        "latest_transactions": latest_transactions
    }

def get_network_status(request):
    sync_status = check_node_synchronization()
    return JsonResponse(sync_status)
# quantumapp/views.py

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import requests

NODE_URLS = [
    "https://app.cashewstable.com",
    "http://161.35.219.10:2020"  # Ensure this is the correct address
]

def get_node_latest_transaction(node_url):
    try:
        response = requests.get(f"{node_url}/api/latest_transaction/")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching latest transaction from {node_url}: {e}")
        return None

def get_node_transaction_pool(node_url):
    try:
        response = requests.get(f"{node_url}/api/transaction_pool/")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching transaction pool from {node_url}: {e}")
        return None

def check_node_synchronization():
    if len(NODE_URLS) < 2:
        return {
            "is_synchronized": False,
            "message": "Not enough nodes to check synchronization",
            "nodes": NODE_URLS,
        }

    node1_url = NODE_URLS[0]
    node2_url = NODE_URLS[1] if len(NODE_URLS) > 1 else None

    node1_latest_tx = get_node_latest_transaction(node1_url)
    node1_tx_pool = get_node_transaction_pool(node1_url)
    node2_latest_tx = get_node_latest_transaction(node2_url) if node2_url else None
    node2_tx_pool = get_node_transaction_pool(node2_url) if node2_url else None

    is_synchronized = node1_latest_tx == node2_latest_tx
    return {
        "is_synchronized": is_synchronized,
        "node1_latest_transaction": node1_latest_tx,
        "node1_transaction_pool": node1_tx_pool,
        "node2_latest_transaction": node2_latest_tx,
        "node2_transaction_pool": node2_tx_pool,
    }

@csrf_exempt
def get_network_status(request):
    sync_status = check_node_synchronization()
    print(f"Synchronization status: {sync_status}")
    return JsonResponse(sync_status)
def get_active_nodes():
    return NODE_URLS

def check_node_synchronization():
    nodes = get_active_nodes()

    if len(nodes) < 2:
        return {
            "is_synchronized": False,
            "message": "Not enough nodes to check synchronization",
            "nodes": nodes,
        }

    node1_url = nodes[0]
    node2_url = nodes[1]

    node1_latest_tx = get_node_latest_transaction(node1_url)
    node1_tx_pool = get_node_transaction_pool(node1_url)
    node2_latest_tx = get_node_latest_transaction(node2_url)
    node2_tx_pool = get_node_transaction_pool(node2_url)

    is_synchronized = node1_latest_tx == node2_latest_tx
    return {
        "is_synchronized": is_synchronized,
        "node1_latest_transaction": node1_latest_tx,
        "node1_transaction_pool": node1_tx_pool,
        "node2_latest_transaction": node2_latest_tx,
        "node2_transaction_pool": node2_tx_pool,
    }
import base64
import hashlib
from mnemonic import Mnemonic
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import binascii
import os
def generate_wallet():
    # Generate a new mnemonic phrase
    mnemo = Mnemonic("english")
    mnemonic_phrase = mnemo.generate(strength=128)
    seed = mnemo.to_seed(mnemonic_phrase)

    # Generate a private key using the seed
    private_key = binascii.hexlify(seed[:32]).decode('utf-8')

    # Generate an Ethereum account from the private key
    account = Account.from_key(private_key)

    return {
        "mnemonic": mnemonic_phrase,
        "private_key": private_key,
        "public_key": account.key.hex(),
        "address": account.address
    }
def import_wallet_from_mnemonic(mnemonic_phrase):
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic_phrase)

    # Generate a private key using the seed
    private_key = binascii.hexlify(seed[:32]).decode('utf-8')

    # Generate an Ethereum account from the private key
    account = Account.from_key(private_key)

    return {
        "mnemonic": mnemonic_phrase,
        "private_key": private_key,
        "public_key": account.key.hex(),
        "address": account.address
    }



@csrf_exempt
def import_wallet(request):
    if request.method == 'POST':
        mnemonic_phrase = request.POST.get('mnemonic')
        mnemo = Mnemonic("english")
        if mnemo.check(mnemonic_phrase):
            wallet_data = import_wallet_from_mnemonic(mnemonic_phrase)
            user, created = User.objects.get_or_create(username=wallet_data['public_key'])
            if created:
                alias = generate_unique_alias(wallet_data['public_key'])
                wallet = Wallet(
                    user=user, 
                    public_key=wallet_data['public_key'], 
                    private_key=wallet_data['private_key'], 
                    alias=alias,
                    address=wallet_data['address']
                )
                wallet.save()
            else:
                wallet = Wallet.objects.get(user=user)

            user = authenticate(username=wallet_data['public_key'], password=None)
            login(request, user)

            return JsonResponse({
                'message': 'Wallet imported successfully',
                'public_key': wallet.public_key,
                'address': wallet.address
            })
        else:
            return JsonResponse({'error': 'Invalid mnemonic phrase'}, status=400)
    return JsonResponse({'error': 'Only POST method allowed'}, status=400)

def get_wallet_balance(public_key_pem):
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        sha256 = hashlib.sha256(public_key_bytes).digest()
        keccak = Web3.keccak(sha256)
        address = Web3.to_checksum_address(keccak[-20:])
        w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:32773'))  # Polygon CDK endpoint
        if not w3.is_connected():
            return None
        balance = w3.eth.get_balance(address)
        balance_eth = w3.from_wei(balance, 'ether')
        return balance_eth
    except Exception as e:
        print(f"Error getting wallet balance: {e}")
        return None
@csrf_exempt
def deploy_contract(request):
    if request.method == 'POST':
        try:
            if not request.POST:
                return JsonResponse({'error': 'Empty request body.'}, status=400)

            logger.info(f"Request body: {request.POST}")

            token_name = request.POST.get('name')
            token_symbol = request.POST.get('symbol')
            initial_supply = request.POST.get('initialSupply')

            if not initial_supply:
                return JsonResponse({'error': 'Initial supply is required.'}, status=400)

            initial_supply = int(initial_supply)

            contract_path = '/home/myuser/myquantumproject/solc/MyToken.sol'
            openzeppelin_path = '/home/myuser/myquantumproject/node_modules/@openzeppelin/contracts'
            chainlink_path = '/home/myuser/myquantumproject/node_modules/@chainlink/contracts'
            combined_json_path = '/home/myuser/myquantumproject/solc/combined.json/combined.json'

            # Compile the contract using solc with OpenZeppelin and Chainlink imports
            compile_command = [
                'solc', '--combined-json', 'abi,bin', '--optimize', '--overwrite',
                '--include-path', openzeppelin_path, '--include-path', chainlink_path,
                '--base-path', '/home/myuser/myquantumproject/solc', contract_path,
                '-o', '/home/myuser/myquantumproject/solc/combined.json'
            ]
            result = subprocess.run(compile_command, capture_output=True, text=True, cwd='/home/myuser/myquantumproject/solc')
            if result.returncode != 0:
                logger.error(f"Compilation failed: {result.stderr}")
                return JsonResponse({'error': f'Compilation failed: {result.stderr}'}, status=500)

            # Load compiled contract
            if not os.path.exists(combined_json_path):
                logger.error(f"Compiled contract file not found: {combined_json_path}")
                return JsonResponse({'error': f'Compiled contract file not found: {combined_json_path}'}, status=500)

            try:
                with open(combined_json_path, 'r') as f:
                    compiled_contracts = json.load(f)
                    logger.info(f"Compiled contracts keys: {compiled_contracts['contracts'].keys()}")

                    # Identify the correct contract key
                    contract_key = None
                    for key in compiled_contracts['contracts'].keys():
                        if key.endswith(':MyToken'):
                            contract_key = key
                            break

                    if not contract_key:
                        logger.error(f"Contract key not found in compiled contracts")
                        return JsonResponse({'error': 'Contract key not found in compiled contracts'}, status=500)
                    
                    contract_data = compiled_contracts['contracts'][contract_key]
            except json.JSONDecodeError as e:
                logger.error(f"Error parsing JSON from compiled contract: {e}")
                return JsonResponse({'error': 'Error parsing JSON from compiled contract'}, status=500)

            abi = json.loads(contract_data['abi'])
            bytecode = contract_data['bin']

            # Connect to local Ethereum node
            w3 = Web3(Web3.HTTPProvider('http://159.89.106.101:8545'))

            # Check if connected
            if not w3.is_connected():
                logger.error('Could not connect to Ethereum node.')
                return JsonResponse({'error': 'Could not connect to Ethereum node.'}, status=500)

            # Check for available accounts
            if not w3.eth.accounts:
                logger.error('No Ethereum accounts found.')
                return JsonResponse({'error': 'No Ethereum accounts found.'}, status=500)

            # Get default account for deployment
            w3.eth.default_account = w3.eth.accounts[0]

            # Create web3 contract instance
            Web3Contract = w3.eth.contract(abi=abi, bytecode=bytecode)

            # Deploy contract
            try:
                initial_owner = w3.eth.default_account
                estimated_gas = Web3Contract.constructor(token_name, token_symbol, initial_supply).estimate_gas({'from': w3.eth.default_account})

                # Log estimated gas
                logger.info(f"Estimated gas: {estimated_gas}")

                # Setting a higher gas limit to avoid "exceeds allowance" issue
                gas_limit = estimated_gas + 500000  # Increased gas limit

                tx_hash = Web3Contract.constructor(token_name, token_symbol, initial_supply).transact({'from': w3.eth.default_account, 'gas': gas_limit})
                tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
                logger.info(f"Contract deployed at address: {tx_receipt.contractAddress}")

                # Save contract details in the database
                Contract.objects.create(
                    address=tx_receipt.contractAddress,
                    abi=json.dumps(abi)
                )

                response_data = {
                    'deployed': True,
                    'contract_address': tx_receipt.contractAddress
                }

                return JsonResponse(response_data)
            except ValueError as e:
                logger.error(f"Error deploying contract: {e}")
                if 'exceeds block gas limit' in str(e):
                    return JsonResponse({'error': 'Gas required exceeds block gas limit. Please increase the gas limit.'}, status=500)
                else:
                    return JsonResponse({'error': f'Error deploying contract: {str(e)}'}, status=500)
            except Exception as e:
                logger.error(f"Error deploying contract: {str(e)}")
                return JsonResponse({'error': f'Error deploying contract: {str(e)}'}, status=500)

        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'An unexpected error occurred.'}, status=500)

    return JsonResponse({'error': 'Invalid request method.'}, status=400)
import os
import json
import logging
import subprocess
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from web3 import Web3
from quantumapp.models import Contract

logger = logging.getLogger(__name__)

@csrf_exempt
def deploy_contract(request):
    if request.method == 'POST':
        try:
            if not request.POST:
                return JsonResponse({'error': 'Empty request body.'}, status=400)

            logger.info(f"Request body: {request.POST}")

            token_name = request.POST.get('name')
            token_symbol = request.POST.get('symbol')
            initial_supply = request.POST.get('initialSupply')

            if not initial_supply:
                return JsonResponse({'error': 'Initial supply is required.'}, status=400)

            initial_supply = int(initial_supply)

            contract_path = '/home/myuser/myquantumproject/solc/MyToken.sol'
            openzeppelin_path = '/home/myuser/myquantumproject/node_modules/@openzeppelin/contracts'
            chainlink_path = '/home/myuser/myquantumproject/node_modules/@chainlink/contracts'
            combined_json_path = '/home/myuser/myquantumproject/solc/combined.json/combined.json'

            # Compile the contract using solc with OpenZeppelin and Chainlink imports
            compile_command = [
                'solc', '--combined-json', 'abi,bin', '--optimize', '--overwrite',
                '--include-path', openzeppelin_path, '--include-path', chainlink_path,
                '--base-path', '/home/myuser/myquantumproject/solc', contract_path,
                '-o', '/home/myuser/myquantumproject/solc/combined.json'
            ]
            result = subprocess.run(compile_command, capture_output=True, text=True, cwd='/home/myuser/myquantumproject/solc')
            if result.returncode != 0:
                logger.error(f"Compilation failed: {result.stderr}")
                return JsonResponse({'error': f'Compilation failed: {result.stderr}'}, status=500)

            # Load compiled contract
            if not os.path.exists(combined_json_path):
                logger.error(f"Compiled contract file not found: {combined_json_path}")
                return JsonResponse({'error': f'Compiled contract file not found: {combined_json_path}'}, status=500)

            try:
                with open(combined_json_path, 'r') as f:
                    compiled_contracts = json.load(f)
                    logger.info(f"Compiled contracts keys: {compiled_contracts['contracts'].keys()}")

                    # Identify the correct contract key
                    contract_key = None
                    for key in compiled_contracts['contracts'].keys():
                        if key.endswith(':MyToken'):
                            contract_key = key
                            break

                    if not contract_key:
                        logger.error(f"Contract key not found in compiled contracts")
                        return JsonResponse({'error': 'Contract key not found in compiled contracts'}, status=500)
                    
                    contract_data = compiled_contracts['contracts'][contract_key]
            except json.JSONDecodeError as e:
                logger.error(f"Error parsing JSON from compiled contract: {e}")
                return JsonResponse({'error': 'Error parsing JSON from compiled contract'}, status=500)

            abi = json.loads(contract_data['abi']) if isinstance(contract_data['abi'], str) else contract_data['abi']
            bytecode = contract_data['bin']
            w3 = Web3(Web3.HTTPProvider('http://161.35.219.10:32787'))

            # Check if connected
            if not w3.is_connected():
                logger.error('Could not connect to Ethereum node.')
                return JsonResponse({'error': 'Could not connect to Ethereum node.'}, status=500)

            # Check for available accounts
            if not w3.eth.accounts:
                logger.error('No Ethereum accounts found.')
                return JsonResponse({'error': 'No Ethereum accounts found.'}, status=500)

            # Get default account for deployment
            w3.eth.default_account = w3.eth.accounts[0]

            # Create web3 contract instance
            Web3Contract = w3.eth.contract(abi=abi, bytecode=bytecode)

            # Deploy contract
            try:
                initial_owner = w3.eth.default_account
                estimated_gas = Web3Contract.constructor(token_name, token_symbol, initial_supply).estimate_gas({'from': w3.eth.default_account})

                # Log estimated gas
                logger.info(f"Estimated gas: {estimated_gas}")

                # Setting a higher gas limit to avoid "exceeds allowance" issue
                gas_limit = estimated_gas + 500000  # Increased gas limit

                tx_hash = Web3Contract.constructor(token_name, token_symbol, initial_supply).transact({'from': w3.eth.default_account, 'gas': gas_limit})
                tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
                logger.info(f"Contract deployed at address: {tx_receipt.contractAddress}")

                # Save contract details in the database
                Contract.objects.create(
                    address=tx_receipt.contractAddress,
                    abi=json.dumps(abi) if isinstance(abi, dict) else abi
                )

                response_data = {
                    'deployed': True,
                    'contract_address': tx_receipt.contractAddress
                }

                return JsonResponse(response_data)
            except ValueError as e:
                logger.error(f"Error deploying contract: {e}")
                if 'exceeds block gas limit' in str(e):
                    return JsonResponse({'error': 'Gas required exceeds block gas limit. Please increase the gas limit.'}, status=500)
                else:
                    return JsonResponse({'error': f'Error deploying contract: {str(e)}'}, status=500)
            except Exception as e:
                logger.error(f"Error deploying contract: {str(e)}")
                return JsonResponse({'error': f'Error deploying contract: {str(e)}'}, status=500)

        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'An unexpected error occurred.'}, status=500)

    return JsonResponse({'error': 'Invalid request method.'}, status=400)

           
import os
import json
import subprocess
import logging

from web3 import Web3
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Contract

logger = logging.getLogger(__name__)

from web3 import Web3, Account
from web3.middleware import geth_poa_middleware
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Wallet  # Assuming you have a Wallet model to store private keys
import subprocess
import os
import json
import logging
import re
import os
import subprocess
import json
import logging
from web3 import Web3
from web3.middleware import geth_poa_middleware
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

logger = logging.getLogger(__name__)

@csrf_exempt
@login_required
def deploy_contract(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            logger.info(f"Request body: {data}")

            token_name = data.get('name')
            token_symbol = data.get('symbol')
            initial_supply = data.get('initialSupply')
            network = data.get('network')

            if not token_name or not token_symbol or not initial_supply or not network:
                return JsonResponse({'error': 'Name, symbol, initial supply, and network are required.'}, status=400)

            initial_supply = int(initial_supply)

            # Fetch the wallet of the currently authenticated user
            user_wallet = Wallet.objects.get(user=request.user)

            private_key = user_wallet.private_key
            wallet_address = user_wallet.address

            # Your node URL (e.g., Infura, Alchemy, or local node)
            node_url = 'https://polygon-rpc.com'
            web3 = Web3(Web3.HTTPProvider(node_url))

            if not web3.is_connected():
                return JsonResponse({'error': 'Unable to connect to the network'}, status=500)

            account = web3.eth.account.from_key(private_key)

            # Compile the contract
            base_path = '/home/myuser/myquantumproject'
            contract_path = os.path.join(base_path, 'solc', 'MyToken.sol')
            openzeppelin_path = os.path.join(base_path, 'node_modules', '@openzeppelin', 'contracts')
            chainlink_path = os.path.join(base_path, 'node_modules', '@chainlink', 'contracts')
            combined_json_path = os.path.join(base_path, 'solc', 'combined.json', 'combined.json')

            compile_command = [
                'solc', '--combined-json', 'abi,bin', '--optimize', '--overwrite',
                '--include-path', openzeppelin_path, '--include-path', chainlink_path,
                '--base-path', os.path.join(base_path, 'solc'), contract_path,
                '-o', os.path.join(base_path, 'solc', 'combined.json')
            ]
            result = subprocess.run(compile_command, capture_output=True, text=True, cwd=os.path.join(base_path, 'solc'))
            if result.returncode != 0:
                logger.error(f"Compilation failed: {result.stderr}")
                return JsonResponse({'error': f'Compilation failed: {result.stderr}'}, status=500)

            # Load compiled contract
            if not os.path.exists(combined_json_path):
                logger.error(f"Compiled contract file not found: {combined_json_path}")
                return JsonResponse({'error': f'Compiled contract file not found: {combined_json_path}'}, status=500)

            try:
                with open(combined_json_path, 'r') as f:
                    compiled_contracts = json.load(f)
                    logger.info(f"Compiled contracts keys: {compiled_contracts['contracts'].keys()}")

                    # Identify the correct contract key
                    contract_key = None
                    for key in compiled_contracts['contracts'].keys():
                        if key.endswith(':MyToken'):
                            contract_key = key
                            break

                    if not contract_key:
                        logger.error(f"Contract key not found in compiled contracts")
                        return JsonResponse({'error': 'Contract key not found in compiled contracts'}, status=500)

                    contract_data = compiled_contracts['contracts'][contract_key]
            except json.JSONDecodeError as e:
                logger.error(f"Error parsing JSON from compiled contract: {e}")
                return JsonResponse({'error': 'Error parsing JSON from compiled contract'}, status=500)

            abi = json.loads(contract_data['abi']) if isinstance(contract_data['abi'], str) else contract_data['abi']
            bytecode = contract_data['bin']

            # Create the contract deployment transaction manually
            MyToken = web3.eth.contract(abi=abi, bytecode=bytecode)
            nonce = web3.eth.get_transaction_count(account.address)
            transaction = {
                'chainId': web3.eth.chain_id,
                'gas': 2000000,
                'gasPrice': web3.to_wei('50', 'gwei'),
                'nonce': nonce,
                'data': MyToken.constructor(token_name, token_symbol, initial_supply).data_in_transaction,
                'from': account.address,
            }

            # Sign the transaction
            signed_txn = account.sign_transaction(transaction)

            # Send the transaction
            tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)

            # Wait for the transaction receipt
            tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

            if tx_receipt['status'] == 1:
                contract_address = tx_receipt['contractAddress']
                response_data = {
                    'transactionHash': tx_hash.hex(),
                    'contractAddress': contract_address,
                    'abi': abi,
                    'bytecode': bytecode,
                    'message': 'Contract deployed successfully'
                }
                return JsonResponse(response_data)
            else:
                return JsonResponse({'error': 'Contract deployment failed'}, status=500)

        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'An unexpected error occurred.'}, status=500)

    return JsonResponse({'error': 'Invalid request method.'}, status=400)


import threading
@csrf_exempt
@login_required
def mine_block(request, shard_id):
    from decimal import Decimal

    print(f"[INFO] Starting mining process for shard_id: {shard_id}")
    try:
        shard = Shard.objects.get(id=shard_id)
        print(f"[INFO] Shard found: {shard}")
    except Shard.DoesNotExist:
        print("[ERROR] Shard not found")
        return JsonResponse({'error': 'Shard not found'}, status=404)

    transactions = Transaction.objects.filter(is_approved=False, shard=shard)
    print(f"[DEBUG] Found {transactions.count()} transactions to process")
    
    previous_block_hash = '0000000000000000000000000000000000000000000000000000000000000000'
    proof = proof_of_work(previous_block_hash)
    miner_wallet = Wallet.objects.get(user=request.user)
    print(f"[INFO] Miner wallet found: {miner_wallet}")

    total_fees = Decimal(0)
    for transaction in transactions:
        try:
            print(f"[DEBUG] Validating transaction {transaction.hash}")
            if validate_transaction(transaction):
                print(f"[DEBUG] Approving transaction {transaction.hash}")
                approve_transaction(transaction)
                total_fees += transaction.fee
                print(f"[INFO] Transaction {transaction.hash} approved")
            else:
                print(f"[DEBUG] Transaction {transaction.hash} is not valid")
        except ValueError as e:
            print(f"[ERROR] Transaction {transaction.hash} approval failed: {e}")

    current_time = timezone.now()
    genesis_time = timezone.datetime(2020, 1, 1, tzinfo=timezone.utc)
    years_elapsed = (current_time - genesis_time).days / 365.25
    reward_halvings = int(years_elapsed // 4)
    block_reward = Decimal(50) / (2 ** reward_halvings)
    total_reward = block_reward + total_fees

    print(f"[INFO] Total reward to be added to wallet: {total_reward}")
    miner_wallet.balance += total_reward
    miner_wallet.save()
    print(f"[INFO] Updated wallet balance: {miner_wallet.balance}")

    reward_transaction = Transaction(
        hash=generate_unique_hash(),
        sender=miner_wallet,
        receiver=miner_wallet,
        amount=block_reward,
        fee=Decimal(0),
        signature="reward_signature",
        timestamp=timezone.now(),
        is_approved=True,
        shard=shard
    )
    reward_transaction.save()

    print(f"[INFO] Block mined successfully: Reward = {block_reward}, Fees = {total_fees}, Total reward = {total_reward}")
    return JsonResponse({
        'message': f'Block mined successfully in shard {shard.name}',
        'proof': proof,
        'reward': block_reward,
        'fees': total_fees,
        'total_reward': total_reward
    })
class CustomMiner:
    def __init__(self, miner_id, resource_capability, is_system=False):
        self.id = miner_id
        self.resource_capability = resource_capability
        self.assigned_task = None
        self.contribution = 0
        self.reward = 0
        self.task_completion_times = []
        self.tasks_assigned = 0
        self.tasks_completed = 0
        self.is_system = is_system

    def assign_task(self, task):
        self.assigned_task = task
        self.tasks_assigned += 1
        print(f"Miner {self.id} assigned to {task.task_id} with difficulty {task.difficulty} and resource requirement {task.resource_requirement}")

    def add_contribution(self, contribution):
        self.contribution += contribution

    def add_reward(self, reward):
        self.reward += reward
        print(f"Miner {self.id} received reward: {reward}")

    def complete_task(self, task, completion_time):
        self.task_completion_times.append(completion_time)
        self.tasks_completed += 1
        self.add_contribution(calculate_contribution(self, task))
def get_miners():
    db_miners = Miner.objects.all()
    miners = []
    system_miner = CustomMiner(miner_id="system", resource_capability=float('inf'), is_system=True)
    miners.append(system_miner)
    
    for db_miner in db_miners:
        miner = CustomMiner(
            miner_id=db_miner.user.id,
            resource_capability=db_miner.resource_capability
        )
        miner.contribution = db_miner.contribution
        miner.reward = db_miner.reward
        miner.tasks_assigned = db_miner.tasks_assigned
        miner.tasks_completed = db_miner.tasks_completed
        miner.task_completion_times = db_miner.task_completion_times
        miners.append(miner)
    
    return miners
from decimal import Decimal
import hashlib
import time
from django.utils import timezone
from django.db.models import Sum
from django.http import JsonResponse

# Constants for the blockchain
GENESIS_TIME = timezone.datetime(2020, 1, 1, tzinfo=timezone.utc)
INITIAL_REWARD = Decimal(50)
HALVING_INTERVAL_YEARS = 4
TOTAL_SUPPLY_CAP = Decimal(1_000_000_000)
DEFAULT_DIFFICULTY = 1

def adjust_difficulty_and_reward():
    current_time = timezone.now()
    years_elapsed = (current_time - GENESIS_TIME).days / 365.25
    reward_halvings = int(years_elapsed // HALVING_INTERVAL_YEARS)
    block_reward = INITIAL_REWARD / (2 ** reward_halvings)

    # Adjust difficulty based on hashrate
    target_time_per_block = 10 * 60  # 10 minutes
    actual_time_per_block = 600  # Placeholder, should be calculated based on actual block times
    difficulty_adjustment_factor = target_time_per_block / actual_time_per_block
    difficulty = max(1, int(difficulty_adjustment_factor * DEFAULT_DIFFICULTY))  # Ensure difficulty is at least 1

    return block_reward, difficulty

def proof_of_work(last_hash):
    proof = 0
    _, difficulty = adjust_difficulty_and_reward()
    while not valid_proof(last_hash, proof, difficulty):
        proof += 1
    return proof

def mine_single_block(user, shard_id):
    global mining_statistics
    try:
        shard = Shard.objects.get(id=shard_id)
    except Shard.DoesNotExist:
        print("Shard not found")
        return JsonResponse({'error': 'Shard not found'}, status=404)

    transactions = Transaction.objects.filter(is_approved=False, shard=shard)
    previous_block_hash = '0000000000000000000000000000000000000000000000000000000000000000'
    proof = proof_of_work(previous_block_hash)
    miner_wallet = Wallet.objects.get(user=user)
    system_wallet = ensure_system_wallet()

    total_fees = Decimal(0)
    for transaction in transactions:
        print(f"Validating transaction {transaction.hash}")
        if validate_transaction(transaction):
            transaction.is_approved = True
            transaction.save()
            total_fees += Decimal(transaction.fee)
            print(f"Transaction {transaction.hash} approved. Fee: {transaction.fee}")
        else:
            print(f"Transaction {transaction.hash} was not approved")

    print(f"Total fees from approved transactions: {total_fees}")

    current_time = timezone.now()
    block_reward, _ = adjust_difficulty_and_reward()
    total_reward = block_reward + total_fees

    print(f"Calculated block reward: {block_reward}")
    print(f"Total reward (block reward + total fees): {total_reward}")

    # Calculate current supply excluding the system wallet
    current_supply = Wallet.objects.exclude(user=system_wallet.user).aggregate(Sum('balance'))['balance__sum'] or Decimal(0)
    print(f"Current supply: {current_supply}")
    if current_supply + total_reward > TOTAL_SUPPLY_CAP:
        total_reward = TOTAL_SUPPLY_CAP - current_supply
        block_reward = total_reward - total_fees
        print(f"Adjusted total reward due to supply cap: {total_reward}")
        print(f"Adjusted block reward due to supply cap: {block_reward}")

    if total_reward <= 0:
        print(f"No reward due to supply cap. Skipping block mining.")
        return JsonResponse({
            'message': 'No reward due to supply cap. Skipping block mining.',
            'proof': proof,
            'reward': 0,
            'fees': total_fees,
            'total_reward': 0
        })

    print(f"Before mining, miner wallet balance: {miner_wallet.balance}")
    print(f"System wallet balance: {system_wallet.balance}")
    print(f"Final Block Reward: {block_reward}, Total Fees: {total_fees}, Total Reward: {total_reward}")

    miner_wallet.balance += total_reward
    miner_wallet.save()
    print(f"After mining, miner wallet balance: {miner_wallet.balance}")

    new_block_hash = generate_unique_hash()
    new_block = Block(hash=new_block_hash, previous_hash=previous_block_hash, timestamp=current_time)
    dag[new_block_hash] = new_block
    if previous_block_hash in dag:
        dag[previous_block_hash].children.append(new_block)

    reward_transaction = Transaction(
        hash=generate_unique_hash(),
        sender=system_wallet,
        receiver=miner_wallet,
        amount=block_reward,
        fee=Decimal(0),
        signature="reward_signature",
        timestamp=current_time,
        is_approved=True,
        shard=shard
    )
    reward_transaction.save()

    print(f"Reward Transaction Amount: {reward_transaction.amount}, Fee: {reward_transaction.fee}")

    mining_statistics["blocks_mined"] += 1
    mining_statistics["total_rewards"] += float(total_reward)
    print(f"Mined block. Hashrate: {mining_statistics['hashrate']}, Blocks Mined: {mining_statistics['blocks_mined']}, Total Rewards: {mining_statistics['total_rewards']}")

    ordered_blocks = order_blocks(dag)
    well_connected_subset = select_well_connected_subset(dag)

    print(f"Ordered Blocks: {[block.hash for block in ordered_blocks]}")
    print(f"Well Connected Subset: {[block.hash for block in well_connected_subset]}")

    record_miner_contribution(miner_wallet, reward_transaction)
    distribute_rewards(get_miners(), total_reward)

    return JsonResponse({
        'message': f'Block mined successfully in shard {shard.name}',
        'proof': proof,
        'reward': block_reward,
        'fees': total_fees,
        'total_reward': total_reward
    })

def distribute_rewards(miners, total_reward):
    total_contribution = sum(miner.contribution for miner in miners)
    if total_contribution == 0:
        print("[WARNING] No contributions found. Skipping reward distribution.")
        return

    for miner in miners:
        miner_reward = (miner.contribution / total_contribution) * total_reward if total_contribution else 0
        miner.add_reward(miner_reward)
        miner.save()

def ensure_system_wallet():
    system_user, _ = User.objects.get_or_create(username='system')
    system_wallet, _ = Wallet.objects.get_or_create(user=system_user, defaults={'balance': Decimal(0)})
    if system_wallet.balance < Decimal(1_000_000_000):
        system_wallet.balance = Decimal(1_000_000_000)  # Set to unlimited supply for reward generation
        system_wallet.save()
    return system_wallet

def generate_unique_hash():
    return hashlib.sha256(str(timezone.now()).encode('utf-8')).hexdigest()

def valid_proof(last_hash, proof, difficulty=4):
    guess = f'{last_hash}{proof}'.encode()
    guess_hash = hashlib.sha256(guess).hexdigest()
    return guess_hash[:difficulty] == "0" * difficulty

def validate_transaction(transaction):
    if not transaction.signature:
        print(f"[ERROR] Transaction {transaction.hash} invalid: missing signature")
        return False

    if transaction.sender.balance < (transaction.amount + transaction.fee):
        print(f"[ERROR] Transaction {transaction.hash} invalid: insufficient balance. Sender balance: {transaction.sender.balance}, Transaction amount: {transaction.amount}, Fee: {transaction.fee}")
        return False

    if Transaction.objects.filter(hash=transaction.hash, is_approved=True).exists():
        print(f"[ERROR] Transaction {transaction.hash} invalid: duplicate transaction")
        return False

    print(f"[DEBUG] Transaction {transaction.hash} is valid")
    return True

# quantumapp/views.py

from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from .models import Wallet, Contract, Shard, Transaction
from .forms import ContractForm
from decimal import Decimal
from django.utils import timezone
from django.http import JsonResponse

@csrf_exempt
def home(request):
    contract, created = Contract.objects.get_or_create(
        pk=1, 
        defaults={
            'address': '',  
            'abi': '[]'
        }
    )

    if request.method == 'POST':
        form = ContractForm(request.POST, instance=contract)
        if form.is_valid():
            form.save()
            return redirect('deploy_contract')
    else:
        form = ContractForm(instance=contract)

    # Handle transaction creation if form is submitted
    if request.method == 'POST' and 'create_transaction' in request.POST:
        try:
            sender_address = request.POST.get('sender')
            receiver_address = request.POST.get('receiver')
            amount = Decimal(request.POST.get('amount'))
            fee = Decimal(request.POST.get('fee'))

            if not sender_address or not receiver_address or not amount or not fee:
                return JsonResponse({'error': 'All fields (sender, receiver, amount, fee) are required'}, status=400)

            sender = Wallet.objects.get(address=sender_address)
            receiver = Wallet.objects.get(address=receiver_address)
            shard = Shard.objects.first()  # Assuming you have at least one shard

            if sender.balance < (amount + fee):
                return JsonResponse({'error': 'Insufficient balance'}, status=400)

            transaction = Transaction(
                sender=sender,
                receiver=receiver,
                amount=amount,
                fee=fee,
                timestamp=timezone.now(),
                shard=shard,
                is_approved=False  # Transaction starts as not approved
            )
            transaction.hash = transaction.create_hash()
            transaction.signature = "simulated_signature"  # You should replace this with actual signature logic
            transaction.save()

            # Attempt to approve the transaction immediately
            try:
                if validate_transaction(transaction):
                    approve_transaction(transaction)
                    message = 'Transaction created and approved'
                else:
                    message = 'Transaction created but not approved due to validation failure'
            except Exception as e:
                message = f'Transaction created but approval failed: {str(e)}'

            return JsonResponse({'message': message, 'transaction_hash': transaction.hash})

        except Wallet.DoesNotExist:
            return JsonResponse({'error': 'Wallet not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from .models import Wallet, Contract
from .forms import ContractForm
from .models import Transaction
from decimal import Decimal
from django.utils import timezone
from django.http import JsonResponse
@login_required
def some_view(request):
    try:
        wallet = Wallet.objects.get(user=request.user)
        wallet_address = wallet.address
    except Wallet.DoesNotExist:
        wallet_address = None  # Or handle this case appropriately

    return render(request, 'your_template.html', {
        'wallet_address': wallet_address,
    })

@csrf_exempt
def home(request):
    contract, created = Contract.objects.get_or_create(
        pk=1, 
        defaults={
            'address': '',  
            'abi': '[]'
        }
    )

    if request.method == 'POST' and 'contract_form' in request.POST:
        form = ContractForm(request.POST, instance=contract)
        if form.is_valid():
            form.save()
            return redirect('deploy_contract')
    else:
        form = ContractForm(instance=contract)

    # Handle transaction creation if form is submitted
    if request.method == 'POST' and 'create_transaction' in request.POST:
        try:
            sender_address = request.POST.get('sender')
            receiver_address = request.POST.get('receiver')
            amount = Decimal(request.POST.get('amount'))
            fee = Decimal(request.POST.get('fee'))

            if not sender_address or not receiver_address or not amount or not fee:
                return JsonResponse({'error': 'All fields (sender, receiver, amount, fee) are required'}, status=400)

            sender = Wallet.objects.get(address=sender_address)
            receiver = Wallet.objects.get(address=receiver_address)
            shard = Shard.objects.first()  # Assuming you have at least one shard

            if sender.balance < (amount + fee):
                return JsonResponse({'error': 'Insufficient balance'}, status=400)

            transaction = Transaction(
                sender=sender,
                receiver=receiver,
                amount=amount,
                fee=fee,
                timestamp=timezone.now(),
                shard=shard,
                is_approved=False  # Transaction starts as not approved
            )
            transaction.hash = transaction.create_hash()
            transaction.signature = "simulated_signature"  # You should replace this with actual signature logic
            transaction.save()

            # Attempt to approve the transaction immediately
            try:
                if validate_transaction(transaction):
                    approve_transaction(transaction)
                    message = 'Transaction created and approved'
                else:
                    message = 'Transaction created but not approved due to validation failure'
            except Exception as e:
                message = f'Transaction created but approval failed: {str(e)}'

            return JsonResponse({'message': message, 'transaction_hash': transaction.hash})

        except Wallet.DoesNotExist:
            return JsonResponse({'error': 'Wallet not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    # Fetch wallets excluding the system wallet
    wallets = Wallet.objects.exclude(user__username='system')  

    try:
        wallet = Wallet.objects.get(user=request.user)
        wallet_address = wallet.address
    except Wallet.DoesNotExist:
        wallet_address = None  # Handle appropriately

    context = {
        'form': form,
        'wallets': wallets,
        'wallet_address': wallet_address,
    }

    return render(request, 'index.html', context)

def broadcast_dag_update(dag):
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        'dag_updates',
        {
            'type': 'dag.update',
            'dag': json.dumps([block.__dict__ for block in dag.values()])
        }
    )
    # views.py

# views.py

from django.http import JsonResponse
from .models import Transaction, Node

def get_transaction_data(request):
    transactions = Transaction.objects.all()
    data = {
        'transactions': transactions.count(),
    }
    return JsonResponse(data)

def get_node_data(request):
    nodes = Node.objects.all()
    data = {
        'nodes': nodes.count(),
    }
    return JsonResponse(data)
# views.py

from django.http import JsonResponse
from .models import Transaction, Node

def get_transaction_data(request):
    transactions = Transaction.objects.all()
    data = {
        'transactions': transactions.count(),
    }
    return JsonResponse(data)

def get_node_data(request):
    nodes = Node.objects.all()
    data = {
        'nodes': nodes.count(),
    }
    return JsonResponse(data)
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from web3 import Web3
from web3.middleware import geth_poa_middleware

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from web3 import Web3
from web3.middleware import geth_poa_middleware
from .models import Wallet
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from web3 import Web3
from web3.middleware import geth_poa_middleware

# Generic ERC20 ABI
ERC20_ABI = [
    {
        "constant": True,
        "inputs": [],
        "name": "name",
        "outputs": [{"name": "", "type": "string"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [{"name": "spender", "type": "address"}, {"name": "value", "type": "uint256"}],
        "name": "approve",
        "outputs": [{"name": "", "type": "bool"}],
        "payable": False,
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "totalSupply",
        "outputs": [{"name": "", "type": "uint256"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [{"name": "from", "type": "address"}, {"name": "to", "type": "address"}, {"name": "value", "type": "uint256"}],
        "name": "transferFrom",
        "outputs": [{"name": "", "type": "bool"}],
        "payable": False,
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "symbol",
        "outputs": [{"name": "", "type": "string"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [{"name": "to", "type": "address"}, {"name": "value", "type": "uint256"}],
        "name": "transfer",
        "outputs": [{"name": "", "type": "bool"}],
        "payable": False,
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [{"name": "owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "", "type": "uint256"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [{"name": "amount", "type": "uint256"}],
        "name": "burn",
        "outputs": [],
        "payable": False,
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}],
        "name": "mint",
        "outputs": [],
        "payable": False,
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

@csrf_exempt
@login_required
def token_action(request):
    if request.method == 'POST':
        action_type = request.POST.get('action_type')
        amount = request.POST.get('amount')
        recipient = request.POST.get('recipient', None)
        contract_address = request.POST.get('contractAddress')
        wallet_address = request.POST.get('walletAddress')

        if not action_type or not amount or not wallet_address or not contract_address:
            return JsonResponse({'error': 'Missing required fields'}, status=400)

        amount = int(amount)

        w3 = Web3(Web3.HTTPProvider(POLYGON_CDK_URL))
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        contract = w3.eth.contract(address=contract_address, abi=ERC20_ABI)

        try:
            # Fetch private key from the wallet
            wallet = Wallet.objects.get(address=wallet_address)
            account_private_key = wallet.private_key
            account_address = wallet_address
            nonce = w3.eth.get_transaction_count(account_address)

            tx = None
            if action_type == 'send':
                tx = {
                    'from': account_address,
                    'to': contract_address,
                    'value': 0,
                    'gas': 70000,
                    'gasPrice': w3.to_wei('1', 'gwei'),
                    'nonce': nonce,
                    'data': contract.encodeABI(fn_name='transfer', args=[recipient, amount])
                }
            elif action_type == 'burn':
                tx = {
                    'from': account_address,
                    'to': contract_address,
                    'value': 0,
                    'gas': 70000,
                    'gasPrice': w3.to_wei('1', 'gwei'),
                    'nonce': nonce,
                    'data': contract.encodeABI(fn_name='burn', args=[amount])
                }
            elif action_type == 'mint':
                tx = {
                    'from': account_address,
                    'to': contract_address,
                    'value': 0,
                    'gas': 70000,
                    'gasPrice': w3.to_wei('1', 'gwei'),
                    'nonce': nonce,
                    'data': contract.encodeABI(fn_name='mint', args=[recipient, amount])
                }

            if tx:
                signed_tx = w3.eth.account.sign_transaction(tx, private_key=account_private_key)
                tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

                return JsonResponse({'success': True, 'message': f'Transaction {action_type} successful!', 'tx_hash': tx_hash.hex()})
            else:
                return JsonResponse({'error': 'Unsupported action type'}, status=400)
        except Wallet.DoesNotExist:
            return JsonResponse({'error': 'Wallet not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Only POST method is allowed'}, status=400)
import os
import subprocess
import json
import logging
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from web3 import Web3
from web3.middleware import geth_poa_middleware

logger = logging.getLogger(__name__)

from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from web3 import Web3
import json
import os
import subprocess

INFURA_URL = 'http://127.0.0.1:32796'
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:32796'))

@csrf_exempt
def get_contract_details(request):
    base_path = '/home/myuser/myquantumproject/my-token-project/backupcontract'
    contract_path = os.path.join(base_path, 'contracts', 'LiquidityPool.sol')
    openzeppelin_path = os.path.join(base_path, 'node_modules', '@openzeppelin', 'contracts')
    chainlink_path = os.path.join(base_path, 'node_modules', '@chainlink', 'contracts')
    combined_json_path = os.path.join(base_path, 'compiled', 'combined.json')

    compile_command = [
        'solc', '--combined-json', 'abi,bin', '--optimize', '--overwrite',
        '--include-path', openzeppelin_path, '--include-path', chainlink_path,
        '--base-path', os.path.join(base_path, 'contracts'), contract_path,
        '-o', os.path.join(base_path, 'compiled')
    ]
    result = subprocess.run(compile_command, capture_output=True, text=True)
    if result.returncode != 0:
        return JsonResponse({'error': f'Compilation failed: {result.stderr}'}, status=500)

    with open(combined_json_path, 'r') as f:
        compiled_contracts = json.load(f)

    contract_key = 'LiquidityPool.sol:LiquidityPool'
    contract_data = compiled_contracts['contracts'][contract_key]
    abi = json.loads(contract_data['abi']) if isinstance(contract_data['abi'], str) else contract_data['abi']
    bytecode = contract_data['bin']

    return JsonResponse({'abi': abi, 'bytecode': bytecode})

@csrf_exempt
def create_pool(request):
    if request.method == 'POST':
        try:
            token1_address = request.POST.get('token1Address')
            token2_address = request.POST.get('token2Address')
            price_feed1 = request.POST.get('priceFeed1')
            price_feed2 = request.POST.get('priceFeed2')
            use_native_coin = request.POST.get('useNativeCoin') == 'on'

            if not Web3.isAddress(token1_address):
                return JsonResponse({'error': 'Invalid Token 1 Address'}, status=400)
            if token2_address and not Web3.isAddress(token2_address):
                return JsonResponse({'error': 'Invalid Token 2 Address'}, status=400)
            if not Web3.isAddress(price_feed1):
                return JsonResponse({'error': 'Invalid Price Feed 1 Address'}, status=400)
            if price_feed2 and not Web3.isAddress(price_feed2):
                return JsonResponse({'error': 'Invalid Price Feed 2 Address'}, status=400)

            web3 = Web3(Web3.HTTPProvider(INFURA_URL))
            if not web3.is_connected():
                return JsonResponse({'error': 'Failed to connect to Ethereum network'}, status=500)

            account_address = request.session.get('account_address')
            private_key = request.session.get('private_key')
            if not account_address or not private_key:
                return JsonResponse({'error': 'User wallet not found'}, status=400)

            contract = web3.eth.contract(abi=CONTRACT_ABI, bytecode=CONTRACT_BYTECODE)
            construct_txn = contract.constructor(token1_address, token2_address, price_feed1, price_feed2).buildTransaction({
                'from': account_address,
                'nonce': web3.eth.get_transaction_count(account_address),
                'gas': 3000000,
                'gasPrice': web3.to_wei('10', 'gwei'),
            })

            signed_txn = web3.eth.account.signTransaction(construct_txn, private_key=private_key)
            txn_hash = web3.eth.sendRawTransaction(signed_txn.rawTransaction)
            txn_receipt = web3.eth.waitForTransactionReceipt(txn_hash)

            return JsonResponse({'message': 'Pool created successfully!', 'transaction_hash': txn_hash.hex(), 'contract_address': txn_receipt.contractAddress})

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Only POST method allowed'}, status=400)
from django.shortcuts import render

def dashboard(request):
    return render(request, 'dashboard.html')

def market(request):
    return render(request, 'market.html')

def trading_bot(request):
    return render(request, 'trading_bot.html')

# Add other views as needed
from web3 import Web3
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Wallet, CustomToken
import logging

logger = logging.getLogger(__name__)
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from web3 import Web3
import logging
from .models import Wallet

logger = logging.getLogger(__name__)

node_url = 'https://polygon-rpc.com'
web3 = Web3(Web3.HTTPProvider(node_url))

@csrf_exempt
def send_token(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            recipient = data.get('recipient')
            amount = data.get('amount')
            token_address = data.get('tokenAddress')

            if not all([recipient, amount, token_address]):
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            # Convert amount to wei
            amount_in_wei = int(float(amount) * 10**18)

            # Fetch the user's wallet (assuming one wallet per user for simplicity)
            wallet = Wallet.objects.get(user=request.user)

            # ERC20 Token ABI (simplified)
            token_abi = [
                {
                    "constant": False,
                    "inputs": [
                        {"name": "_to", "type": "address"},
                        {"name": "_value", "type": "uint256"}
                    ],
                    "name": "transfer",
                    "outputs": [{"name": "", "type": "bool"}],
                    "type": "function"
                }
            ]

            # Initialize contract
            token_contract = web3.eth.contract(address=web3.to_checksum_address(token_address), abi=token_abi)

            # Create the data for the transaction
            transfer_function = token_contract.functions.transfer(recipient, amount_in_wei)
            transaction_data = transfer_function._encode_transaction_data()

            # Get the nonce
            nonce = web3.eth.get_transaction_count(wallet.address)

            # Build the transaction
            transaction = {
                'to': token_address,
                'value': 0,
                'gas': 2000000,
                'gasPrice': web3.to_wei('30', 'gwei'),
                'nonce': nonce,
                'data': transaction_data,
                'chainId': 137  # Polygon Mainnet chain ID
            }

            # Sign transaction
            signed_txn = web3.eth.account.sign_transaction(transaction, private_key=wallet.private_key)

            # Send transaction
            txn_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)

            return JsonResponse({'success': True, 'txn_hash': txn_hash.hex()})
        except Wallet.DoesNotExist:
            return JsonResponse({'error': 'Wallet not found'}, status=404)
        except Exception as e:
            logger.error(f"Error sending token: {e}")
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Only POST method is allowed'}, status=400)
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from web3 import Web3
import logging
from .models import Wallet

logger = logging.getLogger(__name__)

node_url = 'https://polygon-rpc.com'
web3 = Web3(Web3.HTTPProvider(node_url))

def build_and_send_transaction(wallet, to_address, data):
    try:
        nonce = web3.eth.get_transaction_count(wallet.address)
        transaction = {
            'to': to_address,
            'value': 0,
            'gas': 2000000,
            'gasPrice': web3.to_wei('30', 'gwei'),
            'nonce': nonce,
            'data': data,
            'chainId': 137  # Polygon Mainnet chain ID
        }

        signed_txn = web3.eth.account.sign_transaction(transaction, private_key=wallet.private_key)
        txn_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)

        return txn_hash.hex()
    except Exception as e:
        logger.error(f"Error building and sending transaction: {e}")
        return None

@csrf_exempt
def burn_token(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            amount = data.get('amount')
            token_address = data.get('tokenAddress')

            if not all([amount, token_address]):
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            amount_in_wei = int(float(amount) * 10**18)
            wallet = Wallet.objects.get(user=request.user)

            token_abi = [
                {
                    "constant": False,
                    "inputs": [
                        {"name": "_value", "type": "uint256"}
                    ],
                    "name": "burn",
                    "outputs": [],
                    "type": "function"
                }
            ]

            token_contract = web3.eth.contract(address=web3.to_checksum_address(token_address), abi=token_abi)
            burn_function = token_contract.functions.burn(amount_in_wei)
            transaction_data = burn_function._encode_transaction_data()

            txn_hash = build_and_send_transaction(wallet, token_address, transaction_data)

            if txn_hash:
                return JsonResponse({'success': True, 'txn_hash': txn_hash})
            else:
                return JsonResponse({'error': 'Failed to send transaction'}, status=500)
        except Wallet.DoesNotExist:
            return JsonResponse({'error': 'Wallet not found'}, status=404)
        except Exception as e:
            logger.error(f"Error burning token: {e}")
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Only POST method is allowed'}, status=400)

@csrf_exempt
def mint_token(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            amount = data.get('amount')
            token_address = data.get('tokenAddress')

            if not all([amount, token_address]):
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            amount_in_wei = int(float(amount) * 10**18)
            wallet = Wallet.objects.get(user=request.user)

            token_abi = [
                {
                    "constant": False,
                    "inputs": [
                        {"name": "_to", "type": "address"},
                        {"name": "_value", "type": "uint256"}
                    ],
                    "name": "mint",
                    "outputs": [],
                    "type": "function"
                }
            ]

            token_contract = web3.eth.contract(address=web3.to_checksum_address(token_address), abi=token_abi)
            mint_function = token_contract.functions.mint(wallet.address, amount_in_wei)
            transaction_data = mint_function._encode_transaction_data()

            txn_hash = build_and_send_transaction(wallet, token_address, transaction_data)

            if txn_hash:
                return JsonResponse({'success': True, 'txn_hash': txn_hash})
            else:
                return JsonResponse({'error': 'Failed to send transaction'}, status=500)
        except Wallet.DoesNotExist:
            return JsonResponse({'error': 'Wallet not found'}, status=404)
        except Exception as e:
            logger.error(f"Error minting token: {e}")
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Only POST method is allowed'}, status=400)
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from web3 import Web3
import json
import logging
import time
from .models import Wallet

logger = logging.getLogger(__name__)

node_url = 'https://polygon-rpc.com'
web3 = Web3(Web3.HTTPProvider(node_url))

# ABI for the ERC20 token
erc20_abi = [
    {
        "constant": True,
        "inputs": [
            {"name": "_owner", "type": "address"}
        ],
        "name": "balanceOf",
        "outputs": [
            {"name": "balance", "type": "uint256"}
        ],
        "payable": False,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [
            {"name": "spender", "type": "address"},
            {"name": "value", "type": "uint256"}
        ],
        "name": "approve",
        "outputs": [
            {"name": "", "type": "bool"}
        ],
        "type": "function"
    }
]

# ABI for the V2 router
router_abi = [
    {
        "constant": False,
        "inputs": [
            {"name": "tokenA", "type": "address"},
            {"name": "tokenB", "type": "address"},
            {"name": "amountADesired", "type": "uint256"},
            {"name": "amountBDesired", "type": "uint256"},
            {"name": "amountAMin", "type": "uint256"},
            {"name": "amountBMin", "type": "uint256"},
            {"name": "to", "type": "address"},
            {"name": "deadline", "type": "uint256"}
        ],
        "name": "addLiquidity",
        "outputs": [
            {"name": "amountA", "type": "uint256"},
            {"name": "amountB", "type": "uint256"},
            {"name": "liquidity", "type": "uint256"}
        ],
        "payable": False,
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

router_address = '0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff'

@csrf_exempt
def create_pool(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            token1_address = data.get('token1Address')
            token1_amount = data.get('token1Amount')
            token2_address = data.get('token2Address')
            token2_amount = data.get('token2Amount')
            use_native_coin = data.get('useNativeCoin')

            if not all([token1_address, token1_amount, token2_address, token2_amount]):
                return JsonResponse({'error': 'All token addresses and amounts are required'}, status=400)

            wallet = Wallet.objects.get(user=request.user)
            private_key = wallet.private_key
            wallet_address = wallet.address

            logger.debug(f"Wallet address: {wallet_address}")
            logger.debug(f"Token1 address: {token1_address}, Token1 amount: {token1_amount}")
            logger.debug(f"Token2 address: {token2_address}, Token2 amount: {token2_amount}")

            if not wallet_address or not private_key:
                return JsonResponse({'error': 'Invalid wallet configuration'}, status=400)

            if use_native_coin:
                token2_address = '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE'  # Address for native token

            # Convert amounts to wei
            token1_amount_wei = web3.to_wei(float(token1_amount), 'ether')
            token2_amount_wei = web3.to_wei(float(token2_amount), 'ether')

            nonce = web3.eth.get_transaction_count(wallet_address)
            logger.debug(f"Nonce: {nonce}")

            # Get current gas prices
            gas_price = web3.eth.gas_price
            base_fee = web3.eth.fee_history(1, 'latest')['baseFeePerGas'][0]
            max_fee_per_gas = base_fee + web3.to_wei(2, 'gwei')  # Example: base fee + 2 gwei
            max_priority_fee_per_gas = web3.to_wei(2, 'gwei')  # Example: 2 gwei

            logger.debug(f"Gas price: {gas_price}, Base fee: {base_fee}, Max fee per gas: {max_fee_per_gas}")

            # Check token balances
            token1_contract = web3.eth.contract(address=web3.to_checksum_address(token1_address), abi=erc20_abi)
            token2_contract = web3.eth.contract(address=web3.to_checksum_address(token2_address), abi=erc20_abi)
            token1_balance = token1_contract.functions.balanceOf(wallet_address).call()
            token2_balance = token2_contract.functions.balanceOf(wallet_address).call()
            if token1_balance < token1_amount_wei or token2_balance < token2_amount_wei:
                return JsonResponse({'error': 'Insufficient token balance'}, status=400)

            # Manually build approve transaction for token1
            token1_approve_txn = {
                'chainId': 137,
                'gas': 200000,
                'maxFeePerGas': max_fee_per_gas,
                'maxPriorityFeePerGas': max_priority_fee_per_gas,
                'nonce': nonce,
                'to': web3.to_checksum_address(token1_address),
                'data': token1_contract.encodeABI(fn_name='approve', args=[router_address, token1_amount_wei])
            }
            signed_token1_approve_txn = web3.eth.account.sign_transaction(token1_approve_txn, private_key=private_key)
            token1_approve_tx_hash = web3.eth.send_raw_transaction(signed_token1_approve_txn.rawTransaction)
            logger.debug(f"Token1 approve transaction hash: {token1_approve_tx_hash.hex()}")

            if not use_native_coin:
                token2_approve_txn = {
                    'chainId': 137,
                    'gas': 200000,
                    'maxFeePerGas': max_fee_per_gas,
                    'maxPriorityFeePerGas': max_priority_fee_per_gas,
                    'nonce': nonce + 1,
                    'to': web3.to_checksum_address(token2_address),
                    'data': token2_contract.encodeABI(fn_name='approve', args=[router_address, token2_amount_wei])
                }
                signed_token2_approve_txn = web3.eth.account.sign_transaction(token2_approve_txn, private_key=private_key)
                token2_approve_tx_hash = web3.eth.send_raw_transaction(signed_token2_approve_txn.rawTransaction)
                logger.debug(f"Token2 approve transaction hash: {token2_approve_tx_hash.hex()}")

            # Wait for the approval transactions to be mined
            web3.eth.wait_for_transaction_receipt(token1_approve_tx_hash, timeout=120)
            if not use_native_coin:
                web3.eth.wait_for_transaction_receipt(token2_approve_tx_hash, timeout=120)

            # Manually build addLiquidity transaction
            router_contract = web3.eth.contract(address=router_address, abi=router_abi)
            add_liquidity_txn = {
                'chainId': 137,
                'maxFeePerGas': max_fee_per_gas,
                'maxPriorityFeePerGas': max_priority_fee_per_gas,
                'nonce': nonce + (2 if not use_native_coin else 1),
                'to': router_address,
                'data': router_contract.encodeABI(
                    fn_name='addLiquidity',
                    args=[
                        web3.to_checksum_address(token1_address),
                        web3.to_checksum_address(token2_address),
                        token1_amount_wei,
                        token2_amount_wei,
                        web3.to_wei(0.9 * float(token1_amount), 'ether'),
                        web3.to_wei(0.9 * float(token2_amount), 'ether'),
                        wallet_address,
                        int(time.time()) + 600
                    ]
                )
            }

            # Estimate gas and multiply by 10x
            try:
                gas_estimate = web3.eth.estimate_gas(add_liquidity_txn)
                add_liquidity_txn['gas'] = gas_estimate * 10
                logger.debug(f"Gas estimate: {gas_estimate}")
            except Exception as e:
                logger.error(f"Gas estimation failed: {e}", exc_info=True)
                return JsonResponse({'error': 'Gas estimation failed: ' + str(e)}, status=500)

            signed_add_liquidity_txn = web3.eth.account.sign_transaction(add_liquidity_txn, private_key=private_key)
            txn_hash = web3.eth.send_raw_transaction(signed_add_liquidity_txn.rawTransaction)

            return JsonResponse({'success': True, 'txn_hash': txn_hash.hex(), 'router_address': router_address})
        except Wallet.DoesNotExist:
            return JsonResponse({'error': 'Wallet not found'}, status=404)
        except Exception as e:
            logger.error(f"Error creating liquidity pool: {e}", exc_info=True)
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Only POST method is allowed'}, status=400)

def dashboard(request):
    contract, created = Contract.objects.get_or_create(
        pk=1, 
        defaults={
            'address': '',  
            'abi': '[]'
        }
    )

    if request.method == 'POST' and 'contract_form' in request.POST:
        form = ContractForm(request.POST, instance=contract)
        if form.is_valid():
            form.save()
            return redirect('deploy_contract')
    else:
        form = ContractForm(instance=contract)

    if request.method == 'POST' and 'create_transaction' in request.POST:
        try:
            sender_address = request.POST.get('sender')
            receiver_address = request.POST.get('receiver')
            amount = Decimal(request.POST.get('amount'))
            fee = Decimal(request.POST.get('fee'))

            if not sender_address or not receiver_address or not amount or not fee:
                return JsonResponse({'error': 'All fields (sender, receiver, amount, fee) are required'}, status=400)

            sender = Wallet.objects.get(address=sender_address)
            receiver = Wallet.objects.get(address=receiver_address)
            shard = Shard.objects.first()

            if sender.balance < (amount + fee):
                return JsonResponse({'error': 'Insufficient balance'}, status=400)

            transaction = Transaction(
                sender=sender,
                receiver=receiver,
                amount=amount,
                fee=fee,
                timestamp=timezone.now(),
                shard=shard,
                is_approved=False
            )
            transaction.hash = transaction.create_hash()
            transaction.signature = "simulated_signature" 
            transaction.save()

            try:
                if validate_transaction(transaction):
                    approve_transaction(transaction)
                    message = 'Transaction created and approved'
                else:
                    message = 'Transaction created but not approved due to validation failure'
            except Exception as e:
                message = f'Transaction created but approval failed: {str(e)}'

            return JsonResponse({'message': message, 'transaction_hash': transaction.hash})

        except Wallet.DoesNotExist:
            return JsonResponse({'error': 'Wallet not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    wallets = Wallet.objects.exclude(user__username='system')

    wallet_address = None
    try:
        wallet = Wallet.objects.get(user=request.user)
        wallet_address = wallet.address
    except Wallet.DoesNotExist:
        logger.error("Wallet not found for user: %s", request.user.username)
    except Exception as e:
        logger.error("Error fetching wallet for user %s: %s", request.user.username, str(e))

    context = {
        'form': form,
        'wallets': wallets,
        'wallet_address': wallet_address,
    }

    return render(request, 'dashboard.html', context)
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from django.conf import settings
import json
import os
from django.core.management import call_command
from django.utils import timezone
from .models import Node  # Assuming you have a Node model

# Register the node with the master node
def register_with_master_node():
    master_node_url = os.getenv('MASTER_NODE_URL')
    current_node_url = os.getenv('CURRENT_NODE_URL')
    if master_node_url and current_node_url:
        try:
            response = requests.post(f"{master_node_url}/api/register_node/", json={'url': current_node_url})
            if response.status_code == 200:
                print("Successfully registered with master node.")
            else:
                print("Failed to register with master node.")
        except Exception as e:
            print(f"Error registering with master node: {e}")

# Call the registration function during Django startup
register_with_master_node()

@csrf_exempt
@login_required
def get_mining_statistics(request):
    print("Fetching mining statistics:", mining_statistics)
    return JsonResponse(mining_statistics)

def get_active_nodes(master_node_url):
    try:
        response = requests.get(f"{master_node_url}/api/nodes/")
        response.raise_for_status()
        nodes = response.json()
        return nodes
    except requests.exceptions.RequestException as e:
        print(f"Error fetching nodes from master node: {e}")
        return []

def get_node_latest_transaction(node_url):
    try:
        response = requests.get(f"{node_url}/api/latest_transaction/")
        response.raise_for_status()
        latest_transaction = response.json()
        return latest_transaction
    except requests.exceptions.RequestException as e:
        print(f"Error fetching latest transaction from {node_url}: {e}")
        return None

def fetch_node_data(node_url):
    return {
        "url": node_url,
        "latest_transaction": get_node_latest_transaction(node_url)
    }

def check_node_synchronization():
    master_node_url = os.getenv('MASTER_NODE_URL')
    if not master_node_url:
        return {
            "is_synchronized": False,
            "message": "MASTER_NODE_URL environment variable is not set",
        }

    nodes = get_active_nodes(master_node_url)

    if len(nodes) < 2:
        return {
            "is_synchronized": False,
            "message": "Not enough nodes to check synchronization",
            "nodes": nodes,
        }

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(fetch_node_data, node['url']) for node in nodes[:2]]
        results = {future.result()['url']: future.result() for future in as_completed(futures)}

    node1_url, node2_url = list(results.keys())[:2]
    node1_data = results[node1_url]
    node2_data = results[node2_url]

    is_synchronized = node1_data['latest_transaction'] == node2_data['latest_transaction']
    return {
        "is_synchronized": is_synchronized,
        "node1_latest_transaction": node1_data['latest_transaction'],
        "node2_latest_transaction": node2_data['latest_transaction'],
    }

@csrf_exempt
def get_network_status(request):
    sync_status = check_node_synchronization()
    return JsonResponse(sync_status)

# Periodic sync check using Django management command
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = 'Sync with master node'

    def handle(self, *args, **kwargs):
        master_node_url = os.getenv('MASTER_NODE_URL')
        if not master_node_url:
            self.stdout.write(self.style.ERROR('MASTER_NODE_URL is not set'))
            return
        
        try:
            response = requests.get(f"{master_node_url}/api/get_latest_data/")
            if response.status_code == 200:
                data = response.json()
                # Process data (transactions, blocks, etc.)
                self.stdout.write(self.style.SUCCESS('Successfully synced with master node.'))
            else:
                self.stdout.write(self.style.ERROR('Failed to sync with master node.'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error syncing with master node: {e}"))

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

@csrf_exempt
@login_required
def get_mining_statistics(request):
    print("Fetching mining statistics:", mining_statistics)
    return JsonResponse(mining_statistics)

def get_active_nodes(master_node_url):
    try:
        response = requests.get(f"{master_node_url}/api/nodes/")
        response.raise_for_status()
        nodes = response.json()
        print(f"Nodes fetched from master node: {nodes}")
        return nodes
    except requests.exceptions.RequestException as e:
        print(f"Error fetching nodes from master node: {e}")
        return []

def get_node_latest_transaction(node_url):
    try:
        response = requests.get(f"{node_url}/api/latest_transaction/")
        response.raise_for_status()
        latest_transaction = response.json()
        print(f"Latest transaction from {node_url}: {latest_transaction}")
        return latest_transaction
    except requests.exceptions.RequestException as e:
        print(f"Error fetching latest transaction from {node_url}: {e}")
        return None

def fetch_node_data(node_url):
    return {
        "url": node_url,
        "latest_transaction": get_node_latest_transaction(node_url)
    }

def check_node_synchronization():
    master_node_url = "https://app.cashewstable.com"
    nodes = get_active_nodes(master_node_url)

    if len(nodes) < 2:
        print(f"Not enough nodes to check synchronization. Nodes: {nodes}")
        return {
            "is_synchronized": False,
            "message": "Not enough nodes to check synchronization",
            "nodes": nodes,
        }

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(fetch_node_data, node['url']) for node in nodes[:2]]
        results = {future.result()['url']: future.result() for future in as_completed(futures)}

    node1_url, node2_url = list(results.keys())[:2]
    node1_data = results[node1_url]
    node2_data = results[node2_url]

    is_synchronized = node1_data['latest_transaction'] == node2_data['latest_transaction']
    return {
        "is_synchronized": is_synchronized,
        "node1_latest_transaction": node1_data['latest_transaction'],
        "node2_latest_transaction": node2_data['latest_transaction'],
    }

@csrf_exempt
def get_network_status(request):
    sync_status = check_node_synchronization()
    print(f"Network status data: {sync_status}")
    return JsonResponse(sync_status)

# views.py

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def list_nodes(request):
    # This is just an example. You need to implement the logic to return the list of active nodes.
    nodes = [
        {"url": "https://app.cashewstable.com"},
        {"url": "https://app3.cashewstable.com"},
        # Add more nodes as needed
    ]
    return JsonResponse(nodes, safe=False)
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Transaction

@csrf_exempt
def get_transaction(request, tx_hash):
    try:
        transaction = Transaction.objects.get(hash=tx_hash)
        data = {
            "hash": transaction.hash,
            "sender": transaction.sender.address,
            "receiver": transaction.receiver.address,
            "amount": transaction.amount,
            "fee": transaction.fee,
            "timestamp": transaction.timestamp.isoformat(),
            # Add other fields as needed
        }
        return JsonResponse(data)
    except Transaction.DoesNotExist:
        return JsonResponse({"error": "Transaction not found"}, status=404)

@csrf_exempt
def receive_transaction(request):
    if request.method == 'POST':
        transaction_data = json.loads(request.body)
        # Logic to save the transaction in your database
        transaction, created = Transaction.objects.get_or_create(
            hash=transaction_data['hash'],
            defaults={
                'sender': transaction_data['sender'],
                'receiver': transaction_data['receiver'],
                'amount': transaction_data['amount'],
                'fee': transaction_data['fee'],
                'timestamp': transaction_data['timestamp'],
                # Add other fields as needed
            }
        )
        if created:
            # Transaction was created, propagate to other nodes if needed
            # This can be done asynchronously or in a separate process
            propagate_transaction(transaction)

        return JsonResponse({"status": "Transaction received"})
    return JsonResponse({"error": "Only POST method allowed"}, status=400)
# views.py on master node

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

nodes = []

@csrf_exempt
@require_POST
def register_node(request):
    data = json.loads(request.body)
    node_url = data.get("url")
    if node_url and node_url not in nodes:
        nodes.append(node_url)
    return JsonResponse({"status": "success", "nodes": nodes})

@csrf_exempt
def list_nodes(request):
    return JsonResponse(nodes, safe=False)
    
import requests
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

def get_active_nodes(master_node_url):
    try:
        response = requests.get(f"{master_node_url}/api/nodes/")
        response.raise_for_status()
        nodes = response.json()
        return [{"url": node} for node in nodes]  # Ensure nodes are returned as list of dictionaries
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching nodes from master node: {e}")
        return []

def get_node_latest_transaction(node_url):
    try:
        response = requests.get(f"{node_url}/api/latest_transaction/")
        response.raise_for_status()
        latest_transaction = response.json()
        return latest_transaction
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching latest transaction from {node_url}: {e}")
        return None

def fetch_node_data(node_url):
    return {
        "url": node_url,
        "latest_transaction": get_node_latest_transaction(node_url)
    }

def check_node_synchronization():
    master_node_url = os.getenv('MASTER_NODE_URL')
    if not master_node_url:
        return {
            "is_synchronized": False,
            "message": "MASTER_NODE_URL environment variable is not set",
        }

    nodes = get_active_nodes(master_node_url)

    if len(nodes) < 2:
        return {
            "is_synchronized": False,
            "message": "Not enough nodes to check synchronization",
            "nodes": nodes,
        }

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(fetch_node_data, node['url']) for node in nodes[:2]]
        results = {future.result()['url']: future.result() for future in as_completed(futures)}

    node1_url, node2_url = list(results.keys())[:2]
    node1_data = results[node1_url]
    node2_data = results[node2_url]

    is_synchronized = node1_data['latest_transaction'] == node2_data['latest_transaction']
    return {
        "is_synchronized": is_synchronized,
        "node1_latest_transaction": node1_data['latest_transaction'],
        "node2_latest_transaction": node2_data['latest_transaction'],
    }
