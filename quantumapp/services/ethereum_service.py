# services/ethereum_service.py

from web3 import Web3
from django.conf import settings
from .models import Contract

class EthereumService:
    def __init__(self):
        self.web3 = Web3(Web3.HTTPProvider(settings.WEB3_PROVIDER_URI))
        self.contract = self.get_contract_instance()

    def get_contract_instance(self):
        try:
            contract = Contract.objects.first()
            if contract:
                return self.web3.eth.contract(address=contract.address, abi=contract.abi)
            else:
                raise Exception("Contract not found")
        except Exception as e:
            print(f"Error retrieving contract: {e}")
            return None

    def get_balance(self, address):
        return self.web3.eth.getBalance(address)

    def send_transaction(self, from_address, private_key, to_address, value):
        nonce = self.web3.eth.getTransactionCount(from_address)
        tx = {
            'nonce': nonce,
            'to': to_address,
            'value': self.web3.toWei(value, 'ether'),
            'gas': 2000000,
            'gasPrice': self.web3.toWei('50', 'gwei')
        }
        signed_tx = self.web3.eth.account.signTransaction(tx, private_key)
        tx_hash = self.web3.eth.sendRawTransaction(signed_tx.rawTransaction)
        return self.web3.toHex(tx_hash)
