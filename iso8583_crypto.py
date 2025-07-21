from web3 import Web3
from tronpy import Tron
from tronpy.keys import PrivateKey
from iso8583 import iso8583
import socket, random, os
from datetime import datetime
import requests

# Default wallets (sync with config.json!)
DEFAULT_ERC20_WALLET = "0x1234567890abcdef1234567890abcdef12345678"
DEFAULT_TRC20_WALLET = "TXYZ1234567890abcdefghijklmnopqrs"

def send_iso8583_transaction(card_data, host, port):
    # ... unchanged ...

def get_eth_gas_price():
    # Get current gas price from Infura or other provider
    response = requests.get("https://api.etherscan.io/api?module=proxy&action=eth_gasPrice")
    if response.ok:
        return int(response.json()['result'], 16)
    else:
        return 30_000_000_000  # fallback 30 Gwei

def send_erc20_payout(private_key, to_address, amount, contract_address, infura_url, deduct_gas_fee=False):
    web3 = Web3(Web3.HTTPProvider(infura_url))
    acct = web3.eth.account.privateKeyToAccount(private_key)
    contract = web3.eth.contract(address=Web3.toChecksumAddress(contract_address), abi=erc20_abi())
    decimals = contract.functions.decimals().call()
    amt_wei = int(float(amount) * (10 ** decimals))
    nonce = web3.eth.getTransactionCount(acct.address)
    gas_price = get_eth_gas_price()
    gas_limit = 60000
    fee_wei = gas_limit * gas_price
    if deduct_gas_fee:
        balance = contract.functions.balanceOf(acct.address).call()
        if balance < amt_wei + fee_wei:
            amt_wei = balance - fee_wei
    tx = contract.functions.transfer(Web3.toChecksumAddress(to_address), amt_wei).buildTransaction({
        'chainId': 1,
        'gas': gas_limit,
        'gasPrice': gas_price,
        'nonce': nonce,
    })
    signed = acct.sign_transaction(tx)
    tx_hash = web3.eth.sendRawTransaction(signed.rawTransaction)
    return web3.toHex(tx_hash)

# ... rest of unchanged code ...
