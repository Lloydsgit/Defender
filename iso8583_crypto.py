import socket
import random
import os
import json
from datetime import datetime
from web3 import Web3
from tronpy import Tron
from tronpy.keys import PrivateKey
from iso8583 import iso8583
import socket, random, os
from datetime import datetime

def send_iso8583_transaction(card_data, host, port):
    msg = iso8583.ISO8583()
    msg.set_mti('0200')
    msg.set_bit(2, card_data['pan'])  # Primary account number
    msg.set_bit(3, '000000')  # Processing code
    msg.set_bit(4, str(card_data['amount']).zfill(12))  # Amount
    msg.set_bit(7, datetime.now().strftime('%m%d%H%M%S'))  # Transmission date and time
    msg.set_bit(11, str(random.randint(100000, 999999)))  # STAN
    msg.set_bit(14, card_data['expiry'])  # Expiration date
    msg.set_bit(18, '5999')  # Merchant type
    msg.set_bit(22, '051')  # POS entry mode
    msg.set_bit(25, '00')  # POS condition code
    msg.set_bit(35, f"{card_data['pan']}={card_data['expiry']}{card_data['cvv']}")  # Track 2
    msg.set_bit(41, 'TERMID01')  # Terminal ID
    msg.set_bit(49, card_data.get('currency', '840'))  # Currency code
    msg.set_bit(52, card_data['cvv'])  # PIN data
    msg.set_bit(123, 'ISO8583 DEMO')  # Additional data

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(msg.get_network_message())
        resp_raw = s.recv(2048)
        resp = iso8583.ISO8583()
        resp.unpack(resp_raw)
    return resp.get_bit(39), resp


def send_erc20_payout(private_key, to_address, amount, contract_address, infura_url):
    web3 = Web3(Web3.HTTPProvider(infura_url))
    acct = web3.eth.account.privateKeyToAccount(private_key)
    contract = web3.eth.contract(address=Web3.toChecksumAddress(contract_address), abi=erc20_abi())
    decimals = contract.functions.decimals().call()
    amt_wei = int(float(amount) * (10 ** decimals))
    nonce = web3.eth.getTransactionCount(acct.address)
    tx = contract.functions.transfer(Web3.toChecksumAddress(to_address), amt_wei).buildTransaction({
        'chainId': 1,
        'gas': 60000,
        'gasPrice': web3.eth.gas_price,
        'nonce': nonce,
    })
    signed = acct.sign_transaction(tx)
    tx_hash = web3.eth.sendRawTransaction(signed.rawTransaction)
    return web3.toHex(tx_hash)

def erc20_abi():
    return [
        {"constant": False, "inputs": [{"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}],
         "name": "transfer", "outputs": [{"name": "", "type": "bool"}], "type": "function"},
        {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}],
         "type": "function"}
    ]

def send_trc20_payout(tron_private_key, to_address, amount, contract_address):
    client = Tron()
    priv_key = PrivateKey(bytes.fromhex(tron_private_key))
    contract = client.get_contract(contract_address)
    decimals = contract.functions.decimals()
    amt = int(float(amount) * (10 ** decimals))
    txn = (
        contract.functions.transfer(to_address, amt)
        .with_owner(priv_key.public_key.to_base58check_address())
        .fee_limit(1_000_000)
        .build()
        .sign(priv_key)
    )
    result = txn.broadcast()
    return result['txid']

from web3 import Web3
import requests

# --- ISO 8583 TRANSACTION SECTION ---
def send_iso8583_transaction(card_data, host, port):
    msg = iso8583.ISO8583(specs=specs.default_ascii)
    msg.set_mti('0200')

    msg.set_bit(2, card_data['pan'])
    msg.set_bit(3, '000000')  # Processing code
    msg.set_bit(4, str(card_data['amount']).zfill(12))  # Transaction amount
    msg.set_bit(7, datetime.now().strftime('%m%d%H%M%S'))  # Transmission date & time
    msg.set_bit(11, str(random.randint(100000, 999999)))  # STAN
    msg.set_bit(14, card_data['expiry'])  # MMYY
    msg.set_bit(18, '5999')  # Merchant type
    msg.set_bit(22, '051')  # POS entry mode
    msg.set_bit(25, '00')  # POS condition code
    msg.set_bit(35, f"{card_data['pan']}={card_data['expiry']}{card_data['cvv']}")  # Track 2
    msg.set_bit(41, 'TERMID01')  # Terminal ID
    msg.set_bit(49, card_data.get('currency', '840'))  # Currency code
    msg.set_bit(52, card_data['cvv'])  # PIN data (repurposed)
    msg.set_bit(123, 'ISO8583 DEMO TXN')  # Additional data

    packed_msg = msg.get_network_message()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(packed_msg)
        response_raw = s.recv(2048)

    response = iso8583.ISO8583(specs=specs.default_ascii)
    response.unpack(response_raw)

    return response.get_bit(39), response  # Return response code & object

# --- ERC20 PAYOUT SECTION ---
def send_erc20_payout(to_address, amount, private_key, infura_url, contract_address, gas_token_balance):
    w3 = Web3(Web3.HTTPProvider(infura_url))

    if not w3.isConnected():
        raise Exception("Web3 not connected")

    from_addr = w3.eth.account.from_key(private_key).address
    contract_abi = json.loads(open("erc20_abi.json").read())
    contract = w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=contract_abi)

    # Estimate Gas + Gas Fee Handling
    decimals = contract.functions.decimals().call()
    payout_amount = int(amount * (10 ** decimals))
    txn = contract.functions.transfer(to_address, payout_amount).build_transaction({
        'from': from_addr,
        'nonce': w3.eth.get_transaction_count(from_addr),
        'gasPrice': w3.eth.gas_price,
        'gas': 60000,
        'chainId': w3.eth.chain_id
    })

    # Check ETH balance for gas
    if w3.eth.get_balance(from_addr) < txn['gas'] * txn['gasPrice']:
        raise Exception("Insufficient ETH for gas fee")

    signed = w3.eth.account.sign_transaction(txn, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    return tx_hash.hex()

# --- TRC20 PAYOUT SECTION ---
def send_trc20_payout(to_address, amount, private_key, tron_api_url, contract_address):
    headers = {'Content-Type': 'application/json'}

    payload = {
        "owner_address": to_address,
        "to_address": to_address,
        "amount": int(amount * 1e6),  # TRC20 uses 6 decimals
        "contract_address": contract_address,
        "privateKey": private_key
    }

    response = requests.post(f"{tron_api_url}/wallet/triggersmartcontract", headers=headers, json=payload)
    result = response.json()

    if 'txid' in result:
        return result['txid']
    else:
        raise Exception(f"TRC20 payout failed: {result}")

# --- CONFIG LOADER ---
def load_config(path='config.json'):
    if not os.path.exists(path):
        raise Exception("Config file missing")

    with open(path) as f:
        return json.load(f)
