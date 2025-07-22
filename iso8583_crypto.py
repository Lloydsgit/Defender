# --- ISO8583, ERC20, TRC20 Integration Additions (Appended) ---
from web3 import Web3
from tronpy import Tron
from tronpy.keys import PrivateKey
from iso8583 import Iso8583
import socket, random, os
from datetime import datetime

def send_iso8583_transaction(card_data, host, port):
    msg = iso8583.Message()
    msg.set_mti('0200')
    msg.set_bit(2, card_data['pan'])
    msg.set_bit(3, '000000')
    msg.set_bit(4, str(card_data['amount']).zfill(12))
    msg.set_bit(7, datetime.now().strftime('%m%d%H%M%S'))
    msg.set_bit(11, str(random.randint(100000,999999)))
    msg.set_bit(14, card_data['expiry'])
    msg.set_bit(18, '5999')
    msg.set_bit(22, '051')
    msg.set_bit(25, '00')
    msg.set_bit(35, f"{card_data['pan']}={card_data['expiry']}{card_data['cvv']}")
    msg.set_bit(41, 'TERMID01')
    msg.set_bit(49, card_data.get('currency', '840'))
    msg.set_bit(52, card_data['cvv'])
    msg.set_bit(123, 'ISO8583 DEMO')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(msg.get_network_message())
        resp_raw = s.recv(2048)
        resp = iso8583.Message()
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
        {"constant":False,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"},
        {"constant":True,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"}
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
