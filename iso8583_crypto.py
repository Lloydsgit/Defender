import os
import json
import decimal
from web3 import Web3
from tronpy import Tron
from tronpy.keys import PrivateKey

def load_config():
    config = {
        "ENV": os.getenv("ENV", "testnet"),  # testnet or mainnet
        "ETHEREUM_RPC": os.getenv("ETHEREUM_RPC", "https://sepolia.infura.io/v3/YOUR_INFURA_KEY"),
        "ETHEREUM_PRIVATE_KEY": os.getenv("ETHEREUM_PRIVATE_KEY", "YOUR_PRIVATE_KEY"),
        "ERC20_TOKEN_ADDRESS": os.getenv("ERC20_TOKEN_ADDRESS", "0xYourTestUSDTContract"),
        "TRON_PRIVATE_KEY": os.getenv("TRON_PRIVATE_KEY", "YOUR_TRON_PRIVATE_KEY"),
        "TRC20_TOKEN_ADDRESS": os.getenv("TRC20_TOKEN_ADDRESS", "TNYourTRC20Token"),
    }
    return config

CONFIG = load_config()

def erc20_abi():
    return json.loads("""[
        {
            "constant": true,
            "inputs": [],
            "name": "decimals",
            "outputs": [{"name": "", "type": "uint8"}],
            "type": "function"
        },
        {
            "constant": false,
            "inputs": [{"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}],
            "name": "transfer",
            "outputs": [{"name": "", "type": "bool"}],
            "type": "function"
        },
        {
            "constant": true,
            "inputs": [{"name": "_owner", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "balance", "type": "uint256"}],
            "type": "function"
        }
    ]""")

# ERC20 payout logic
def send_erc20_payout(to_address, amount):
    web3 = Web3(Web3.HTTPProvider(CONFIG["ETHEREUM_RPC"]))
    if not web3.is_connected():
        raise Exception("Ethereum RPC not connected.")

    from_account = web3.eth.account.from_key(CONFIG["ETHEREUM_PRIVATE_KEY"])
    token = web3.eth.contract(address=Web3.to_checksum_address(CONFIG["ERC20_TOKEN_ADDRESS"]),
                              abi=erc20_abi())
    decimals = token.functions.decimals().call()
    raw_amount = int(decimal.Decimal(amount) * 10**decimals)

    nonce = web3.eth.get_transaction_count(from_account.address)
    tx = token.functions.transfer(to_address, raw_amount).build_transaction({
        'chainId': web3.eth.chain_id,
        'gas': 80000,
        'gasPrice': web3.eth.gas_price,
        'nonce': nonce,
    })

    signed_tx = from_account.sign_transaction(tx)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    return tx_hash.hex()

# TRC20 payout logic
def send_trc20_payout(to_address, amount):
    client = Tron(network='nile' if CONFIG["ENV"] == "testnet" else 'mainnet')
    priv_key = PrivateKey(bytes.fromhex(CONFIG["TRON_PRIVATE_KEY"]))
    token_contract = client.get_contract(CONFIG["TRC20_TOKEN_ADDRESS"])
    decimals = token_contract.functions.decimals()
    raw_amount = int(decimal.Decimal(amount) * 10**decimals)

    txn = (
        token_contract.functions.transfer(to_address, raw_amount)
        .with_owner(priv_key.public_key.to_base58check_address())
        .fee_limit(1_000_000)
        .build()
        .sign(priv_key)
    )
    result = txn.broadcast().wait()
    if result['receipt']['result'] != 'SUCCESS':
        raise Exception("TRC20 payout failed")
    return result['txid']
