import json
import os
import hashlib
import random
from flask import Flask, render_template, request, redirect, session, url_for, send_file, flash
from datetime import datetime
from functools import wraps

# Import your crypto and ISO8583 functions
from iso8583_crypto import send_iso8583_transaction, send_erc20_payout, send_trc20_payout

app = Flask(__name__)
app.secret_key = 'blackrock_secret_key_8583'

MASTER_USERNAME = "blackrock"
MASTER_PASSWORD = "Br_3339"
PASSWORD_FILE = "password.json"
CONFIG_FILE = "config.json"
TRANSACTION_FILE = "transactions.json"

def ensure_password_file():
    try:
        if not os.path.exists(PASSWORD_FILE):
            raise FileNotFoundError
        with open(PASSWORD_FILE) as f:
            u = json.load(f)
        if "password" not in u:
            raise ValueError("Missing 'password' key")
    except Exception:
        with open(PASSWORD_FILE, "w") as f:
            hashed = hashlib.sha256(MASTER_PASSWORD.encode()).hexdigest()
            json.dump({"username": MASTER_USERNAME, "password": hashed}, f)

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

def log_transaction(txn):
    txns = []
    if os.path.exists(TRANSACTION_FILE):
        with open(TRANSACTION_FILE) as f:
            txns = json.load(f)
    txns.append(txn)
    with open(TRANSACTION_FILE, "w") as f:
        json.dump(txns, f)

def get_transactions():
    if not os.path.exists(TRANSACTION_FILE):
        return []
    with open(TRANSACTION_FILE) as f:
        return json.load(f)

def check_password(raw):
    with open(PASSWORD_FILE) as f:
        u = json.load(f)
        stored = u['password']
        username = u.get('username', MASTER_USERNAME)
    return (raw == MASTER_PASSWORD or hashlib.sha256(raw.encode()).hexdigest() == stored)

def set_password(newpass):
    with open(PASSWORD_FILE, "w") as f:
        hashed = hashlib.sha256(newpass.encode()).hexdigest()
        json.dump({"username": MASTER_USERNAME, "password": hashed}, f)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            flash("You must be logged in.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username')
        passwd = request.form.get('password')
        if user == MASTER_USERNAME and check_password(passwd):
            session['logged_in'] = True
            return redirect(url_for('protocol'))
        flash("Invalid username or password.")
    return render_template('login.html', username=MASTER_USERNAME)

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        set_password(MASTER_PASSWORD)
        flash("Password reset to default. Please login.")
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

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
    protocols = ["POS-101.1", "POS-101.4", "POS-101.6", "POS-101.7", "POS-101.8", "POS-201.1", "POS-201.3", "POS-201.5"]
    if request.method == 'POST':
        selected = request.form.get('protocol')
        session['protocol'] = selected
        return redirect(url_for('amount'))
    return render_template('protocols.html', protocols=protocols)

@app.route('/amount', methods=['GET', 'POST'])
@login_required
def amount():
    if request.method == 'POST':
        amount = request.form.get('amount')
        currency = request.form.get('currency')
        if float(amount) > 1_000_000_000:
            flash("Amount exceeds backend maximum (1 Billion).")
            return redirect(url_for('amount'))
        session['amount'] = amount
        session['currency'] = currency
        return redirect(url_for('payout'))
    return render_template('amount.html')

@app.route('/payout', methods=['GET', 'POST'])
@login_required
def payout():
    if request.method == 'POST':
        method = request.form['method']
        session['payout_type'] = method
        if method == 'ERC20':
            wallet = request.form.get('erc20_wallet', '').strip() or CONFIG['erc20_wallet']
            session['wallet'] = wallet
        elif method == 'TRC20':
            wallet = request.form.get('trc20_wallet', '').strip() or CONFIG['trc20_wallet']
            session['wallet'] = wallet
        return redirect(url_for('card'))
    return render_template('payout.html', config=CONFIG)

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
        session['auth_code'] = code

        # Prepare card data for ISO8583 transaction
        card_data = {
            "pan": session.get('pan'),
            "expiry": session.get('expiry'),
            "cvv": session.get('cvv'),
            "auth_code": code,
            "amount": session.get('amount'),
            "currency": session.get('currency')
        }

        # Replace these with actual ISO8583 host/port config
        iso_host = os.getenv("ISO8583_HOST", "127.0.0.1")
        iso_port = int(os.getenv("ISO8583_PORT", "8583"))

        # Send ISO8583 transaction using your module
        iso_response = send_iso8583_transaction(card_data, iso_host, iso_port)

        # Store txn_id or generate fallback
        session['txn_id'] = iso_response.get("txn_id", f"TXN{random.randint(100000,999999)}")
        session['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Trigger crypto payout if needed
        payout_type = session.get('payout_type')
        wallet = session.get('wallet')

        if payout_type == "ERC20":
            private_key = os.getenv("ERC20_PRIVATE_KEY")
            contract_address = os.getenv("ERC20_CONTRACT_ADDRESS")
            infura_url = os.getenv("INFURA_URL")
            if private_key and contract_address and infura_url:
                tx_hash = send_erc20_payout(private_key, wallet, session['amount'], contract_address, infura_url)
                session['crypto_tx_hash'] = tx_hash

        elif payout_type == "TRC20":
            # Implement TRC20 payout similarly if function available
            pass

        return redirect(url_for('success'))
    return render_template('auth.html')

@app.route('/success')
@login_required
def success():
    txn = {
        "txn_id": session.get("txn_id"),
        "amount": session.get("amount"),
        "currency": session.get("currency"),
        "wallet": session.get("wallet"),
        "timestamp": session.get("timestamp"),
        "status": "success",
        "crypto_tx_hash": session.get("crypto_tx_hash", None)
    }
    log_transaction(txn)
    return render_template('success.html',
                           txn_id=session.get("txn_id"),
                           arn=session.get("arn"),
                           pan=session.get("pan", "")[-4:],
                           amount=session.get("amount"),
                           timestamp=session.get("timestamp"),
                           crypto_tx_hash=session.get("crypto_tx_hash"))

@app.route('/transactions')
@login_required
def transactions():
    txns = get_transactions()
    return render_template('transactions.html', txns=txns)

if __name__ == '__main__':
    ensure_password_file()
    app.run(host='0.0.0.0', port=10000)
