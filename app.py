# --- Constants and Imports ---
import json
import os
import hashlib
import random
from flask import Flask, render_template, request, redirect, session, url_for, send_file, flash
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'rutland_secret_key_8583'

# --- Default Credentials ---
MASTER_USERNAME = "blackrock"
MASTER_PASSWORD = "Br_3339"
PASSWORD_FILE = "password.json"
CONFIG_FILE = "config.json"
TRANSACTION_FILE = "transactions.json"

# --- Ensure Password File Exists ---
def ensure_password_file():
    if not os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "w") as f:
            hashed = hashlib.sha256(MASTER_PASSWORD.encode()).hexdigest()
            json.dump({"username": MASTER_USERNAME, "password": hashed}, f)
ensure_password_file()

# --- Load/Store Config (Default Wallets) ---
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

# --- Transaction History ---
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

# --- Authentication & Session ---
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

# --- Routes ---

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
        # Reset to master
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
    # ... unchanged ...
    pass

@app.route('/amount', methods=['GET', 'POST'])
@login_required
def amount():
    if request.method == 'POST':
        amount = request.form.get('amount')
        currency = request.form.get('currency')
        # Backend: Accept up to 1 Billion, but interface will limit to 10 Million
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

        # Use default wallets if not provided
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
    # Support drag-and-drop, MM/YY separator, etc. (handled in template)
    # ... unchanged core logic ...
    pass

@app.route('/auth', methods=['GET', 'POST'])
@login_required
def auth():
    # ... unchanged core logic ...
    pass

@app.route('/success')
@login_required
def success():
    # Log transaction
    txn = {
        "txn_id": session.get("txn_id"),
        "amount": session.get("amount"),
        "currency": session.get("currency"),
        "wallet": session.get("wallet"),
        "timestamp": session.get("timestamp"),
        "status": "success"
    }
    log_transaction(txn)
    return render_template('success.html', txn_id=session.get("txn_id"), arn=session.get("arn"),
        pan=session.get("pan", "")[-4:], amount=session.get("amount"),
        timestamp=session.get("timestamp")
    )

@app.route('/transactions')
@login_required
def transactions():
    txns = get_transactions()
    return render_template('transactions.html', txns=txns)

# ... rest of your unchanged routes ...

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

