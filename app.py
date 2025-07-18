from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
import csv, io, datetime

# ... previous code (login, password logic, etc.) ...

# Dummy data for demo; replace with persistent storage/database in production
transactions = [
    {
        "timestamp": "2025-07-18 09:55:22",
        "txn_id": "TXN123456",
        "amount": "1000.00",
        "status": "Approved",
        "terminal_id": "0001",
        "pan": "4111111111111111",
        "payout": "USDT ERC20"
    },
    # ... more transactions ...
]
terminals = [
    {
        "terminal_id": "0001",
        "status": "online",
        "last_active": "2025-07-18 09:50:00",
        "operator": "admin"
    },
    {
        "terminal_id": "0002",
        "status": "offline",
        "last_active": "2025-07-17 23:25:00",
        "operator": "john"
    },
    # ... more terminals ...
]

@app.route("/superadmin")
@login_required
def superadmin():
    if session.get("user") != "admin":
        flash("Superadmin access only.")
        return redirect(url_for("login"))
    return render_template("superadmin.html")

@app.route("/history")
@login_required
def history():
    query = request.args.get("search", "").lower()
    results = [txn for txn in transactions if query in txn["txn_id"].lower() or query in txn["pan"][-4:] or query in txn["amount"]]
    return render_template("history.html", transactions=results)

@app.route("/terminals")
@login_required
def terminals_panel():
    return render_template("terminals.html", terminals=terminals)

@app.route("/reset-password/<terminal_id>", methods=["GET", "POST"])
@login_required
def reset_password(terminal_id):
    if request.method == "POST":
        # Logic to reset password for terminal_id
        flash(f"Password reset for terminal {terminal_id}.")
        return redirect(url_for("terminals_panel"))
    return render_template("reset_password.html", terminal_id=terminal_id)

@app.route("/export_data", methods=["GET", "POST"])
@login_required
def export_data():
    # Generate CSV on POST
    if request.method == "POST":
        si = io.StringIO()
        writer = csv.writer(si)
        writer.writerow(["Date", "Txn ID", "Amount", "Status", "Terminal", "Card", "Payout"])
        for txn in transactions:
            writer.writerow([
                txn["timestamp"],
                txn["txn_id"],
                txn["amount"],
                txn["status"],
                txn["terminal_id"],
                "****" + txn["pan"][-4:],
                txn["payout"]
            ])
        mem = io.BytesIO()
        mem.write(si.getvalue().encode("utf-8"))
        mem.seek(0)
        filename = f"blackrockpay_txn_{datetime.datetime.now().strftime('%Y%m%d')}.csv"
        return send_file(mem, mimetype="text/csv", as_attachment=True, download_name=filename)
    return render_template("export_data.html", download_link=None)
