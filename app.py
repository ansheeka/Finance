import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    user_id = session["user_id"]
    transactions = db.execute(
        "SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0",
        user_id)

    holdings = []
    total_assets = 0

    for transaction in transactions:
        stock = lookup(transaction["symbol"])
        total_value = stock["price"] * transaction["total_shares"]
        holdings.append({
            "symbol": transaction["symbol"],
            "shares": transaction["total_shares"],
            "price": usd(stock["price"]),
            "total": usd(total_value)
        })
        total_assets += total_value

    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
    total_assets += cash

    return render_template("index.html", holdings=holdings, cash=usd(cash), total=usd(total_assets))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares_input = request.form.get("shares")

        # Attempt to convert shares input to integer and validate
        try:
            shares = int(shares_input)
            if shares <= 0:
                return apology("Number of shares must be a positive integer", 400)
        except ValueError:
            return apology("Number of shares must be a whole number", 400)

        stock = lookup(symbol)
        if not stock:
            return apology("Invalid symbol", 400)

        user_id = session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        total_cost = shares * stock["price"]

        if cash < total_cost:
            return apology("Insufficient funds", 400)

        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total_cost, user_id)
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price_per_share) VALUES (?, ?, ?, ?)",
                   user_id, symbol, shares, stock["price"])

        flash("Bought!")
        return redirect("/")
    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    user_id = session["user_id"]
    transactions = db.execute(
        "SELECT symbol, shares, price_per_share, timestamp FROM transactions WHERE user_id = ? ORDER BY timestamp DESC",
        user_id)

    for transaction in transactions:
        transaction["price"] = usd(transaction["price_per_share"])

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        stock = lookup(symbol)

        if stock is None:
            return apology("Invalid symbol", 400)

        return render_template("quoted.html", stock=stock)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username or not password or not confirmation or password != confirmation:
            return apology("Invalid registration details")

        hash = generate_password_hash(password)
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
        except ValueError:
            return apology("Username already exists")

        return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares_to_sell = int(request.form.get("shares"))

        if shares_to_sell <= 0:
            return apology("Must sell at least one share", 400)

        user_id = session["user_id"]
        stock = lookup(symbol)

        if not stock:
            return apology("Invalid symbol", 400)

        shares_owned = db.execute("SELECT SUM(shares) as total_shares FROM transactions WHERE user_id = ? AND symbol = ?",
                                  user_id, symbol)[0]["total_shares"]

        if shares_to_sell > shares_owned:
            return apology("Cannot sell more shares than you own", 400)

        db.execute("INSERT INTO transactions (user_id, symbol, shares, price_per_share) VALUES (?, ?, ?, ?)",
                   user_id, symbol, -shares_to_sell, stock["price"])
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?",
                   shares_to_sell * stock["price"], user_id)

        flash("Sold!")
        return redirect("/")
    else:
        user_id = session["user_id"]
        symbols = db.execute(
            "SELECT DISTINCT symbol FROM transactions WHERE user_id = ? ORDER BY symbol", user_id)
        return render_template("sell.html", symbols=[row["symbol"] for row in symbols])
