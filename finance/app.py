import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
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
    """Show portfolio of stocks"""
    # Query database for user's cash balance
    user_id = session["user_id"]
    user_data = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    cash_balance = user_data[0]["cash"]

    # Query database for user's stock portfolio
    portfolio = db.execute(
        "SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0",
        user_id
    )

    # List to hold stock information
    stocks = []

    # Calculate total value of stocks
    total_stock_value = 0

    for stock in portfolio:
        symbol = stock["symbol"]
        shares = stock["total_shares"]
        stock_info = lookup(symbol)
        current_price = stock_info["price"]
        total_value = shares * current_price
        stocks.append({
            "symbol": symbol,
            "shares": shares,
            "current_price": usd(current_price),
            "total_value": usd(total_value)
        })
        total_stock_value += total_value

    # Calculate grand total (cash + stocks)
    grand_total = cash_balance + total_stock_value

    return render_template("index.html", stocks=stocks, cash_balance=usd(cash_balance), grand_total=usd(grand_total))



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")

        # Ensure symbol was submitted
        if not symbol:
            return apology("must provide stock symbol", 400)

        # Ensure shares was submitted
        elif not shares:
            return apology("must provide number of shares", 400)

        # Ensure shares is a positive integer
        try:
            shares = int(shares)
            if shares <= 0:
                return apology("shares must be a positive integer", 400)
        except ValueError:
            return apology("shares must be a positive integer", 400)

        # Look up the stock symbol
        stock = lookup(symbol)
        if stock is None:
            return apology("invalid stock symbol", 400)

        # Calculate the total cost
        total_cost = shares * stock["price"]

        # Query database for user's cash
        user_id = session["user_id"]
        user = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        if len(user) != 1:
            return apology("user not found", 400)

        cash = user[0]["cash"]

        # Ensure the user can afford the purchase
        if total_cost > cash:
            return apology("can't afford", 400)

        # Record the purchase in the transactions table
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                   user_id, symbol, shares, stock["price"])

        # Update the user's cash
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total_cost, user_id)

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]

    # Fetch all transactions for the user
    transactions = db.execute("SELECT symbol, shares, price, transacted FROM transactions WHERE user_id = ? ORDER BY transacted DESC", user_id)

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
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 400)

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
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("must provide stock symbol", 400)

        stock = lookup(symbol)

        if stock is None:
            return apology("invalid stock symbol", 400)

        return render_template("quoted.html", stock=stock)

    return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Ensure username was submitted
        username = request.form.get("username")
        if not username:
            return apology("must provide username", 400)

        # Ensure password was submitted
        password = request.form.get("password")
        if not password:
            return apology("must provide password", 400)

        # Ensure password confirmation was submitted and matches password
        confirmation = request.form.get("confirmation")
        if not confirmation or password != confirmation:
            return apology("passwords do not match", 400)

        # Check if username already exists
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) > 0:
            return apology("username already exists, choose another", 400, redirect_url=url_for('register'), button_text="Try Again")

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Insert the user into the database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_password)

        # Redirect to home page after successful registration
        return redirect("/")

    return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Ensure symbol was submitted
        if not symbol:
            return apology("must provide stock symbol", 400)

        # Ensure shares was submitted
        if not shares:
            return apology("must provide number of shares", 400)

        # Check if shares is a positive integer
        try:
            shares = int(shares)
            if shares <= 0:
                return apology("must provide a positive number of shares", 400)
        except ValueError:
            return apology("must provide a valid number of shares", 400)

        # Check if the user owns the stock
        user_shares = db.execute("SELECT SUM(shares) as total_shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol", user_id, symbol)
        if len(user_shares) != 1 or user_shares[0]["total_shares"] < shares:
            return apology("not enough shares", 400)

        # Look up the current price of the stock
        stock_info = lookup(symbol)
        if not stock_info:
            return apology("invalid stock symbol", 400)

        current_price = stock_info["price"]
        total_sale_value = shares * current_price

        # Update transactions
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)", user_id, symbol, -shares, current_price)

        # Update user's cash balance
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", total_sale_value, user_id)

        # Redirect to home page
        return redirect("/")

    else:
        # Get the list of stocks the user owns
        user_stocks = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", user_id)
        return render_template("sell.html", stocks=user_stocks)

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """Show and update user profile"""
    if request.method == "POST":
        if "change_username" in request.form:
            return redirect(url_for('change_username'))
        elif "change_password" in request.form:
            return redirect(url_for('change_password'))

    return render_template("profile.html")
@app.route("/change_username", methods=["GET", "POST"])
@login_required
def change_username():
    """Change username"""
    if request.method == "POST":
        new_username = request.form.get("new_username")

        # Ensure new username was submitted
        if not new_username:
            return apology("must provide new username", 400)

        # Check if new username already exists
        existing_user = db.execute("SELECT * FROM users WHERE username = ?", new_username)
        if existing_user:
            return apology("username already exists, choose another", 400, redirect_url=url_for('profile'))

        # Update the user's username
        user_id = session["user_id"]
        db.execute("UPDATE users SET username = ? WHERE id = ?", new_username, user_id)

        # Redirect to profile page with success message
        flash("Username updated successfully!", "success")
        return redirect(url_for('profile'))

    return render_template("change_username.html")
@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change password"""
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # Ensure all fields were submitted
        if not current_password or not new_password or not confirm_password:
            return apology("must provide all fields", 400)

        # Query current user's information
        user_id = session["user_id"]
        user = db.execute("SELECT * FROM users WHERE id = ?", user_id)
        if not user or not check_password_hash(user[0]["hash"], current_password):
            return apology("incorrect current password", 400)

        # Ensure new password matches confirmation
        if new_password != confirm_password:
            return apology("new passwords do not match", 400)

        # Hash the new password
        hashed_password = generate_password_hash(new_password)

        # Update user's password in the database
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hashed_password, user_id)

        # Redirect to profile page with success message
        flash("Password updated successfully!", "success")
        return redirect(url_for('profile'))

    return render_template("change_password.html")

