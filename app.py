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
    """Show portfolio of stocks"""
    juser = db.execute("SELECT username FROM users WHERE id =?", session["user_id"])[0]["username"]
    # return render_template("index.html", juser=juser[0]["username"])
    bows = db.execute(
        "SELECT stock_name, price, SUM(shares_number) as tshares FROM purchases WHERE user_id = ? GROUP BY stock_name", session["user_id"])

    # bum = bows[0]["price"]

    Grand_total = 0
    x = 0
    for z in bows:
        check_price = lookup(bows[x]["stock_name"])

        current_price = check_price["price"]

        bows[x]["price"] = current_price

        totalny = (bows[x]["price"] * bows[x]["tshares"])

        bows[x]["total"] = float(totalny)

        Grand_total += totalny

        x += 1

    luzers = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]["cash"]

    Grand_total += float(luzers)

    return render_template("index.html", bows=bows, luzers=luzers, Grand_total=Grand_total, usd=usd, juser=juser)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide symbol to buy", 400)
        gielda1 = lookup(request.form.get("symbol"))

        if gielda1 == None:
            return apology("this symbol does not exist bro", 400)

        if not request.form.get("shares"):
            return apology("must provide number of shares to buy bro", 400)

        akcje = request.form.get("shares")

        if not akcje.isdigit():
            return apology("must provide only positive integer bro", 400)

        if int(akcje) == 0:
            return apology("must provide only positive integer brother", 400)

        price = gielda1["price"]
        nazwa = gielda1["symbol"]
        user_id = session["user_id"]
        typ = "bought"

        cash_left = db.execute("SELECT cash FROM users WHERE id = ?", user_id)

        suma = float(price) * float(akcje)

        if suma > float(cash_left[0]["cash"]):  # moze byc zle
            return apology("You cannot afford that number of shares bro", 400)

        koniec = cash_left[0]["cash"] - suma

        db.execute("UPDATE users SET (cash) = ? WHERE id = ?", koniec, user_id)

        db.execute("INSERT INTO purchases (user_id, stock_name, price, shares_number, type) VALUES(?, ?, ?, ?, ?)",
                   user_id, nazwa, price, akcje, typ)

        return redirect("/")

    else:

        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    lows = db.execute("SELECT type, stock_name, price, shares_number, date FROM purchases WHERE user_id = ?", session["user_id"])

    return render_template("history.html", lows=lows, usd=usd)


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
        if not request.form.get("symbol"):
            return apology("must provide symbol bro", 400)

        gielda = lookup(request.form.get("symbol"))

        if gielda == None:
            return apology("this symbol is not a stock symbol", 400)

        return render_template("quoted.html", gielda=gielda, usd=usd)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username lol", 400)
        tows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        if len(tows) != 0:  # could be if len(tows): or sth else
            return apology("The username already exists", 400)

        if not request.form.get("password"):
            return apology("must provide password lol", 400)

        if not request.form.get("confirmation"):
            return apology("must confirm the password", 400)

        if (request.form.get("password") != request.form.get("confirmation")):
            return apology("the passwords are not the same", 400)

        haslo = generate_password_hash(request.form.get("password"), method='pbkdf2', salt_length=16)

        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", request.form.get("username"), haslo)
        return redirect("/")

    else:

        return render_template("register.html")
        # return apology("lol")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    lista = []
    b = 0
    stocks = db.execute("SELECT stock_name FROM purchases WHERE user_id = ? GROUP BY stock_name", session["user_id"])
    for a in stocks:
        lista.append(stocks[b]["stock_name"])
        b += 1

    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("You should pick the stock bro!", 400)
        if not request.form.get("shares"):
            return apology("You should provide the number of shares!", 400)
        if request.form.get("symbol") not in lista:
            return apology("You should not give different stocks!", 400)
        numer = request.form.get("shares")
        symbolik = request.form.get("symbol")

        if not numer.isdigit():
            return apology("must provide positive integer bro!", 400)
        if int(numer) == 0:
            return apology("must provide positive integer bro!", 400)

        owned_shares = db.execute("SELECT SUM(shares_number) FROM purchases WHERE stock_name = ? AND user_id = ?",
                                  symbolik, session["user_id"])[0]["SUM(shares_number)"]

        if int(numer) > int(owned_shares):
            return apology("You dont have that many shares Sire", 400)

        gielda2 = lookup(request.form.get("symbol"))

        if gielda2 == None:
            return apology("this symbol does not exist bro", 400)

        price2 = gielda2["price"]
        typ2 = "sold"
        nazwa2 = gielda2["symbol"]

        cash_left2 = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

        suma2 = float(price2) * float(numer)

        koniec2 = cash_left2[0]["cash"] + suma2

        subtract = -int(numer)

        db.execute("UPDATE users SET (cash) = ? WHERE id = ?", koniec2, session["user_id"])

        db.execute("INSERT INTO purchases (user_id, stock_name, price, shares_number, type) VALUES(?, ?, ?, ?, ?)",
                   session["user_id"], nazwa2, price2, subtract, typ2)

        teraz_owned_shares = db.execute(
            "SELECT SUM(shares_number) FROM purchases WHERE stock_name = ? AND user_id = ?", symbolik, session["user_id"])[0]["SUM(shares_number)"]

        return redirect("/")
        # return render_template("sell.html", stocks=stocks, lista=lista, owned_shares=owned_shares, teraz_owned_shares=teraz_owned_shares)
    else:
        return render_template("sell.html", stocks=stocks, lista=lista)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        if not request.form.get("add"):
            return apology("must provide amount of cash to add", 400)

        current_balance = db.execute("SELECT cash FROM users WHERE id= ?", session["user_id"])[0]["cash"]

        if float(request.form.get("add")) < 1:
            return apology("Minimum deposit is 1$ bro", 400)

        sum = float(current_balance) + float(request.form.get("add"))

        db.execute("UPDATE users SET (cash) = ? WHERE id = ?", sum, session["user_id"])

        return redirect("/")
    else:
        return render_template("buy.html")
