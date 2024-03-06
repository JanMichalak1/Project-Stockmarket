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

    Grand_total2 = Grand_total

    net = (Grand_total2)-10000

    return render_template("index.html", bows=bows, luzers=luzers, Grand_total=Grand_total, usd=usd, juser=juser, net=net)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide symbol to buy", 400)
        gielda1 = lookup(request.form.get("symbol"))

        if gielda1 == None:
            return apology("Sorry, this symbol does not exist. Please provide official symbol.", 400)

        if not request.form.get("shares"):
            return apology("Did not provide number of shares to buy", 400)

        akcje = request.form.get("shares")

        if not akcje.isdigit():
            return apology("Please provide only positive integer", 400)

        if int(akcje) == 0:
            return apology("Please provide only positive integer", 400)

        price = gielda1["price"]
        nazwa = gielda1["symbol"]
        user_id = session["user_id"]
        typ = "bought"

        cash_left = db.execute("SELECT cash FROM users WHERE id = ?", user_id)

        suma = float(price) * float(akcje)

        message = "Sorry, You don't have enough cash to buy that stock"

        if suma > float(cash_left[0]["cash"]):  # moze byc zle
            return render_template("guidance_to_buy.html", message=message) #RETURN TEMPLATE WITH GUIDANCE TO BUY SECTION

        koniec = cash_left[0]["cash"] - suma

        db.execute("UPDATE users SET (cash) = ? WHERE id = ?", koniec, user_id)

        db.execute("INSERT INTO purchases (user_id, stock_name, price, shares_number, type) VALUES(?, ?, ?, ?, ?)",
                   user_id, nazwa, price, akcje, typ)

        return redirect("/")

    else:

        stock_table = db.execute("SELECT COUNT(stock_name), stock_name, price FROM purchases GROUP BY stock_name ORDER BY COUNT(stock_name) DESC LIMIT 10")

    # bum = bows[0]["price"]
        
        x = 0
        for z in stock_table:
            check_price = lookup(stock_table[x]["stock_name"])

            current_price = check_price["price"]

            stock_table[x]["price"] = current_price
            # tabela = db.execute(")
            x += 1

        return render_template("buy.html", stock_table=stock_table, usd=usd)


@app.route("/history")
@login_required
def history():
    
    lows = db.execute("SELECT type, stock_name, price, shares_number, date FROM purchases WHERE user_id = ? ORDER BY date DESC", session["user_id"])

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
            return apology("Must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("Must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("Invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")
    
    # taken from CS50x course


@app.route("/logout")
def logout():
    

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

# taken from CS50 course


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        gielda = lookup(request.form.get("symbol"))

        if gielda == None:
            return apology("Sorry, this symbol is not a stock symbol", 400)

        return render_template("quoted.html", gielda=gielda, usd=usd)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 400)
        tows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        if len(tows) != 0:  # could be if len(tows): or sth else
            return apology("Sorry, that username already exists", 400)

        if not request.form.get("password"):
            return apology("Must provide password", 400)

        if not request.form.get("confirmation"):
            return apology("Must confirm the password", 400)

        if (request.form.get("password") != request.form.get("confirmation")):
            return apology("The passwords are not the same", 400)

        haslo = generate_password_hash(request.form.get("password"), method='pbkdf2', salt_length=16)

        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", request.form.get("username"), haslo)
        
        start_user = request.form.get("username")

        return render_template("welcome.html", start_user=start_user)

        # return redirect("/")

    else:

        return render_template("register.html")
        


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    lista = []
    b = 0
    stocks = db.execute("SELECT stock_name FROM purchases WHERE user_id = ? GROUP BY stock_name", session["user_id"])
    for a in stocks:
        lista.append(stocks[b]["stock_name"])
        b += 1
    choices = db.execute("SELECT SUM(shares_number), stock_name FROM purchases WHERE user_id = ? GROUP BY stock_name", session["user_id"])

    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("You did not pick the stock", 400)
        if not request.form.get("shares"):
            return apology("You did not provide the number of shares", 400)
        if request.form.get("symbol") not in lista:
            return apology("You should not give different stocks!", 400) #check
        numer = request.form.get("shares")
        symbolik = request.form.get("symbol")

        if not numer.isdigit():
            return apology("Must provide positive integer", 400)
        if int(numer) == 0:
            return apology("Must provide positive integer", 400)

        owned_shares = db.execute("SELECT SUM(shares_number) FROM purchases WHERE stock_name = ? AND user_id = ?",
                                  symbolik, session["user_id"])[0]["SUM(shares_number)"]

        if int(numer) > int(owned_shares):
            return apology("You do not have that many shares of that stock", 400)

        gielda2 = lookup(request.form.get("symbol"))

        if gielda2 == None:
            return apology("This symbol does not exist", 400)

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
        return render_template("sell.html", stocks=stocks, lista=lista, choices=choices)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        if not request.form.get("add"):
            return apology("Must provide amount of cash to add", 400)

        current_balance = db.execute("SELECT cash FROM users WHERE id= ?", session["user_id"])[0]["cash"]

        if float(request.form.get("add")) < 1:
            return apology("Minimum deposit is 1$", 400)

        sum = float(current_balance) + float(request.form.get("add"))

        db.execute("UPDATE users SET (cash) = ? WHERE id = ?", sum, session["user_id"])

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/Forum", methods=["GET", "POST"])
@login_required
def post():
    # post_content=''
    # user=[{}]
    
    if request.method == "POST":
        if not request.form.get("post"):
            return apology("In order to post, write at least one letter", 400)
        
        post_content = request.form.get("post")

        user = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"] )[0]["username"]

        db.execute("INSERT INTO posts (user_id, username, content) VALUES(?, ?, ?)", session["user_id"], user, post_content)

        return redirect("/Forum")
    
    else:

        post_board = db.execute("SELECT content, date, username FROM posts ORDER BY date DESC")

        return render_template("forum.html", post_board=post_board)

@app.route("/portfolios")
@login_required
def portfolios():
    
    user_table=[]
    user_list=[]
    user = db.execute("SELECT id FROM users")

    jusername_list=[]
    jusername= db.execute("SELECT username FROM users")

    for y in jusername:
        jusername_id= y["username"]
        jusername_list.append(jusername_id)

    y=0
    for x in user:
        # user_id = db.execute("SELECT id FROM users")[y]["id"]
        user_id = x["id"]
        user_list.append(user_id)
        y+=1
    a=0
    for z in user_list:
        user_table.append(db.execute("SELECT user_id, stock_name, SUM(shares_number) FROM purchases WHERE user_id = ? GROUP BY stock_name", z))
        a+=1 #moga byc problemy z "z" bo nie wiadomo czy to int czy str


    return render_template("user_portfolios.html", user_table=user_table, user_list=user_list, jusername_list=jusername_list)


@app.route("/activity")
@login_required
def activity():
    
    activity = db.execute("SELECT type, stock_name, price, shares_number, date, username FROM purchases JOIN users ON purchases.user_id=users.id ORDER BY date DESC LIMIT 30")

    return render_template("activity.html", activity=activity, usd=usd)