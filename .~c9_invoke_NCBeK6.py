import os

from flask import Flask, redirect, jsonify, render_template, request, session
from flask_session import Session
from cs50 import SQL
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from helper import apology, login_required

app = Flask(__name__)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


db = SQL("sqlite:///appointments.db")

def is_name_provided():
    if not request.form.get("name"):
        return apology("must provide name",403)
def is_password_provided():
    if not request.form.get("password"):
        return apology("must provide password",403)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        result_of_checks = is_name_provided() or is_password_provided()
        if result_of_checks != None:
            return result_of_checks
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirmation must be the same")

        prim_key = db.execute("INSERT INTO clients (name, hash) VALUES (:name, :hash)",
                    name=request.form.get("name"),
                    hash=generate_password_hash(request.form.get("password")))
        if prim_key == None:
            return apology("Registration Error. Checkif name already exists.", 403)
        session["user_id"] = prim_key
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("name"):
            return apology("must provide name", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM clients WHERE name = :name",
                          name=request.form.get("name"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid name and/or password", 403)

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

@app.route("/")
@login_required
def history():
    names = db.execute("SELECT name FROM clients WHERE id =:id",id = session["user_id"])
    dates = db.execute("SELECT date FROM appointments WHERE clientId = :id ORDER BY date DESC",id = session["user_id"])
    return render_template("history.html",names = names, dates = dates)

@app.route("/make",methods=["GET","POST"])
@login_required
def make():
    if request.method == "POST":
        rows = db.execute("INSERT INTO appointments (date,clientId) VALUES (:date, :id) ",date=request.form.get("appointment"),id = session["user_id"])
        return redirect("/")
    else:
        return render_template("make.html")

@app.route("/password", methods=["GET", "POST"])
def password():
    """Re-register user"""
    if request.method == "POST":
        result_of_checks = is_name_provided() or is_password_provided()
        if result_of_checks != None:
            return result_of_checks
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirmation must be the same")

        prim_key = db.execute("UPDATE clients SET hash = :hash WHERE name= :name",
                    name=request.form.get("name"),
                    hash=generate_password_hash(request.form.get("password")))
        if prim_key == None:
            return apology("Registration Error. Checkif name already exists.", 403)
        session["user_id"] = prim_key
        return redirect("/login")
    else:
        return render_template("password.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)

# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


