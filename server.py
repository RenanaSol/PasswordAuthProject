
import logging
import json
import os
from flask import Flask, request, redirect, url_for, session, render_template, flash
from werkzeug.security import generate_password_hash, check_password_hash
from logHandle import log_login_attempt
from usersHandle import load_users, save_users

GROUP_SEED = 3976056

app = Flask(__name__)
app.secret_key = "change-this-secret-key"

users = load_users()

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username not in users:
            log_login_attempt(username, False, GROUP_SEED)
            flash("User does not exist.")
            return redirect(url_for("login"))

        user_data = users[username]
        stored_hash = user_data["password_hash"]
        user_seed = user_data["group_seed"]


        if not check_password_hash(stored_hash, password):
            log_login_attempt(username, False, GROUP_SEED)
            flash("Wrong password.")
            return redirect(url_for("login"))

        session["username"] = username
        session["group_seed"] = user_seed
        
        log_login_attempt(username, True, GROUP_SEED)
        flash("Logged in successfully.")
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.")
            return redirect(url_for("register"))

        if username in users:
            flash("Username already taken.")
            return redirect(url_for("register"))
    
        password_hash = generate_password_hash(password)
        users[username] = password_hash

        #save new user to JSON file
        save_users(users)

        flash("Registered successfully, you can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("Logged out.")
    return redirect(url_for("index"))


@app.route("/secret")
def secret():
    if "username" not in session:
        flash("You must be logged in to see that page.")
        return redirect(url_for("login"))
    return render_template("secret.html")


if __name__ == "__main__":
    app.run(debug=True, port=8000)
