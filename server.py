
import time
import logging
import json
import os
import sqlite3
from flask import Flask, request, redirect, url_for, session, render_template, flash
from werkzeug.security import generate_password_hash, check_password_hash
from logHandle import log_login_attempt
from usersHandle import load_users, save_users
import bcrypt
import hashlib
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import base64
import hmac


app = Flask(__name__)
app.secret_key = "change-this-secret-key"

DB_FILE = "db/users.db"
CONFIG_FILE = "config.json"

# load config
config = json.load(open(CONFIG_FILE))

#users = load_users()

hash_type = "bcrypt_pepper"
is_ppeper = False

def verify_argon2(password, stored_hash, pepper):
    print ("in argon2")
    ph = PasswordHasher()
    password_peppered = password + pepper
    try:
        return ph.verify(stored_hash, password_peppered)
    except VerifyMismatchError:
        return False


def verify_sha256(password, stored_hash, salt_hex, pepper):
    password_peppered = password + pepper
    salt_bytes = bytes.fromhex(salt_hex)
    hashed = hashlib.sha256(salt_bytes + password_peppered.encode()).hexdigest()
    return hashed == stored_hash

def verify_bcrypt_with_hmac_sha384(password, stored_hash, pepper ) :
    hmac_digest = hmac.new(
        key=pepper.encode(),
        msg=password.encode(),
        digestmod=hashlib.sha384
    ).digest()

    prehash = base64.b64encode(hmac_digest)

    return bcrypt.checkpw(
        prehash,
        stored_hash.encode())

def verify_bcrypt(password, stored_hash, pepper):
    password_peppered = (password + pepper).encode()
    stored_hash_bytes = stored_hash.encode()
    return bcrypt.checkpw(password_peppered, stored_hash_bytes)

def verify_password(password, stored_hash, hash_type, salt, pepper):
    if hash_type == "argon2":
        start = time.perf_counter()
        result = verify_argon2(password, stored_hash, "")
        end = time.perf_counter()
        latency_ms = (end - start) * 1000
        return result, latency_ms
    
    elif hash_type == "bcrypt":
        start = time.perf_counter()
        result = verify_bcrypt(password, stored_hash, "")
        end = time.perf_counter()
        latency_ms = (end - start) * 1000
        return result, latency_ms
    
    elif hash_type == "sha256_salt": 
        start = time.perf_counter()
        result = verify_sha256(password, stored_hash, salt, "")
        end = time.perf_counter()
        latency_ms = (end - start) * 1000
        return result, latency_ms
    
    elif hash_type == "argon2_pepper": 
        start = time.perf_counter()
        result = verify_argon2(password, stored_hash, pepper)
        end = time.perf_counter()
        latency_ms = (end - start) * 1000
        return result, latency_ms
    
    elif hash_type == "bcrypt_pepper":
        start = time.perf_counter()
        result = verify_bcrypt_with_hmac_sha384(password, stored_hash, pepper)
        end = time.perf_counter()
        latency_ms = (end - start) * 1000
        return result, latency_ms
    
    elif hash_type == "sha256_salt_pepper": 
        start = time.perf_counter()
        result = verify_sha256(password, stored_hash, salt, pepper)
        end = time.perf_counter()
        latency_ms = (end - start) * 1000
        return result, latency_ms    
    else:
        raise ValueError(f"Unknown hash type: {hash_type}")

def hash_argon2(password):
    ph = PasswordHasher(
        time_cost=config.get("argon2_time_cost", 1),
        memory_cost=config.get("argon2_memory_cost", 65536)
    )
    return ph.hash(password), None, "argon2"

def hash_bcrypt(password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=config.get("bcrypt_cost", 12)))
    return hashed.decode(), None, "bcrypt"

def hash_sha256(password):
    salt = os.urandom(32)  
    hashed = hashlib.sha256(salt + password.encode()).hexdigest()
    return hashed, salt.hex(), "sha256_salt"

def hash_password_with_pepper(password,method):
    PEPPER = config.get("pepper", "default-secret-pepper")
    password_peppered = password + PEPPER
    if method == "argon2":
        return hash_argon2(password_peppered)
    elif method == "bcrypt":
        return hash_bcrypt(password_peppered)
    elif method == "sha256_salt":
        return hash_sha256(password_peppered)
    else:
        raise ValueError(f"Unknown hash method: {method}")

def get_user_from_db(username,hash_type ):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT username, password_hash, salt, hash_type
        FROM users
        WHERE 
        username = ?
       and hash_type  = ?        
    """, (username, hash_type))

    row = cursor.fetchone()
    
    conn.close()

    if row is None:
        return None 

    return dict(row)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        PEPPER = config.get("pepper", "default-secret-pepper")
        userdetails = get_user_from_db (username, hash_type ) 
        
        if userdetails is None:
            log_login_attempt(username, False, latency_ms,is_ppeper,hash_type)
            flash("User does not exist.")
            return redirect(url_for("login"))   
        
        try:     
            result , latency_ms  = verify_password(password, userdetails["password_hash"], hash_type, userdetails["salt"], PEPPER)
            if not result:
                log_login_attempt(username, False,latency_ms,is_ppeper,hash_type)
                flash("Wrong password.")
                return redirect(url_for("login"))
        except VerifyMismatchError:  
            log_login_attempt(username, False ,latency_ms,is_ppeper,hash_type)
            flash("Wrong password.")
            return redirect(url_for("login"))
        except Exception as e: 
            logging.error(f"Error verifying password for {username}: {e}")
            flash("An error occurred. Please try again.")
            return redirect(url_for("login"))

        session["username"] = username
        log_login_attempt(username, True, latency_ms,is_ppeper,hash_type)
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

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # בדיקה האם המשתמש כבר קיים (לפי username + hash_type)
        cursor.execute("""
            SELECT 1 FROM users
            WHERE username = ? AND hash_type = ?
        """, (username, hash_type))

        exists = cursor.fetchone() is not None

        if exists:
            conn.close()
            flash("User already exists.")
            return redirect(url_for("register"))

        # חישוב hash
        password_hash, salt = hash_password_with_pepper(password, hash_type)

        # הכנסת המשתמש ל־DB
        cursor.execute("""
            INSERT INTO users (username, password_hash, salt, hash_type)
            VALUES (?, ?, ?, ?)
        """, (username, password_hash, salt, hash_type))

        conn.commit()
        conn.close()

        flash("Registered successfully, you can now log in.")
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
