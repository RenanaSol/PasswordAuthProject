import logging
import time
import json
import sqlite3
import pyotp
from collections import defaultdict, deque
from flask import Flask, request, redirect, url_for, session, render_template, flash, jsonify
from werkzeug.security import  check_password_hash
from logHandle import log_login_attempt
from usersHandle import load_users, save_users
from argon2.exceptions import VerifyMismatchError
from loginDefence.rateLimit.loginRateLimiter import LoginRateLimiter
from loginDefence.lockout.accountLockout import AccountLockoutManager
from loginDefence.totp.totp_manager import TOTPManager
from hash.verifyPassword import *
from hash.hashPassword import *
from loginDefence.captcha.captchaManager import CaptchaManager

VALID_CAPTCHA_TOKENS = set()
captcha_mgr = CaptchaManager(threshold=3)
failed_attempts_captcha = {}
GROUP_SEED = 3976056
CAPTCHA_THRESHOLD = 3
PENDING_2FA_TIMEOUT = 120  

app = Flask(__name__)
app.secret_key = "mysecret"

DB_FILE = "db/users.db"
CONFIG_FILE = "config.json"


config = json.load(open(CONFIG_FILE))

hash_type = "argon2"  

protection_flag = "CAPTCHA" 
totp_manager = TOTPManager(interval=30, digits=6)
login_rate_limiter = LoginRateLimiter(capacity=5, refill_rate=5.0/60)
lockout_manager = AccountLockoutManager(max_failed_attempts=10, lockout_seconds=120)



def get_user_from_db(username,hash_type ):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT username, password_hash, salt, hash_type , totp_secret
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

@app.route('/admin/get_captcha_token', methods=['GET'])
def get_captcha_token():
    seed_raw = request.args.get('group_seed')
    if seed_raw is None:
        return jsonify({"error": "missing group_seed"}), 400
    try:
        seed = int(seed_raw)
    except ValueError:
        return jsonify({"error": "group_seed must be an integer"}), 400

    if seed != GROUP_SEED:
        return jsonify({"error": "Unauthorized seed"}), 403

    new_token = captcha_mgr.issue_token()
    return jsonify({"captcha_token": new_token})

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        start_time = time.perf_counter()
        userIP = request.remote_addr or "unknown"
        is_pepper = False
        captcha_token = ""
        latency_ms = 0
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        lockout_key = f"{username}:{userIP}"
        
    
        if protection_flag == "CAPTCHA":
            if captcha_mgr.is_captcha_required(username):
                captcha_token = request.form.get("captcha_token")

                if not captcha_token:
                    session["pending_captcha_user"] = username
                    session["captcha_required"] = True

                    end_time = time.perf_counter()
                    latency_ms = (end_time - start_time) * 1000
                    log_login_attempt(username, False, latency_ms, is_pepper, hash_type, protection_flag, GROUP_SEED)

                    flash("CAPTCHA required")
                    return render_template("login.html", captcha_required=True, username_prefill=username)

                if not captcha_mgr.consume_token(captcha_token):
                    session["pending_captcha_user"] = username
                    session["captcha_required"] = True

                    end_time = time.perf_counter()
                    latency_ms = (end_time - start_time) * 1000
                    log_login_attempt(username, False, latency_ms, is_pepper, hash_type, protection_flag, GROUP_SEED)

                    flash("Invalid or expired CAPTCHA token")
                    return render_template("login.html", captcha_required=True, username_prefill=username)

        
        if protection_flag == "LOCKOUT":
            if lockout_manager.is_locked(lockout_key):
                remaining = int(lockout_manager.get_remaining_lock_time(lockout_key))
                flash(
                    f"Your account: {username} is temporarily locked due to too many failed attempts. "
                    f"Please wait {remaining} seconds and try again.",
                    "danger"
                )
                end_time = time.perf_counter()
                latency_ms = (end_time - start_time) * 1000  
                log_login_attempt(username, False, latency_ms, is_pepper, hash_type, protection_flag, GROUP_SEED)
                session.clear()
                return redirect(url_for("login"))
    
        elif protection_flag == "RATE_LIMIT":
            if not login_rate_limiter.allow(lockout_key):
                flash("Too many login attempts. Please try again later.")
                return redirect(url_for("login"))
            
        elif protection_flag == "PEPPER":
            is_pepper = True

        PEPPER = config.get("pepper", "default-secret-pepper")
        userdetails = get_user_from_db (username, hash_type ) 
        
        if userdetails is None:
            end_time = time.perf_counter()
            latency_ms = (end_time - start_time) * 1000  
            log_login_attempt(username,False,latency_ms,is_pepper,hash_type,protection_flag,GROUP_SEED)
            flash("User does not exist.")
            return redirect(url_for("login"))   

        try:     
            result = verify_password(password, userdetails["password_hash"], hash_type, userdetails["salt"], PEPPER)
            if not result:              
                if protection_flag == "LOCKOUT":
                    lockout_manager.register_failure(lockout_key)
                    if lockout_manager.is_locked(lockout_key):
                        remaining = int(lockout_manager.get_remaining_lock_time(lockout_key))
                        flash(f"Your account: {username} is temporarily locked due to too many failed attempts. "
                        f"Please wait {remaining} seconds and try again.", "danger")

                elif protection_flag == "CAPTCHA":                       
                   captcha_mgr.register_failure(username)  
                    
                end_time = time.perf_counter()
                latency_ms = (end_time - start_time) * 1000        
                log_login_attempt(username,False,latency_ms,is_pepper,hash_type,protection_flag,GROUP_SEED)
                flash("Wrong password.")
                return redirect(url_for("login"))
        
        except VerifyMismatchError:  
            end_time = time.perf_counter()
            latency_ms = (end_time - start_time) * 1000  
            log_login_attempt(username,False,latency_ms,is_pepper,hash_type,protection_flag,GROUP_SEED)
        
        except Exception as e: 
            logging.error(f"Error verifying password for {username}: {e}")
            flash("An error occurred. Please try again.")
            return redirect(url_for("login"))

        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000        
        log_login_attempt(username,True,latency_ms,is_pepper,hash_type,protection_flag,GROUP_SEED)
        flash("Logged in successfully.")

        if protection_flag == "LOCKOUT":
            lockout_manager.register_success(lockout_key)

        if protection_flag == "CAPTCHA":
            captcha_mgr.reset(username)
        
        elif protection_flag == "TOTP":
            session["pending_2fa_user"] = username
            session["pending_2fa_seed"] = GROUP_SEED
            session["pending_2fa_started_at"] = time.time()
            flash("Password verified. Please enter your TOTP code.", "info")
            return redirect(url_for("login_totp"))
        
        session["username"] = username
        session["group_seed"] = GROUP_SEED
        session.pop("pending_captcha_user", None)
        session.pop("captcha_required", None)
        return redirect(url_for("index"))

    username_prefill = session.get("pending_captcha_user", "")
    captcha_required = session.get("captcha_required", False)
    return render_template("login.html", username_prefill=username_prefill, captcha_required=captcha_required)



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        totp_secret = pyotp.random_base32()
        if not username or not password:
            flash("Username and password are required.")
            return redirect(url_for("register"))

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        
        cursor.execute("""
            SELECT 1 FROM users
            WHERE username = ? AND hash_type = ?
        """, (username, hash_type))

        exists = cursor.fetchone() is not None

        if exists:
            conn.close()
            flash("User already exists.")
            return redirect(url_for("register"))

        
        password_hash, salt, returned_hash_type = hash_password_with_pepper(password, hash_type)

        cursor.execute("""
            INSERT INTO users (username, password_hash, salt, hash_type, totp_secret)
            VALUES (?, ?, ?, ?, ?)
        """, (username, password_hash, salt, hash_type, totp_secret))

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


@app.route("/login_totp", methods=["GET", "POST"])
def login_totp():
    pending_user = session.get("pending_2fa_user")
    started_at = session.get("pending_2fa_started_at")

    if not started_at or (time.time() - started_at) > PENDING_2FA_TIMEOUT:
        session.pop("pending_2fa_user", None)
        session.pop("pending_2fa_seed", None)
        session.pop("pending_2fa_started_at", None)

        flash("TOTP session expired. Please login again.", "warning")
        return redirect(url_for("login"))
    
    if not pending_user:
        flash("Please login with username and password first.", "warning")
        return redirect(url_for("login"))
    
    userdetails = get_user_from_db(pending_user, hash_type)
    if userdetails is None:
        flash("User not found in database.", "danger")
        session.pop("pending_2fa_user", None)
        return redirect(url_for("login"))
    
    totp_secret = userdetails.get("totp_secret")
    if not totp_secret:
        flash("Missing totp_secret for this user.", "danger")
        session.pop("pending_2fa_user", None)
        return redirect(url_for("login"))
    
    if request.method == "POST":
        token = request.form.get("totp", "").strip()
        server_now = time.time()
        if not totp_manager.verify(totp_secret, token, server_time=server_now, valid_window=1):
            flash("Invalid TOTP code.", "danger")
            return redirect(url_for("login_totp"))
    
        session.pop("pending_2fa_user", None)
        session["username"] = pending_user
        session["group_seed"] = session.pop("pending_2fa_seed", GROUP_SEED)

        flash("Logged in successfully (2FA).", "success")
        return redirect(url_for("index"))

    return render_template("login_totp.html")

if __name__ == "__main__":
    app.run(debug=True, port=8000)
