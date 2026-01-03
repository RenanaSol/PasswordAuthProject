import os
import sqlite3
import json
import bcrypt 
import hashlib
import os
from datetime import datetime
from argon2 import PasswordHasher 
import base64
import hmac

USERS_JSON = "users.json"

with open(USERS_JSON, "r") as f:
    users = json.load(f)

DB_FILE = "db/users.db"
CONFIG_FILE = "config.json"

config = json.load(open(CONFIG_FILE))

print("Using DB file at:", os.path.abspath(DB_FILE))

hashTyps= ["argon2","bcrypt","sha256_salt"]



def hash_argon2(password):
    security = config.get("security", {})
    ph = PasswordHasher(
            time_cost=security.get("argon2_time_cost", 1),
            memory_cost=security.get("argon2_memory_cost", 65536),
            parallelism=security.get("argon2_parallelism", 1),
)
   
    return ph.hash(password), None, "argon2"

def bcrypt_with_hmac_sha384(password: str, pepper: str, cost: int = 12) -> str:
   
    hmac_digest = hmac.new( key=pepper.encode(), msg=password.encode(), digestmod=hashlib.sha384).digest()

    
    prehash = base64.b64encode(hmac_digest)

    bcrypt_hash = bcrypt.hashpw(
        prehash,
        bcrypt.gensalt(rounds=cost)
    )

    return bcrypt_hash.decode(),None, "bcrypt"

def hash_bcrypt(password):
    security = config.get("security", {})
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=security.get("bcrypt_cost", 12)))
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
        return bcrypt_with_hmac_sha384(password, PEPPER, cost=12)
    elif method == "sha256_salt":
        return hash_sha256(password_peppered)
    else:
        raise ValueError(f"Unknown hash method: {method}")

def hash_password_without_pepper(password,method): 
    if method == "argon2":
        return hash_argon2(password)
    elif method == "bcrypt":
        return hash_bcrypt(password)
    elif method == "sha256_salt":
        return hash_sha256(password)
    else:
        raise ValueError(f"Unknown hash method: {method}")

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()
cursor.execute(''' CREATE TABLE IF NOT EXISTS users ( id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, password_hash TEXT NOT NULL, salt TEXT, hash_type TEXT NOT NULL, created_at TEXT, totp_secret TEXT ) ''')
cursor.execute("DELETE FROM users;")
cursor.execute("DELETE FROM sqlite_sequence WHERE name='users';")
conn.commit()
for username,  data in users.items():
    password = data["password"]
    totp_secret = data.get("totp_secret")
    group_seed = data.get("group_seed")
    for h in hashTyps:   
        hashed, salt, hash_type = hash_password_with_pepper(password, h)

        cursor.execute("""
        INSERT INTO users (username, password_hash, salt, hash_type, created_at, totp_secret)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            username,
            hashed,
            salt,
            f"{h}_pepper",
            datetime.now().isoformat(),
            totp_secret
        ))

        hashed, salt, hash_type = hash_password_without_pepper(password, h)

        cursor.execute("""
        INSERT INTO users (username, password_hash, salt, hash_type, created_at,totp_secret)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            username,
            hashed,
            salt,
            h,
            datetime.now().isoformat(),
            totp_secret
        ))

    print(f"User '{username}' added with all hash variants.")


conn.commit()
conn.close()
