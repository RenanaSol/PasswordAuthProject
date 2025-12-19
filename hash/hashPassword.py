import time
import bcrypt
import hashlib
import base64
import hmac
import os
import json
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from loginDefence.rateLimit.loginRateLimiter import LoginRateLimiter
from loginDefence.lockout.accountLockout import AccountLockoutManager

CONFIG_FILE = "config.json"

# load config
config = json.load(open(CONFIG_FILE))

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
