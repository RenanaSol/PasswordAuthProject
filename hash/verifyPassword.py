import time
import bcrypt
import hashlib
import base64
import hmac
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from loginDefence.rateLimit.loginRateLimiter import LoginRateLimiter
from loginDefence.lockout.accountLockout import AccountLockoutManager


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