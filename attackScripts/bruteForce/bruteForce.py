import requests
import time
import json
import random

LOGIN_URL = "http://127.0.0.1:8000/login"
PASSWORDS_FILE = "passwords_50k.json"
SLEEP_SECONDS = 0.3

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

passwords = []
with open(PASSWORDS_FILE, "r", encoding="utf-8") as f:
    passwords = json.load(f)

random.shuffle(passwords)

for username, correct_password in test_vectors.items():
    for pwd in passwords:
        requests.post(
            LOGIN_URL,
            data={
                "username": username,
                "password": pwd
            }
        )
        time.sleep(SLEEP_SECONDS)