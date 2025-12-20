import requests
import time

LOGIN_URL = "http://127.0.0.1:8000/login"

test_vectors = {
    "admin": {
        "correct": "admin",
        "wrong": ["12345", "password", "qwerty","admin1", "adm1n", "admi" ,"admn" ,"adnmi" ,"adnim" ,"aadmin" ,"aadmn" ,"admni" ]
    },
    "user": {
        "correct": "12345",
        "wrong": ["password", "qwerty", "usr", "user1", "usre", "uers", "use", "uuser", "uuserr", "userr"]
    },
    "john": {
        "correct": "qwerty",
        "wrong": ["12345", "password", "admin", "jhon", "johhn", "johnn", "joohn", "joh", "john1", "johny"]
    },
    "laura": {
        "correct": "Summer2025",
        "wrong": ["summer", "laura1", "laur", "lauraa", "luraa", "laaura", "laurab", "laurap", "summer2024", "Summer2024", "Summer2023"]
    }
}

for username, tv in test_vectors.items(): 
    for pwd in tv["wrong"]:
        requests.post(LOGIN_URL, data={"username": username, "password": pwd})
        time.sleep(0.3)

    requests.post(LOGIN_URL, data={"username": username, "password": tv["correct"]})
    time.sleep(0.3)