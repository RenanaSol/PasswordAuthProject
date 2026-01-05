# 🛡️ Password Authentication & Security Research Project

A research and development project examining the resilience of authentication systems against various attack vectors. The system demonstrates the use of modern hashing algorithms combined with active defense layers to prevent Brute-Force and Password Spraying attacks.



## 🚀 Key Features

- **Hashing Mechanisms:** Comparison between Argon2id, Bcrypt, and SHA-256 (including Salt and Pepper).
- **Defense in Depth:**
    - ⏳ **Rate Limiting:** Request throttling based on the Token Bucket algorithm.
    - 🔒 **Account Lockout:** Automatic account locking after a sequence of failed attempts.
    - 🧩 **CAPTCHA:** Logical verification mechanism to prevent bots and automated scripts.
    - 📱 **TOTP (2FA):** Time-based One-Time Password support (RFC 6238).
- **Monitoring System (Logging):** Detailed documentation of response times (Latency) and experiment results for statistical analysis.
- **Attack Tools:** Dedicated scripts for simulating Brute-Force attacks to test system resilience.

---

## 📁 Project Structure

```text
PasswordAuthProject/
│
├── server.py              # Main Flask-based server
├── config.json            # Security configuration (algorithms, rate limits, secrets)
├── usersHandle.py         # User management and validation logic
├── logHandle.py           # Logging and monitoring system
│
├── hash/                  # Hashing function implementations (Argon2, Bcrypt, SHA)
├── loginDefence/          # Defense mechanisms (Rate Limit, Lockout, TOTP, CAPTCHA)
├── db/                    # Database initialization and management scripts (SQLite3)
├── attackScripts/         # Scripts simulating Brute-Force and Password Spraying attacks
└── templates/             # User Interface (Jinja2 HTML Templates)

---

## 🛠️ Requirements

- Python **3.8+**
- Flask
- argon2, bcrypt, pyotp

Install dependencies:

```bash
pip install flask
pip install flask argon2-cffi bcrypt pyotp requests
```

---

## ▶️ Running the Application

```bash
python db/initialize_db.py
python servey.py
```

App runs at:

```
http://127.0.0.1:8000/
```

---

This project was developed for educational and research purposes only. The code demonstrates security principles but is not intended for use in Production systems without further adjustments and comprehensive penetration testing.

Developers- Aya Santandreu and Renana Solomon
