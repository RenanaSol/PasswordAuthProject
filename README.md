# passwordAuthProject

A clean and simple web app demonstrating user registration, login, logout, and a protected page using Python’s Flask framework.

**Features**
- **Password hashing & verification**: secure password hashing utilities in `hash/`.
- **TOTP**: Time-based one-time password support in `loginDefence/totp/`.
- **Rate limiting & token bucket**: per-IP and per-account throttling in `loginDefence/rateLimit/`.
- **Account lockout**: account lockout policies in `loginDefence/lockout/`.
- **DB initialization**: lightweight DB setup in `db/initialize_db.py`.

**Repository layout (important files)**
- `server.py`: Main application entrypoint (starts the auth server).
- `config.json`: Configuration for app settings (ports, rate limits, secrets).
- `users.json`: Simple user store used by the demo.
- `usersHandle.py`, `logHandle.py`: helpers for user and logging operations.
- `hash/`: password hashing and verification helpers.
- `loginDefence/`: defence mechanisms (rate limiting, lockout, TOTP).
- `db/`: DB initialization scripts.
- `attackScripts/`: example attack scripts for testing (brute force, password spraying).

**Requirements**
- Python 3.8+


Security notes
- This project is a learning system.


## ✨ Features

- 🔐 Register with username & password  
- 🔑 Login using valid credentials  
- 🛡️ Passwords stored **securely (hashed, never plain text)**  
- 👤 Persistent user session using Flask sessions  
- 🚫 Protected `/secret` page accessible only when logged in  
- 📄 Organized project structure with Jinja template inheritance  

---

## 📁 Project Structure

```
PasswordAuthProject/
│
├── servey.py               # Main Flask server
│
└── templates/
    ├── layout.html         # Base template
    ├── index.html          # Home / landing page
    ├── login.html          # Login form
    ├── register.html       # Registration form
    └── secret.html         # Protected page
```

---

## 🛠️ Requirements

- Python **3.8+**
- Flask

Install dependencies:

```bash
pip install flask
```

---

## ▶️ Running the Application

```bash
python servey.py
```

App runs at:

```
http://127.0.0.1:8000/
```

---

## 🔐 Authentication Flow

### Registration
- Password is hashed with Werkzeug.
- User saved in a simple in-memory dictionary.

### Login
- Password verified with `check_password_hash`.
- Username stored in Flask session.

### Protected Route
- `/secret` only loads if logged in.

### Logout
- Removes the username from session.

---

## 🧠 Password Security

Uses hashed passwords:

```python
check_password_hash(stored_hash, input)
```

---

## 🎨 Templates

Uses Jinja2 with template inheritance:

```html
{% extends "layout.html" %}
{% block content %}{% endblock %}
```
