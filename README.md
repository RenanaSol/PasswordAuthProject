# PasswordAuthProject


A clean and simple web app demonstrating **user registration**, **login**, **logout**, and a **protected page** using Python’s Flask framework.

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
http://127.0.0.1:5000/
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
generate_password_hash(password)
check_password_hash(stored_hash, input)
```

---

## 🎨 Templates

Uses Jinja2 with template inheritance:

```html
{% extends "layout.html" %}
{% block content %}{% endblock %}
```

---

## 🔧 Future Improvements

- Use SQLite/PostgreSQL instead of dictionary  
- Add Bootstrap styling  
- Add user roles  
- Add email-based authentication  
- Add rate limiting

---

## 📜 License

Free for learning and modification.
