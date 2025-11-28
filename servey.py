from flask import Flask, request, redirect, url_for, session, render_template_string, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change-this-secret-key"  # needed for sessions, change to something random

# Very simple "database": a dictionary in memory
# In real life you would use SQLite/PostgreSQL/etc.
users = {}  # username -> password_hash

# ---------- HTML TEMPLATES (inline for simplicity) ----------

layout = """
<!DOCTYPE html>
<html>
<head>
    <title>Simple Login App</title>
</head>
<body>
    <h1>Simple Login App</h1>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <ul style="color:red;">
          {% for msg in messages %}
            <li>{{ msg }}</li>
          {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}

    {% block content %}{% endblock %}
</body>
</html>
"""

index_page = """
{% extends "layout" %}
{% block content %}
    {% if 'username' in session %}
        <p>Hello, <b>{{ session['username'] }}</b>! You are logged in.</p>
        <p><a href="{{ url_for('logout') }}">Logout</a></p>
    {% else %}
        <p>You are not logged in.</p>
        <p><a href="{{ url_for('login') }}">Login</a> | <a href="{{ url_for('register') }}">Register</a></p>
    {% endif %}
{% endblock %}
"""

login_page = """
{% extends "layout" %}
{% block content %}
    <h2>Login</h2>
    <form method="post">
        <label>Username:</label>
        <input type="text" name="username" required><br><br>
        <label>Password:</label>
        <input type="password" name="password" required><br><br>
        <button type="submit">Login</button>
    </form>
    <p>No account? <a href="{{ url_for('register') }}">Register here</a></p>
{% endblock %}
"""

register_page = """
{% extends "layout" %}
{% block content %}
    <h2>Register</h2>
    <form method="post">
        <label>Username:</label>
        <input type="text" name="username" required><br><br>
        <label>Password:</label>
        <input type="password" name="password" required><br><br>
        <button type="submit">Register</button>
    </form>
    <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a></p>
{% endblock %}
"""

protected_page = """
{% extends "layout" %}
{% block content %}
    <h2>Secret Page</h2>
    <p>Only logged-in users can see this 🎉</p>
    <p>Hello, <b>{{ session['username'] }}</b>!</p>
    <p><a href="{{ url_for('index') }}">Back to home</a></p>
{% endblock %}
"""

# ---------- ROUTES ----------

@app.route("/")
def index():
    return render_template_string(index_page, session=session, layout=layout)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")

        if username not in users:
            flash("User does not exist.")
            return redirect(url_for("login"))

        stored_hash = users[username]
        if not check_password_hash(stored_hash, password):
            flash("Wrong password.")
            return redirect(url_for("login"))

        # success
        session["username"] = username
        flash("Logged in successfully.")
        return redirect(url_for("index"))

    return render_template_string(login_page, layout=layout)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")

        if not username or not password:
            flash("Username and password are required.")
            return redirect(url_for("register"))

        if username in users:
            flash("Username already taken.")
            return redirect(url_for("register"))

        # hash the password before storing
        password_hash = generate_password_hash(password)
        users[username] = password_hash

        flash("Registered successfully, you can now log in.")
        return redirect(url_for("login"))

    return render_template_string(register_page, layout=layout)

@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("Logged out.")
    return redirect(url_for("index"))

@app.route("/secret")
def secret():
    if "username" not in session:
        flash("You must be logged in to see that page.")
        return redirect(url_for("login"))
    return render_template_string(protected_page, session=session, layout=layout)

if __name__ == "__main__":
    app.run(debug=True)
