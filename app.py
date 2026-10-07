from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change-this-secret-key"

DB_PATH = Path(__file__).with_name("app.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                text TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        db.commit()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        with get_db() as db:
            existing = db.execute(
                "SELECT id FROM users WHERE username = ? OR email = ?",
                (username, email)
            ).fetchone()

            if existing:
                flash("Пользователь с таким логином или email уже существует.", "danger")
                return render_template("register.html")

            password_hash = generate_password_hash(password)
            db.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, password_hash)
            )
            db.commit()

        flash("Регистрация успешна. Теперь войдите в аккаунт.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Вы успешно вошли.", "success")
            return redirect(url_for("dashboard"))

        flash("Неверный логин или пароль.", "danger")

    return render_template("login.html")


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        flash("Сначала войдите в аккаунт.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form["title"].strip()
        text = request.form["text"].strip()

        if title and text:
            with get_db() as db:
                db.execute(
                    "INSERT INTO notes (user_id, title, text) VALUES (?, ?, ?)",
                    (session["user_id"], title, text)
                )
                db.commit()
            flash("Заметка добавлена.", "success")
            return redirect(url_for("dashboard"))

    with get_db() as db:
        notes = db.execute(
            "SELECT * FROM notes WHERE user_id = ? ORDER BY id DESC",
            (session["user_id"],)
        ).fetchall()

    return render_template("dashboard.html", notes=notes)


@app.route("/logout")
def logout():
    session.clear()
    flash("Вы вышли из аккаунта.", "info")
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
