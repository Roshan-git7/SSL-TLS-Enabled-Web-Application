import os
import sys
import ssl
import sqlite3
import logging
import threading
import secrets
from functools import wraps
from datetime import timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, g, flash, abort, current_app,
)
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger(__name__)

HTTPS_HOST = "127.0.0.1"
HTTPS_PORT = 5000
HTTP_REDIRECT_PORT = 5001


def get_db():
    if "db" not in g:
        db_path = current_app.config["DATABASE"]
        g.db = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT    NOT NULL,
            created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)
    cols = [row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()]
    if "password_hash" not in cols and "password" in cols:
        db.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
        rows = db.execute("SELECT id, password FROM users").fetchall()
        for r in rows:
            if r["password"]:
                db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                           (generate_password_hash(r["password"]), r["id"]))
        try:
            db.execute("ALTER TABLE users DROP COLUMN password")
        except sqlite3.OperationalError:
            pass
    db.commit()
    log.info("Database ready: %s", current_app.config["DATABASE"])


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


class _RedirectHandler(BaseHTTPRequestHandler):
    _HTTPS_ORIGIN = f"https://127.0.0.1:{HTTPS_PORT}"

    def _redirect(self):
        path = self.path if self.path.startswith("/") else "/"
        while path.startswith("//"):
            path = "/" + path.lstrip("/")
        target = self._HTTPS_ORIGIN + path
        self.send_response(302)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):  self._redirect()
    def do_POST(self): self._redirect()
    def do_HEAD(self): self._redirect()

    def log_message(self, fmt, *args):
        log.debug("http-redirect: " + fmt, *args)


def start_http_redirect_listener():
    def _run():
        try:
            server = HTTPServer((HTTPS_HOST, HTTP_REDIRECT_PORT), _RedirectHandler)
            log.info("HTTP redirect: http://%s:%d -> https://%s:%d",
                     HTTPS_HOST, HTTP_REDIRECT_PORT, HTTPS_HOST, HTTPS_PORT)
            server.serve_forever()
        except OSError as exc:
            log.warning("HTTP redirect listener could not start: %s", exc)

    t = threading.Thread(target=_run, daemon=True, name="http-redirect")
    t.start()
    return t


def build_ssl_context():
    base = os.path.dirname(os.path.abspath(__file__))
    cert_file = os.environ.get("CERT_FILE")
    key_file  = os.environ.get("KEY_FILE")

    if not cert_file or not key_file:
        for d in [os.path.join(base, "certs"), base]:
            c = os.path.join(d, "cert.pem")
            k = os.path.join(d, "key.pem")
            if os.path.isfile(c) and os.path.isfile(k):
                cert_file, key_file = c, k
                break

    if not cert_file or not key_file or not os.path.isfile(cert_file) or not os.path.isfile(key_file):
        print("ERROR: SSL certificate or private key not found.", file=sys.stderr)
        print("Please run gen_cert.py or gen_cert.bat first.", file=sys.stderr)
        sys.exit(1)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    log.info("SSL context loaded: cert=%s", cert_file)
    return ctx


def create_app(test_config=None):
    app = Flask(__name__)

    secret = os.environ.get("SECRET_KEY")
    if not secret:
        if os.environ.get("FLASK_ENV") == "production":
            sys.exit("FATAL: SECRET_KEY is not set in production.")
        secret = secrets.token_hex(32)
        log.warning("SECRET_KEY not set — using temporary key.")

    app.config.update(
        SECRET_KEY=secret,
        DATABASE=os.environ.get("DB_PATH", "users.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
        WTF_CSRF_TIME_LIMIT=3600,
        TEMPLATES_AUTO_RELOAD=True,
        MAX_CONTENT_LENGTH=1 * 1024 * 1024,
    )

    if test_config is not None:
        app.config.update(test_config)

    CSRFProtect(app)
    app.teardown_appcontext(close_db)

    @app.after_request
    def add_security_headers(response):
        is_https = (request.is_secure or request.headers.get("X-Forwarded-Proto") == "https")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self'; "
            "img-src 'self' data:; "
            "frame-ancestors 'none';"
        )
        if is_https:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirm  = request.form.get("confirm_password", "")
            errors = []
            if len(username) < 3:
                errors.append("Username must be at least 3 characters.")
            if len(username) > 30:
                errors.append("Username must be 30 characters or fewer.")
            if username and not username.replace("_", "").replace("-", "").isalnum():
                errors.append("Username may only contain letters, numbers, hyphens, underscores.")
            if len(password) < 8:
                errors.append("Password must be at least 8 characters.")
            if password != confirm:
                errors.append("Passwords do not match.")
            if errors:
                for msg in errors:
                    flash(msg, "error")
                return render_template("register.html", username=username), 400
            db = get_db()
            existing = db.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if existing:
                flash("Username already taken. Please choose another.", "error")
                return render_template("register.html"), 409
            pw_hash = generate_password_hash(password)
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, pw_hash),
            )
            db.commit()
            flash("Account created successfully — please log in.", "success")
            return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            db = get_db()
            user = db.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session.permanent = True
                session["user_id"]  = user["id"]
                session["username"] = user["username"]
                flash(f"Welcome back, {user['username']}!", "success")
                return redirect(url_for("dashboard"))
            flash("Invalid username or password.", "error")
            return render_template("login.html"), 401
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        session.clear()
        flash("You have been signed out successfully.", "info")
        return redirect(url_for("index"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        db = get_db()
        user = db.execute(
            "SELECT id, username, created_at FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()
        if not user:
            session.clear()
            abort(401)
        is_https = (request.is_secure or request.headers.get("X-Forwarded-Proto") == "https")
        return render_template("dashboard.html", user=user, is_https=is_https)

    @app.route("/security")
    def security():
        return render_template("security.html")

    @app.errorhandler(404)
    def not_found(e):
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        log.error("Internal server error: %s", e, exc_info=True)
        return render_template("500.html"), 500

    @app.errorhandler(CSRFError)
    def csrf_error(e):
        flash("Security token expired or invalid — please try again.", "error")
        return redirect(request.referrer or url_for("index"))

    return app


app = create_app()

if __name__ == "__main__":
    with app.app_context():
        init_db()
    start_http_redirect_listener()
    ssl_ctx = build_ssl_context()
    print()
    print("=" * 60)
    print("  Secure Web App Server")
    print(f"  HTTPS : https://{HTTPS_HOST}:{HTTPS_PORT}")
    print(f"  HTTP  : http://{HTTPS_HOST}:{HTTP_REDIRECT_PORT}")
    print("=" * 60)
    print()
    app.run(
        host=HTTPS_HOST,
        port=HTTPS_PORT,
        ssl_context=ssl_ctx,
        debug=True,
        use_reloader=False,
    )
