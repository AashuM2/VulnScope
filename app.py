import hashlib
import os
from datetime import datetime, timedelta
from urllib.parse import urlsplit, urlunsplit

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_caching import Cache
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

from database.db import get_db
from scanner.core import Scanner
from scanner.risk_scorer import RiskScorer

app = Flask(__name__)

# Use a stable secret across restarts. Set VULNSCOPE_SECRET_KEY in your environment
# before deployment; the fallback is for local development only.
app.secret_key = os.environ.get("VULNSCOPE_SECRET_KEY") or "local-dev-only-change-this-secret-key"

# Cookie protections. Secure must be enabled when serving over HTTPS.
# Keep it disabled for local http://127.0.0.1 development or the browser will not
# send the session cookie over plain HTTP.
COOKIE_SECURE = os.environ.get("VULNSCOPE_HTTPS", "0").strip() == "1"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SECURE=COOKIE_SECURE,
    REMEMBER_COOKIE_SAMESITE="Lax",
)

# In-process cache; repeated scans by the same user and normalized URL reuse the
# most recent scan for 10 minutes. It resets when the Flask process restarts.
app.config.update(
    CACHE_TYPE="SimpleCache",
    CACHE_DEFAULT_TIMEOUT=600,
    CACHE_THRESHOLD=500,
)
cache = Cache(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please login to access VulnScope."
login_manager.login_message_category = "error"


class User(UserMixin):
    def __init__(self, user_id, username, email):
        self.id = user_id
        self.username = username
        self.email = email


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT id, username, email FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        return User(user["id"], user["username"], user["email"]) if user else None
    finally:
        db.close()


def normalize_url(raw_url):
    """Normalize common URL variations before cache lookup."""
    value = (raw_url or "").strip()
    if not value:
        raise ValueError("Please enter a URL.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname:
        raise ValueError("Enter a valid URL, such as https://example.com.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded usernames or passwords are not supported.")
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower()
    # Preserve a non-default port, but remove the default port for the scheme.
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("The URL contains an invalid port.")
    netloc = hostname
    if ":" in hostname and not hostname.startswith("["):
        netloc = f"[{hostname}]"
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{netloc}:{port}"
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def verify_password(stored_hash, password):
    """Support secure Werkzeug hashes and transparently upgrade old SHA-256 hashes."""
    if not stored_hash:
        return False, None
    try:
        if check_password_hash(stored_hash, password):
            return True, None
    except (ValueError, TypeError):
        pass

    # Older project versions stored plain SHA-256 digests. Upgrade after a successful login.
    legacy_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    if stored_hash == legacy_hash:
        return True, generate_password_hash(password)
    return False, None


# -------------------- Authentication --------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not username or not email or not password:
            flash("All fields are required.", "error")
            return render_template("register.html")
        if len(username) > 100 or len(email) > 255:
            flash("Username or email is too long.", "error")
            return render_template("register.html")
        if len(password) < 8:
            flash("Use a password with at least 8 characters.", "error")
            return render_template("register.html")

        db = get_db()
        try:
            cursor = db.cursor(dictionary=True)
            cursor.execute(
                "SELECT id FROM users WHERE username = %s OR email = %s",
                (username, email),
            )
            if cursor.fetchone():
                flash("Username or email already exists.", "error")
                return render_template("register.html")

            password_hash = generate_password_hash(
    password, method="pbkdf2:sha256"
)
            cursor.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                (username, email, password_hash),
            )
            db.commit()
            flash("Account created successfully. Please login.", "success")
            return redirect(url_for("login"))
        except Exception:
            db.rollback()
            app.logger.exception("Registration failed")
            flash("Could not create the account. Check the database connection and try again.", "error")
        finally:
            db.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        try:
            cursor = db.cursor(dictionary=True)
            cursor.execute(
                "SELECT id, username, email, password_hash FROM users WHERE username = %s",
                (username,),
            )
            user = cursor.fetchone()
            cursor.close()
            valid, upgraded_hash = (
                verify_password(user["password_hash"], password) if user else (False, None)
            )
            if valid:
                if upgraded_hash:
                    cursor = db.cursor()
                    cursor.execute(
                        "UPDATE users SET password_hash = %s WHERE id = %s",
                        (upgraded_hash, user["id"]),
                    )
                    db.commit()
                    cursor.close()
                login_user(User(user["id"], user["username"], user["email"]), remember=False)
                return redirect(url_for("home"))
            flash("Invalid username or password.", "error")
        except Exception:
            app.logger.exception("Login failed")
            flash("Could not log in. Check the database connection and try again.", "error")
        finally:
            db.close()

    return render_template("login.html")


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# -------------------- Main pages and scanning --------------------

@app.route("/")
@login_required
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
@login_required
def scan():
    data = request.get_json(silent=True) or {}
    try:
        url = normalize_url(data.get("url", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    # Cache entries are isolated per user, so one account cannot receive another
    # account's scan history/result ID. URL normalization avoids duplicate cache keys.
    cache_key = f"scan:{current_user.id}:{hashlib.sha256(url.encode('utf-8')).hexdigest()}"
    cached_scan_id = cache.get(cache_key)
    if cached_scan_id:
        return jsonify({"scan_id": cached_scan_id, "cached": True})

    scanner = Scanner(url)
    try:
        results = scanner.scan()
        scorer = RiskScorer(results)
        risk_score = scorer.calculate_score()

        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO targets (url, user_id) VALUES (%s, %s)",
                (url, current_user.id),
            )
            target_id = cursor.lastrowid
            cursor.execute(
                """INSERT INTO scans
                   (target_id, risk_score, total_vulnerabilities, user_id)
                   VALUES (%s, %s, %s, %s)""",
                (target_id, risk_score, len(results), current_user.id),
            )
            scan_id = cursor.lastrowid
            for result in results:
                cursor.execute(
                    """INSERT INTO vulnerabilities
                       (scan_id, vuln_type, severity, detected_by, description, fix_suggestion)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    (
                        scan_id,
                        result.get("vuln_type", "Unclassified"),
                        result.get("severity", "Info"),
                        result.get("detected_by", "Unknown"),
                        result.get("description", ""),
                        result.get("fix_suggestion", ""),
                    ),
                )
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

        cache.set(cache_key, scan_id, timeout=600)
        return jsonify({"scan_id": scan_id, "cached": False})
    except Exception:
        app.logger.exception("Scan failed")
        return jsonify({"error": "The scan could not be completed. Check the application and database logs."}), 500


@app.route("/results/<int:scan_id>")
@login_required
def results(scan_id):
    db = get_db()
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            """SELECT s.*, t.url FROM scans s
               JOIN targets t ON s.target_id = t.id
               WHERE s.id = %s AND s.user_id = %s""",
            (scan_id, current_user.id),
        )
        scan_row = cursor.fetchone()
        if not scan_row:
            return "Scan not found or access denied.", 404
        cursor.execute("SELECT * FROM vulnerabilities WHERE scan_id = %s", (scan_id,))
        vulnerabilities = cursor.fetchall()
    finally:
        db.close()

    grade, color = RiskScorer([]).get_grade(scan_row["risk_score"])
    return render_template(
        "results.html",
        scan=scan_row,
        vulnerabilities=vulnerabilities,
        grade=grade,
        color=color,
    )


@app.route("/history")
@login_required
def history():
    db = get_db()
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            """SELECT s.*, t.url FROM scans s
               JOIN targets t ON s.target_id = t.id
               WHERE s.user_id = %s
               ORDER BY s.scanned_at DESC""",
            (current_user.id,),
        )
        scans = cursor.fetchall()
    finally:
        db.close()
    return render_template("history.html", scans=scans)


@app.route("/schedule")
@login_required
def schedule_page():
    db = get_db()
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM scheduled_scans WHERE user_id = %s ORDER BY added_on DESC",
            (current_user.id,),
        )
        scheduled = cursor.fetchall()
    finally:
        db.close()
    return render_template("schedule.html", scheduled=scheduled)


@app.route("/schedule/add", methods=["POST"])
@login_required
def schedule_add():
    data = request.get_json(silent=True) or {}
    try:
        url = normalize_url(data.get("url", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    email = (data.get("email") or "").strip() or None
    try:
        frequency = int(data.get("frequency", 7))
    except (TypeError, ValueError):
        return jsonify({"error": "Frequency must be a number of days."}), 400
    if not 1 <= frequency <= 365:
        return jsonify({"error": "Frequency must be between 1 and 365 days."}), 400

    db = get_db()
    try:
        cursor = db.cursor()
        next_scan = datetime.now() + timedelta(days=frequency)
        cursor.execute(
            """INSERT INTO scheduled_scans
               (url, frequency_days, alert_email, next_scan, user_id)
               VALUES (%s, %s, %s, %s, %s)""",
            (url, frequency, email, next_scan, current_user.id),
        )
        db.commit()
    except Exception:
        db.rollback()
        app.logger.exception("Could not schedule scan")
        return jsonify({"error": "Could not save the scheduled scan."}), 500
    finally:
        db.close()
    return jsonify({"success": True, "message": f"{url} added to scheduled scans"})


@app.route("/schedule/delete/<int:id>", methods=["POST"])
@login_required
def schedule_delete(id):
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute(
            "UPDATE scheduled_scans SET is_active = 0 WHERE id = %s AND user_id = %s",
            (id, current_user.id),
        )
        db.commit()
        if cursor.rowcount == 0:
            return jsonify({"error": "Scheduled scan not found."}), 404
    finally:
        db.close()
    return jsonify({"success": True})


@app.route("/monitor")
@login_required
def monitor():
    return render_template("monitor.html")


@app.route("/monitor/data")
@login_required
def monitor_data():
    db = get_db()
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            "SELECT DISTINCT url FROM scheduled_scans WHERE is_active = 1 AND user_id = %s",
            (current_user.id,),
        )
        urls = cursor.fetchall()
        result = []
        for url_row in urls:
            url = url_row["url"]
            cursor.execute(
                """SELECT s.id AS scan_id, s.risk_score, s.total_vulnerabilities,
                          s.scanned_at AS last_scan
                   FROM scans s JOIN targets t ON s.target_id = t.id
                   WHERE t.url = %s AND s.user_id = %s
                   ORDER BY s.scanned_at DESC LIMIT 1""",
                (url, current_user.id),
            )
            scan_row = cursor.fetchone()
            if scan_row:
                result.append({
                    "url": url,
                    "risk_score": scan_row["risk_score"],
                    "total_vulnerabilities": scan_row["total_vulnerabilities"],
                    "scan_id": scan_row["scan_id"],
                    "last_scan": str(scan_row["last_scan"]),
                })
    finally:
        db.close()
    result.sort(key=lambda item: item["risk_score"] or 0, reverse=True)
    return jsonify(result)


@app.route("/knowledge")
@login_required
def knowledge():
    return render_template("knowledge.html")


@app.route("/report/<int:scan_id>")
@login_required
def download_report(scan_id):
    from report.pdf_generator import generate_pdf

    db = get_db()
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            """SELECT s.*, t.url FROM scans s
               JOIN targets t ON s.target_id = t.id
               WHERE s.id = %s AND s.user_id = %s""",
            (scan_id, current_user.id),
        )
        scan_row = cursor.fetchone()
        if not scan_row:
            return "Scan not found or access denied.", 404
        cursor.execute("SELECT * FROM vulnerabilities WHERE scan_id = %s", (scan_id,))
        vulnerabilities = cursor.fetchall()
    finally:
        db.close()

    buffer = generate_pdf(scan_row, vulnerabilities)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"VulnScope_Report_Scan_{scan_id}.pdf",
        mimetype="application/pdf",
    )


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    # Do not set HSTS for local HTTP development. Enable only on HTTPS deployments.
    if COOKIE_SECURE:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


if __name__ == "__main__":
    # Start background scheduler only in the main process to avoid duplicate
    # scheduler threads from imports and Flask's debug reloader.
    from scanner.scheduler import start_scheduler

    start_scheduler()
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1", use_reloader=False)
