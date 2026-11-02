# VulnScope — Web Application Vulnerability Scanner

VulnScope is a Flask/MySQL educational scanner for checking selected web security issues. Only scan systems you own or have explicit permission to test. Some checks send active test requests; findings are indicators for review, not proof of exploitability.

## Features

- User registration and login with password hashing.
- User-specific scan history, reports, monitoring, and scheduled scans.
- Seven-category Security Knowledge page at `/knowledge`.
- Ten-minute in-memory cache for repeated scans of the same normalized URL by the same user.
- Session cookie protections: `HttpOnly`, `SameSite=Lax`, and `Secure` when HTTPS mode is enabled.
- Common response security headers and a responsive sidebar interface.
- PDF report generation.

## Requirements

- Python 3.10 or newer recommended.
- MySQL 8.x recommended.
- A working MySQL account with permission to create/use the `vulnscope` database.
- Only scan targets for which you have authorization.

## 1. Create a virtual environment

From the project folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 2. Configure MySQL

Set the database credentials in your shell. Do not put real passwords in source code.

```bash
export VULNSCOPE_DB_HOST="127.0.0.1"
export VULNSCOPE_DB_PORT="3306"
export VULNSCOPE_DB_USER="root"
export VULNSCOPE_DB_PASSWORD="YOUR_MYSQL_PASSWORD"
export VULNSCOPE_DB_NAME="vulnscope"
```

Replace `YOUR_MYSQL_PASSWORD` with your actual MySQL password. The environment variable is read by `database/db.py`.

### Fresh database

Run the schema once:

```bash
mysql -u root -p < setup_db.sql
```

If your MySQL binary is installed in a non-standard location on macOS, use its full path, for example:

```bash
/usr/local/mysql/bin/mysql -u root -p < setup_db.sql
```

### Existing VulnScope database

Back up your database before changing its schema. Then run the migration script to add the account-isolation columns to older installations where they are missing:

```bash
/usr/local/mysql/bin/mysqldump -u root -p vulnscope > vulnscope_backup.sql
/usr/local/mysql/bin/mysql -u root -p vulnscope < migrate_db.sql
```

The migration is designed to preserve existing records. Existing scans that have no `user_id` remain unassigned; they are not automatically shown in a newly registered user's history. Do not drop or recreate your database to apply this update.

If your database already has a different schema, inspect it first with `SHOW CREATE TABLE targets;`, `SHOW CREATE TABLE scans;`, and `SHOW CREATE TABLE scheduled_scans;`.

## 3. Configure Flask session cookies

For local development over `http://127.0.0.1:5000`, leave secure-cookie mode disabled:

```bash
export VULNSCOPE_HTTPS=0
export VULNSCOPE_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
```

Keep the generated `VULNSCOPE_SECRET_KEY` the same across restarts. If you open a new Terminal session, export the same key again or put it in a local, untracked environment file and load it securely.

When deployed behind correctly configured HTTPS, set:

```bash
export VULNSCOPE_HTTPS=1
```

The `Secure` cookie attribute must not be enabled for plain HTTP local development, because browsers will not send secure cookies over HTTP. `HttpOnly` and `SameSite=Lax` are enabled by default. The remember-me cookie is not used; login sessions end when the session expires or the browser session ends.

## 4. Start the application

Activate the virtual environment and ensure the database environment variables are set, then run:

```bash
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000), register a new account, log in, and use the scanner.

## Cache behavior

- Cache backend: Flask-Caching `SimpleCache` (process memory).
- Timeout: 600 seconds (10 minutes).
- Cache key includes the logged-in user and normalized URL.
- A cache hit opens the existing scan result instead of making new scan requests or creating a duplicate history entry.
- The cache is cleared when the Flask process restarts and is not shared across multiple app workers.

## Account isolation

Scan, result, report, history, schedule, and monitor routes require login. Database queries filter by the logged-in user's ID. Passwords are stored using Werkzeug's password hashing; older SHA-256 password hashes are upgraded to the current hash format after a successful login.

For an older database, apply `migrate_db.sql` before running this version. Always back up data before migrations.

## Important security notes

- The included fallback Flask secret key is for local development only. Configure a strong `VULNSCOPE_SECRET_KEY` before any deployment.
- Do not expose the development server to the public internet.
- `VULNSCOPE_HTTPS=1` should only be used when the app is actually served over HTTPS.
- In-memory caching is suitable for a single-process college demo, not a multi-worker production deployment.
- Active checks can create traffic and may affect target systems. Use explicit authorization and a controlled test environment.
- The scanner's checks are educational and heuristic; results may contain false positives and false negatives.

## Troubleshooting

- `Access denied for user`: verify `VULNSCOPE_DB_USER` and `VULNSCOPE_DB_PASSWORD`.
- `Unknown database 'vulnscope'`: run `setup_db.sql` or check `VULNSCOPE_DB_NAME`.
- Missing `user_id` column: back up the database, then run `migrate_db.sql`.
- Login session disappears after restart: keep `VULNSCOPE_SECRET_KEY` unchanged between restarts.
- A repeated URL returns a cached result: wait 10 minutes or restart the app to clear the in-memory cache.

## Main project structure

```text
VulnScope/
├── app.py
├── database/
│   └── db.py
├── scanner/
│   ├── core.py
│   ├── risk_scorer.py
│   └── scheduler.py
├── report/
│   └── pdf_generator.py
├── templates/
├── static/
│   ├── css/style.css
│   └── js/main.js
├── setup_db.sql
├── migrate_db.sql
├── requirements.txt
└── README.md
```
