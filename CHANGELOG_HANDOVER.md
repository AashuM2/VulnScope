# VulnScope update handover

This package was updated to address the five professor-requested items.

## Changes made

1. **Knowledge page** — `/knowledge` is linked in the sidebar and has seven vulnerability cards. Each card includes an explanation, a real-world example, a detection note, and remediation guidance. Added an authorized-testing notice and clarified that scanner findings are heuristic.
2. **GUI** — retained the existing sidebar layout and applied a more consistent responsive dark theme, spacing, focus states, card surfaces, and mobile layout refinements.
3. **Caching** — Flask-Caching `SimpleCache` caches a user's most recent scan ID for 600 seconds, keyed by the user ID and normalized URL. A cache hit reuses the previous result instead of making another network scan.
4. **Session management** — Flask-Login protects the application pages and user-specific database queries. Registration uses Werkzeug password hashes. Existing legacy SHA-256 hashes can be upgraded after a successful login. Scan history, reports, monitoring, and scheduled scans are scoped to the logged-in account.
5. **Cookie security** — `HttpOnly=True` and `SameSite=Lax` are configured for session and remember cookies. `Secure` is controlled by `VULNSCOPE_HTTPS`; enable it only when the application is served over HTTPS. The app also adds common response security headers.

## Database and configuration

- `database/db.py` no longer contains a hard-coded MySQL password. Set `VULNSCOPE_DB_PASSWORD` and other `VULNSCOPE_DB_*` variables in the shell.
- `setup_db.sql` creates the expected schema for a fresh database.
- `migrate_db.sql` adds missing user ownership columns and indexes to an older installation and expands URL columns without dropping existing data. Back up first.
- `README.md` has setup and migration commands.
- `.env.example` documents configuration names; it is a template and is not automatically loaded by Flask.

## Validation performed here

- Python source files passed Python AST syntax parsing.
- Jinja templates parsed successfully.
- The knowledge template contains seven cards and seven real-world example sections.
- A live Flask/MySQL integration test was not run in this environment because the Flask and MySQL connector packages and the user's MySQL server/database are not available here. Install `requirements.txt` and test locally after reviewing the migration.

## Important notes

- The SimpleCache backend is in-process memory and is suitable for a single-process demonstration; it clears on restart and is not shared across workers.
- The local fallback Flask secret key is for development only. Set a stable, strong `VULNSCOPE_SECRET_KEY` for any deployment.
- Keep `VULNSCOPE_HTTPS=0` for local HTTP testing. Set it to `1` only behind HTTPS.
- Existing scans with `user_id IS NULL` remain unassigned after migration and will not appear in a new user's private history. Existing data is not deleted.
- Scan only systems you own or have explicit authorization to test.
