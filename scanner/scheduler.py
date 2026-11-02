import threading
import schedule
import time
from datetime import datetime, timedelta


def run_scheduled_scan(url, scheduled_id):
    """Run one due scan and save it under the schedule owner's account."""
    db = None
    try:
        from scanner.core import Scanner
        from scanner.risk_scorer import RiskScorer
        from database.db import get_db

        scanner = Scanner(url)
        results = scanner.scan()
        risk_score = RiskScorer(results).calculate_score()

        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            "SELECT user_id, frequency_days FROM scheduled_scans WHERE id = %s",
            (scheduled_id,),
        )
        scheduled = cursor.fetchone()
        if not scheduled:
            cursor.close()
            return

        user_id = scheduled["user_id"]
        frequency = max(1, int(scheduled.get("frequency_days") or 7))
        cursor.execute(
            "INSERT INTO targets (url, user_id) VALUES (%s, %s)",
            (url, user_id),
        )
        target_id = cursor.lastrowid
        cursor.execute(
            """INSERT INTO scans
               (target_id, risk_score, total_vulnerabilities, user_id)
               VALUES (%s, %s, %s, %s)""",
            (target_id, risk_score, len(results), user_id),
        )
        new_scan_id = cursor.lastrowid
        for result in results:
            cursor.execute(
                """INSERT INTO vulnerabilities
                   (scan_id, vuln_type, severity, detected_by, description, fix_suggestion)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (
                    new_scan_id,
                    result.get("vuln_type", "Unclassified"),
                    result.get("severity", "Info"),
                    result.get("detected_by", "Unknown"),
                    result.get("description", ""),
                    result.get("fix_suggestion", ""),
                ),
            )
        now = datetime.now()
        cursor.execute(
            "UPDATE scheduled_scans SET last_scanned = %s, next_scan = %s WHERE id = %s",
            (now, now + timedelta(days=frequency), scheduled_id),
        )
        db.commit()
        cursor.close()
    except Exception as exc:
        if db:
            try:
                db.rollback()
            except Exception:
                pass
        print(f"Scheduled scan error for {url}: {exc}")
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def check_due_scans():
    """Claim due rows before starting threads so they are not launched every minute."""
    db = None
    try:
        from database.db import get_db

        db = get_db()
        cursor = db.cursor(dictionary=True)
        now = datetime.now()
        cursor.execute(
            """SELECT * FROM scheduled_scans
               WHERE is_active = 1 AND (next_scan IS NULL OR next_scan <= %s)""",
            (now,),
        )
        due_scans = cursor.fetchall()
        # Claim each row before spawning its worker, preventing duplicate workers
        # on subsequent scheduler ticks.
        for row in due_scans:
            frequency = max(1, int(row.get("frequency_days") or 7))
            cursor.execute(
                "UPDATE scheduled_scans SET next_scan = %s WHERE id = %s AND is_active = 1",
                (now + timedelta(days=frequency), row["id"]),
            )
        db.commit()
        cursor.close()
        for row in due_scans:
            worker = threading.Thread(
                target=run_scheduled_scan,
                args=(row["url"], row["id"]),
                daemon=True,
            )
            worker.start()
    except Exception as exc:
        if db:
            try:
                db.rollback()
            except Exception:
                pass
        print(f"Scheduler check error: {exc}")
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def run_schedule_loop():
    while True:
        schedule.run_pending()
        time.sleep(30)


def start_scheduler():
    schedule.every(1).minutes.do(check_due_scans)
    thread = threading.Thread(target=run_schedule_loop, daemon=True)
    thread.start()
    print("VulnScope scheduler started.")
