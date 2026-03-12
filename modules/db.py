"""
Shared SQLite database module.
Used by both bot.py and dashboard.py independently.
"""

import sqlite3
import os
from datetime import datetime, timedelta
from typing import Optional

from config import DB_FILE


def _connect() -> sqlite3.Connection:
    """Open a connection to the shared database."""
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create all tables if they don't exist."""
    conn = _connect()
    try:
        c = conn.cursor()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                scan_type   TEXT NOT NULL,
                target      TEXT NOT NULL,
                result_summary TEXT,
                full_result TEXT,
                grade       TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS notes (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                content   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS activity_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event     TEXT NOT NULL,
                detail    TEXT
            );

            CREATE TABLE IF NOT EXISTS bot_stats (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                mac        TEXT,
                ip         TEXT,
                vendor     TEXT,
                hostname   TEXT,
                status     TEXT DEFAULT 'unknown',
                first_seen TEXT NOT NULL,
                last_seen  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                target     TEXT,
                detail     TEXT,
                severity   TEXT DEFAULT 'info'
            );

            CREATE TABLE IF NOT EXISTS system_stats (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                cpu       REAL,
                ram       REAL,
                disk      REAL,
                temp      REAL
            );

            CREATE TABLE IF NOT EXISTS ssh_logs (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip        TEXT,
                username  TEXT,
                success   INTEGER DEFAULT 0,
                country   TEXT,
                city      TEXT
            );

            CREATE TABLE IF NOT EXISTS schedules (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                schedule_type TEXT NOT NULL,
                schedule_time TEXT,
                day_of_week   TEXT,
                enabled       INTEGER DEFAULT 1,
                last_run      TEXT,
                created_at    TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS monitored_sites (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                url              TEXT UNIQUE NOT NULL,
                interval_minutes INTEGER DEFAULT 5,
                last_check       TEXT,
                last_status      TEXT,
                status           TEXT DEFAULT 'unknown',
                added_at         TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS webhooks (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                url      TEXT NOT NULL,
                enabled  INTEGER DEFAULT 1,
                events   TEXT DEFAULT 'all',
                added_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_system_stats_ts  ON system_stats(timestamp);
            CREATE INDEX IF NOT EXISTS idx_scan_history_ts  ON scan_history(timestamp);
            CREATE INDEX IF NOT EXISTS idx_activity_log_ts  ON activity_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_ts        ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_ssh_logs_ts      ON ssh_logs(timestamp);
        """)
        conn.commit()

        # Migration: add first_seen / last_seen columns to existing databases
        for col, default in [("first_seen", "''"), ("last_seen", "''")]:
            try:
                conn.execute(f"ALTER TABLE devices ADD COLUMN {col} TEXT NOT NULL DEFAULT {default}")
                conn.commit()
            except Exception:
                pass  # column already exists

        # Rename legacy 'timestamp' column data into last_seen if last_seen is blank
        try:
            conn.execute(
                "UPDATE devices SET last_seen = timestamp, first_seen = timestamp "
                "WHERE last_seen = '' AND timestamp IS NOT NULL"
            )
            conn.commit()
        except Exception:
            pass

        # Migration: add grade column to scan_history
        try:
            conn.execute("ALTER TABLE scan_history ADD COLUMN grade TEXT DEFAULT ''")
            conn.commit()
        except Exception:
            pass  # column already exists

    finally:
        conn.close()


# ── Scan history ───────────────────────────────────────────────────────────────

def log_scan(scan_type: str, target: str, result_summary: str,
             full_result: str = "", grade: str = ""):
    """Insert a scan result into history."""
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO scan_history "
            "(timestamp, scan_type, target, result_summary, full_result, grade) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (datetime.utcnow().isoformat(timespec='seconds'), scan_type, target,
             result_summary[:500], full_result, grade)
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def get_scan_history(limit: int = 50, scan_type: Optional[str] = None) -> list:
    """Return recent scan history rows as dicts."""
    conn = _connect()
    try:
        if scan_type:
            rows = conn.execute(
                "SELECT * FROM scan_history WHERE scan_type = ? ORDER BY id DESC LIMIT ?",
                (scan_type, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scan_history ORDER BY id DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def clear_scan_history():
    """Delete all scan history."""
    conn = _connect()
    try:
        conn.execute("DELETE FROM scan_history")
        conn.commit()
    finally:
        conn.close()


# ── Notes ──────────────────────────────────────────────────────────────────────

def add_note(content: str) -> int:
    """Add a note, return its ID."""
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO notes (timestamp, content) VALUES (?, ?)",
            (datetime.utcnow().isoformat(timespec='seconds'), content)
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_notes() -> list:
    """Return all notes as dicts."""
    conn = _connect()
    try:
        rows = conn.execute("SELECT * FROM notes ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def delete_note(note_id: int) -> bool:
    """Delete a note by ID. Returns True if deleted."""
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# ── Activity log ───────────────────────────────────────────────────────────────

def log_activity(event: str, detail: str = ""):
    """Log a bot activity event."""
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO activity_log (timestamp, event, detail) VALUES (?, ?, ?)",
            (datetime.utcnow().isoformat(timespec='seconds'), event, detail[:500])
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def get_activity_log(limit: int = 100) -> list:
    """Return recent activity log entries."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM activity_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ── Bot stats ──────────────────────────────────────────────────────────────────

def update_stat(key: str, value):
    """Upsert a stat value."""
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO bot_stats (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value))
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def increment_stat(key: str, by: int = 1):
    """Increment an integer stat counter."""
    conn = _connect()
    try:
        cur = conn.execute("SELECT value FROM bot_stats WHERE key = ?", (key,))
        row = cur.fetchone()
        current = int(row["value"]) if row else 0
        conn.execute(
            "INSERT INTO bot_stats (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(current + by))
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def get_stat(key: str, default=None):
    """Get a stat value."""
    conn = _connect()
    try:
        row = conn.execute("SELECT value FROM bot_stats WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def get_all_stats() -> dict:
    """Return all stats as a dict."""
    conn = _connect()
    try:
        rows = conn.execute("SELECT key, value FROM bot_stats").fetchall()
        return {r["key"]: r["value"] for r in rows}
    finally:
        conn.close()


# ── Devices ────────────────────────────────────────────────────────────────────

def log_device(ip: str, mac: str = "", vendor: str = "",
               hostname: str = "", status: str = "unknown"):
    """Insert or update a discovered device record, tracking first_seen and last_seen."""
    conn = _connect()
    try:
        ts = datetime.utcnow().isoformat(timespec='seconds')
        if mac:
            existing = conn.execute("SELECT id FROM devices WHERE mac = ?", (mac,)).fetchone()
            if existing:
                conn.execute(
                    "UPDATE devices SET last_seen=?, ip=?, vendor=?, hostname=?, status=? WHERE mac=?",
                    (ts, ip, vendor, hostname, status, mac)
                )
            else:
                conn.execute(
                    "INSERT INTO devices (mac, ip, vendor, hostname, status, first_seen, last_seen) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (mac, ip, vendor, hostname, status, ts, ts)
                )
        else:
            conn.execute(
                "INSERT INTO devices (mac, ip, vendor, hostname, status, first_seen, last_seen) "
                "VALUES (?,?,?,?,?,?,?)",
                (mac, ip, vendor, hostname, status, ts, ts)
            )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def get_devices(limit: int = 100) -> list:
    """Return recently seen devices."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM devices ORDER BY last_seen DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def clear_devices():
    """Delete all device records."""
    conn = _connect()
    try:
        conn.execute("DELETE FROM devices")
        conn.commit()
    finally:
        conn.close()


# ── Alerts ─────────────────────────────────────────────────────────────────────

def log_alert(alert_type: str, target: str = "", detail: str = "", severity: str = "info"):
    """Insert a network or security alert."""
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO alerts (timestamp, alert_type, target, detail, severity) VALUES (?,?,?,?,?)",
            (datetime.utcnow().isoformat(timespec='seconds'), alert_type, target, detail[:500], severity)
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def get_alerts(limit: int = 100, alert_type: Optional[str] = None) -> list:
    """Return recent alerts."""
    conn = _connect()
    try:
        if alert_type:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE alert_type=? ORDER BY id DESC LIMIT ?",
                (alert_type, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def clear_alerts():
    """Delete all alerts."""
    conn = _connect()
    try:
        conn.execute("DELETE FROM alerts")
        conn.commit()
    finally:
        conn.close()


def get_alerts_today() -> int:
    """Return count of alerts created today."""
    conn = _connect()
    try:
        today = datetime.utcnow().strftime('%Y-%m-%d')
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM alerts WHERE timestamp LIKE ?",
            (f"{today}%",)
        ).fetchone()
        return row["cnt"] if row else 0
    finally:
        conn.close()


# ── System stats ───────────────────────────────────────────────────────────────

def log_system_stats(cpu: float, ram: float, disk: float, temp: float):
    """Record a system stats snapshot."""
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO system_stats (timestamp, cpu, ram, disk, temp) VALUES (?,?,?,?,?)",
            (datetime.utcnow().isoformat(timespec='seconds'), cpu, ram, disk, temp)
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def get_system_stats_history(hours: int = 24) -> list:
    """Return system stats for the last N hours."""
    conn = _connect()
    try:
        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat(timespec='seconds')
        rows = conn.execute(
            "SELECT * FROM system_stats WHERE timestamp >= ? ORDER BY timestamp ASC",
            (since,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ── SSH logs ───────────────────────────────────────────────────────────────────

def log_ssh_attempt(ip: str, username: str, success: bool,
                    country: str = "", city: str = ""):
    """Log an SSH login attempt."""
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO ssh_logs (timestamp, ip, username, success, country, city) "
            "VALUES (?,?,?,?,?,?)",
            (datetime.utcnow().isoformat(timespec='seconds'), ip, username,
             1 if success else 0, country, city)
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def get_ssh_logs(limit: int = 100) -> list:
    """Return recent SSH login attempts."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM ssh_logs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ── Settings ───────────────────────────────────────────────────────────────────

def get_setting(key: str, default: str = "") -> str:
    """Get a setting value."""
    conn = _connect()
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def set_setting(key: str, value: str):
    """Upsert a setting."""
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value)
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def get_all_settings() -> dict:
    """Return all settings as a dict."""
    conn = _connect()
    try:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}
    finally:
        conn.close()


# ── Schedules ──────────────────────────────────────────────────────────────────

def add_schedule(schedule_type: str, schedule_time: str,
                 day_of_week: str = "") -> int:
    """Add a scheduled scan. Returns the new row ID."""
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO schedules (schedule_type, schedule_time, day_of_week, created_at) "
            "VALUES (?,?,?,?)",
            (schedule_type, schedule_time, day_of_week,
             datetime.utcnow().isoformat(timespec='seconds'))
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_schedules(enabled_only: bool = False) -> list:
    """Return all scheduled scans."""
    conn = _connect()
    try:
        if enabled_only:
            rows = conn.execute(
                "SELECT * FROM schedules WHERE enabled = 1 ORDER BY id ASC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM schedules ORDER BY id ASC"
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def update_schedule(schedule_id: int, enabled: bool = None, last_run: str = None):
    """Update a schedule's enabled flag and/or last_run timestamp."""
    conn = _connect()
    try:
        if enabled is not None:
            conn.execute(
                "UPDATE schedules SET enabled = ? WHERE id = ?",
                (1 if enabled else 0, schedule_id)
            )
        if last_run is not None:
            conn.execute(
                "UPDATE schedules SET last_run = ? WHERE id = ?",
                (last_run, schedule_id)
            )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def delete_schedule(schedule_id: int):
    """Delete a schedule by ID."""
    conn = _connect()
    try:
        conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


# ── Monitored sites ────────────────────────────────────────────────────────────

def add_monitored_site(url: str, interval_minutes: int = 5) -> bool:
    """Add a site to monitoring. Returns True if added, False if already exists."""
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO monitored_sites (url, interval_minutes, added_at) VALUES (?,?,?)",
            (url, interval_minutes, datetime.utcnow().isoformat(timespec='seconds'))
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # UNIQUE constraint — already exists
    except Exception:
        return False
    finally:
        conn.close()


def get_monitored_sites() -> list:
    """Return all monitored sites."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM monitored_sites ORDER BY id ASC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def update_site_status(url: str, status: str, last_status: str = ""):
    """Update a monitored site's status."""
    conn = _connect()
    try:
        conn.execute(
            "UPDATE monitored_sites SET status=?, last_status=?, last_check=? WHERE url=?",
            (status, last_status, datetime.utcnow().isoformat(timespec='seconds'), url)
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def remove_monitored_site(url: str):
    """Remove a site from monitoring."""
    conn = _connect()
    try:
        conn.execute("DELETE FROM monitored_sites WHERE url = ?", (url,))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


# ── Webhooks ───────────────────────────────────────────────────────────────────

def set_webhook(url: str, events: str = "all"):
    """Set/update webhook URL (replaces any existing entry)."""
    conn = _connect()
    try:
        # Keep only one webhook row: delete all then insert fresh
        conn.execute("DELETE FROM webhooks")
        conn.execute(
            "INSERT INTO webhooks (url, enabled, events, added_at) VALUES (?,1,?,?)",
            (url, events, datetime.utcnow().isoformat(timespec='seconds'))
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def get_webhook() -> Optional[dict]:
    """Return the active webhook config, or None if not configured."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM webhooks ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def disable_webhook():
    """Disable the active webhook."""
    conn = _connect()
    try:
        conn.execute("UPDATE webhooks SET enabled = 0")
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


# ── Maintenance ────────────────────────────────────────────────────────────────

def cleanup_old_data(days: int = 30):
    """Remove data older than N days from system_stats, activity_log, and ssh_logs."""
    conn = _connect()
    try:
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat(timespec='seconds')
        conn.execute("DELETE FROM system_stats WHERE timestamp < ?", (cutoff,))
        conn.execute("DELETE FROM activity_log WHERE timestamp < ?", (cutoff,))
        conn.execute("DELETE FROM ssh_logs WHERE timestamp < ?", (cutoff,))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()
