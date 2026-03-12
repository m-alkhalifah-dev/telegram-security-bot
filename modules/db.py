"""
Shared SQLite database module
Used by both bot.py and dashboard.py independently
"""

import sqlite3
import os
import json
from datetime import datetime
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
                full_result TEXT
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
    finally:
        conn.close()


# ── Scan history ──────────────────────────────────────────────────────────────

def log_scan(scan_type: str, target: str, result_summary: str, full_result: str = ""):
    """Insert a scan result into history."""
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO scan_history (timestamp, scan_type, target, result_summary, full_result) "
            "VALUES (?, ?, ?, ?, ?)",
            (datetime.utcnow().isoformat(timespec='seconds'), scan_type, target,
             result_summary[:500], full_result)
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


# ── Notes ─────────────────────────────────────────────────────────────────────

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


# ── Activity log ──────────────────────────────────────────────────────────────

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


# ── Bot stats ─────────────────────────────────────────────────────────────────

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


# ── Devices ───────────────────────────────────────────────────────────────────

def log_device(ip: str, mac: str = "", vendor: str = "", hostname: str = "", status: str = "unknown"):
    """Insert or update a discovered device record, tracking first_seen and last_seen."""
    conn = _connect()
    try:
        ts = datetime.utcnow().isoformat(timespec='seconds')
        if mac:
            existing = conn.execute("SELECT id FROM devices WHERE mac = ?", (mac,)).fetchone()
            if existing:
                # Update all fields except first_seen
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
            "SELECT * FROM devices ORDER BY timestamp DESC LIMIT ?", (limit,)
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


# ── Alerts ────────────────────────────────────────────────────────────────────

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
