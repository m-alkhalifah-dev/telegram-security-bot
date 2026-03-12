#!/usr/bin/env python3
"""
Web Dashboard for Telegram Security Bot
Flask app — runs independently from the bot process
Access at http://<pi-ip>:5000
"""

import os
import time
import json
import subprocess
from datetime import datetime
from functools import wraps
from collections import defaultdict

import psutil
from flask import (
    Flask, render_template, redirect, url_for,
    request, session, jsonify, flash
)

from config import (
    DASHBOARD_USER, DASHBOARD_PASS, DASHBOARD_SECRET_KEY,
    DASHBOARD_HOST, DASHBOARD_PORT, BOT_VERSION, NETWORK_INTERFACE
)
from modules.db import (
    init_db, get_scan_history, get_notes, add_note, delete_note,
    get_activity_log, get_all_stats, log_activity, clear_scan_history,
    get_devices, log_device, log_scan,
)

app = Flask(__name__)
app.secret_key = DASHBOARD_SECRET_KEY

# ── Rate limiting (in-memory, per IP) ────────────────────────────────────────
_rate_data: dict = defaultdict(list)
RATE_LIMIT = 60       # max requests
RATE_WINDOW = 60      # per N seconds


def _check_rate_limit(ip: str) -> bool:
    """Return True if request is allowed, False if rate-limited."""
    now = time.time()
    window = _rate_data[ip]
    # Remove old timestamps
    _rate_data[ip] = [t for t in window if now - t < RATE_WINDOW]
    if len(_rate_data[ip]) >= RATE_LIMIT:
        return False
    _rate_data[ip].append(now)
    return True


def rate_limited(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _check_rate_limit(request.remote_addr):
            return jsonify({"error": "Rate limit exceeded"}), 429
        return f(*args, **kwargs)
    return wrapper


# ── Auth ──────────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if username == DASHBOARD_USER and password == DASHBOARD_PASS:
            session['logged_in'] = True
            log_activity("Dashboard login", f"from {request.remote_addr}")
            return redirect(url_for('index'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ── Pages ─────────────────────────────────────────────────────────────────────

@app.route('/')
@login_required
def index():
    stats = get_all_stats()
    return render_template('index.html', stats=stats, version=BOT_VERSION)


@app.route('/network')
@login_required
def network():
    devices = get_devices(limit=100)
    return render_template('network.html', devices=devices, version=BOT_VERSION)


@app.route('/scans')
@login_required
def scans():
    history = get_scan_history(limit=100)
    return render_template('scans.html', history=history, version=BOT_VERSION)


@app.route('/scans/clear', methods=['POST'])
@login_required
def scans_clear():
    clear_scan_history()
    log_activity("Scan history cleared", f"by {request.remote_addr}")
    flash('Scan history cleared', 'success')
    return redirect(url_for('scans'))


@app.route('/logs')
@login_required
def logs():
    activity = get_activity_log(limit=200)
    return render_template('logs.html', activity=activity, version=BOT_VERSION)


@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', version=BOT_VERSION)


# ── Notes (used by /notes bot command and dashboard) ─────────────────────────

@app.route('/notes/add', methods=['POST'])
@login_required
def notes_add():
    content = request.form.get('content', '').strip()
    if content:
        add_note(content)
        log_activity("Note added", content[:80])
    return redirect(url_for('settings'))


@app.route('/notes/delete/<int:note_id>', methods=['POST'])
@login_required
def notes_delete(note_id):
    delete_note(note_id)
    return redirect(url_for('settings'))


# ── API endpoints (used by dashboard JS) ─────────────────────────────────────

@app.route('/api/stats')
@login_required
@rate_limited
def api_stats():
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    temp = _get_temp()
    uptime_secs = int(time.time() - psutil.boot_time())
    h, rem = divmod(uptime_secs, 3600)
    m, s   = divmod(rem, 60)

    return jsonify({
        "cpu_percent":  cpu,
        "ram_percent":  mem.percent,
        "ram_used_gb":  round(mem.used / 1_073_741_824, 2),
        "ram_total_gb": round(mem.total / 1_073_741_824, 2),
        "disk_percent": disk.percent,
        "disk_used_gb": round(disk.used / 1_073_741_824, 2),
        "disk_total_gb":round(disk.total / 1_073_741_824, 2),
        "temp_c":       temp,
        "uptime":       f"{h}h {m}m {s}s",
        "bot_version":  BOT_VERSION,
        "timestamp":    datetime.utcnow().isoformat(timespec='seconds'),
    })


@app.route('/api/bandwidth')
@login_required
@rate_limited
def api_bandwidth():
    try:
        net1 = psutil.net_io_counters(pernic=True).get(NETWORK_INTERFACE)
        time.sleep(1)
        net2 = psutil.net_io_counters(pernic=True).get(NETWORK_INTERFACE)
        if net1 and net2:
            rx_kbps = round((net2.bytes_recv - net1.bytes_recv) * 8 / 1000, 2)
            tx_kbps = round((net2.bytes_sent - net1.bytes_sent) * 8 / 1000, 2)
        else:
            rx_kbps = tx_kbps = 0
    except Exception:
        rx_kbps = tx_kbps = 0
    return jsonify({"rx_kbps": rx_kbps, "tx_kbps": tx_kbps})


@app.route('/api/network')
@login_required
@rate_limited
def api_network():
    devices = get_devices(limit=100)
    return jsonify({"devices": devices, "count": len(devices)})


@app.route('/api/devices')
@login_required
@rate_limited
def api_devices():
    devices = get_devices(limit=100)
    return jsonify({"devices": devices, "count": len(devices)})


@app.route('/api/scan', methods=['POST'])
@login_required
@rate_limited
def api_scan():
    """Trigger a network scan, save results to DB, return discovered devices."""
    from config import NETWORK_RANGE, KNOWN_DEVICES_FILE
    found = {}

    # Try arp-scan first
    try:
        result = subprocess.run(
            ['sudo', 'arp-scan', '--localnet', '--retry=2'],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                parts = line.split('\t')
                if len(parts) >= 2 and '.' in parts[0]:
                    ip = parts[0].strip()
                    mac = parts[1].strip().upper()
                    vendor = parts[2].strip() if len(parts) > 2 else "Unknown"
                    found[mac] = {'ip': ip, 'mac': mac, 'vendor': vendor}
    except Exception:
        pass

    # Fallback: nmap ping scan
    if not found:
        try:
            result = subprocess.run(
                ['nmap', '-sn', NETWORK_RANGE],
                capture_output=True, text=True, timeout=60
            )
            current_ip = None
            for line in result.stdout.split('\n'):
                if 'Nmap scan report for' in line:
                    current_ip = line.split()[-1].strip('()')
                elif 'MAC Address:' in line and current_ip:
                    parts = line.split()
                    mac = parts[2].upper()
                    vendor = ' '.join(parts[3:]).strip('()')
                    found[mac] = {'ip': current_ip, 'mac': mac, 'vendor': vendor}
                    current_ip = None
        except Exception:
            pass

    if not found:
        return jsonify({"error": "Scan failed — arp-scan and nmap both unavailable", "devices": []}), 500

    # Load known devices to set status
    known = {}
    if os.path.exists(KNOWN_DEVICES_FILE):
        try:
            with open(KNOWN_DEVICES_FILE) as f:
                known = json.load(f)
        except Exception:
            pass

    for mac, info in found.items():
        status = "known" if mac in known else "unknown"
        log_device(
            ip=info['ip'], mac=mac, vendor=info['vendor'],
            hostname=known.get(mac, {}).get('name', ''), status=status
        )

    log_scan("network_scan", "local",
             f"Dashboard scan: {len(found)} device(s) found",
             f"Devices: {list(found.keys())}")
    log_activity("network_scan", f"Dashboard triggered: {len(found)} devices")

    devices = get_devices(limit=100)
    return jsonify({"devices": devices, "count": len(devices)})


@app.route('/api/scans')
@login_required
@rate_limited
def api_scans():
    limit = min(int(request.args.get('limit', 20)), 100)
    scan_type = request.args.get('type')
    history = get_scan_history(limit=limit, scan_type=scan_type)
    return jsonify({"scans": history, "count": len(history)})


@app.route('/api/logs')
@login_required
@rate_limited
def api_logs():
    limit = min(int(request.args.get('limit', 50)), 200)
    activity = get_activity_log(limit=limit)
    return jsonify({"logs": activity, "count": len(activity)})


@app.route('/api/notes')
@login_required
@rate_limited
def api_notes():
    return jsonify({"notes": get_notes()})


@app.route('/api/processes')
@login_required
@rate_limited
def api_processes():
    procs = []
    for p in sorted(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']),
                    key=lambda x: x.info.get('cpu_percent', 0) or 0, reverse=True)[:15]:
        procs.append({
            "pid":    p.info['pid'],
            "name":   p.info['name'],
            "cpu":    round(p.info['cpu_percent'] or 0, 1),
            "mem":    round(p.info['memory_percent'] or 0, 1),
        })
    return jsonify({"processes": procs})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_temp() -> float:
    try:
        temps = psutil.sensors_temperatures()
        if 'cpu_thermal' in temps:
            return round(temps['cpu_thermal'][0].current, 1)
        for entries in temps.values():
            if entries:
                return round(entries[0].current, 1)
    except Exception:
        pass
    try:
        with open('/sys/class/thermal/thermal_zone0/temp') as f:
            return round(int(f.read().strip()) / 1000, 1)
    except Exception:
        return 0.0


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    log_activity("Dashboard started", f"v{BOT_VERSION}")
    print(f"Dashboard starting on http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False)
