#!/usr/bin/env python3
"""
Security Operations Center Dashboard v3.0
Flask web app — runs independently from the bot process
Access at http://<pi-ip>:5000
"""

import os
import time
import json
import logging
import subprocess
import socket
import threading
import secrets as _secrets
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

import psutil
from flask import (
    Flask, render_template, redirect, url_for,
    request, session, jsonify, flash, send_file, abort
)

from config import (
    DASHBOARD_USER, DASHBOARD_PASS, DASHBOARD_SECRET_KEY,
    DASHBOARD_HOST, DASHBOARD_PORT, BOT_VERSION, NETWORK_INTERFACE,
    NETWORK_RANGE, KNOWN_DEVICES_FILE, ALERT_CPU_THRESHOLD,
    ALERT_RAM_THRESHOLD, ALERT_TEMP_THRESHOLD, SESSION_TIMEOUT_MINUTES
)
from modules.db import (
    init_db, get_scan_history, get_notes, add_note, delete_note,
    get_activity_log, get_all_stats, log_activity, clear_scan_history,
    get_devices, log_device, log_scan, get_alerts, get_alerts_today,
    log_alert, get_system_stats_history, log_system_stats,
    get_ssh_logs, log_ssh_attempt,
    get_setting, set_setting, get_all_settings,
    get_schedules, add_schedule, update_schedule, delete_schedule,
    add_monitored_site, get_monitored_sites, remove_monitored_site,
    get_webhook, set_webhook, disable_webhook,
    cleanup_old_data, get_stat, increment_stat, update_stat
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = DASHBOARD_SECRET_KEY
app.permanent_session_lifetime = timedelta(minutes=SESSION_TIMEOUT_MINUTES)

# ── CSRF ───────────────────────────────────────────────────────────────────────

def generate_csrf():
    if '_csrf_token' not in session:
        session['_csrf_token'] = _secrets.token_hex(16)
    return session['_csrf_token']

def validate_csrf():
    token = request.form.get('_csrf_token') or request.headers.get('X-CSRF-Token')
    return bool(token and token == session.get('_csrf_token'))

app.jinja_env.globals['csrf_token'] = generate_csrf

# ── Rate limiting ──────────────────────────────────────────────────────────────

_rate_data: dict = defaultdict(list)
_scan_rate_data: dict = defaultdict(list)
RATE_LIMIT = 60
RATE_WINDOW = 60
SCAN_RATE_LIMIT = 10
SCAN_RATE_WINDOW = 60


def _check_rate(ip: str, limit: int, window: int, store: dict) -> bool:
    now = time.time()
    store[ip] = [t for t in store[ip] if now - t < window]
    if len(store[ip]) >= limit:
        return False
    store[ip].append(now)
    return True


def rate_limited(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _check_rate(request.remote_addr, RATE_LIMIT, RATE_WINDOW, _rate_data):
            return jsonify({"error": "Rate limit exceeded"}), 429
        return f(*args, **kwargs)
    return wrapper


def scan_rate_limited(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _check_rate(request.remote_addr, SCAN_RATE_LIMIT, SCAN_RATE_WINDOW, _scan_rate_data):
            return jsonify({"error": "Scan rate limit exceeded (max 10/min)"}), 429
        return f(*args, **kwargs)
    return wrapper


# ── Auth ───────────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        last_active = session.get('last_active', 0)
        if time.time() - last_active > SESSION_TIMEOUT_MINUTES * 60:
            session.clear()
            flash('Session expired — please log in again.', 'warning')
            return redirect(url_for('login'))
        session['last_active'] = time.time()
        return f(*args, **kwargs)
    return wrapper


def csrf_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method == 'POST' and not validate_csrf():
            abort(403)
        return f(*args, **kwargs)
    return wrapper


# ── Pages ──────────────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if username == DASHBOARD_USER and password == DASHBOARD_PASS:
            session.permanent = True
            session['logged_in'] = True
            session['last_active'] = time.time()
            log_activity("Dashboard login", f"from {request.remote_addr}")
            return redirect(url_for('index'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    stats = get_all_stats()
    alerts_today = get_alerts_today()
    devices = get_devices(limit=200)
    known_count = len([d for d in devices if d.get('status') == 'known'])
    unknown_count = len([d for d in devices if d.get('status') == 'unknown'])
    recent_activity = get_activity_log(limit=10)

    threat_level = "LOW"
    threat_color = "success"
    if unknown_count > 0 or alerts_today > 0:
        threat_level = "MEDIUM"
        threat_color = "warning"
    if unknown_count > 3 or alerts_today > 5:
        threat_level = "HIGH"
        threat_color = "danger"

    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "raspberry-pi"

    return render_template('index.html',
        stats=stats, version=BOT_VERSION, hostname=hostname,
        alerts_today=alerts_today, device_total=len(devices),
        known_count=known_count, unknown_count=unknown_count,
        recent_activity=recent_activity,
        threat_level=threat_level, threat_color=threat_color,
    )


@app.route('/network')
@login_required
def network():
    devices = get_devices(limit=200)
    return render_template('network.html', devices=devices, version=BOT_VERSION)


@app.route('/scans')
@login_required
def scans():
    history = get_scan_history(limit=100)
    scan_types = sorted(set(s.get('scan_type', '') for s in history))
    return render_template('scans.html', history=history, version=BOT_VERSION, scan_types=scan_types)


@app.route('/scans/clear', methods=['POST'])
@login_required
@csrf_required
def scans_clear():
    clear_scan_history()
    log_activity("Scan history cleared", f"by {request.remote_addr}")
    flash('Scan history cleared', 'success')
    return redirect(url_for('scans'))


@app.route('/logs')
@login_required
def logs():
    activity = get_activity_log(limit=200)
    ssh_logs = get_ssh_logs(limit=50)
    alerts = get_alerts(limit=50)
    return render_template('logs.html', activity=activity, ssh_logs=ssh_logs, alerts=alerts, version=BOT_VERSION)


@app.route('/settings')
@login_required
def settings():
    notes = get_notes()
    schedules = get_schedules()
    monitored_sites = get_monitored_sites()
    webhook = get_webhook()
    current_settings = get_all_settings()
    known_devices = {}
    if os.path.exists(KNOWN_DEVICES_FILE):
        try:
            with open(KNOWN_DEVICES_FILE) as f:
                known_devices = json.load(f)
        except Exception:
            pass
    return render_template('settings.html',
        version=BOT_VERSION, notes=notes, schedules=schedules,
        monitored_sites=monitored_sites, webhook=webhook,
        current_settings=current_settings, known_devices=known_devices,
    )


# ── Notes ──────────────────────────────────────────────────────────────────────

@app.route('/notes/add', methods=['POST'])
@login_required
@csrf_required
def notes_add():
    content = request.form.get('content', '').strip()[:1000]
    if content:
        add_note(content)
        log_activity("Note added", content[:80])
    return redirect(url_for('settings'))


@app.route('/notes/delete/<int:note_id>', methods=['POST'])
@login_required
@csrf_required
def notes_delete(note_id):
    delete_note(note_id)
    return redirect(url_for('settings'))


# ── Settings management ────────────────────────────────────────────────────────

@app.route('/settings/update', methods=['POST'])
@login_required
@csrf_required
def settings_update():
    allowed_keys = ['scan_interval', 'network_range', 'alert_cpu', 'alert_ram', 'alert_temp']
    for key in allowed_keys:
        val = request.form.get(key, '').strip()
        if val:
            set_setting(key, val)
    log_activity("Settings updated", f"by {request.remote_addr}")
    flash('Settings saved', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/change-password', methods=['POST'])
@login_required
@csrf_required
def change_password():
    new_pass = request.form.get('new_password', '').strip()
    if len(new_pass) < 8:
        flash('Password must be at least 8 characters', 'danger')
    else:
        set_setting('dashboard_password', new_pass)
        log_activity("Password changed", f"by {request.remote_addr}")
        flash('Password updated (restart dashboard to apply)', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/device/add', methods=['POST'])
@login_required
@csrf_required
def device_add():
    mac = request.form.get('mac', '').strip().upper()
    name = request.form.get('name', '').strip()[:64]
    if mac and name:
        try:
            known = {}
            if os.path.exists(KNOWN_DEVICES_FILE):
                with open(KNOWN_DEVICES_FILE) as f:
                    known = json.load(f)
            known[mac] = {'name': name, 'added': datetime.utcnow().isoformat()}
            os.makedirs(os.path.dirname(KNOWN_DEVICES_FILE), exist_ok=True)
            with open(KNOWN_DEVICES_FILE, 'w') as f:
                json.dump(known, f, indent=2)
            log_activity("Device approved", f"{mac} as {name}")
            flash(f'Device {mac} added as "{name}"', 'success')
        except Exception as e:
            flash(f'Error: {e}', 'danger')
    return redirect(url_for('settings'))


@app.route('/settings/device/remove', methods=['POST'])
@login_required
@csrf_required
def device_remove():
    mac = request.form.get('mac', '').strip().upper()
    if mac:
        try:
            known = {}
            if os.path.exists(KNOWN_DEVICES_FILE):
                with open(KNOWN_DEVICES_FILE) as f:
                    known = json.load(f)
            if mac in known:
                del known[mac]
                with open(KNOWN_DEVICES_FILE, 'w') as f:
                    json.dump(known, f, indent=2)
                log_activity("Device removed", mac)
                flash(f'Device {mac} removed', 'success')
        except Exception as e:
            flash(f'Error: {e}', 'danger')
    return redirect(url_for('settings'))


# ── System control ─────────────────────────────────────────────────────────────

@app.route('/system/restart-bot', methods=['POST'])
@login_required
@csrf_required
def restart_bot():
    log_activity("Bot restart requested", f"by {request.remote_addr}")
    try:
        subprocess.Popen(['sudo', 'systemctl', 'restart', 'security-bot.service'])
        flash('Bot restart initiated', 'success')
    except Exception as e:
        flash(f'Restart failed: {e}', 'danger')
    return redirect(url_for('settings'))


@app.route('/system/restart-dashboard', methods=['POST'])
@login_required
@csrf_required
def restart_dashboard():
    log_activity("Dashboard restart requested", f"by {request.remote_addr}")
    flash('Dashboard restarting...', 'info')
    def _restart():
        time.sleep(1)
        os.execv(__file__, ['python3', __file__])
    threading.Thread(target=_restart, daemon=True).start()
    return redirect(url_for('settings'))


# ── Error pages ────────────────────────────────────────────────────────────────

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "Forbidden — invalid or missing CSRF token"}), 403


# ── API: Status ────────────────────────────────────────────────────────────────

@app.route('/api/status')
@login_required
@rate_limited
def api_status():
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    temp = _get_temp()
    uptime_secs = int(time.time() - psutil.boot_time())
    h, rem = divmod(uptime_secs, 3600)
    m, s = divmod(rem, 60)
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
    except Exception:
        hostname = "raspberry-pi"
        ip = "unknown"
    return jsonify({
        "cpu_percent": cpu, "ram_percent": mem.percent,
        "ram_used_gb": round(mem.used / 1_073_741_824, 2),
        "ram_total_gb": round(mem.total / 1_073_741_824, 2),
        "disk_percent": disk.percent,
        "disk_used_gb": round(disk.used / 1_073_741_824, 2),
        "disk_total_gb": round(disk.total / 1_073_741_824, 2),
        "temp_c": temp, "uptime": f"{h}h {m}m {s}s",
        "bot_version": BOT_VERSION, "hostname": hostname, "ip": ip,
        "timestamp": datetime.utcnow().isoformat(timespec='seconds'),
    })

@app.route('/api/stats')
@login_required
@rate_limited
def api_stats():
    return api_status()


@app.route('/api/status/history')
@login_required
@rate_limited
def api_status_history():
    hours = min(int(request.args.get('hours', 24)), 168)
    history = get_system_stats_history(hours=hours)
    return jsonify({"history": history, "count": len(history)})


# ── API: Devices ───────────────────────────────────────────────────────────────

@app.route('/api/devices')
@login_required
@rate_limited
def api_devices():
    devices = get_devices(limit=200)
    known = {}
    if os.path.exists(KNOWN_DEVICES_FILE):
        try:
            with open(KNOWN_DEVICES_FILE) as f:
                known = json.load(f)
        except Exception:
            pass
    for d in devices:
        mac = d.get('mac', '')
        d['friendly_name'] = known.get(mac, {}).get('name', '') if mac else ''
    return jsonify({"devices": devices, "count": len(devices)})

@app.route('/api/network')
@login_required
@rate_limited
def api_network():
    return api_devices()


# ── API: Scans ─────────────────────────────────────────────────────────────────

@app.route('/api/scan/network', methods=['POST'])
@login_required
@scan_rate_limited
def api_scan_network():
    found = _run_network_scan()
    if found is None:
        return jsonify({"error": "Network scan failed — arp-scan and nmap unavailable"}), 500
    devices = get_devices(limit=200)
    log_activity("network_scan", f"Dashboard: {len(found)} devices")
    return jsonify({"devices": devices, "count": len(devices), "found": len(found)})

@app.route('/api/scan', methods=['POST'])
@login_required
@scan_rate_limited
def api_scan():
    return api_scan_network()


@app.route('/api/scan/website', methods=['POST'])
@login_required
@scan_rate_limited
def api_scan_website():
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    if not url.startswith('http'):
        url = 'https://' + url
    try:
        import asyncio
        from modules.webtools import vuln_scan
        result = asyncio.run(vuln_scan(url))
        log_scan("vuln_scan", url, result[:300], result)
        log_activity("vuln_scan", url)
        return jsonify({"result": result, "target": url, "scan_type": "vuln_scan"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan/ports', methods=['POST'])
@login_required
@scan_rate_limited
def api_scan_ports():
    data = request.get_json(silent=True) or {}
    target = data.get('target', '').strip()
    ports = data.get('ports', 'common')
    if not target:
        return jsonify({"error": "Target required"}), 400
    try:
        import asyncio
        from modules.network import port_scan
        result = asyncio.run(port_scan(target, ports))
        log_scan("port_scan", target, result[:300], result)
        log_activity("port_scan", target)
        return jsonify({"result": result, "target": target, "scan_type": "port_scan"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan/dns', methods=['POST'])
@login_required
@scan_rate_limited
def api_scan_dns():
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({"error": "Domain required"}), 400
    try:
        import asyncio
        from modules.analysis import dns_lookup
        result = asyncio.run(dns_lookup(domain))
        log_scan("dns_lookup", domain, result[:300], result)
        log_activity("dns_lookup", domain)
        return jsonify({"result": result, "target": domain, "scan_type": "dns_lookup"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan/whois', methods=['POST'])
@login_required
@scan_rate_limited
def api_scan_whois():
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({"error": "Domain required"}), 400
    try:
        import asyncio
        from modules.analysis import whois_lookup
        result = asyncio.run(whois_lookup(domain))
        log_scan("whois", domain, result[:300], result)
        log_activity("whois", domain)
        return jsonify({"result": result, "target": domain, "scan_type": "whois"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan/ssl', methods=['POST'])
@login_required
@scan_rate_limited
def api_scan_ssl():
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').strip().replace('https://', '').replace('http://', '').split('/')[0]
    if not domain:
        return jsonify({"error": "Domain required"}), 400
    try:
        import asyncio
        from modules.network import check_ssl
        result = asyncio.run(check_ssl(domain))
        log_scan("ssl_check", domain, result[:300], result)
        log_activity("ssl_check", domain)
        return jsonify({"result": result, "target": domain, "scan_type": "ssl_check"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan/tech', methods=['POST'])
@login_required
@scan_rate_limited
def api_scan_tech():
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    if not url.startswith('http'):
        url = 'https://' + url
    try:
        import asyncio
        from modules.webtools import tech_detect
        result = asyncio.run(tech_detect(url))
        log_scan("tech_detect", url, result[:300], result)
        log_activity("tech_detect", url)
        return jsonify({"result": result, "target": url, "scan_type": "tech_detect"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan/subdomains', methods=['POST'])
@login_required
@scan_rate_limited
def api_scan_subdomains():
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({"error": "Domain required"}), 400
    try:
        import asyncio
        from modules.webtools import find_subdomains
        result = asyncio.run(find_subdomains(domain))
        log_scan("subdomains", domain, result[:300], result)
        log_activity("subdomains", domain)
        return jsonify({"result": result, "target": domain, "scan_type": "subdomains"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan/email', methods=['POST'])
@login_required
@scan_rate_limited
def api_scan_email():
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({"error": "Domain required"}), 400
    try:
        import asyncio
        from modules.webtools import email_security_check
        result = asyncio.run(email_security_check(domain))
        log_scan("email_sec", domain, result[:300], result)
        log_activity("email_sec", domain)
        return jsonify({"result": result, "target": domain, "scan_type": "email_sec"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── API: Logs ──────────────────────────────────────────────────────────────────

@app.route('/api/logs')
@login_required
@rate_limited
def api_logs():
    limit = min(int(request.args.get('limit', 50)), 200)
    log_type = request.args.get('type', '')
    activity = get_activity_log(limit=limit)
    if log_type:
        activity = [l for l in activity if log_type.lower() in l.get('event', '').lower()]
    return jsonify({"logs": activity, "count": len(activity)})


@app.route('/api/logs/ssh')
@login_required
@rate_limited
def api_logs_ssh():
    limit = min(int(request.args.get('limit', 50)), 200)
    return jsonify({"ssh_logs": get_ssh_logs(limit=limit)})


# ── API: Bandwidth ─────────────────────────────────────────────────────────────

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


# ── API: Scan history ──────────────────────────────────────────────────────────

@app.route('/api/scans/history')
@login_required
@rate_limited
def api_scans_history():
    limit = min(int(request.args.get('limit', 20)), 100)
    scan_type = request.args.get('type')
    history = get_scan_history(limit=limit, scan_type=scan_type)
    return jsonify({"scans": history, "count": len(history)})

@app.route('/api/scans')
@login_required
@rate_limited
def api_scans():
    return api_scans_history()


# ── API: Alerts ────────────────────────────────────────────────────────────────

@app.route('/api/alerts')
@login_required
@rate_limited
def api_alerts():
    limit = min(int(request.args.get('limit', 50)), 200)
    alerts = get_alerts(limit=limit)
    return jsonify({"alerts": alerts, "count": len(alerts), "today": get_alerts_today()})


# ── API: Settings ──────────────────────────────────────────────────────────────

@app.route('/api/settings', methods=['GET', 'POST'])
@login_required
@rate_limited
def api_settings():
    if request.method == 'GET':
        return jsonify(get_all_settings())
    data = request.get_json(silent=True) or {}
    if not validate_csrf():
        abort(403)
    allowed_keys = ['scan_interval', 'network_range', 'alert_cpu', 'alert_ram', 'alert_temp']
    for key in allowed_keys:
        if key in data:
            set_setting(key, str(data[key])[:200])
    return jsonify({"status": "ok"})


# ── API: System control ────────────────────────────────────────────────────────

@app.route('/api/system/restart-bot', methods=['POST'])
@login_required
def api_restart_bot():
    if not validate_csrf():
        abort(403)
    log_activity("Bot restart", f"by {request.remote_addr}")
    try:
        subprocess.Popen(['sudo', 'systemctl', 'restart', 'security-bot.service'])
        return jsonify({"status": "restart initiated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/system/restart-dashboard', methods=['POST'])
@login_required
def api_restart_dashboard():
    if not validate_csrf():
        abort(403)
    log_activity("Dashboard restart", f"by {request.remote_addr}")
    def _restart():
        time.sleep(1)
        os.execv(__file__, ['python3', __file__])
    threading.Thread(target=_restart, daemon=True).start()
    return jsonify({"status": "restarting"})


# ── API: Bot info ──────────────────────────────────────────────────────────────

@app.route('/api/botinfo')
@login_required
@rate_limited
def api_botinfo():
    stats = get_all_stats()
    return jsonify({
        "version": BOT_VERSION,
        "commands_run": int(stats.get('commands_run', 0)),
        "scans_done": int(stats.get('scans_done', 0)),
        "devices_seen": len(get_devices(limit=1000)),
        "alerts_today": get_alerts_today(),
    })


# ── API: Processes ─────────────────────────────────────────────────────────────

@app.route('/api/processes')
@login_required
@rate_limited
def api_processes():
    procs = []
    for p in sorted(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']),
                    key=lambda x: x.info.get('cpu_percent', 0) or 0, reverse=True)[:15]:
        procs.append({
            "pid": p.info['pid'], "name": p.info['name'],
            "cpu": round(p.info['cpu_percent'] or 0, 1),
            "mem": round(p.info['memory_percent'] or 0, 1),
        })
    return jsonify({"processes": procs})


# ── API: Notes ─────────────────────────────────────────────────────────────────

@app.route('/api/notes')
@login_required
@rate_limited
def api_notes():
    return jsonify({"notes": get_notes()})


# ── API: PDF Reports ──────────────────────────────────────────────────────────

@app.route('/api/report/system')
@login_required
@rate_limited
def api_report_system():
    try:
        import asyncio
        from modules.pdf_report import generate_system_report
        buf = asyncio.run(generate_system_report())
        log_activity("pdf_report", "system")
        return send_file(buf, mimetype='application/pdf', as_attachment=True,
                         download_name=f"system_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf")
    except ImportError:
        return jsonify({"error": "reportlab not installed — run: pip install reportlab"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/report/network')
@login_required
@rate_limited
def api_report_network():
    try:
        import asyncio
        from modules.pdf_report import generate_network_report
        buf = asyncio.run(generate_network_report())
        log_activity("pdf_report", "network")
        return send_file(buf, mimetype='application/pdf', as_attachment=True,
                         download_name=f"network_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf")
    except ImportError:
        return jsonify({"error": "reportlab not installed"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/report/full')
@login_required
@rate_limited
def api_report_full():
    try:
        import asyncio
        from modules.pdf_report import generate_full_report
        buf = asyncio.run(generate_full_report())
        log_activity("pdf_report", "full")
        return send_file(buf, mimetype='application/pdf', as_attachment=True,
                         download_name=f"full_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf")
    except ImportError:
        return jsonify({"error": "reportlab not installed"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Background tasks ───────────────────────────────────────────────────────────

def _stats_recorder():
    """Record system stats every 5 minutes."""
    while True:
        try:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            temp = _get_temp()
            log_system_stats(cpu, mem.percent, disk.percent, temp)
        except Exception as e:
            logger.error(f"Stats recorder error: {e}")
        time.sleep(300)


def _ssh_monitor():
    """Parse auth.log for SSH attempts every 60 seconds."""
    import re
    last_pos = 0
    log_path = '/var/log/auth.log'
    while True:
        try:
            if os.path.exists(log_path):
                with open(log_path, 'r', errors='ignore') as f:
                    f.seek(last_pos)
                    new_lines = f.readlines()
                    last_pos = f.tell()
                for line in new_lines:
                    if 'sshd' not in line:
                        continue
                    fail = re.search(r'Failed password for (?:invalid user )?(\S+) from (\S+)', line)
                    if fail:
                        log_ssh_attempt(fail.group(2), fail.group(1), False)
                        log_alert("ssh_fail", fail.group(2), f"Failed SSH: {fail.group(1)} from {fail.group(2)}", "warning")
                        continue
                    ok = re.search(r'Accepted \S+ for (\S+) from (\S+)', line)
                    if ok:
                        log_ssh_attempt(ok.group(2), ok.group(1), True)
                        log_alert("ssh_success", ok.group(2), f"SSH login: {ok.group(1)} from {ok.group(2)}", "info")
        except Exception as e:
            logger.error(f"SSH monitor error: {e}")
        time.sleep(60)


def _cleanup_worker():
    """Remove data older than 30 days, runs once per day."""
    while True:
        try:
            cleanup_old_data(days=30)
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
        time.sleep(86400)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get_temp() -> float:
    try:
        temps = psutil.sensors_temperatures()
        if temps:
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


def _run_network_scan() -> dict:
    """Run network scan and update DB. Returns found dict or None on failure."""
    found = {}
    try:
        result = subprocess.run(
            ['sudo', 'arp-scan', '--localnet', '--retry=2'],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                parts = line.split('\t')
                if len(parts) >= 2 and '.' in parts[0]:
                    ip, mac = parts[0].strip(), parts[1].strip().upper()
                    vendor = parts[2].strip() if len(parts) > 2 else "Unknown"
                    found[mac] = {'ip': ip, 'mac': mac, 'vendor': vendor}
    except Exception:
        pass
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
        return None
    known = {}
    if os.path.exists(KNOWN_DEVICES_FILE):
        try:
            with open(KNOWN_DEVICES_FILE) as f:
                known = json.load(f)
        except Exception:
            pass
    for mac, info in found.items():
        status = "known" if mac in known else "unknown"
        log_device(ip=info['ip'], mac=mac, vendor=info['vendor'],
                   hostname=known.get(mac, {}).get('name', ''), status=status)
    log_scan("network_scan", "local", f"Dashboard scan: {len(found)} device(s)", str(list(found.keys())))
    return found


# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    log_activity("Dashboard started", f"v{BOT_VERSION}")
    print(f"[SecBot Dashboard v{BOT_VERSION}] Starting on http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    threading.Thread(target=_stats_recorder, daemon=True, name="stats-recorder").start()
    threading.Thread(target=_ssh_monitor, daemon=True, name="ssh-monitor").start()
    threading.Thread(target=_cleanup_worker, daemon=True, name="cleanup").start()
    logger.info("Background threads started")
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False, threaded=True)
