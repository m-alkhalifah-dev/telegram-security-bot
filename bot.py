#!/usr/bin/env python3
"""
Telegram Security Bot v2.0
Personal cybersecurity assistant running on Raspberry Pi
"""

import io
import logging
import asyncio
import os
import time
import subprocess
from datetime import datetime, timedelta
from functools import wraps

import aiohttp

from telegram import Update, BotCommand, InputFile
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
)

from config import (
    BOT_TOKEN, ALLOWED_CHAT_IDS, SCAN_INTERVAL, ABUSEIPDB_API_KEY,
    BOT_VERSION, DASHBOARD_ENABLED, DASHBOARD_HOST, DASHBOARD_PORT,
)
from modules.db import (
    init_db, add_note, get_notes, delete_note,
    log_activity, increment_stat, log_scan, log_device, log_alert,
)
from modules.system import get_system_status, get_top_processes
from modules.network import ping_host, port_scan, check_website, check_ssl, get_public_ip
from modules.monitor import NetworkMonitor
from modules.analysis import whois_lookup, dns_lookup, geoip_lookup, reverse_dns, full_domain_report
from modules.webtools import vuln_scan, find_subdomains, tech_detect, email_security_check
from modules.security import check_password, identify_hash, run_speedtest, get_bandwidth
from modules.breach import breach_check, analyze_email_header, blacklist_check
from modules.webscan import crawl_website, js_scan, cors_test, waf_detect, header_check, robots_check
from modules.crypto_tools import encode_text, decode_text, gen_hash, gen_password, cert_scan
from modules.sysadmin import (
    list_cron_jobs, list_users, disk_usage, list_services,
    check_updates, get_history, backup_bot, get_resource_value,
    daily_report_content,
)
from modules.threat import get_threat_feed, abuse_check, ip_lookup

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

network_monitor = NetworkMonitor()

# Active resource alerts: {(chat_id, resource): threshold}
active_alerts: dict = {}
# Cooldown tracker: {(chat_id, resource): last_alert_unix_time}
alert_last_sent: dict = {}

# Bot start time for uptime calculation
bot_start_time = time.time()

# Active timers: {chat_id: asyncio.Task}
active_timers: dict = {}

# Daily report: {chat_id: "HH:MM"}
daily_report_schedule: dict = {}
# Daily report tasks: {chat_id: asyncio.Task}
daily_report_tasks: dict = {}


# ============================================================
# Authorization decorator
# ============================================================
def authorized_only(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        chat_id = update.effective_chat.id
        if chat_id not in ALLOWED_CHAT_IDS:
            await update.message.reply_text(
                f"Access denied. Your Chat ID: `{chat_id}`",
                parse_mode='Markdown'
            )
            logger.warning(f"Unauthorized access attempt from Chat ID: {chat_id}")
            return
        return await func(update, context)
    return wrapper


# ============================================================
# Helper
# ============================================================
async def send_long(update: Update, text: str):
    """Send a message, splitting into chunks if over 4000 chars."""
    if len(text) <= 4000:
        await update.message.reply_text(text, parse_mode='Markdown')
    else:
        for chunk in [text[i:i+4000] for i in range(0, len(text), 4000)]:
            await update.message.reply_text(chunk, parse_mode='Markdown')


# ============================================================
# /start  /help
# ============================================================
@authorized_only
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg1 = (
        "🤖 *Telegram Security Bot*\n\n"
        "📊 *System Monitoring:*\n"
        "├ /status — CPU, RAM, temp, disk\n"
        "├ /processes — top resource consumers\n"
        "├ /myip — public IP info\n"
        "├ /bandwidth — live network usage\n"
        "├ /diskusage — disk breakdown\n"
        "├ /servicelist — running services\n"
        "├ /cron — scheduled cron jobs\n"
        "├ /users — system users & logins\n"
        "├ /history — last 20 shell commands\n"
        "├ /update — available apt updates\n"
        "├ /backup — backup bot config/data\n"
        "└ /alert `[CPU|RAM|TEMP]` `[%]` — set alert\n\n"
        "🌐 *Network Tools:*\n"
        "├ /ping `[host]` — ICMP ping\n"
        "├ /portscan `[IP]` — port scanner\n"
        "├ /checksite `[URL]` — site check\n"
        "├ /ssl `[domain]` — SSL certificate\n"
        "├ /scan — local network ARP scan\n"
        "├ /devices — connected devices\n"
        "└ /monitor — auto device monitoring\n"
    )
    msg2 = (
        "🕵️ *Web Security:*\n"
        "├ /vulnscan `[URL]` — vuln scan + A–F grade\n"
        "├ /subdomains `[domain]` — subdomain finder\n"
        "├ /techdetect `[URL]` — tech stack detection\n"
        "├ /emailsec `[domain]` — SPF/DKIM/DMARC\n"
        "├ /crawl `[URL]` — spider site for links/forms\n"
        "├ /jsscan `[URL]` — JS file secret scanner\n"
        "├ /corstest `[URL]` — CORS misconfiguration test\n"
        "├ /waf `[URL]` — WAF detection\n"
        "├ /headercheck `[URL]` — HTTP header analysis\n"
        "└ /robotscheck `[URL]` — robots.txt & sitemap\n\n"
        "🔍 *Domain & OSINT:*\n"
        "├ /whois `[domain]` — WHOIS lookup\n"
        "├ /dns `[domain]` — DNS records\n"
        "├ /geoip `[IP]` — geolocation\n"
        "└ /report `[domain]` — full domain report\n\n"
        "📧 *Email & Breach Intel:*\n"
        "├ /breachcheck `[email]` — data breach lookup\n"
        "├ /emailheader — analyze raw email headers\n"
        "└ /blacklistcheck `[IP/domain]` — DNSBL check\n"
    )
    msg3 = (
        "🛠 *Security Tools:*\n"
        "├ /passcheck `[password]` — strength + HIBP check\n"
        "├ /hash `[value]` — hash identifier + lookup\n"
        "├ /speedtest — download/upload/ping test\n"
        "├ /certscan `[domain]` — deep TLS analysis\n"
        "├ /encode `[type]` `[text]` — encode text\n"
        "├ /decode `[type]` `[text]` — decode text\n"
        "├ /genhash `[algo]` `[text]` — generate hash\n"
        "└ /genpass `[length]` — secure password gen\n\n"
        "🌍 *Threat Intelligence:*\n"
        "├ /threatfeed — latest CISA KEV + NVD CVEs\n"
        "├ /abusecheck `[IP]` — AbuseIPDB reputation\n"
        "└ /iplookup `[IP]` — full IP: geo, ports, abuse\n\n"
        "🧰 *Utilities:*\n"
        "├ /dashboard — web dashboard link\n"
        "├ /screenshot — Pi desktop screenshot\n"
        "├ /qr `[text]` — generate QR code\n"
        "├ /shorten `[URL]` — shorten a URL\n"
        "├ /weather `[city]` — weather info\n"
        "├ /notes `[add|list|del]` — manage notes\n"
        "├ /timer `[seconds]` — countdown timer\n"
        "├ /botinfo — bot version & stats\n"
        "├ /changelog — what's new in v2.0\n"
        "└ /dailyreport `[on|off]` — scheduled daily summary\n\n"
        "💡 Use /help for usage examples"
    )
    await update.message.reply_text(msg1, parse_mode='Markdown')
    await update.message.reply_text(msg2, parse_mode='Markdown')
    await update.message.reply_text(msg3, parse_mode='Markdown')


@authorized_only
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "📖 *Usage Examples*\n\n"
        "*Network:*\n"
        "├ `/ping google.com`\n"
        "├ `/portscan 192.168.1.1`\n"
        "├ `/ssl google.com`\n\n"
        "*Web Security:*\n"
        "├ `/vulnscan https://example.com`\n"
        "├ `/subdomains example.com`\n"
        "├ `/techdetect https://example.com`\n"
        "├ `/emailsec gmail.com`\n"
        "├ `/crawl https://example.com`\n"
        "├ `/jsscan https://example.com`\n"
        "├ `/corstest https://example.com`\n"
        "├ `/waf https://example.com`\n"
        "├ `/headercheck https://example.com`\n"
        "└ `/robotscheck https://example.com`\n\n"
        "*Breach & Email:*\n"
        "├ `/breachcheck user@example.com`\n"
        "├ `/blacklistcheck 8.8.8.8`\n"
        "└ `/emailheader` then paste raw headers on next line\n\n"
        "*Crypto Tools:*\n"
        "├ `/encode b64 Hello World`\n"
        "├ `/decode hex 48656c6c6f`\n"
        "├ `/genhash sha256 mytext`\n"
        "├ `/genpass 24`\n"
        "└ `/certscan google.com`\n\n"
        "*System:*\n"
        "├ `/alert CPU 90` — notify when CPU > 90%\n"
        "├ `/alert RAM 85`\n"
        "└ `/alert TEMP 75`\n\n"
        "*Threat Intel:*\n"
        "├ `/threatfeed`\n"
        "├ `/abusecheck 1.2.3.4`\n"
        "└ `/iplookup 8.8.8.8`\n\n"
        "*Automation:*\n"
        "├ `/dailyreport on` — enable daily report at 08:00\n"
        "├ `/dailyreport on 07:30` — enable at custom time\n"
        "└ `/dailyreport off` — disable\n\n"
        "⚠️ Only scan systems you are authorized to test."
    )
    await update.message.reply_text(msg, parse_mode='Markdown')


# ============================================================
# System commands
# ============================================================
@authorized_only
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Checking system...")
    await send_long(update, get_system_status())


@authorized_only
async def processes_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await send_long(update, get_top_processes())


@authorized_only
async def myip_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Fetching public IP...")
    await send_long(update, await get_public_ip())


@authorized_only
async def bandwidth_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Sampling network for 2 seconds...")
    await send_long(update, await get_bandwidth())


@authorized_only
async def diskusage_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Analyzing disk usage...")
    await send_long(update, await disk_usage())


@authorized_only
async def servicelist_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Listing services...")
    await send_long(update, await list_services())


@authorized_only
async def cron_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await send_long(update, await list_cron_jobs())


@authorized_only
async def users_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await send_long(update, await list_users())


@authorized_only
async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await send_long(update, await get_history())


@authorized_only
async def update_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Checking for updates (may take ~60s)...")
    await send_long(update, await check_updates())


@authorized_only
async def backup_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Creating backup...")
    await send_long(update, await backup_bot())


@authorized_only
async def alert_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Set a resource alert: /alert [CPU|RAM|TEMP] [threshold]"""
    if len(context.args) < 2:
        await update.message.reply_text(
            "❓ *Usage:* `/alert [CPU|RAM|TEMP] [threshold]`\n"
            "*Examples:*\n"
            "├ `/alert CPU 90` — alert when CPU > 90%\n"
            "├ `/alert RAM 85` — alert when RAM > 85%\n"
            "└ `/alert TEMP 75` — alert when temp > 75°C\n\n"
            "To cancel: `/alert CPU 0`",
            parse_mode='Markdown'
        )
        return

    resource = context.args[0].upper()
    if resource not in ('CPU', 'RAM', 'TEMP'):
        await update.message.reply_text(
            "❌ Resource must be `CPU`, `RAM`, or `TEMP`",
            parse_mode='Markdown'
        )
        return

    try:
        threshold = float(context.args[1])
    except ValueError:
        await update.message.reply_text("❌ Threshold must be a number (e.g. 90)")
        return

    chat_id = update.effective_chat.id
    key = (chat_id, resource)

    if threshold <= 0:
        active_alerts.pop(key, None)
        alert_last_sent.pop(key, None)
        await update.message.reply_text(
            f"⏹ *Alert for {resource} removed*", parse_mode='Markdown'
        )
        return

    active_alerts[key] = threshold
    await update.message.reply_text(
        f"✅ *Alert set:* {resource} > `{threshold}%`\n"
        f"You will be notified when exceeded.",
        parse_mode='Markdown'
    )
    asyncio.create_task(_alert_monitor(context, chat_id, resource, threshold))


async def _alert_monitor(context: ContextTypes.DEFAULT_TYPE, chat_id: int, resource: str, threshold: float):
    """Background task: check a resource against its threshold every 60s."""
    key = (chat_id, resource)
    logger.info(f"Alert monitor started: {resource} > {threshold} for {chat_id}")

    while active_alerts.get(key) == threshold:
        try:
            val = await get_resource_value(resource)
            if val >= threshold:
                now = time.time()
                if now - alert_last_sent.get(key, 0) > 300:  # 5-min cooldown
                    alert_last_sent[key] = now
                    unit = "°C" if resource == "TEMP" else "%"
                    await context.bot.send_message(
                        chat_id=chat_id,
                        text=(
                            f"🚨 *Resource Alert!*\n\n"
                            f"⚠️ *{resource}* is at `{val:.1f}{unit}`\n"
                            f"Threshold: `{threshold}{unit}`\n\n"
                            f"Use /status to check the system."
                        ),
                        parse_mode='Markdown'
                    )
        except Exception as e:
            logger.error(f"Alert monitor error ({resource}): {e}")
        await asyncio.sleep(60)

    logger.info(f"Alert monitor stopped: {resource} for {chat_id}")


# ============================================================
# Network commands
# ============================================================
@authorized_only
async def ping_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/ping [host]`\n*Example:* `/ping google.com`",
            parse_mode='Markdown'
        )
        return
    host = context.args[0]
    await update.message.reply_text(f"Pinging `{host}`...", parse_mode='Markdown')
    await send_long(update, await ping_host(host))


@authorized_only
async def portscan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/portscan [IP] [ports]`\n"
            "*Example:* `/portscan 192.168.1.1`\n"
            "*Custom ports:* `/portscan 192.168.1.1 80,443,8080`",
            parse_mode='Markdown'
        )
        return
    target = context.args[0]
    ports  = context.args[1] if len(context.args) > 1 else "common"
    await update.message.reply_text(f"Scanning `{target}`...", parse_mode='Markdown')
    result = await port_scan(target, ports)
    log_scan("portscan", target, f"Port scan on {target} (ports: {ports})", result)
    log_activity("portscan", target)
    await send_long(update, result)


@authorized_only
async def checksite_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/checksite [URL]`\n*Example:* `/checksite github.com`",
            parse_mode='Markdown'
        )
        return
    url = context.args[0]
    await update.message.reply_text(f"Checking `{url}`...", parse_mode='Markdown')
    result = await check_website(url)
    log_scan("checksite", url, f"Site check: {url}", result)
    log_activity("checksite", url)
    await send_long(update, result)


@authorized_only
async def ssl_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/ssl [domain]`\n*Example:* `/ssl google.com`",
            parse_mode='Markdown'
        )
        return
    domain = context.args[0]
    await update.message.reply_text(f"Checking SSL for `{domain}`...", parse_mode='Markdown')
    result = await check_ssl(domain)
    log_scan("ssl", domain, f"SSL check: {domain}", result)
    log_activity("ssl_check", domain)
    await send_long(update, result)


@authorized_only
async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Scanning local network...")
    devices = await network_monitor.scan_network()
    # Save each discovered device to the database
    known = network_monitor.known_devices
    for mac, info in devices.items():
        status = "known" if mac in known else "unknown"
        log_device(
            ip=info.get('ip', ''),
            mac=mac,
            vendor=info.get('vendor', ''),
            hostname=known.get(mac, {}).get('name', ''),
            status=status,
        )
    log_scan("network_scan", "local", f"Network scan: {len(devices)} device(s) found",
             f"Devices: {list(devices.keys())}")
    log_activity("network_scan", f"{len(devices)} devices found")
    await send_long(update, network_monitor.get_devices_list())


@authorized_only
async def devices_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not network_monitor.current_devices:
        await update.message.reply_text("Scanning network first...")
        await network_monitor.scan_network()
    await send_long(update, network_monitor.get_devices_list())


@authorized_only
async def approve_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/approve [MAC] [name]`\n"
            "*Example:* `/approve AA:BB:CC:DD:EE:FF MyPhone`",
            parse_mode='Markdown'
        )
        return
    mac  = context.args[0].upper()
    name = ' '.join(context.args[1:]) if len(context.args) > 1 else ""
    if network_monitor.approve_device(mac, name):
        await update.message.reply_text(
            f"✅ Device `{mac}` added to known devices"
            + (f" as *{name}*" if name else ""),
            parse_mode='Markdown'
        )
    else:
        await update.message.reply_text(
            f"❌ Device `{mac}` not found in current scan. Run /scan first.",
            parse_mode='Markdown'
        )


@authorized_only
async def approve_all_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    count = network_monitor.approve_all_current()
    await update.message.reply_text(
        f"✅ Added *{count}* new device(s) to known list",
        parse_mode='Markdown'
    )


@authorized_only
async def monitor_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if network_monitor.is_running:
        network_monitor.is_running = False
        await update.message.reply_text("⏹ *Network monitoring stopped*", parse_mode='Markdown')
    else:
        network_monitor.is_running = True
        await update.message.reply_text(
            f"▶️ *Network monitoring started*\n"
            f"Scanning every {SCAN_INTERVAL // 60} minute(s)\n"
            f"You will be alerted on new devices.",
            parse_mode='Markdown'
        )
        asyncio.create_task(background_monitor(context, update.effective_chat.id))


async def background_monitor(context: ContextTypes.DEFAULT_TYPE, chat_id: int):
    logger.info("Network background monitor started")
    while network_monitor.is_running:
        try:
            new_devices = await network_monitor.check_new_devices()
            for device in new_devices:
                # Save new device and alert to database
                log_device(
                    ip=device.get('ip', ''),
                    mac=device.get('mac', ''),
                    vendor=device.get('vendor', ''),
                    status='unknown',
                )
                log_alert(
                    alert_type="new_device",
                    target=device.get('ip', ''),
                    detail=f"New device: MAC={device.get('mac','')} Vendor={device.get('vendor','')}",
                    severity="warning",
                )
                await context.bot.send_message(
                    chat_id=chat_id,
                    text=network_monitor.format_alert(device),
                    parse_mode='Markdown'
                )
        except Exception as e:
            logger.error(f"Monitor error: {e}")
        await asyncio.sleep(SCAN_INTERVAL)
    logger.info("Network background monitor stopped")


# ============================================================
# Domain analysis commands
# ============================================================
@authorized_only
async def whois_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/whois [domain]`\n*Example:* `/whois google.com`",
            parse_mode='Markdown'
        )
        return
    domain = context.args[0]
    await update.message.reply_text(f"Looking up `{domain}`...", parse_mode='Markdown')
    result = await whois_lookup(domain)
    log_scan("whois", domain, f"WHOIS: {domain}", result)
    log_activity("whois_lookup", domain)
    await send_long(update, result)


@authorized_only
async def dns_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/dns [domain]`\n*Example:* `/dns cloudflare.com`",
            parse_mode='Markdown'
        )
        return
    domain = context.args[0]
    await update.message.reply_text(f"Fetching DNS records for `{domain}`...", parse_mode='Markdown')
    result = await dns_lookup(domain)
    log_scan("dns", domain, f"DNS lookup: {domain}", result)
    log_activity("dns_lookup", domain)
    await send_long(update, result)


@authorized_only
async def geoip_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/geoip [IP]`\n*Example:* `/geoip 8.8.8.8`",
            parse_mode='Markdown'
        )
        return
    ip = context.args[0]
    await update.message.reply_text(f"Looking up `{ip}`...", parse_mode='Markdown')
    result = await geoip_lookup(ip)
    log_scan("geoip", ip, f"GeoIP: {ip}", result)
    log_activity("geoip_lookup", ip)
    await send_long(update, result)


@authorized_only
async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/report [domain]`\n*Example:* `/report example.com`",
            parse_mode='Markdown'
        )
        return
    domain = context.args[0]
    await update.message.reply_text(f"Building full report for `{domain}`... (~30s)", parse_mode='Markdown')
    result = await full_domain_report(domain)
    log_scan("domain_report", domain, f"Full domain report: {domain}", result)
    log_activity("domain_report", domain)
    await send_long(update, result)


# ============================================================
# Web security commands (from webtools.py)
# ============================================================
@authorized_only
async def vulnscan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/vulnscan [URL]`\n*Example:* `/vulnscan https://example.com`",
            parse_mode='Markdown'
        )
        return
    url = context.args[0]
    await update.message.reply_text(f"Scanning `{url}` for vulnerabilities (~30s)...", parse_mode='Markdown')
    result = await vuln_scan(url)
    log_scan("vulnscan", url, f"Vuln scan: {url}", result)
    log_activity("vulnscan", url)
    await send_long(update, result)


@authorized_only
async def subdomains_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/subdomains [domain]`\n*Example:* `/subdomains example.com`",
            parse_mode='Markdown'
        )
        return
    domain = context.args[0].lower().strip()
    await update.message.reply_text(f"Enumerating subdomains for `{domain}` via crt.sh...", parse_mode='Markdown')
    result = await find_subdomains(domain)
    log_scan("subdomains", domain, f"Subdomain enum: {domain}", result)
    log_activity("subdomains", domain)
    await send_long(update, result)


@authorized_only
async def techdetect_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/techdetect [URL]`\n*Example:* `/techdetect https://wordpress.org`",
            parse_mode='Markdown'
        )
        return
    url = context.args[0]
    await update.message.reply_text(f"Detecting technologies on `{url}`...", parse_mode='Markdown')
    result = await tech_detect(url)
    log_scan("techdetect", url, f"Tech detect: {url}", result)
    log_activity("techdetect", url)
    await send_long(update, result)


@authorized_only
async def emailsec_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/emailsec [domain]`\n*Example:* `/emailsec gmail.com`",
            parse_mode='Markdown'
        )
        return
    domain = context.args[0].lower().strip()
    await update.message.reply_text(f"Checking email security for `{domain}`...", parse_mode='Markdown')
    result = await email_security_check(domain)
    log_scan("emailsec", domain, f"Email security: {domain}", result)
    log_activity("emailsec", domain)
    await send_long(update, result)


# ============================================================
# Advanced web scan commands (from webscan.py)
# ============================================================
@authorized_only
async def crawl_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/crawl [URL]`\n*Example:* `/crawl https://example.com`",
            parse_mode='Markdown'
        )
        return
    url = context.args[0]
    await update.message.reply_text(f"Crawling `{url}` (up to 25 pages)...", parse_mode='Markdown')
    await send_long(update, await crawl_website(url))


@authorized_only
async def jsscan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/jsscan [URL]`\n*Example:* `/jsscan https://example.com`",
            parse_mode='Markdown'
        )
        return
    url = context.args[0]
    await update.message.reply_text(f"Scanning JavaScript files on `{url}`...", parse_mode='Markdown')
    await send_long(update, await js_scan(url))


@authorized_only
async def corstest_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/corstest [URL]`\n*Example:* `/corstest https://api.example.com`",
            parse_mode='Markdown'
        )
        return
    url = context.args[0]
    await update.message.reply_text(f"Testing CORS on `{url}`...", parse_mode='Markdown')
    await send_long(update, await cors_test(url))


@authorized_only
async def waf_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/waf [URL]`\n*Example:* `/waf https://example.com`",
            parse_mode='Markdown'
        )
        return
    url = context.args[0]
    await update.message.reply_text(f"Detecting WAF on `{url}`...", parse_mode='Markdown')
    await send_long(update, await waf_detect(url))


@authorized_only
async def headercheck_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/headercheck [URL]`\n*Example:* `/headercheck https://example.com`",
            parse_mode='Markdown'
        )
        return
    url = context.args[0]
    await update.message.reply_text(f"Analyzing headers for `{url}`...", parse_mode='Markdown')
    await send_long(update, await header_check(url))


@authorized_only
async def robotscheck_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/robotscheck [URL]`\n*Example:* `/robotscheck https://example.com`",
            parse_mode='Markdown'
        )
        return
    url = context.args[0]
    await update.message.reply_text(f"Fetching robots.txt and sitemap for `{url}`...", parse_mode='Markdown')
    await send_long(update, await robots_check(url))


# ============================================================
# Security tools (from security.py)
# ============================================================
@authorized_only
async def speedtest_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Running speed test (~30 seconds)...")
    await send_long(update, await run_speedtest())


@authorized_only
async def passcheck_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/passcheck [password]`\n"
            "*Example:* `/passcheck MyP@ssword123`\n\n"
            "⚠️ HIBP check sends only the first 5 chars of the SHA1 hash (k-anonymity).",
            parse_mode='Markdown'
        )
        return
    password = ' '.join(context.args)
    await send_long(update, await check_password(password))


@authorized_only
async def hash_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/hash [value]`\n"
            "*Example:* `/hash 5f4dcc3b5aa765d61d8327deb882cf99`",
            parse_mode='Markdown'
        )
        return
    value = context.args[0]
    await update.message.reply_text("Analyzing hash...", parse_mode='Markdown')
    await send_long(update, await identify_hash(value))


# ============================================================
# Breach & email intel commands
# ============================================================
@authorized_only
async def breachcheck_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/breachcheck [email]`\n"
            "*Example:* `/breachcheck user@example.com`",
            parse_mode='Markdown'
        )
        return
    email = context.args[0]
    await update.message.reply_text(f"Checking breaches for `{email}`...", parse_mode='Markdown')
    await send_long(update, await breach_check(email))


@authorized_only
async def emailheader_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Analyze raw email headers — paste them after the command"""
    full_text = update.message.text or ''
    # Strip the /emailheader command prefix (handles @botname suffix too)
    parts = full_text.split(None, 1)
    header_text = parts[1] if len(parts) > 1 else ''

    if not header_text.strip():
        await update.message.reply_text(
            "❓ *Usage:* `/emailheader [paste raw headers]`\n\n"
            "Paste the raw email headers directly after the command, e.g.:\n"
            "`/emailheader`\n"
            "`Received: from mail.example.com ...`\n"
            "`From: sender@example.com`\n"
            "`Subject: Hello`",
            parse_mode='Markdown'
        )
        return

    await update.message.reply_text("Analyzing email headers...", parse_mode='Markdown')
    await send_long(update, await analyze_email_header(header_text))


@authorized_only
async def blacklistcheck_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/blacklistcheck [IP or domain]`\n"
            "*Examples:*\n"
            "├ `/blacklistcheck 1.2.3.4`\n"
            "└ `/blacklistcheck example.com`",
            parse_mode='Markdown'
        )
        return
    target = context.args[0]
    await update.message.reply_text(f"Checking `{target}` against DNSBL blacklists...", parse_mode='Markdown')
    await send_long(update, await blacklist_check(target))


# ============================================================
# Crypto & encoding commands
# ============================================================
@authorized_only
async def encode_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 2:
        await update.message.reply_text(
            "❓ *Usage:* `/encode [type] [text]`\n"
            "*Types:* `b64 hex url bin rot13 md5 sha1 sha256`\n"
            "*Example:* `/encode b64 Hello World`",
            parse_mode='Markdown'
        )
        return
    enc_type = context.args[0]
    text = ' '.join(context.args[1:])
    await send_long(update, await encode_text(enc_type, text))


@authorized_only
async def decode_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 2:
        await update.message.reply_text(
            "❓ *Usage:* `/decode [type] [text]`\n"
            "*Types:* `b64 hex url bin rot13`\n"
            "*Example:* `/decode b64 SGVsbG8gV29ybGQ=`",
            parse_mode='Markdown'
        )
        return
    dec_type = context.args[0]
    text = ' '.join(context.args[1:])
    await send_long(update, await decode_text(dec_type, text))


@authorized_only
async def genhash_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 2:
        await update.message.reply_text(
            "❓ *Usage:* `/genhash [algorithm] [text]`\n"
            "*Algorithms:* `md5 sha1 sha224 sha256 sha384 sha512`\n"
            "*Example:* `/genhash sha256 mypassword`",
            parse_mode='Markdown'
        )
        return
    algo = context.args[0]
    text = ' '.join(context.args[1:])
    await send_long(update, await gen_hash(algo, text))


@authorized_only
async def genpass_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        length = int(context.args[0]) if context.args else 20
    except ValueError:
        length = 20
    await send_long(update, await gen_password(length))


@authorized_only
async def certscan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/certscan [domain]`\n"
            "*Example:* `/certscan google.com`",
            parse_mode='Markdown'
        )
        return
    domain = context.args[0]
    await update.message.reply_text(f"Deep TLS scan for `{domain}`...", parse_mode='Markdown')
    result = await cert_scan(domain)
    log_scan("certscan", domain, f"TLS/cert scan: {domain}", result)
    log_activity("certscan", domain)
    await send_long(update, result)


# ============================================================
# Threat intelligence commands
# ============================================================
@authorized_only
async def threatfeed_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Fetching latest threat data...")
    await send_long(update, await get_threat_feed())


@authorized_only
async def abusecheck_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/abusecheck [IP]`\n"
            "*Example:* `/abusecheck 1.2.3.4`",
            parse_mode='Markdown'
        )
        return
    ip = context.args[0]
    await update.message.reply_text(f"Checking `{ip}` on AbuseIPDB...", parse_mode='Markdown')
    result = await abuse_check(ip, ABUSEIPDB_API_KEY)
    log_scan("abusecheck", ip, f"AbuseIPDB check: {ip}", result)
    log_activity("abusecheck", ip)
    await send_long(update, result)


@authorized_only
async def iplookup_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Comprehensive IP lookup: geo, ISP, ports, abuse score"""
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/iplookup [IP]`\n"
            "*Example:* `/iplookup 8.8.8.8`\n\n"
            "Shows: location, ISP, open ports, abuse reputation",
            parse_mode='Markdown'
        )
        return
    ip = context.args[0]
    await update.message.reply_text(f"🔍 Looking up `{ip}`...", parse_mode='Markdown')
    await send_long(update, await ip_lookup(ip, ABUSEIPDB_API_KEY))


@authorized_only
async def dailyreport_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Enable/disable daily auto-report: /dailyreport on [HH:MM] | off"""
    chat_id = update.effective_chat.id

    if not context.args:
        current = daily_report_schedule.get(chat_id)
        status = f"✅ Enabled at `{current}`" if current else "❌ Disabled"
        await update.message.reply_text(
            f"📅 *Daily Report*\n\n"
            f"Status: {status}\n\n"
            f"*Usage:*\n"
            f"├ `/dailyreport on` — enable at 08:00\n"
            f"├ `/dailyreport on 07:30` — enable at custom time\n"
            f"└ `/dailyreport off` — disable",
            parse_mode='Markdown'
        )
        return

    action = context.args[0].lower()

    if action == 'off':
        if chat_id in daily_report_tasks:
            daily_report_tasks[chat_id].cancel()
            del daily_report_tasks[chat_id]
        daily_report_schedule.pop(chat_id, None)
        await update.message.reply_text("⏹ *Daily report disabled*", parse_mode='Markdown')
        return

    if action == 'on':
        # Parse optional time argument
        time_str = context.args[1] if len(context.args) > 1 else '08:00'
        try:
            hour, minute = map(int, time_str.split(':'))
            if not (0 <= hour <= 23 and 0 <= minute <= 59):
                raise ValueError
        except (ValueError, AttributeError):
            await update.message.reply_text(
                "❌ Invalid time format. Use `HH:MM` (e.g. `08:00`)",
                parse_mode='Markdown'
            )
            return

        time_str = f"{hour:02d}:{minute:02d}"

        # Cancel any existing task
        if chat_id in daily_report_tasks:
            daily_report_tasks[chat_id].cancel()

        daily_report_schedule[chat_id] = time_str
        task = asyncio.create_task(_daily_report_loop(context, chat_id, hour, minute))
        daily_report_tasks[chat_id] = task

        await update.message.reply_text(
            f"✅ *Daily report enabled*\n"
            f"📅 Will send every day at `{time_str}`\n\n"
            f"Use `/dailyreport off` to disable",
            parse_mode='Markdown'
        )
        return

    await update.message.reply_text(
        "❓ Use `/dailyreport on [HH:MM]` or `/dailyreport off`",
        parse_mode='Markdown'
    )


async def _daily_report_loop(context: ContextTypes.DEFAULT_TYPE, chat_id: int, hour: int, minute: int):
    """Background task: send daily report at the scheduled time."""
    logger.info(f"Daily report loop started for chat {chat_id} at {hour:02d}:{minute:02d}")
    while daily_report_schedule.get(chat_id):
        try:
            now = datetime.now()
            target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if target <= now:
                target += timedelta(days=1)
            wait_secs = (target - datetime.now()).total_seconds()
            if wait_secs > 0:
                await asyncio.sleep(wait_secs)

            # Generate and send report
            if daily_report_schedule.get(chat_id):
                report = await daily_report_content()
                try:
                    await context.bot.send_message(
                        chat_id=chat_id,
                        text=report,
                        parse_mode='Markdown'
                    )
                    logger.info(f"Daily report sent to chat {chat_id}")
                except Exception as e:
                    logger.error(f"Failed to send daily report to {chat_id}: {e}")

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Daily report loop error for {chat_id}: {e}")
            await asyncio.sleep(3600)  # Retry in 1 hour on error

    logger.info(f"Daily report loop stopped for chat {chat_id}")


# ============================================================
# Utility commands (new in v2.0)
# ============================================================

@authorized_only
async def dashboard_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show the web dashboard URL."""
    import socket
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "your-pi-ip"
    if DASHBOARD_ENABLED:
        msg = (
            f"🖥 *Web Dashboard*\n\n"
            f"URL: `http://{local_ip}:{DASHBOARD_PORT}`\n\n"
            "Login with the credentials set in `config.py`\n"
            "(`DASHBOARD_USER` / `DASHBOARD_PASS`)"
        )
    else:
        msg = "⚠️ Dashboard is disabled. Set `DASHBOARD_ENABLED = True` in `config.py`."
    await update.message.reply_text(msg, parse_mode='Markdown')


@authorized_only
async def screenshot_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Take a desktop screenshot using scrot."""
    path = "/tmp/secbot_screenshot.png"
    await update.message.reply_text("Taking screenshot...", parse_mode='Markdown')
    try:
        proc = await asyncio.create_subprocess_exec(
            'scrot', '-z', path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
        if proc.returncode == 0 and os.path.exists(path):
            with open(path, 'rb') as f:
                await update.message.reply_photo(photo=InputFile(f), caption="Desktop screenshot")
            os.remove(path)
        else:
            err = stderr.decode().strip()[:200]
            await update.message.reply_text(
                f"❌ Screenshot failed: `{err or 'scrot not installed? Run: sudo apt install scrot'}`",
                parse_mode='Markdown'
            )
    except asyncio.TimeoutError:
        await update.message.reply_text("❌ Screenshot timed out", parse_mode='Markdown')
    except Exception as e:
        await update.message.reply_text(f"❌ Error: `{str(e)[:100]}`", parse_mode='Markdown')


@authorized_only
async def qr_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Generate a QR code image from text."""
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/qr [text or URL]`\n*Example:* `/qr https://example.com`",
            parse_mode='Markdown'
        )
        return
    text = ' '.join(context.args)
    if len(text) > 2000:
        await update.message.reply_text("❌ Text too long (max 2000 chars)", parse_mode='Markdown')
        return
    try:
        import qrcode  # lazy import — installed via: pip install qrcode[pil]
        img = qrcode.make(text)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        await update.message.reply_photo(
            photo=InputFile(buf, filename='qr.png'),
            caption=f"QR code for: `{text[:80]}`",
            parse_mode='Markdown'
        )
    except Exception as e:
        await update.message.reply_text(f"❌ Error: `{str(e)[:100]}`", parse_mode='Markdown')


@authorized_only
async def shorten_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Shorten a URL using TinyURL."""
    if not context.args:
        await update.message.reply_text(
            "❓ *Usage:* `/shorten [URL]`\n*Example:* `/shorten https://example.com/very/long/path`",
            parse_mode='Markdown'
        )
        return
    url = context.args[0]
    if not url.startswith(('http://', 'https://')):
        await update.message.reply_text("❌ URL must start with `http://` or `https://`", parse_mode='Markdown')
        return
    await update.message.reply_text("Shortening URL...", parse_mode='Markdown')
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f'https://tinyurl.com/api-create.php?url={url}',
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    short = await resp.text()
                    await update.message.reply_text(
                        f"🔗 *Shortened URL*\n\n"
                        f"Original: `{url[:80]}`\n"
                        f"Short: `{short.strip()}`",
                        parse_mode='Markdown'
                    )
                else:
                    await update.message.reply_text(f"❌ TinyURL returned HTTP {resp.status}", parse_mode='Markdown')
    except Exception as e:
        await update.message.reply_text(f"❌ Error: `{str(e)[:100]}`", parse_mode='Markdown')


@authorized_only
async def weather_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Get weather info for a city using wttr.in."""
    city = '+'.join(context.args) if context.args else ''
    if not city:
        await update.message.reply_text(
            "❓ *Usage:* `/weather [city]`\n*Example:* `/weather London`",
            parse_mode='Markdown'
        )
        return
    city_safe = city.replace('/', '').replace('\\', '').strip()[:100]
    await update.message.reply_text(f"Fetching weather for *{city_safe}*...", parse_mode='Markdown')
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f'https://wttr.in/{city_safe}?format=j1',
                timeout=aiohttp.ClientTimeout(total=10),
                headers={'User-Agent': 'TelegramSecurityBot/2.0'}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    cc  = data['current_condition'][0]
                    area = data['nearest_area'][0]
                    city_name = area['areaName'][0]['value']
                    country   = area['country'][0]['value']
                    temp_c    = cc['temp_C']
                    feels_c   = cc['FeelsLikeC']
                    humidity  = cc['humidity']
                    wind_kmph = cc['windspeedKmph']
                    wind_dir  = cc['winddir16Point']
                    desc      = cc['weatherDesc'][0]['value']
                    vis_km    = cc['visibility']
                    result = (
                        f"🌤 *Weather — {city_name}, {country}*\n\n"
                        f"├ Condition: *{desc}*\n"
                        f"├ Temp: *{temp_c}°C* (feels like {feels_c}°C)\n"
                        f"├ Humidity: {humidity}%\n"
                        f"├ Wind: {wind_kmph} km/h {wind_dir}\n"
                        f"└ Visibility: {vis_km} km\n\n"
                        f"📡 Source: wttr.in"
                    )
                    await update.message.reply_text(result, parse_mode='Markdown')
                else:
                    await update.message.reply_text(f"❌ Weather API returned HTTP {resp.status}", parse_mode='Markdown')
    except Exception as e:
        await update.message.reply_text(f"❌ Error: `{str(e)[:100]}`", parse_mode='Markdown')


@authorized_only
async def notes_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Manage notes: /notes add <text> | /notes list | /notes del <id>"""
    if not context.args:
        await update.message.reply_text(
            "📝 *Notes Commands:*\n"
            "├ `/notes add [text]` — add a note\n"
            "├ `/notes list` — show all notes\n"
            "└ `/notes del [id]` — delete note by ID",
            parse_mode='Markdown'
        )
        return

    subcmd = context.args[0].lower()

    if subcmd == 'add':
        text = ' '.join(context.args[1:]).strip()
        if not text:
            await update.message.reply_text("❓ Usage: `/notes add [your note]`", parse_mode='Markdown')
            return
        note_id = add_note(text)
        await update.message.reply_text(f"✅ Note `#{note_id}` saved.", parse_mode='Markdown')

    elif subcmd == 'list':
        notes = get_notes()
        if not notes:
            await update.message.reply_text("📋 No notes saved yet.", parse_mode='Markdown')
            return
        lines = ["📝 *Your Notes:*\n"]
        for n in notes:
            lines.append(f"*#{n['id']}* — {n['content'][:80]}\n`{n['timestamp']}`")
        await send_long(update, '\n\n'.join(lines))

    elif subcmd == 'del':
        if len(context.args) < 2 or not context.args[1].isdigit():
            await update.message.reply_text("❓ Usage: `/notes del [id]`", parse_mode='Markdown')
            return
        note_id = int(context.args[1])
        if delete_note(note_id):
            await update.message.reply_text(f"🗑 Note `#{note_id}` deleted.", parse_mode='Markdown')
        else:
            await update.message.reply_text(f"❌ Note `#{note_id}` not found.", parse_mode='Markdown')
    else:
        await update.message.reply_text(
            "❓ Unknown subcommand. Use `/notes add`, `/notes list`, or `/notes del [id]`.",
            parse_mode='Markdown'
        )


@authorized_only
async def timer_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Set a countdown timer in seconds."""
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text(
            "❓ *Usage:* `/timer [seconds]`\n"
            "*Example:* `/timer 60` — alert in 1 minute\n"
            "Max: 3600 seconds (1 hour)",
            parse_mode='Markdown'
        )
        return
    secs = int(context.args[0])
    if secs < 1:
        await update.message.reply_text("❌ Timer must be at least 1 second.", parse_mode='Markdown')
        return
    if secs > 3600:
        await update.message.reply_text("❌ Max timer is 3600 seconds (1 hour).", parse_mode='Markdown')
        return

    chat_id = update.effective_chat.id

    # Cancel existing timer for this chat
    if chat_id in active_timers and not active_timers[chat_id].done():
        active_timers[chat_id].cancel()

    mins, s = divmod(secs, 60)
    label = f"{mins}m {s}s" if mins else f"{s}s"
    await update.message.reply_text(f"⏱ Timer set for *{label}*. I'll notify you when done!", parse_mode='Markdown')

    async def _timer_task():
        await asyncio.sleep(secs)
        try:
            await update.message.reply_text(
                f"⏰ *Timer Done!*\n\n✅ Your {label} timer has finished!",
                parse_mode='Markdown'
            )
        except Exception:
            pass

    active_timers[chat_id] = asyncio.create_task(_timer_task())


@authorized_only
async def botinfo_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show bot version, uptime, and stats."""
    uptime_secs = int(time.time() - bot_start_time)
    h, rem = divmod(uptime_secs, 3600)
    m, s   = divmod(rem, 60)
    uptime_str = f"{h}h {m}m {s}s"

    import psutil
    proc = psutil.Process(os.getpid())
    mem_mb = proc.memory_info().rss / 1_048_576

    result = (
        f"🤖 *Bot Information*\n\n"
        f"├ Version: `{BOT_VERSION}`\n"
        f"├ Uptime: `{uptime_str}`\n"
        f"├ Memory: `{mem_mb:.1f} MB`\n"
        f"├ Python PID: `{os.getpid()}`\n"
        f"├ Dashboard: {'✅ Enabled' if DASHBOARD_ENABLED else '❌ Disabled'}\n"
        f"│  Port: `{DASHBOARD_PORT}`\n"
        f"└ Monitoring: {'✅ Active' if network_monitor.is_running else '❌ Inactive'}\n\n"
        f"📅 Started: `{datetime.fromtimestamp(bot_start_time).strftime('%Y-%m-%d %H:%M:%S')}`"
    )
    await update.message.reply_text(result, parse_mode='Markdown')


@authorized_only
async def changelog_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show what's new in this version."""
    msg = (
        f"📋 *Changelog — v{BOT_VERSION}*\n\n"
        "🆕 *New in v2.0:*\n\n"
        "🌐 *Web Dashboard*\n"
        "├ Flask dashboard at port 5000\n"
        "├ Real-time CPU/RAM/Temp/Disk gauges\n"
        "├ Network devices table\n"
        "├ Scan history browser\n"
        "├ Activity log viewer\n"
        "└ Notes manager\n\n"
        "🧰 *New Commands:*\n"
        "├ /dashboard — open dashboard in browser\n"
        "├ /screenshot — capture Pi desktop\n"
        "├ /qr — generate QR codes\n"
        "├ /shorten — URL shortener\n"
        "├ /weather — weather by city\n"
        "├ /notes — persistent note-taking\n"
        "├ /timer — countdown timer\n"
        "├ /botinfo — version & runtime stats\n"
        "└ /changelog — this list\n\n"
        "🔧 *Improvements:*\n"
        "├ SQLite history database\n"
        "├ Scan history logged automatically\n"
        "└ Bot/dashboard run independently\n\n"
        "📦 *Total commands: 60+*"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')


# ============================================================
# Bot setup
# ============================================================
async def post_init(application: Application):
    commands = [
        # System
        BotCommand("status",        "CPU, RAM, temp, disk"),
        BotCommand("processes",     "Top resource processes"),
        BotCommand("myip",          "Public IP info"),
        BotCommand("bandwidth",     "Live network usage"),
        BotCommand("diskusage",     "Disk usage breakdown"),
        BotCommand("servicelist",   "Running services"),
        BotCommand("cron",          "Scheduled cron jobs"),
        BotCommand("users",         "System users & logins"),
        BotCommand("history",       "Last 20 shell commands"),
        BotCommand("update",        "Check apt updates"),
        BotCommand("backup",        "Backup bot config/data"),
        BotCommand("alert",         "Set resource alert threshold"),
        # Network
        BotCommand("ping",          "ICMP ping a host"),
        BotCommand("portscan",      "Port scanner"),
        BotCommand("checksite",     "Check website status"),
        BotCommand("ssl",           "SSL certificate check"),
        BotCommand("scan",          "Local network ARP scan"),
        BotCommand("devices",       "Show connected devices"),
        BotCommand("monitor",       "Auto network monitoring"),
        # Domain
        BotCommand("whois",         "WHOIS lookup"),
        BotCommand("dns",           "DNS records"),
        BotCommand("geoip",         "IP geolocation"),
        BotCommand("report",        "Full domain report"),
        # Web security
        BotCommand("vulnscan",      "Vulnerability scan + grade"),
        BotCommand("subdomains",    "Subdomain enumeration"),
        BotCommand("techdetect",    "Detect web technologies"),
        BotCommand("emailsec",      "SPF/DKIM/DMARC check"),
        BotCommand("crawl",         "Spider site for links/forms"),
        BotCommand("jsscan",        "JS file secret scanner"),
        BotCommand("corstest",      "CORS misconfiguration test"),
        BotCommand("waf",           "WAF detection"),
        BotCommand("headercheck",   "Deep HTTP header analysis"),
        BotCommand("robotscheck",   "robots.txt & sitemap analysis"),
        # Breach & email
        BotCommand("breachcheck",   "Email data breach lookup"),
        BotCommand("emailheader",   "Analyze raw email headers"),
        BotCommand("blacklistcheck","DNSBL spam blacklist check"),
        # Security tools
        BotCommand("passcheck",     "Password strength + HIBP"),
        BotCommand("hash",          "Hash type identifier + lookup"),
        BotCommand("speedtest",     "Internet speed test"),
        BotCommand("certscan",      "Deep TLS/SSL analysis"),
        BotCommand("encode",        "Encode text (b64/hex/etc)"),
        BotCommand("decode",        "Decode text (b64/hex/etc)"),
        BotCommand("genhash",       "Generate hash of text"),
        BotCommand("genpass",       "Generate secure password"),
        # Threat intel
        BotCommand("threatfeed",    "Latest CVEs from CISA+NVD"),
        BotCommand("abusecheck",    "AbuseIPDB IP reputation"),
        BotCommand("iplookup",      "Full IP info: geo, ports, abuse"),
        BotCommand("dailyreport",   "Scheduled daily system report"),
        # Utilities
        BotCommand("dashboard",     "Open web dashboard"),
        BotCommand("screenshot",    "Pi desktop screenshot"),
        BotCommand("qr",            "Generate QR code"),
        BotCommand("shorten",       "Shorten a URL"),
        BotCommand("weather",       "Weather by city"),
        BotCommand("notes",         "Add/list/delete notes"),
        BotCommand("timer",         "Set countdown timer"),
        BotCommand("botinfo",       "Bot version & runtime stats"),
        BotCommand("changelog",     "What's new in v2.0"),
        # Meta
        BotCommand("start",         "Show all commands"),
        BotCommand("help",          "Usage examples"),
    ]
    await application.bot.set_my_commands(commands)


def main():
    print(f"Starting Telegram Security Bot v{BOT_VERSION}...")
    print("=" * 40)

    if BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("ERROR: Set your BOT_TOKEN in config.py")
        return

    # Initialize shared database
    init_db()
    log_activity(f"Bot started", f"v{BOT_VERSION}")

    app = Application.builder().token(BOT_TOKEN).post_init(post_init).build()

    # System
    app.add_handler(CommandHandler("status",         status_command))
    app.add_handler(CommandHandler("processes",      processes_command))
    app.add_handler(CommandHandler("myip",           myip_command))
    app.add_handler(CommandHandler("bandwidth",      bandwidth_command))
    app.add_handler(CommandHandler("diskusage",      diskusage_command))
    app.add_handler(CommandHandler("servicelist",    servicelist_command))
    app.add_handler(CommandHandler("cron",           cron_command))
    app.add_handler(CommandHandler("users",          users_command))
    app.add_handler(CommandHandler("history",        history_command))
    app.add_handler(CommandHandler("update",         update_command))
    app.add_handler(CommandHandler("backup",         backup_command))
    app.add_handler(CommandHandler("alert",          alert_command))
    # Network
    app.add_handler(CommandHandler("ping",           ping_command))
    app.add_handler(CommandHandler("portscan",       portscan_command))
    app.add_handler(CommandHandler("checksite",      checksite_command))
    app.add_handler(CommandHandler("ssl",            ssl_command))
    app.add_handler(CommandHandler("scan",           scan_command))
    app.add_handler(CommandHandler("devices",        devices_command))
    app.add_handler(CommandHandler("approve",        approve_command))
    app.add_handler(CommandHandler("approve_all",    approve_all_command))
    app.add_handler(CommandHandler("monitor",        monitor_command))
    # Domain
    app.add_handler(CommandHandler("whois",          whois_command))
    app.add_handler(CommandHandler("dns",            dns_command))
    app.add_handler(CommandHandler("geoip",          geoip_command))
    app.add_handler(CommandHandler("report",         report_command))
    # Web security
    app.add_handler(CommandHandler("vulnscan",       vulnscan_command))
    app.add_handler(CommandHandler("subdomains",     subdomains_command))
    app.add_handler(CommandHandler("techdetect",     techdetect_command))
    app.add_handler(CommandHandler("emailsec",       emailsec_command))
    app.add_handler(CommandHandler("crawl",          crawl_command))
    app.add_handler(CommandHandler("jsscan",         jsscan_command))
    app.add_handler(CommandHandler("corstest",       corstest_command))
    app.add_handler(CommandHandler("waf",            waf_command))
    app.add_handler(CommandHandler("headercheck",    headercheck_command))
    app.add_handler(CommandHandler("robotscheck",    robotscheck_command))
    # Breach & email
    app.add_handler(CommandHandler("breachcheck",    breachcheck_command))
    app.add_handler(CommandHandler("emailheader",    emailheader_command))
    app.add_handler(CommandHandler("blacklistcheck", blacklistcheck_command))
    # Security tools
    app.add_handler(CommandHandler("passcheck",      passcheck_command))
    app.add_handler(CommandHandler("hash",           hash_command))
    app.add_handler(CommandHandler("speedtest",      speedtest_command))
    app.add_handler(CommandHandler("certscan",       certscan_command))
    app.add_handler(CommandHandler("encode",         encode_command))
    app.add_handler(CommandHandler("decode",         decode_command))
    app.add_handler(CommandHandler("genhash",        genhash_command))
    app.add_handler(CommandHandler("genpass",        genpass_command))
    # Threat intel
    app.add_handler(CommandHandler("threatfeed",     threatfeed_command))
    app.add_handler(CommandHandler("abusecheck",     abusecheck_command))
    app.add_handler(CommandHandler("iplookup",       iplookup_command))
    app.add_handler(CommandHandler("dailyreport",    dailyreport_command))
    # Utilities (v2.0)
    app.add_handler(CommandHandler("dashboard",      dashboard_command))
    app.add_handler(CommandHandler("screenshot",     screenshot_command))
    app.add_handler(CommandHandler("qr",             qr_command))
    app.add_handler(CommandHandler("shorten",        shorten_command))
    app.add_handler(CommandHandler("weather",        weather_command))
    app.add_handler(CommandHandler("notes",          notes_command))
    app.add_handler(CommandHandler("timer",          timer_command))
    app.add_handler(CommandHandler("botinfo",        botinfo_command))
    app.add_handler(CommandHandler("changelog",      changelog_command))
    # Meta
    app.add_handler(CommandHandler("start",          start_command))
    app.add_handler(CommandHandler("help",           help_command))

    print(f"Bot ready! Allowed Chat IDs: {ALLOWED_CHAT_IDS}")
    print("Press Ctrl+C to stop.")
    print("=" * 40)

    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()
