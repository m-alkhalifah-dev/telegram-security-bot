#!/usr/bin/env python3
"""
Scheduled scan manager.
Stores schedule config in DB. Asyncio-based scheduling.
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# Global reference to bot application (set during bot startup)
_bot_app = None
_scheduler_task: Optional[asyncio.Task] = None
_uptime_monitor_task: Optional[asyncio.Task] = None


def set_bot_app(app):
    """Set the bot application reference for sending messages."""
    global _bot_app
    _bot_app = app


async def run_scheduled_scan(chat_ids: list) -> str:
    """
    Run a full scheduled security scan.
    Returns summary string.
    """
    from modules.system import get_system_status
    from modules.monitor import NetworkMonitor
    from modules.sysadmin import get_resource_value
    from modules.db import log_scan, log_activity, get_alerts_today

    results = []
    results.append(f"*Scheduled Security Scan — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*\n")

    # System health
    try:
        cpu = await get_resource_value('cpu')
        ram = await get_resource_value('ram')
        temp = await get_resource_value('temp')
        results.append(f"*System Health*")
        results.append(f"CPU: {cpu}% | RAM: {ram}% | Temp: {temp}°C")

        warnings = []
        if float(cpu) > 80:
            warnings.append(f"HIGH CPU: {cpu}%")
        if float(ram) > 85:
            warnings.append(f"HIGH RAM: {ram}%")
        if float(temp) > 75:
            warnings.append(f"HIGH TEMP: {temp}°C")
        if warnings:
            results.append(f"WARNINGS: {', '.join(warnings)}")
    except Exception as e:
        results.append(f"System check error: {e}")

    # Network scan
    try:
        nm = NetworkMonitor()
        devices = await nm.scan_network()
        known = [d for d in devices if d.get('status') == 'known']
        unknown = [d for d in devices if d.get('status') == 'unknown']
        results.append(f"\n*Network Scan*")
        results.append(f"Total: {len(devices)} | Known: {len(known)} | Unknown: {len(unknown)}")
        if unknown:
            results.append(f"Unknown devices: {', '.join(d.get('ip', '?') for d in unknown)}")
    except Exception as e:
        results.append(f"Network scan error: {e}")

    # Alerts summary
    try:
        alerts_today = get_alerts_today()
        results.append(f"\n*Alerts Today:* {alerts_today}")
    except Exception:
        pass

    # SSH attempts (recent)
    try:
        from modules.db import get_ssh_logs
        ssh = get_ssh_logs(limit=50)
        failed = [s for s in ssh if not s.get('success')]
        results.append(f"*SSH Failed Attempts (recent):* {len(failed)}")
    except Exception:
        pass

    summary = "\n".join(results)
    log_scan("scheduled_scan", "local", "Scheduled scan complete", summary)
    log_activity("scheduled_scan", f"Scheduled scan ran at {datetime.utcnow().isoformat()}")

    return summary


async def scheduler_loop(chat_ids: list):
    """
    Background task that checks schedules every minute
    and runs scans when due.
    """
    from modules.db import get_schedules, update_schedule

    logger.info("Scheduler loop started")

    while True:
        try:
            await asyncio.sleep(60)  # Check every minute

            now = datetime.utcnow()
            current_time = now.strftime("%H:%M")
            current_day = now.strftime("%A").lower()

            schedules = get_schedules(enabled_only=True)

            for sched in schedules:
                stype = sched.get('schedule_type')
                stime = sched.get('schedule_time', '')
                sday = sched.get('day_of_week', '').lower()
                last_run = sched.get('last_run', '')

                should_run = False

                if stype == 'daily' and stime == current_time:
                    # Check if already ran today
                    if last_run:
                        try:
                            lr = datetime.fromisoformat(last_run)
                            if lr.date() == now.date():
                                continue  # Already ran today
                        except Exception:
                            pass
                    should_run = True

                elif stype == 'weekly' and sday == current_day and stime == current_time:
                    # Check if already ran this week
                    if last_run:
                        try:
                            lr = datetime.fromisoformat(last_run)
                            if (now - lr).days < 7:
                                continue
                        except Exception:
                            pass
                    should_run = True

                if should_run:
                    logger.info(f"Running scheduled scan (type={stype})")
                    update_schedule(sched['id'], last_run=now.isoformat())

                    summary = await run_scheduled_scan(chat_ids)

                    if _bot_app and chat_ids:
                        for chat_id in chat_ids:
                            try:
                                chunks = [summary[i:i+4000] for i in range(0, len(summary), 4000)]
                                for chunk in chunks:
                                    await _bot_app.bot.send_message(
                                        chat_id=chat_id,
                                        text=chunk,
                                        parse_mode='Markdown'
                                    )
                            except Exception as e:
                                logger.error(f"Failed to send scheduled scan to {chat_id}: {e}")

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Scheduler loop error: {e}")


async def uptime_monitor_loop(chat_ids: list):
    """
    Background task that monitors website uptime.
    Checks each site at its configured interval.
    """
    import aiohttp
    from modules.db import get_monitored_sites, update_site_status, log_alert

    logger.info("Uptime monitor loop started")

    last_checks: dict = {}  # url -> last check datetime

    while True:
        try:
            await asyncio.sleep(30)  # Poll every 30 seconds

            now = datetime.utcnow()
            sites = get_monitored_sites()

            for site in sites:
                url = site['url']
                interval = site.get('interval_minutes', 5)
                last = last_checks.get(url)

                if last and (now - last).total_seconds() < interval * 60:
                    continue

                last_checks[url] = now

                try:
                    async with aiohttp.ClientSession() as sess:
                        async with sess.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            new_status = 'up' if resp.status < 400 else 'down'
                            last_status = str(resp.status)
                except Exception:
                    new_status = 'down'
                    last_status = 'timeout'

                old_status = site.get('status', 'unknown')
                update_site_status(url, new_status, last_status)

                # Alert on status change
                if old_status != new_status and _bot_app and chat_ids:
                    emoji = "UP" if new_status == 'up' else "DOWN"
                    msg = (
                        f"*Site Monitor Alert*\n"
                        f"{url} is now *{emoji}*\n"
                        f"Status: {last_status}"
                    )
                    log_alert(
                        "site_monitor", url,
                        f"Status changed to {new_status}",
                        "warning" if new_status == 'down' else "info"
                    )

                    for chat_id in chat_ids:
                        try:
                            await _bot_app.bot.send_message(
                                chat_id=chat_id, text=msg, parse_mode='Markdown'
                            )
                        except Exception as e:
                            logger.error(f"Failed to send site alert: {e}")

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Uptime monitor error: {e}")


def start_scheduler(app, chat_ids: list):
    """Start all background scheduler tasks."""
    global _scheduler_task, _uptime_monitor_task
    set_bot_app(app)
    _scheduler_task = asyncio.create_task(scheduler_loop(chat_ids))
    _uptime_monitor_task = asyncio.create_task(uptime_monitor_loop(chat_ids))
    logger.info("Scheduler and uptime monitor started")


def stop_scheduler():
    """Stop all scheduler tasks."""
    if _scheduler_task:
        _scheduler_task.cancel()
    if _uptime_monitor_task:
        _uptime_monitor_task.cancel()
