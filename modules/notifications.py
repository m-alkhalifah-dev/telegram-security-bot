#!/usr/bin/env python3
"""
Webhook notification system for external alerts (Discord, Slack, generic HTTP).
"""

import logging
import aiohttp
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


async def send_webhook(url: str, payload: dict) -> bool:
    """Send a webhook notification. Returns True on success."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                return resp.status < 400
    except Exception as e:
        logger.error(f"Webhook send error: {e}")
        return False


def _is_discord(url: str) -> bool:
    return 'discord.com/api/webhooks' in url or 'discordapp.com/api/webhooks' in url


def _is_slack(url: str) -> bool:
    return 'hooks.slack.com' in url


def _build_payload(url: str, title: str, message: str, severity: str = "info") -> dict:
    """Build platform-specific webhook payload."""
    color_map = {
        "info":     0x00ff88,
        "warning":  0xffaa00,
        "critical": 0xff4444,
        "success":  0x00cc66,
    }
    color = color_map.get(severity, 0x00ff88)

    if _is_discord(url):
        return {
            "username": "SecBot",
            "embeds": [{
                "title": title,
                "description": message,
                "color": color,
                "timestamp": datetime.utcnow().isoformat(),
                "footer": {"text": "Telegram Security Bot v3.0"}
            }]
        }
    elif _is_slack(url):
        return {
            "text": f"*{title}*",
            "attachments": [{
                "text": message,
                "color": "#00ff88" if severity == "info" else "#ff4444",
                "footer": "Telegram Security Bot",
                "ts": str(int(datetime.utcnow().timestamp()))
            }]
        }
    else:
        # Generic JSON webhook
        return {
            "title": title,
            "message": message,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
            "source": "telegram-security-bot"
        }


async def notify(title: str, message: str, severity: str = "info",
                 event_type: str = "general") -> bool:
    """
    Send notification via configured webhook.
    Returns True if webhook was sent successfully.
    """
    from modules.db import get_webhook

    webhook = get_webhook()
    if not webhook or not webhook.get('enabled'):
        return False

    url = webhook.get('url', '')
    events = webhook.get('events', 'all')

    # Check if this event type is configured
    if events != 'all' and event_type not in events.split(','):
        return False

    payload = _build_payload(url, title, message, severity)
    success = await send_webhook(url, payload)

    if success:
        logger.info(f"Webhook notification sent: {title}")
    else:
        logger.warning(f"Webhook notification failed: {title}")

    return success


async def notify_new_device(ip: str, mac: str, vendor: str):
    """Send alert for a newly discovered unknown device."""
    await notify(
        title="New Unknown Device Detected",
        message=f"IP: {ip}\nMAC: {mac}\nVendor: {vendor}",
        severity="warning",
        event_type="new_device"
    )


async def notify_high_cpu(cpu_percent: float):
    """Send alert for high CPU usage."""
    await notify(
        title="High CPU Usage Alert",
        message=f"CPU is at {cpu_percent}% — check running processes",
        severity="warning",
        event_type="cpu_alert"
    )


async def notify_high_temp(temp_c: float):
    """Send alert for high temperature."""
    await notify(
        title="High Temperature Alert",
        message=f"CPU temperature is {temp_c}°C — check cooling",
        severity="critical",
        event_type="temp_alert"
    )


async def notify_ssh_attempt(ip: str, username: str, success: bool):
    """Send alert for an SSH login attempt."""
    status = "SUCCESSFUL" if success else "FAILED"
    severity = "critical" if success else "warning"
    await notify(
        title=f"SSH Login {status}",
        message=f"IP: {ip}\nUsername: {username}\nResult: {status}",
        severity=severity,
        event_type="ssh_attempt"
    )


async def notify_scan_complete(scan_type: str, target: str, summary: str):
    """Send notification when a scheduled scan completes."""
    await notify(
        title=f"Scheduled Scan Complete: {scan_type}",
        message=f"Target: {target}\n{summary[:500]}",
        severity="info",
        event_type="scan_complete"
    )


async def get_webhook_status() -> str:
    """Return formatted webhook status string for Telegram."""
    from modules.db import get_webhook

    webhook = get_webhook()
    if not webhook:
        return "*Webhook Status:* Not configured\n\nUse `/webhook set <URL>` to configure."

    status = "ACTIVE" if webhook.get('enabled') else "DISABLED"
    url = webhook.get('url', '')
    display_url = url[:50] + "..." if len(url) > 50 else url

    return (
        f"*Webhook Status:* {status}\n"
        f"URL: `{display_url}`\n"
        f"Events: {webhook.get('events', 'all')}\n\n"
        f"Use `/webhook test` to send a test notification.\n"
        f"Use `/webhook off` to disable."
    )
