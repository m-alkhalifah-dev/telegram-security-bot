#!/usr/bin/env python3
"""
PDF report generation using ReportLab.
Generates professional security assessment PDFs.
"""

import io
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


def _get_reportlab() -> bool:
    """Lazy import check for reportlab."""
    try:
        from reportlab.lib.pagesizes import A4  # noqa: F401
        return True
    except ImportError:
        return False


def _build_pdf(title: str, sections: list, filename: str = None) -> io.BytesIO:
    """
    Build a PDF document.

    sections = [
        {
            "heading":  "Section Title",
            "content":  "plain text"  OR  [("Label", "Value"), ...],
            "severity": "info" | "warning" | "critical" | "success"   (optional)
        },
        ...
    ]

    Returns a BytesIO buffer positioned at offset 0.
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor, black, white
    from reportlab.lib.units import inch, cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT  # noqa: F401

    # Color palette
    GREEN   = HexColor('#00ff88')
    DARK_BG = HexColor('#0a0e17')
    ACCENT  = HexColor('#00cc66')

    buf = io.BytesIO()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
        title=title
    )

    # Styles
    style_heading = ParagraphStyle(
        'Heading', fontSize=13, textColor=DARK_BG, fontName='Helvetica-Bold',
        spaceBefore=12, spaceAfter=6
    )
    style_body = ParagraphStyle(
        'Body', fontSize=8.5, textColor=black, spaceAfter=3, leading=14
    )

    story = []

    # ── Header ─────────────────────────────────────────────────────────────────
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    try:
        import socket
        hostname = socket.gethostname()
    except Exception:
        hostname = "raspberry-pi"

    header_data = [[
        Paragraph(
            f'<b>{title}</b>',
            ParagraphStyle('H', fontSize=16, textColor=DARK_BG, fontName='Helvetica-Bold')
        ),
        Paragraph(
            f'Generated: {now}<br/>Host: {hostname}<br/>SecBot v3.0.0',
            ParagraphStyle('HR', fontSize=8, textColor=HexColor('#555555'), alignment=2)
        )
    ]]
    header_table = Table(header_data, colWidths=[12*cm, 5*cm])
    header_table.setStyle(TableStyle([
        ('ALIGN',         (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('BACKGROUND',    (0, 0), (-1, -1), HexColor('#e8f5e9')),
        ('LINEBELOW',     (0, 0), (-1, 0),  2, ACCENT),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 0.3*inch))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT))
    story.append(Spacer(1, 0.2*inch))

    # ── Table of contents ──────────────────────────────────────────────────────
    story.append(Paragraph('Table of Contents', style_heading))
    for i, section in enumerate(sections, 1):
        heading = section.get('heading', f'Section {i}')
        story.append(Paragraph(f'{i}. {heading}', style_body))
    story.append(Spacer(1, 0.2*inch))
    story.append(PageBreak())

    # ── Sections ───────────────────────────────────────────────────────────────
    sev_colors = {
        'critical': '#ff4444',
        'warning':  '#ffaa00',
        'info':     '#00cc66',
        'success':  '#00ff88',
    }

    for i, section in enumerate(sections, 1):
        heading  = section.get('heading', f'Section {i}')
        content  = section.get('content', '')
        severity = section.get('severity', 'info')
        sev_color = HexColor(sev_colors.get(severity, '#00cc66'))

        story.append(Paragraph(f'{i}. {heading}', style_heading))
        story.append(HRFlowable(width="100%", thickness=1, color=sev_color))
        story.append(Spacer(1, 0.1*inch))

        if isinstance(content, list):
            # List of (label, value) tuples — render as two-column table
            if content:
                table_data = [
                    [Paragraph(f'<b>{k}</b>', style_body), Paragraph(str(v), style_body)]
                    for k, v in content
                ]
                t = Table(table_data, colWidths=[5*cm, 12*cm])
                t.setStyle(TableStyle([
                    ('BACKGROUND',    (0, 0), (0, -1), HexColor('#f0f8f0')),
                    ('TEXTCOLOR',     (0, 0), (-1, -1), black),
                    ('ALIGN',         (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
                    ('ROWBACKGROUNDS',(0, 0), (-1, -1), [white, HexColor('#f9f9f9')]),
                    ('GRID',          (0, 0), (-1, -1), 0.5, HexColor('#dddddd')),
                    ('TOPPADDING',    (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING',   (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING',  (0, 0), (-1, -1), 6),
                ]))
                story.append(t)

        elif isinstance(content, str):
            for line in content.split('\n'):
                if line.strip():
                    story.append(Paragraph(line.strip(), style_body))
                else:
                    story.append(Spacer(1, 0.05*inch))

        story.append(Spacer(1, 0.2*inch))

    # ── Footer ─────────────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor('#cccccc')))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph(
        f'This report was automatically generated by Telegram Security Bot v3.0.0 '
        f'on {now}. All findings should be verified by a qualified security professional.',
        ParagraphStyle('Footer', fontSize=7, textColor=HexColor('#888888'))
    ))

    doc.build(story)
    buf.seek(0)
    return buf


# ── Public report generators ───────────────────────────────────────────────────

async def generate_system_report() -> io.BytesIO:
    """Generate a system health PDF report."""
    sections = []

    # Executive Summary
    try:
        import psutil
        cpu  = psutil.cpu_percent(interval=1)
        mem  = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        temp = 0.0
        try:
            with open('/sys/class/thermal/thermal_zone0/temp') as f:
                temp = round(int(f.read().strip()) / 1000, 1)
        except Exception:
            pass

        health = "GOOD"
        if cpu > 80 or mem.percent > 85 or temp > 75:
            health = "WARNING"
        if cpu > 95 or temp > 85:
            health = "CRITICAL"

        sections.append({
            "heading": "Executive Summary",
            "content": [
                ("Report Type",   "System Health Assessment"),
                ("Overall Health", health),
                ("CPU Usage",     f"{cpu}%"),
                ("RAM Usage",     f"{mem.percent}% ({round(mem.used/1e9, 1)}GB / {round(mem.total/1e9, 1)}GB)"),
                ("Disk Usage",    f"{disk.percent}% ({round(disk.used/1e9, 1)}GB / {round(disk.total/1e9, 1)}GB)"),
                ("Temperature",   f"{temp}°C"),
                ("Report Time",   datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')),
            ],
            "severity": (
                "critical" if health == "CRITICAL"
                else "warning" if health == "WARNING"
                else "success"
            )
        })
    except Exception as e:
        sections.append({"heading": "Executive Summary", "content": f"Error collecting data: {e}"})

    # Top Processes
    try:
        import psutil
        procs = sorted(
            psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']),
            key=lambda x: x.info.get('cpu_percent') or 0,
            reverse=True
        )[:10]
        proc_data = [
            (p.info['name'],
             f"CPU: {p.info['cpu_percent']:.1f}% | RAM: {p.info['memory_percent']:.1f}%")
            for p in procs
        ]
        sections.append({"heading": "Top Processes", "content": proc_data})
    except Exception as e:
        sections.append({"heading": "Top Processes", "content": f"Error: {e}"})

    # Recommendations
    sections.append({
        "heading": "Recommendations",
        "content": [
            ("Monitor CPU",    "Alert if CPU stays above 80% for extended periods"),
            ("Temperature",    "Ensure Pi has adequate cooling, consider heatsink"),
            ("Disk Space",     "Monitor disk usage and clean old logs periodically"),
            ("Updates",        "Run /update regularly to check for security patches"),
        ]
    })

    return _build_pdf("System Health Report", sections)


async def generate_network_report() -> io.BytesIO:
    """Generate a network security PDF report."""
    from modules.db import get_devices, get_alerts

    sections = []

    # Device inventory
    try:
        devices = get_devices(limit=100)
        known   = [d for d in devices if d.get('status') == 'known']
        unknown = [d for d in devices if d.get('status') == 'unknown']

        sections.append({
            "heading": "Executive Summary",
            "content": [
                ("Total Devices",   str(len(devices))),
                ("Known Devices",   str(len(known))),
                ("Unknown Devices", str(len(unknown))),
                ("Risk Level",      "HIGH" if unknown else "LOW"),
            ],
            "severity": "warning" if unknown else "success"
        })

        # Full device table (capped at 30)
        device_data = [
            (d.get('ip', '?'),
             f"MAC: {d.get('mac', '?')} | Vendor: {d.get('vendor', '?')} | Status: {d.get('status', '?')}")
            for d in devices[:30]
        ]
        sections.append({"heading": "Discovered Devices", "content": device_data})

        if unknown:
            unk_data = [
                (d.get('ip', '?'),
                 f"MAC: {d.get('mac', '?')} | Vendor: {d.get('vendor', '?')} | First seen: {d.get('first_seen', '?')}")
                for d in unknown
            ]
            sections.append({
                "heading": "Unknown Devices (Action Required)",
                "content": unk_data,
                "severity": "warning"
            })
    except Exception as e:
        sections.append({"heading": "Network Devices", "content": f"Error: {e}"})

    # Recent alerts
    try:
        alerts = get_alerts(limit=20)
        if alerts:
            alert_data = [
                (a.get('alert_type', '?'),
                 f"{a.get('detail', '')} [{a.get('severity', 'info')}] @ {a.get('timestamp', '?')}")
                for a in alerts
            ]
            sections.append({
                "heading": "Recent Alerts",
                "content": alert_data,
                "severity": "warning"
            })
    except Exception:
        pass

    sections.append({
        "heading": "Recommendations",
        "content": [
            ("Unknown Devices",   "Investigate and approve or block unknown devices"),
            ("Network Monitoring","Enable continuous monitoring with /monitor"),
            ("ARP Scans",        "Run regular scans to detect new devices"),
            ("Access Control",   "Use MAC filtering on router for added security"),
        ]
    })

    return _build_pdf("Network Security Report", sections)


async def generate_website_report(url: str) -> io.BytesIO:
    """Generate a website security audit PDF."""
    from modules.webtools import vuln_scan
    from modules.network import check_ssl

    sections = []

    # Vulnerability scan
    try:
        result = await vuln_scan(url)
        grade = "?"
        for line in result.split('\n'):
            if 'Grade:' in line or 'grade:' in line.lower():
                for part in line.split():
                    if len(part) <= 2 and part.upper() in {'A', 'B', 'C', 'D', 'E', 'F', 'A+', 'A-'}:
                        grade = part.upper()

        severity = (
            'success'  if grade in {'A', 'A+'}
            else 'warning'  if grade in {'B', 'C'}
            else 'critical'
        )

        sections.append({
            "heading": "Executive Summary",
            "content": [
                ("Target URL",    url),
                ("Security Grade", grade),
                ("Scan Time",     datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')),
            ],
            "severity": severity
        })
        sections.append({"heading": "Vulnerability Scan Results", "content": result[:3000]})
    except Exception as e:
        sections.append({"heading": "Vulnerability Scan", "content": f"Error: {e}"})

    # SSL check
    try:
        domain = url.replace('https://', '').replace('http://', '').split('/')[0]
        ssl_result = await check_ssl(domain)
        sections.append({"heading": "SSL/TLS Analysis", "content": ssl_result[:2000]})
    except Exception as e:
        sections.append({"heading": "SSL/TLS Analysis", "content": f"Error: {e}"})

    sections.append({
        "heading": "Recommendations",
        "content": [
            ("HTTPS",            "Ensure all traffic uses HTTPS with valid certificate"),
            ("Security Headers", "Implement CSP, HSTS, X-Frame-Options, X-Content-Type-Options"),
            ("Updates",          "Keep CMS, plugins, and frameworks up to date"),
            ("WAF",              "Consider deploying a Web Application Firewall"),
        ]
    })

    return _build_pdf(f"Website Security Audit — {url}", sections)


async def generate_full_report() -> io.BytesIO:
    """Generate a complete security assessment PDF."""
    from modules.db import get_devices, get_alerts, get_scan_history, get_ssh_logs

    sections = []

    # System health
    try:
        import psutil
        cpu  = psutil.cpu_percent(interval=1)
        mem  = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        temp = 0.0
        try:
            with open('/sys/class/thermal/thermal_zone0/temp') as f:
                temp = round(int(f.read().strip()) / 1000, 1)
        except Exception:
            pass

        sections.append({
            "heading": "System Health",
            "content": [
                ("CPU",         f"{cpu}%"),
                ("RAM",         f"{mem.percent}%"),
                ("Disk",        f"{disk.percent}%"),
                ("Temperature", f"{temp}°C"),
            ]
        })
    except Exception:
        pass

    # Network summary
    try:
        devices = get_devices(limit=50)
        unknown = [d for d in devices if d.get('status') == 'unknown']
        sections.append({
            "heading": "Network Summary",
            "content": [
                ("Total Devices",   str(len(devices))),
                ("Unknown Devices", str(len(unknown))),
                ("Risk",            "HIGH" if unknown else "LOW"),
            ],
            "severity": "warning" if unknown else "success"
        })
    except Exception:
        pass

    # Recent scans
    try:
        scans = get_scan_history(limit=10)
        if scans:
            scan_data = [
                (s.get('scan_type', '?'),
                 f"{s.get('target', '?')} @ {s.get('timestamp', '?')}")
                for s in scans
            ]
            sections.append({"heading": "Recent Scans", "content": scan_data})
    except Exception:
        pass

    # Security alerts
    try:
        alerts = get_alerts(limit=20)
        if alerts:
            alert_data = [
                (a.get('alert_type', '?'),
                 f"{a.get('detail', '')} [{a.get('severity', 'info')}]")
                for a in alerts
            ]
            sections.append({
                "heading": "Security Alerts",
                "content": alert_data,
                "severity": "warning"
            })
    except Exception:
        pass

    # SSH login attempts
    try:
        ssh = get_ssh_logs(limit=20)
        if ssh:
            ssh_data = [
                (s.get('ip', '?'),
                 f"User: {s.get('username','?')} | Result: {'OK' if s.get('success') else 'FAIL'} | {s.get('timestamp','?')}")
                for s in ssh
            ]
            sections.append({"heading": "SSH Login Attempts", "content": ssh_data})
    except Exception:
        pass

    # Executive recommendations
    sections.append({
        "heading": "Executive Recommendations",
        "content": [
            ("Priority 1", "Investigate all unknown network devices"),
            ("Priority 2", "Review failed SSH login attempts and consider fail2ban"),
            ("Priority 3", "Ensure all web-facing services use HTTPS"),
            ("Priority 4", "Enable automatic security updates"),
            ("Priority 5", "Regular backups using /backup command"),
        ]
    })

    return _build_pdf("Complete Security Assessment", sections)
