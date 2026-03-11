"""
System Administration Module
Cron jobs, users, disk usage, services, updates, history, backup, resource alerts
"""

import asyncio
import glob
import os
import pwd
import re
import zipfile
from datetime import datetime
from typing import Optional

import psutil


async def list_cron_jobs() -> str:
    """List all cron jobs on the system"""
    result = "⏰ *Cron Jobs*\n\n"
    found_any = False

    # Current user's crontab
    result += "👤 *Current User Crontab:*\n"
    try:
        proc = await asyncio.create_subprocess_exec(
            'crontab', '-l',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode().strip()
        if output and 'no crontab for' not in output:
            for line in output.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    result += f"├ `{line[:80]}`\n"
                    found_any = True
        else:
            result += "├ No crontab entries\n"
    except Exception as e:
        result += f"├ Error: `{str(e)[:60]}`\n"
    result += "\n"

    # System cron directories
    for cron_dir, label in [
        ('/etc/cron.d',       'cron.d'),
        ('/etc/cron.daily',   'Daily'),
        ('/etc/cron.hourly',  'Hourly'),
        ('/etc/cron.weekly',  'Weekly'),
        ('/etc/cron.monthly', 'Monthly'),
    ]:
        if os.path.isdir(cron_dir):
            files = [f for f in os.listdir(cron_dir) if not f.startswith('.') and not f.endswith('~')]
            if files:
                result += f"📁 *{label}:*\n"
                for f in sorted(files)[:10]:
                    result += f"├ `{f}`\n"
                result += "\n"
                found_any = True

    # /etc/crontab
    if os.path.exists('/etc/crontab'):
        result += "📄 */etc/crontab:*\n"
        try:
            with open('/etc/crontab', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        result += f"├ `{line[:80]}`\n"
                        found_any = True
        except Exception:
            pass
        result += "\n"

    if not found_any:
        result += "⚠️ No cron jobs found\n"

    return result


async def list_users() -> str:
    """Show system users, currently logged in users, and last logins"""
    result = "👥 *System Users*\n\n"

    # User accounts
    result += "🧑 *User Accounts:*\n"
    try:
        for entry in sorted(pwd.getpwall(), key=lambda e: e.pw_uid):
            if entry.pw_uid == 0 or entry.pw_uid >= 1000:
                shell = entry.pw_shell.split('/')[-1]
                result += f"├ `{entry.pw_name}` (UID {entry.pw_uid})\n"
                result += f"│  Home: `{entry.pw_dir}` | Shell: `{shell}`\n"
    except Exception as e:
        result += f"├ Error: `{str(e)[:60]}`\n"
    result += "\n"

    # Currently logged in
    result += "🟢 *Currently Logged In:*\n"
    try:
        users = psutil.users()
        if users:
            for u in users:
                since = datetime.fromtimestamp(u.started).strftime('%Y-%m-%d %H:%M')
                result += f"├ `{u.name}` — terminal: `{u.terminal or 'N/A'}`\n"
                result += f"│  Since: {since} | Host: `{u.host or 'local'}`\n"
        else:
            result += "├ No users currently logged in\n"
    except Exception as e:
        result += f"├ Error: `{str(e)[:60]}`\n"
    result += "\n"

    # Last logins
    result += "📅 *Recent Login History:*\n"
    try:
        proc = await asyncio.create_subprocess_exec(
            'last', '-n', '10',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        for line in stdout.decode().splitlines()[:10]:
            if line.strip() and not line.startswith('wtmp'):
                result += f"`{line[:70]}`\n"
    except Exception as e:
        result += f"├ Error: `{str(e)[:60]}`\n"

    return result


async def disk_usage() -> str:
    """Detailed disk usage breakdown"""
    result = "💾 *Disk Usage*\n\n"

    # Partitions
    result += "📀 *Disk Partitions:*\n"
    try:
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                total_gb = usage.total / 1_073_741_824
                used_gb  = usage.used  / 1_073_741_824
                free_gb  = usage.free  / 1_073_741_824
                pct = usage.percent
                bar = '█' * int(pct / 10) + '░' * (10 - int(pct / 10))
                status = "🔴" if pct > 90 else ("🟡" if pct > 75 else "🟢")
                result += f"\n{status} *{part.mountpoint}* ({part.fstype})\n"
                result += f"├ [{bar}] {pct}%\n"
                result += f"├ Used: {used_gb:.1f} GB / {total_gb:.1f} GB\n"
                result += f"└ Free: {free_gb:.1f} GB\n"
            except PermissionError:
                continue
    except Exception as e:
        result += f"├ Error: `{str(e)[:60]}`\n"

    # Top directories by size
    result += "\n📁 *Top Directories by Size:*\n"
    try:
        proc = await asyncio.create_subprocess_exec(
            'du', '-sh', '--max-depth=1', '/',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
        lines = [l for l in stdout.decode().splitlines() if '\t' in l]
        for line in lines[:15]:
            size, path = line.split('\t', 1)
            if path.strip() != '/':
                result += f"├ `{size:>8}` — `{path.strip()}`\n"
    except asyncio.TimeoutError:
        result += "├ Scan timed out\n"
    except Exception as e:
        result += f"├ Error: `{str(e)[:60]}`\n"

    # Home directory
    result += "\n🏠 *Home Directory:*\n"
    try:
        home = os.path.expanduser('~')
        proc = await asyncio.create_subprocess_exec(
            'du', '-sh', home,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        result += f"├ `{stdout.decode().strip()}`\n"
    except Exception:
        pass

    return result


async def list_services() -> str:
    """List all running systemd services"""
    result = "⚙️ *Running System Services*\n\n"

    try:
        proc = await asyncio.create_subprocess_exec(
            'systemctl', 'list-units', '--type=service', '--state=running',
            '--no-pager', '--plain', '--no-legend',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode().strip()

        if output:
            services = []
            for line in output.splitlines():
                if line.strip():
                    name = line.split()[0].replace('.service', '')
                    services.append(name)

            result += f"🟢 *{len(services)} Running Services:*\n"
            for svc in sorted(services)[:35]:
                result += f"├ `{svc}`\n"
            if len(services) > 35:
                result += f"└ ...and {len(services) - 35} more\n"
        else:
            result += "⚠️ No running services found via systemctl\n"

    except Exception as e:
        result += f"❌ *Error:* `{str(e)}`\n"

    # Always check common services as a quick reference
    result += "\n🔍 *Common Services Status:*\n"
    common = ['ssh', 'sshd', 'nginx', 'apache2', 'mysql', 'cron',
              'docker', 'ufw', 'fail2ban', 'redis-server', 'bluetooth']
    for svc in common:
        try:
            p = await asyncio.create_subprocess_exec(
                'systemctl', 'is-active', svc,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            out, _ = await p.communicate()
            status = out.decode().strip()
            emoji = "🟢" if status == "active" else "🔴"
            result += f"├ {emoji} `{svc}` — {status}\n"
        except Exception:
            pass

    return result


async def check_updates() -> str:
    """Check for available apt package updates"""
    result = "🔄 *System Update Check*\n\n"

    # Refresh apt cache
    try:
        proc = await asyncio.create_subprocess_exec(
            'sudo', 'apt', 'update', '-qq',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await asyncio.wait_for(proc.communicate(), timeout=60)
        result += "✅ Package lists updated\n\n"
    except asyncio.TimeoutError:
        result += "⚠️ `apt update` timed out — using cached data\n\n"
    except Exception:
        result += "⚠️ Could not refresh cache (no sudo?) — using cached data\n\n"

    try:
        proc = await asyncio.create_subprocess_exec(
            'apt', 'list', '--upgradable', '--quiet',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        lines = [l for l in stdout.decode().splitlines() if '/' in l]

        if lines:
            security = [l for l in lines if 'security' in l.lower()]
            regular  = [l for l in lines if 'security' not in l.lower()]

            result += f"⚠️ *{len(lines)} package(s) available:*\n\n"
            if security:
                result += f"🔴 *Security Updates ({len(security)}):*\n"
                for pkg in security[:10]:
                    result += f"├ `{pkg.split('/')[0]}`\n"
                result += "\n"
            if regular:
                result += f"🟡 *Regular Updates ({len(regular)}):*\n"
                for pkg in regular[:15]:
                    result += f"├ `{pkg.split('/')[0]}`\n"
                if len(regular) > 15:
                    result += f"└ ...and {len(regular) - 15} more\n"

            result += f"\n💡 Upgrade with: `sudo apt upgrade -y`\n"
        else:
            result += "✅ *System is up to date!*\n"
    except asyncio.TimeoutError:
        result += "❌ Timed out checking updates"
    except Exception as e:
        result += f"❌ *Error:* `{str(e)}`"

    return result


async def get_history() -> str:
    """Show last 20 commands from shell history"""
    result = "📜 *Recent Terminal Commands*\n\n"

    history_files = [
        os.path.expanduser('~/.bash_history'),
        os.path.expanduser('~/.zsh_history'),
        '/root/.bash_history',
    ]

    for hist_file in history_files:
        if os.path.exists(hist_file):
            try:
                with open(hist_file, 'r', errors='ignore') as f:
                    lines = f.readlines()

                commands = []
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith(':') or line.startswith('#'):
                        continue
                    # zsh ": timestamp:0;command" format
                    if re.match(r'^: \d+:\d+;', line):
                        line = line.split(';', 1)[1] if ';' in line else line
                    commands.append(line)

                last20 = commands[-20:]
                result += f"📂 Source: `{hist_file}`\n"
                result += f"📊 Total commands stored: {len(commands)}\n\n"
                result += "*Last 20 commands:*\n"
                for i, cmd in enumerate(last20, 1):
                    result += f"`{i:2}. {cmd[:60]}`\n"
                return result
            except Exception as e:
                result += f"⚠️ Error reading `{hist_file}`: `{str(e)[:50]}`\n"

    result += "❌ No history file found\n"
    result += f"Checked: {', '.join(f'`{f}`' for f in history_files)}\n"
    return result


async def backup_bot(bot_dir: str = '/home/pi/Desktop/telegram-security-bot') -> str:
    """Backup bot config and data files to a timestamped zip"""
    result = "💾 *Bot Backup*\n\n"
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir  = os.path.join(bot_dir, 'backups')
    backup_path = os.path.join(backup_dir, f'backup_{timestamp}.zip')

    files_to_backup = [
        os.path.join(bot_dir, 'config.py'),
        os.path.join(bot_dir, 'requirements.txt'),
        os.path.join(bot_dir, 'data', 'known_devices.json'),
    ]

    try:
        os.makedirs(backup_dir, exist_ok=True)
        backed_up = []
        skipped   = []

        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for filepath in files_to_backup:
                if os.path.exists(filepath):
                    arcname = os.path.relpath(filepath, bot_dir)
                    zf.write(filepath, arcname)
                    backed_up.append((arcname, os.path.getsize(filepath)))
                else:
                    skipped.append(os.path.relpath(filepath, bot_dir))

        total_size = os.path.getsize(backup_path)
        result += f"✅ *Backup created successfully*\n\n"
        result += f"📦 File: `{backup_path}`\n"
        result += f"📏 Size: `{total_size:,} bytes`\n\n"
        result += "*Files included:*\n"
        for arcname, size in backed_up:
            result += f"├ `{arcname}` ({size:,} B)\n"
        if skipped:
            result += "\n⚠️ *Skipped (not found):*\n"
            for f in skipped:
                result += f"├ `{f}`\n"

        # Keep only last 5 backups
        old_backups = sorted(glob.glob(os.path.join(backup_dir, 'backup_*.zip')))
        for old in old_backups[:-5]:
            try:
                os.remove(old)
                result += f"\n🗑 Removed old backup: `{os.path.basename(old)}`"
            except Exception:
                pass

        result += f"\n\n📁 Backups directory: `{backup_dir}`"

    except Exception as e:
        result += f"❌ *Backup failed:* `{str(e)}`"

    return result


async def get_resource_value(resource: str) -> float:
    """Get current value of CPU/RAM/TEMP for alert monitoring"""
    r = resource.upper()
    if r == 'CPU':
        return psutil.cpu_percent(interval=1)
    elif r == 'RAM':
        return psutil.virtual_memory().percent
    elif r == 'TEMP':
        try:
            temps = psutil.sensors_temperatures()
            if 'cpu_thermal' in temps:
                return temps['cpu_thermal'][0].current
            for entries in temps.values():
                if entries:
                    return entries[0].current
        except Exception:
            pass
        try:
            with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                return int(f.read().strip()) / 1000
        except Exception:
            return 0.0
    return 0.0
