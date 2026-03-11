"""
Security Tools Module
Password strength checker, hash identifier/lookup, speed test, bandwidth monitor
"""

import asyncio
import hashlib
import math
import re
import time
from typing import Optional

import aiohttp
import psutil


async def check_password(password: str) -> str:
    """Check password strength, complexity, common patterns, and breach status"""
    length = len(password)
    result = f"🔐 *Password Strength Analysis*\n\n"
    result += f"Length: `{length}` characters\n\n"

    score = 0
    issues = []

    # --- Length ---
    result += "📏 *Length:*\n"
    if length < 8:
        result += f"├ ❌ Too short ({length} chars) — minimum 8\n"
        issues.append("Use at least 8 characters (12+ recommended)")
    elif length < 12:
        result += f"├ ⚠️ Acceptable ({length} chars) — 12+ recommended\n"
        score += 10
    elif length < 16:
        result += f"├ ✅ Good length ({length} chars)\n"
        score += 20
    else:
        result += f"├ ✅ Excellent length ({length} chars)\n"
        score += 30

    # --- Character Types ---
    result += "\n🔤 *Character Variety:*\n"
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>?/\\|`~]', password))

    for label, has_it, penalty_msg in [
        ("Lowercase letters", has_lower, "Add lowercase letters"),
        ("Uppercase letters", has_upper, "Add uppercase letters"),
        ("Numbers",           has_digit, "Add numbers"),
        ("Special characters (!@#$...)", has_special, "Add special characters"),
    ]:
        if has_it:
            result += f"├ ✅ {label}\n"
            score += 10
        else:
            result += f"├ ❌ {label} — missing\n"
            issues.append(penalty_msg)

    # --- Common Patterns ---
    result += "\n⚠️ *Pattern Analysis:*\n"
    common_words = [
        'password', '123456', 'qwerty', 'abc123', 'letmein', 'monkey',
        'master', 'dragon', 'admin', 'welcome', 'login', 'iloveyou',
        'sunshine', 'princess', 'football', 'shadow', 'superman', 'michael',
    ]
    pw_lower = password.lower()

    is_common = any(w in pw_lower for w in common_words)
    has_repeat = bool(re.search(r'(.)\1{2,}', password))
    has_sequence = bool(re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)', pw_lower))
    is_keyboard = bool(re.search(r'(qwerty|asdfgh|zxcvbn|qazwsx)', pw_lower))

    checks = [
        (is_common,    "❌ Contains common password words",    -20, "Avoid common dictionary words"),
        (has_repeat,   "⚠️ Repeated characters (e.g. aaa)",   -5,  "Avoid repeating the same character"),
        (has_sequence, "⚠️ Sequential chars (123, abc)",       -5,  "Avoid sequential patterns"),
        (is_keyboard,  "⚠️ Keyboard pattern (qwerty, asdf)",  -5,  "Avoid keyboard walk patterns"),
    ]
    for flag, bad_msg, penalty, advice in checks:
        if flag:
            result += f"├ {bad_msg}\n"
            score += penalty
            issues.append(advice)
        else:
            result += f"├ ✅ No {bad_msg.split(' ', 2)[2]}\n"

    # --- Entropy ---
    charset_size = (26 if has_lower else 0) + (26 if has_upper else 0) + \
                   (10 if has_digit else 0) + (32 if has_special else 0)
    if charset_size > 0 and length > 0:
        entropy = length * math.log2(charset_size)
        result += f"\n📊 *Entropy:* ~{entropy:.0f} bits\n"
        if entropy >= 80:
            result += "├ ✅ Very high entropy\n"
            score += 10
        elif entropy >= 60:
            result += "├ ✅ Good entropy\n"
            score += 5
        elif entropy >= 40:
            result += "├ ⚠️ Moderate entropy\n"
        else:
            result += "├ ❌ Low entropy — easy to brute force\n"
            score -= 10

    # --- HaveIBeenPwned (k-anonymity) ---
    result += "\n🔎 *Breach Database Check (HIBP):*\n"
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                timeout=aiohttp.ClientTimeout(total=6),
                headers={'User-Agent': 'TelegramSecurityBot/1.0'}
            ) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    found_count = 0
                    for line in text.splitlines():
                        if line.upper().startswith(suffix):
                            found_count = int(line.split(':')[1])
                            break
                    if found_count > 0:
                        result += f"├ 🚨 *PWNED!* Seen in {found_count:,} data breaches\n"
                        score -= 30
                        issues.insert(0, "Password is in breach databases — change it!")
                    else:
                        result += "├ ✅ Not found in known breach databases\n"
                        score += 10
    except Exception as e:
        result += f"├ ⚠️ Could not reach HIBP: `{str(e)}`\n"

    # --- Final Grade ---
    score = max(0, min(100, score))
    if score >= 80:
        grade, grade_emoji = "Strong 💪", "🟢"
    elif score >= 60:
        grade, grade_emoji = "Good 👍", "🟡"
    elif score >= 40:
        grade, grade_emoji = "Weak ⚠️", "🟠"
    else:
        grade, grade_emoji = "Very Weak ❌", "🔴"

    result += f"\n{'='*28}\n"
    result += f"📊 *Score:* {score}/100\n"
    result += f"{grade_emoji} *Strength:* {grade}\n"

    if issues:
        result += f"\n💡 *Recommendations:*\n"
        for issue in issues[:5]:
            result += f"├ {issue}\n"

    return result


async def identify_hash(value: str) -> str:
    """Identify hash type by length/pattern and attempt online lookup"""
    value = value.strip()
    result = f"#️⃣ *Hash Analysis*\n\n"
    result += f"Value: `{value}`\n"
    result += f"Length: `{len(value)}` chars\n\n"

    # Pattern definitions: (regex, short_type, description)
    hash_patterns = [
        (r'^[a-f0-9]{32}$',          'MD5',        'MD5 (128-bit)'),
        (r'^[a-f0-9]{40}$',          'SHA1',       'SHA-1 (160-bit)'),
        (r'^[a-f0-9]{56}$',          'SHA224',     'SHA-224 (224-bit)'),
        (r'^[a-f0-9]{64}$',          'SHA256',     'SHA-256 (256-bit)'),
        (r'^[a-f0-9]{96}$',          'SHA384',     'SHA-384 (384-bit)'),
        (r'^[a-f0-9]{128}$',         'SHA512',     'SHA-512 (512-bit)'),
        (r'^\$2[ayb]\$.{56}$',       'BCRYPT',     'bcrypt (salted)'),
        (r'^\$6\$.{86}$',            'SHA512CRYPT','SHA-512 crypt'),
        (r'^\$1\$.{22}$',            'MD5CRYPT',   'MD5 crypt'),
        (r'^\*[A-F0-9]{40}$',        'MYSQL41',    'MySQL 4.1+ password hash'),
        (r'^[a-zA-Z0-9+/]{44}={0,2}$','B64SHA256', 'Base64-encoded SHA-256'),
        (r'^[a-z0-9]{13}$',          'DES',        'DES crypt (Unix)'),
        (r'^[a-f0-9]{32}:[a-z0-9]+$','MD5SALT',    'MD5 with salt'),
    ]

    identified = []
    for pattern, short_type, description in hash_patterns:
        if re.match(pattern, value, re.IGNORECASE):
            identified.append((short_type, description))

    result += "🔍 *Identified Hash Type(s):*\n"
    if identified:
        for short_type, description in identified:
            result += f"├ ✅ *{description}*\n"
    else:
        result += "├ ⚠️ Unknown format — does not match common hash lengths\n"
        result += f"├ Length {len(value)} is not a standard hash length\n"

    # Online lookup for crackable hash types
    if identified and identified[0][0] in ('MD5', 'SHA1', 'SHA256'):
        short_type = identified[0][0]
        result += f"\n🌐 *Online Lookup ({short_type}):*\n"
        cracked = await _lookup_hash_online(value, short_type)
        if cracked:
            result += f"├ 🚨 *Hash cracked:* `{cracked}`\n"
            result += "├ This hash is in public rainbow tables!\n"
        else:
            result += "├ ✅ Not found in checked online databases\n"

    result += "\n💡 *Note:* Online lookup uses free public databases (limited)."
    return result


async def _lookup_hash_online(hash_value: str, hash_type: str) -> Optional[str]:
    """Attempt to crack hash using free public databases"""
    # Try md5decrypt.net API
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f'https://md5decrypt.net/Api/api.php?hash={hash_value}'
                f'&hash_type={hash_type.lower()}&email=&code=',
                timeout=aiohttp.ClientTimeout(total=5),
                headers={'User-Agent': 'Mozilla/5.0'}
            ) as resp:
                if resp.status == 200:
                    text = (await resp.text()).strip()
                    if text and len(text) < 200 and not text.startswith('ERROR') and text != hash_value:
                        return text
    except Exception:
        pass

    # Fallback: nitrxgen for MD5
    if hash_type == 'MD5':
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'https://www.nitrxgen.net/md5db/{hash_value}',
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    text = (await resp.text()).strip()
                    if text and len(text) < 100:
                        return text
        except Exception:
            pass

    return None


async def run_speedtest() -> str:
    """Run internet speed test using speedtest-cli"""
    result = "🚀 *Internet Speed Test*\n\n"
    result += "⏳ Running test (this takes ~30 seconds)...\n"

    try:
        import speedtest as st

        loop = asyncio.get_event_loop()

        def do_speedtest():
            s = st.Speedtest(secure=True)
            s.get_best_server()
            download = s.download() / 1_000_000
            upload = s.upload() / 1_000_000
            ping = s.results.ping
            server = s.results.server
            return download, upload, ping, server

        download, upload, ping, server = await loop.run_in_executor(None, do_speedtest)

        if download >= 100:
            rating = "🟢 Excellent"
        elif download >= 25:
            rating = "🟡 Good"
        elif download >= 10:
            rating = "🟠 Fair"
        else:
            rating = "🔴 Slow"

        result = "🚀 *Internet Speed Test Results*\n\n"
        result += f"📥 *Download:* `{download:.2f} Mbps`\n"
        result += f"📤 *Upload:*   `{upload:.2f} Mbps`\n"
        result += f"📡 *Ping:*     `{ping:.1f} ms`\n\n"
        result += f"🖥 *Server:*   {server.get('name', 'N/A')}, {server.get('country', '')}\n"
        result += f"🏢 *Sponsor:*  {server.get('sponsor', 'N/A')}\n\n"
        result += f"📊 *Rating:* {rating}"

    except ImportError:
        result = "❌ speedtest-cli not installed.\nInstall with: `pip install speedtest-cli`"
    except Exception as e:
        result = f"🚀 *Speed Test*\n\n❌ *Failed:* `{str(e)}`"

    return result


async def get_bandwidth() -> str:
    """Show current network upload/download rates sampled over 2 seconds"""
    result = "📊 *Network Bandwidth Monitor*\n\n"

    try:
        net1 = psutil.net_io_counters()
        await asyncio.sleep(2)
        net2 = psutil.net_io_counters()

        bytes_sent = (net2.bytes_sent - net1.bytes_sent) / 2
        bytes_recv = (net2.bytes_recv - net1.bytes_recv) / 2

        def fmt(bps):
            if bps >= 1_000_000:
                return f"{bps / 1_000_000:.2f} MB/s  ({bps * 8 / 1_000_000:.1f} Mbps)"
            elif bps >= 1_000:
                return f"{bps / 1_000:.1f} KB/s  ({bps * 8 / 1_000:.0f} Kbps)"
            return f"{bps:.0f} B/s"

        result += "*Current Rate (2s sample):*\n"
        result += f"📥 Download: `{fmt(bytes_recv)}`\n"
        result += f"📤 Upload:   `{fmt(bytes_sent)}`\n\n"

        result += "📈 *Totals Since Boot:*\n"
        total_recv_gb = net2.bytes_recv / 1_073_741_824
        total_sent_gb = net2.bytes_sent / 1_073_741_824
        result += f"├ Downloaded: `{total_recv_gb:.3f} GB`\n"
        result += f"├ Uploaded:   `{total_sent_gb:.3f} GB`\n"
        result += f"├ Packets In:  `{net2.packets_recv:,}`\n"
        result += f"└ Packets Out: `{net2.packets_sent:,}`\n\n"

        result += "🔌 *Per Interface:*\n"
        per_nic = psutil.net_io_counters(pernic=True)
        for iface, stats in per_nic.items():
            if stats.bytes_recv > 0 or stats.bytes_sent > 0:
                recv_mb = stats.bytes_recv / 1_048_576
                sent_mb = stats.bytes_sent / 1_048_576
                result += f"├ `{iface}`: ↓{recv_mb:.1f} MB  ↑{sent_mb:.1f} MB\n"

    except Exception as e:
        result += f"❌ *Error:* `{str(e)}`"

    return result
