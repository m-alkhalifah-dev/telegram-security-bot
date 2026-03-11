"""
Breach Intelligence Module
Email breach checking, email header analysis, IP/domain blacklist checking
"""

import asyncio
import ipaddress
import re
import socket
from typing import Optional

import aiohttp


async def breach_check(email: str) -> str:
    """Check if email was found in data breaches using free APIs"""
    result = f"🔍 *Breach Check:* `{email}`\n\n"

    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return result + "❌ Invalid email address format"

    found_any = False

    # XposedOrNot — completely free, no key needed
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f'https://api.xposedornot.com/v1/breach-analytics?email={email}',
                timeout=aiohttp.ClientTimeout(total=12),
                headers={'User-Agent': 'TelegramSecurityBot/1.0'}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    breaches = data.get('ExposedBreaches', {}).get('breaches_details', [])
                    analytics = data.get('BreachMetrics', {})

                    if breaches:
                        found_any = True
                        result += f"🚨 *ALERT! Found in {len(breaches)} breach(es)*\n\n"
                        result += "📋 *Breach Details:*\n"
                        for b in breaches[:8]:
                            result += f"\n━━━━━━━━━━\n"
                            result += f"📛 *Name:* {b.get('breach', 'Unknown')}\n"
                            result += f"📅 *Date:* {b.get('xposed_date', 'Unknown')}\n"
                            records = b.get('xposed_records', 0)
                            result += f"👥 *Records:* {records:,}\n"
                            result += f"📂 *Data types:* {b.get('xposed_data', 'Unknown')}\n"
                        if analytics:
                            industry = analytics.get('industry', {})
                            if industry:
                                top = sorted(industry.items(), key=lambda x: x[1], reverse=True)[:3]
                                result += f"\n🏭 Top industries: {', '.join(k for k, v in top)}\n"
                    else:
                        result += "✅ *Not found in XposedOrNot database*\n"
                elif resp.status == 404:
                    result += "✅ *Email not found in XposedOrNot database*\n"
    except Exception as e:
        result += f"⚠️ XposedOrNot unavailable: `{str(e)[:50]}`\n"

    # LeakCheck public fallback
    if not found_any:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'https://leakcheck.io/api/public?check={email}',
                    timeout=aiohttp.ClientTimeout(total=8),
                    headers={'User-Agent': 'TelegramSecurityBot/1.0'}
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        if data.get('success') and data.get('found', 0) > 0:
                            found_any = True
                            result += f"\n🚨 *LeakCheck: Found in {data['found']} source(s)*\n"
                            for src in data.get('sources', [])[:5]:
                                result += f"├ `{src}`\n"
                        elif data.get('success'):
                            result += "\n✅ *Not found in LeakCheck database*\n"
        except Exception:
            pass

    if not found_any:
        result += "\n✅ *No confirmed breaches found in checked databases*\n"

    result += "\n📌 *Databases checked:*\n"
    result += "├ XposedOrNot (12B+ records)\n"
    result += "├ LeakCheck public\n"
    result += "└ Also verify at: haveibeenpwned.com\n"
    return result


async def analyze_email_header(header_text: str) -> str:
    """Analyze raw email headers: trace hops, detect spoofing, check IPs"""
    result = "📧 *Email Header Analysis*\n\n"

    if not header_text.strip():
        return result + "❌ No header text provided. Paste raw email headers after the command."

    # Parse headers into dict
    headers = {}
    current_key = None
    for line in header_text.splitlines():
        if line and not line[0].isspace() and ':' in line:
            key, _, value = line.partition(':')
            current_key = key.strip().lower()
            headers.setdefault(current_key, []).append(value.strip())
        elif current_key and line.startswith((' ', '\t')):
            if headers.get(current_key):
                headers[current_key][-1] += ' ' + line.strip()

    sender_from  = headers.get('from',          ['Unknown'])[0]
    reply_to     = headers.get('reply-to',      [''])[0]
    return_path  = headers.get('return-path',   [''])[0]
    subject      = headers.get('subject',       ['Unknown'])[0]
    date         = headers.get('date',          ['Unknown'])[0]
    msg_id       = headers.get('message-id',    ['Unknown'])[0]

    result += "📋 *Basic Info:*\n"
    result += f"├ From: `{sender_from[:80]}`\n"
    result += f"├ Subject: `{subject[:80]}`\n"
    result += f"├ Date: `{date[:60]}`\n"
    result += f"└ Message-ID: `{msg_id[:60]}`\n\n"

    # Spoofing detection
    result += "🕵️ *Spoofing Analysis:*\n"
    from_m = re.search(r'<([^>]+)>', sender_from)
    from_addr = from_m.group(1) if from_m else sender_from
    from_domain = from_addr.split('@')[-1].lower() if '@' in from_addr else ''

    rp_m = re.search(r'<([^>]+)>', return_path)
    rp_addr = rp_m.group(1) if rp_m else return_path
    rp_domain = rp_addr.split('@')[-1].lower() if '@' in rp_addr else ''

    if return_path and from_domain and rp_domain and from_domain != rp_domain:
        result += f"├ ⚠️ From domain `{from_domain}` ≠ Return-Path domain `{rp_domain}`\n"
        result += "├ 🚨 Possible spoofing or forwarding detected\n"
    elif from_domain:
        result += "├ ✅ From and Return-Path domains match\n"

    if reply_to:
        rt_m = re.search(r'<([^>]+)>', reply_to)
        rt_addr = rt_m.group(1) if rt_m else reply_to
        if rt_addr.lower() != from_addr.lower():
            result += f"├ ⚠️ Reply-To differs from From: `{rt_addr[:50]}`\n"

    # Authentication results
    auth_results = headers.get('authentication-results', [''])[0]
    result += "\n🔐 *Authentication:*\n"
    if auth_results:
        result += f"├ SPF:   {'✅ pass' if 'spf=pass'   in auth_results.lower() else '❌ fail/none'}\n"
        result += f"├ DKIM:  {'✅ pass' if 'dkim=pass'  in auth_results.lower() else '❌ fail/none'}\n"
        result += f"└ DMARC: {'✅ pass' if 'dmarc=pass' in auth_results.lower() else '❌ fail/none'}\n"
    else:
        result += "└ ⚠️ No Authentication-Results header found\n"

    # Trace received hops
    received_headers = headers.get('received', [])
    result += f"\n🛤 *Email Path ({len(received_headers)} hop(s)):*\n"

    ips_to_check = []
    for i, recv in enumerate(received_headers[:6]):
        result += f"\n*Hop {i+1}:*\n"
        from_m = re.search(r'from\s+(\S+)', recv, re.IGNORECASE)
        by_m   = re.search(r'by\s+(\S+)',   recv, re.IGNORECASE)
        if from_m:
            result += f"├ From: `{from_m.group(1)[:60]}`\n"
        if by_m:
            result += f"├ By: `{by_m.group(1)[:60]}`\n"
        for ip in re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', recv):
            try:
                addr = ipaddress.ip_address(ip)
                if not addr.is_private and not addr.is_loopback:
                    result += f"├ Public IP: `{ip}`\n"
                    ips_to_check.append(ip)
            except Exception:
                pass

    if ips_to_check:
        orig_ip = ips_to_check[-1]
        result += f"\n🔎 *Originating IP:* `{orig_ip}`\n"
        result += await _quick_dnsbl_check(orig_ip)

    return result


async def blacklist_check(target: str) -> str:
    """Check IP or domain against DNSBL spam blacklists"""
    result = f"🚫 *Blacklist Check:* `{target}`\n\n"

    ip = target
    is_domain = not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target)

    if is_domain:
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, target)
            result += f"📍 *Resolved IP:* `{ip}`\n\n"
        except Exception:
            return result + f"❌ Could not resolve `{target}` to an IP address"

    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            return result + "⚠️ Private IP — blacklists only apply to public IPs"
    except ValueError:
        return result + "❌ Invalid IP address"

    result += await _full_dnsbl_check(ip)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f'http://ip-api.com/json/{ip}?fields=status,isp,org,as,country,city,proxy,hosting',
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                data = await resp.json(content_type=None)
                if data.get('status') == 'success':
                    result += "\n📡 *IP Context:*\n"
                    result += f"├ Location: {data.get('city', '')}, {data.get('country', 'N/A')}\n"
                    result += f"├ ISP: `{data.get('isp', 'N/A')}`\n"
                    result += f"├ AS: `{data.get('as', 'N/A')}`\n"
                    result += f"├ Proxy/VPN: {'⚠️ Yes' if data.get('proxy') else '✅ No'}\n"
                    result += f"└ Hosting/DC: {'⚠️ Yes' if data.get('hosting') else '✅ No'}\n"
    except Exception:
        pass

    return result


async def _full_dnsbl_check(ip: str) -> str:
    dnsbls = [
        ('zen.spamhaus.org',        'Spamhaus ZEN'),
        ('bl.spamcop.net',          'SpamCop'),
        ('b.barracudacentral.org',  'Barracuda'),
        ('cbl.abuseat.org',         'CBL Abuseat'),
        ('dnsbl.sorbs.net',         'SORBS'),
        ('psbl.surriel.com',        'PSBL'),
        ('dnsbl-1.uceprotect.net',  'UCEPROTECT-1'),
        ('drone.abuse.ch',          'Abuse.ch'),
        ('spam.dnsbl.sorbs.net',    'SORBS Spam'),
        ('bl.0spam.org',            '0spam'),
        ('ix.dnsbl.manitu.net',     'Manitu'),
        ('dnsrbl.swinog.ch',        'SwissSINEG'),
    ]
    reversed_ip = '.'.join(reversed(ip.split('.')))
    listed, clean = [], []

    async def check_one(zone, name):
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, socket.gethostbyname, f'{reversed_ip}.{zone}')
            listed.append(name)
        except Exception:
            clean.append(name)

    await asyncio.gather(*[check_one(z, n) for z, n in dnsbls])

    result = f"🔴 *Listed on {len(listed)}/{len(dnsbls)} blacklists*\n\n" if listed else f"✅ *Clean on all {len(dnsbls)} checked blacklists*\n\n"

    if listed:
        result += "❌ *Blacklisted on:*\n"
        for bl in listed:
            result += f"├ 🔴 {bl}\n"
        result += "\n⚠️ This IP has a bad reputation — it may be a spam sender, compromised host, or known attacker.\n"
        result += "💡 Check delisting process on each blacklist's website.\n"

    return result


async def _quick_dnsbl_check(ip: str) -> str:
    dnsbls = [('zen.spamhaus.org', 'Spamhaus'), ('bl.spamcop.net', 'SpamCop'), ('cbl.abuseat.org', 'CBL')]
    reversed_ip = '.'.join(reversed(ip.split('.')))
    listed = []

    async def check(zone, name):
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, socket.gethostbyname, f'{reversed_ip}.{zone}')
            listed.append(name)
        except Exception:
            pass

    await asyncio.gather(*[check(z, n) for z, n in dnsbls])
    if listed:
        return f"├ 🚨 Blacklisted on: {', '.join(listed)}\n"
    return "├ ✅ Not on top blacklists (quick check)\n"
