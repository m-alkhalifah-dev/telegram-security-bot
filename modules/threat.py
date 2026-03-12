"""
Threat Intelligence Module
Latest CVEs/threat feeds from CISA and NVD, IP abuse reputation, IP lookup
"""

import asyncio
import socket
from datetime import datetime
from typing import Optional

import aiohttp


async def get_threat_feed() -> str:
    """Fetch latest critical vulnerabilities from CISA KEV and NVD"""
    result = "🌍 *Threat Intelligence Feed*\n\n"

    # ── CISA Known Exploited Vulnerabilities ─────────────────────────────────
    result += "🚨 *CISA Known Exploited Vulnerabilities (Latest 5):*\n"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
                timeout=aiohttp.ClientTimeout(total=15),
                headers={'User-Agent': 'TelegramSecurityBot/1.0'}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    vulns = sorted(
                        data.get('vulnerabilities', []),
                        key=lambda x: x.get('dateAdded', ''),
                        reverse=True
                    )
                    for v in vulns[:5]:
                        result += "\n━━━━━━━━━━\n"
                        result += f"🔴 *{v.get('cveID', 'N/A')}*\n"
                        result += f"├ Vendor: {v.get('vendorProject', 'N/A')} — {v.get('product', 'N/A')}\n"
                        result += f"├ Name: {v.get('vulnerabilityName', 'N/A')[:60]}\n"
                        result += f"├ Added: {v.get('dateAdded', 'N/A')}\n"
                        desc = v.get('shortDescription', 'N/A')
                        result += f"└ {desc[:120]}{'...' if len(desc) > 120 else ''}\n"
                    result += f"\n📊 Total CISA KEV catalog: {len(vulns)} entries\n"
                else:
                    result += f"⚠️ CISA returned HTTP {resp.status}\n"
    except Exception as e:
        result += f"⚠️ CISA feed error: `{str(e)[:60]}`\n"

    # ── NVD Critical CVEs ──────────────────────────────────────────────────────
    result += "\n⚠️ *NVD Recent Critical CVEs (CVSS ≥ 9.0):*\n"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                'https://services.nvd.nist.gov/rest/json/cves/2.0'
                '?cvssV3Severity=CRITICAL&resultsPerPage=5&startIndex=0',
                timeout=aiohttp.ClientTimeout(total=15),
                headers={'User-Agent': 'TelegramSecurityBot/1.0'}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get('vulnerabilities', []):
                        cve = item.get('cve', {})
                        cve_id = cve.get('id', 'N/A')
                        desc_list = cve.get('descriptions', [])
                        desc = next((d['value'] for d in desc_list if d['lang'] == 'en'), 'N/A')
                        pub_date = cve.get('published', 'N/A')[:10]
                        metrics = cve.get('metrics', {})
                        cvss_list = (metrics.get('cvssMetricV31')
                                     or metrics.get('cvssMetricV30')
                                     or metrics.get('cvssMetricV2')
                                     or [{}])
                        score = cvss_list[0].get('cvssData', {}).get('baseScore', 'N/A') if cvss_list else 'N/A'

                        result += "\n━━━━━━━━━━\n"
                        result += f"🔴 *{cve_id}* (CVSS: {score})\n"
                        result += f"├ Published: {pub_date}\n"
                        result += f"└ {desc[:150]}{'...' if len(desc) > 150 else ''}\n"
                else:
                    result += f"⚠️ NVD returned HTTP {resp.status}\n"
    except Exception as e:
        result += f"⚠️ NVD feed error: `{str(e)[:60]}`\n"

    result += f"\n\n📅 Fetched: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
    result += "🔗 Sources: CISA KEV + NVD API (both free, no key needed)"
    return result


async def abuse_check(ip: str, api_key: str = '') -> str:
    """Check IP reputation on AbuseIPDB (free API key required)"""
    result = f"🚨 *AbuseIPDB Check:* `{ip}`\n\n"

    if not api_key:
        result += "⚠️ *No AbuseIPDB API key configured*\n"
        result += "Get a free key at abuseipdb.com, then add to config.py:\n"
        result += "`ABUSEIPDB_API_KEY = 'your_key_here'`\n\n"
        result += "📡 *Fallback — ip-api.com basic info:*\n"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,proxy,hosting,query',
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    data = await resp.json(content_type=None)
                    if data.get('status') == 'success':
                        result += f"├ IP: `{data.get('query', ip)}`\n"
                        result += f"├ Location: {data.get('city', 'N/A')}, {data.get('country', 'N/A')}\n"
                        result += f"├ ISP: `{data.get('isp', 'N/A')}`\n"
                        result += f"├ Org: `{data.get('org', 'N/A')}`\n"
                        result += f"├ AS: `{data.get('as', 'N/A')}`\n"
                        result += f"├ Proxy/VPN: {'⚠️ Yes' if data.get('proxy') else '✅ No'}\n"
                        result += f"└ Hosting/DC: {'⚠️ Yes' if data.get('hosting') else '✅ No'}\n"
        except Exception as e:
            result += f"└ Error: `{str(e)[:60]}`\n"
        return result

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                'https://api.abuseipdb.com/api/v2/check',
                params={'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': True},
                headers={'Key': api_key, 'Accept': 'application/json'},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    d = (await resp.json()).get('data', {})
                    score = d.get('abuseConfidenceScore', 0)
                    score_emoji = "🔴" if score >= 75 else ("🟡" if score >= 25 else "🟢")

                    result += f"{score_emoji} *Abuse Score:* {score}/100\n\n"
                    result += f"├ Total reports: `{d.get('totalReports', 0)}`\n"
                    result += f"├ Country: `{d.get('countryCode', 'N/A')}`\n"
                    result += f"├ ISP: `{d.get('isp', 'N/A')}`\n"
                    result += f"├ Domain: `{d.get('domain', 'N/A')}`\n"
                    result += f"├ Whitelisted: {'✅ Yes' if d.get('isWhitelisted') else '❌ No'}\n"
                    result += f"├ Tor exit node: {'⚠️ Yes' if d.get('isTor') else '✅ No'}\n"
                    result += f"└ Last reported: `{d.get('lastReportedAt', 'Never')}`\n\n"

                    CAT = {
                        3: 'Fraud Orders', 4: 'DDoS', 5: 'FTP Brute-Force', 7: 'Phishing',
                        9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 14: 'Port Scan',
                        15: 'Hacking', 16: 'SQL Injection', 18: 'Brute-Force',
                        19: 'Bad Web Bot', 21: 'Web App Attack', 22: 'SSH Brute-Force',
                    }
                    reports = d.get('reports', [])
                    if reports:
                        cats: set = set()
                        for rep in reports[:10]:
                            cats.update(rep.get('categories', []))
                        if cats:
                            result += "*Abuse categories:*\n"
                            for c in cats:
                                result += f"├ {CAT.get(c, f'Category {c}')}\n"

                    if score >= 75:
                        result += "\n🚨 *HIGH RISK — block recommended*"
                    elif score >= 25:
                        result += "\n⚠️ *SUSPICIOUS — monitor carefully*"
                    else:
                        result += "\n✅ *IP appears clean*"

                elif resp.status == 401:
                    result += "❌ Invalid API key"
                elif resp.status == 429:
                    result += "❌ Rate limit exceeded (free: 1000/day)"
                else:
                    result += f"❌ AbuseIPDB returned HTTP {resp.status}"
    except Exception as e:
        result += f"❌ *Error:* `{str(e)}`"

    return result


async def ip_lookup(ip: str, abuseipdb_key: str = '') -> str:
    """Comprehensive IP lookup: geo, ISP, ports, abuse score, reverse DNS"""
    result = f"🔍 *IP Lookup: `{ip}`*\n\n"

    # ── Reverse DNS ────────────────────────────────────────────────────────────
    try:
        loop = asyncio.get_event_loop()
        hostname = await loop.run_in_executor(None, lambda: socket.gethostbyaddr(ip))
        result += f"🔄 *Reverse DNS:* `{hostname[0]}`\n"
    except Exception:
        result += "🔄 *Reverse DNS:* No PTR record\n"

    # ── Geo & ISP via ip-api.com ───────────────────────────────────────────────
    result += "\n📍 *Geolocation & ISP:*\n"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,'
                f'regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,mobile,query',
                timeout=aiohttp.ClientTimeout(total=6)
            ) as resp:
                data = await resp.json(content_type=None)

        if data.get('status') == 'success':
            result += f"├ Country: {data.get('country', 'N/A')} ({data.get('countryCode', '')})\n"
            result += f"├ Region/City: {data.get('regionName', 'N/A')}, {data.get('city', 'N/A')}\n"
            result += f"├ Coordinates: `{data.get('lat')}, {data.get('lon')}`\n"
            result += f"├ Timezone: `{data.get('timezone', 'N/A')}`\n"
            result += f"├ ISP: `{data.get('isp', 'N/A')}`\n"
            result += f"├ Org: `{data.get('org', 'N/A')}`\n"
            result += f"├ AS: `{data.get('as', 'N/A')}`\n"
            flags = []
            if data.get('proxy'):
                flags.append('⚠️ Proxy/VPN')
            if data.get('hosting'):
                flags.append('🏢 Hosting/DC')
            if data.get('mobile'):
                flags.append('📱 Mobile')
            result += f"└ Flags: {', '.join(flags) if flags else '✅ None'}\n"
        else:
            result += f"└ Error: {data.get('message', 'Invalid IP')}\n"
    except Exception as e:
        result += f"└ Error: `{str(e)[:60]}`\n"

    # ── Open Ports via HackerTarget ────────────────────────────────────────────
    result += "\n🔌 *Open Ports (HackerTarget scan):*\n"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f'https://api.hackertarget.com/nmap/?q={ip}',
                timeout=aiohttp.ClientTimeout(total=20),
                headers={'User-Agent': 'TelegramSecurityBot/2.0'}
            ) as resp:
                text = await resp.text()
        if 'error' in text.lower() or 'API count' in text:
            result += "└ ⚠️ HackerTarget rate limit or unavailable\n"
        else:
            lines = [l for l in text.splitlines() if '/tcp' in l or '/udp' in l]
            if lines:
                for line in lines[:15]:
                    parts = line.split()
                    if len(parts) >= 3:
                        result += f"├ `{parts[0]}` — {parts[2]}\n"
                if len(lines) > 15:
                    result += f"└ ... and {len(lines)-15} more\n"
            else:
                result += "└ No open ports found (or filtered)\n"
    except Exception as e:
        result += f"└ Scan error: `{str(e)[:60]}`\n"

    # ── Abuse reputation ───────────────────────────────────────────────────────
    result += "\n🚨 *Abuse Reputation:*\n"
    if abuseipdb_key:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    params={'ipAddress': ip, 'maxAgeInDays': 90},
                    headers={'Key': abuseipdb_key, 'Accept': 'application/json'},
                    timeout=aiohttp.ClientTimeout(total=8)
                ) as resp:
                    if resp.status == 200:
                        d = (await resp.json()).get('data', {})
                        score = d.get('abuseConfidenceScore', 0)
                        score_emoji = "🔴" if score >= 75 else ("🟡" if score >= 25 else "🟢")
                        result += f"├ {score_emoji} AbuseIPDB Score: {score}/100\n"
                        result += f"├ Total reports: {d.get('totalReports', 0)}\n"
                        result += f"└ Last reported: {d.get('lastReportedAt', 'Never')}\n"
                    else:
                        result += f"└ AbuseIPDB HTTP {resp.status}\n"
        except Exception as e:
            result += f"└ Error: `{str(e)[:60]}`\n"
    else:
        # Fallback: use ip-api proxy/hosting flags as rough threat indicator
        result += "├ No AbuseIPDB key (add to config.py for full check)\n"
        result += "└ Use /abusecheck for detailed abuse reputation\n"

    # ── Threat score summary ───────────────────────────────────────────────────
    result += f"\n📅 Checked: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    return result
