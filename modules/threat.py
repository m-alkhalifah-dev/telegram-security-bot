"""
Threat Intelligence Module
Latest CVEs/threat feeds from CISA and NVD, IP abuse reputation
"""

import asyncio
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
