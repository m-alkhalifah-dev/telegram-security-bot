"""
موديول التحليل - Analysis Module
أدوات تحليل الدومينات و IP
"""

import socket
import asyncio
from typing import Optional

import aiohttp

# المكتبات الاختيارية
try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


async def whois_lookup(domain: str) -> str:
    """يجيب معلومات Whois عن الدومين"""
    result = f"🔎 *معلومات WHOIS لـ* `{domain}`\n\n"

    if not HAS_WHOIS:
        return result + "❌ مكتبة python-whois غير مثبتة. ثبتها بـ: `pip install python-whois`"

    try:
        # تشغيل whois في thread منفصل عشان ما يوقف البوت
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, whois.whois, domain)

        result += f"📋 *اسم الدومين:* `{w.domain_name}`\n"

        if w.registrar:
            result += f"🏢 *المسجل:* `{w.registrar}`\n"

        if w.creation_date:
            date = w.creation_date
            if isinstance(date, list):
                date = date[0]
            result += f"📅 *تاريخ التسجيل:* `{date}`\n"

        if w.expiration_date:
            date = w.expiration_date
            if isinstance(date, list):
                date = date[0]
            result += f"📅 *تاريخ الانتهاء:* `{date}`\n"

        if w.updated_date:
            date = w.updated_date
            if isinstance(date, list):
                date = date[0]
            result += f"📅 *آخر تحديث:* `{date}`\n"

        if w.name_servers:
            servers = w.name_servers
            if isinstance(servers, list):
                result += f"\n🌐 *خوادم DNS:*\n"
                for ns in servers[:5]:
                    result += f"├ `{ns}`\n"

        if w.org:
            result += f"\n🏛 *المنظمة:* `{w.org}`\n"

        if w.country:
            result += f"🏳 *الدولة:* `{w.country}`\n"

        if w.status:
            statuses = w.status if isinstance(w.status, list) else [w.status]
            result += f"\n📊 *الحالة:*\n"
            for s in statuses[:3]:
                result += f"├ `{s}`\n"

    except Exception as e:
        result += f"❌ *خطأ:* `{str(e)}`\n"
        result += "💡 تأكد إن الدومين صحيح (مثال: google.com)"

    return result


async def dns_lookup(domain: str) -> str:
    """يعرض سجلات DNS"""
    result = f"📡 *سجلات DNS لـ* `{domain}`\n\n"

    if not HAS_DNS:
        return result + "❌ مكتبة dnspython غير مثبتة. ثبتها بـ: `pip install dnspython`"

    record_types = {
        'A': '🔵 سجلات A (IPv4)',
        'AAAA': '🟣 سجلات AAAA (IPv6)',
        'MX': '📧 سجلات MX (البريد)',
        'NS': '🌐 سجلات NS (الأسماء)',
        'TXT': '📝 سجلات TXT',
        'CNAME': '🔗 سجلات CNAME',
    }

    for rtype, label in record_types.items():
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda rt=rtype: dns.resolver.resolve(domain, rt)
            )

            result += f"{label}:\n"
            for rdata in answers:
                if rtype == 'MX':
                    result += f"├ `{rdata.exchange}` (أولوية: {rdata.preference})\n"
                else:
                    result += f"├ `{rdata.to_text()}`\n"
            result += "\n"

        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            return result + f"❌ الدومين `{domain}` غير موجود"
        except Exception:
            pass

    if result.count('├') == 0:
        result += "⚠️ لم يتم العثور على سجلات DNS"

    return result


async def geoip_lookup(ip: str) -> str:
    """يجيب الموقع الجغرافي لأي IP"""
    result = f"📍 *معلومات جغرافية لـ* `{ip}`\n\n"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,'
                f'region,regionName,city,zip,lat,lon,timezone,isp,org,as,query',
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                data = await resp.json()

        if data.get('status') == 'success':
            result += f"🌍 *الدولة:* {data.get('country', 'N/A')} ({data.get('countryCode', '')})\n"
            result += f"🏙 *المدينة:* {data.get('city', 'N/A')}, {data.get('regionName', '')}\n"
            result += f"📮 *الرمز البريدي:* `{data.get('zip', 'N/A')}`\n"
            result += f"📐 *الإحداثيات:* `{data.get('lat')}, {data.get('lon')}`\n"
            result += f"🕐 *المنطقة الزمنية:* `{data.get('timezone', 'N/A')}`\n"
            result += f"🏢 *مزود الخدمة:* `{data.get('isp', 'N/A')}`\n"
            result += f"🌐 *المنظمة:* `{data.get('org', 'N/A')}`\n"
            result += f"🔢 *AS:* `{data.get('as', 'N/A')}`\n"
        else:
            result += f"❌ *خطأ:* {data.get('message', 'IP غير صالح')}"

    except Exception as e:
        result += f"❌ *خطأ:* `{str(e)}`"

    return result


async def reverse_dns(ip: str) -> str:
    """يسوي Reverse DNS lookup"""
    result = f"🔄 *Reverse DNS لـ* `{ip}`\n\n"

    try:
        loop = asyncio.get_event_loop()
        hostname = await loop.run_in_executor(
            None,
            lambda: socket.gethostbyaddr(ip)
        )
        result += f"📋 *Hostname:* `{hostname[0]}`\n"
        if hostname[1]:
            result += f"📝 *الأسماء البديلة:* `{', '.join(hostname[1])}`\n"
    except socket.herror:
        result += "⚠️ لا يوجد سجل PTR لهذا الـ IP"
    except Exception as e:
        result += f"❌ *خطأ:* `{str(e)}`"

    return result


async def full_domain_report(domain: str) -> str:
    """تقرير شامل عن دومين"""
    result = f"📋 *تقرير شامل لـ* `{domain}`\n"
    result += "=" * 30 + "\n\n"

    # DNS
    dns_result = await dns_lookup(domain)
    result += dns_result + "\n"

    # Whois
    whois_result = await whois_lookup(domain)
    result += whois_result + "\n"

    # GeoIP من الـ A Record
    try:
        ip = socket.gethostbyname(domain)
        geo_result = await geoip_lookup(ip)
        result += geo_result
    except Exception:
        pass

    return result
