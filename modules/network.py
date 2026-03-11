"""
موديول الشبكات - Network Module
أدوات فحص الشبكة والمواقع
"""

import subprocess
import socket
import ssl
import time
import asyncio
from datetime import datetime
from typing import Optional

import aiohttp


async def ping_host(host: str, count: int = 4) -> str:
    """يسوي ping لأي هوست"""
    try:
        process = await asyncio.create_subprocess_exec(
            'ping', '-c', str(count), '-W', '3', host,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_out(process.communicate(), timeout=20)

        if process.returncode == 0:
            output = stdout.decode()
            # استخراج الإحصائيات
            lines = output.strip().split('\n')
            stats_line = lines[-1] if lines else ""
            summary_line = lines[-2] if len(lines) > 1 else ""

            result = f"""
🏓 *نتيجة Ping لـ* `{host}`

✅ *الحالة:* متصل
📊 *الإحصائيات:*
`{summary_line}`
`{stats_line}`
"""
        else:
            result = f"""
🏓 *نتيجة Ping لـ* `{host}`

❌ *الحالة:* غير متصل أو لا يستجيب
"""
    except asyncio.TimeoutError:
        result = f"⏰ *انتهى الوقت* - `{host}` لم يستجب خلال 20 ثانية"
    except Exception as e:
        result = f"❌ *خطأ:* `{str(e)}`"

    return result


async def port_scan(target: str, ports: str = "common") -> str:
    """يفحص البورتات المفتوحة"""

    # البورتات الشائعة
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 27017: "MongoDB"
    }

    if ports == "common":
        scan_ports = common_ports
    else:
        # لو المستخدم حدد بورتات معينة
        try:
            port_list = [int(p.strip()) for p in ports.split(',')]
            scan_ports = {p: "Unknown" for p in port_list}
        except ValueError:
            return "❌ صيغة البورتات غلط. استخدم أرقام مفصولة بفواصل مثل: 80,443,8080"

    result = f"🔍 *فحص البورتات لـ* `{target}`\n\n"
    open_ports = []
    closed_count = 0

    for port, service in scan_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            conn_result = sock.connect_ex((target, port))
            sock.close()

            if conn_result == 0:
                open_ports.append((port, service))
        except Exception:
            pass
        finally:
            closed_count += 1

    if open_ports:
        result += "🟢 *البورتات المفتوحة:*\n"
        for port, service in open_ports:
            result += f"├ Port `{port}` — {service}\n"
        result += f"\n📊 فُحص {len(scan_ports)} بورت، مفتوح: {len(open_ports)}"
    else:
        result += f"🔒 لا يوجد بورتات مفتوحة من أصل {len(scan_ports)} بورت تم فحصها"

    return result


async def check_website(url: str) -> str:
    """يفحص حالة موقع"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    result = f"🌐 *فحص الموقع:* `{url}`\n\n"

    try:
        start_time = time.time()
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                   allow_redirects=True) as response:
                elapsed = (time.time() - start_time) * 1000  # بالميلي ثانية

                status = response.status
                # تحديد الإيموجي حسب الحالة
                if 200 <= status < 300:
                    emoji = "✅"
                    status_text = "شغال"
                elif 300 <= status < 400:
                    emoji = "↩️"
                    status_text = "تحويل"
                elif 400 <= status < 500:
                    emoji = "⚠️"
                    status_text = "خطأ عميل"
                else:
                    emoji = "❌"
                    status_text = "خطأ سيرفر"

                # هيدرز أمنية
                headers = response.headers
                security_headers = check_security_headers(headers)

                result += f"{emoji} *الحالة:* {status} ({status_text})\n"
                result += f"⏱ *زمن الاستجابة:* {elapsed:.0f}ms\n"
                result += f"🔗 *الرابط النهائي:* `{response.url}`\n"
                result += f"📡 *السيرفر:* `{headers.get('Server', 'غير معروف')}`\n\n"
                result += security_headers

    except aiohttp.ClientError as e:
        result += f"❌ *فشل الاتصال:* `{str(e)}`"
    except asyncio.TimeoutError:
        result += "⏰ *انتهى الوقت* — الموقع لم يستجب خلال 10 ثواني"
    except Exception as e:
        result += f"❌ *خطأ:* `{str(e)}`"

    return result


def check_security_headers(headers) -> str:
    """يفحص الهيدرز الأمنية للموقع"""

    security_checks = {
        'Strict-Transport-Security': ('HSTS', 'يحمي من هجمات downgrade'),
        'Content-Security-Policy': ('CSP', 'يحمي من XSS'),
        'X-Frame-Options': ('X-Frame', 'يحمي من Clickjacking'),
        'X-Content-Type-Options': ('X-Content-Type', 'يمنع MIME sniffing'),
        'X-XSS-Protection': ('XSS Protection', 'حماية إضافية من XSS'),
        'Referrer-Policy': ('Referrer Policy', 'يتحكم بمعلومات الإحالة'),
    }

    result = "🛡 *الهيدرز الأمنية:*\n"
    found = 0
    total = len(security_checks)

    for header, (name, desc) in security_checks.items():
        if header in headers:
            result += f"├ ✅ {name}\n"
            found += 1
        else:
            result += f"├ ❌ {name} — مفقود\n"

    # تقييم عام
    score = (found / total) * 100
    if score >= 80:
        grade = "🟢 ممتاز"
    elif score >= 50:
        grade = "🟡 مقبول"
    else:
        grade = "🔴 ضعيف"

    result += f"\n📊 *التقييم:* {grade} ({found}/{total})"
    return result


async def check_ssl(domain: str) -> str:
    """يفحص شهادة SSL"""
    result = f"🔐 *فحص SSL لـ* `{domain}`\n\n"

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                # معلومات الشهادة
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                not_after = cert.get('notAfter', 'غير معروف')
                not_before = cert.get('notBefore', 'غير معروف')

                # حساب الأيام المتبقية
                expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry - datetime.now()).days

                if days_left > 30:
                    status_emoji = "✅"
                    status_text = "صالحة"
                elif days_left > 0:
                    status_emoji = "⚠️"
                    status_text = "قربت تنتهي!"
                else:
                    status_emoji = "❌"
                    status_text = "منتهية!"

                result += f"{status_emoji} *الحالة:* {status_text}\n"
                result += f"📋 *صادرة لـ:* `{subject.get('commonName', 'N/A')}`\n"
                result += f"🏢 *صادرة من:* `{issuer.get('organizationName', 'N/A')}`\n"
                result += f"📅 *تبدأ:* `{not_before}`\n"
                result += f"📅 *تنتهي:* `{not_after}`\n"
                result += f"⏳ *متبقي:* {days_left} يوم\n"
                result += f"🔒 *البروتوكول:* `{ssock.version()}`\n"

    except ssl.SSLError as e:
        result += f"❌ *خطأ SSL:* `{str(e)}`"
    except socket.timeout:
        result += "⏰ *انتهى الوقت* — لم يستجب على بورت 443"
    except Exception as e:
        result += f"❌ *خطأ:* `{str(e)}`"

    return result


async def get_public_ip() -> str:
    """يجيب الـ Public IP"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('https://api.ipify.org?format=json',
                                   timeout=aiohttp.ClientTimeout(total=5)) as resp:
                data = await resp.json()
                ip = data.get('ip', 'غير معروف')

            # معلومات إضافية عن الـ IP
            async with session.get(f'http://ip-api.com/json/{ip}',
                                   timeout=aiohttp.ClientTimeout(total=5)) as resp:
                geo = await resp.json()

        result = f"""
🌍 *معلومات IP العام*

📡 *IP:* `{ip}`
🏳 *الدولة:* {geo.get('country', 'N/A')}
🏙 *المدينة:* {geo.get('city', 'N/A')}
🏢 *مزود الخدمة:* `{geo.get('isp', 'N/A')}`
🌐 *المنظمة:* `{geo.get('org', 'N/A')}`
"""
        return result
    except Exception as e:
        return f"❌ *خطأ في جلب IP:* `{str(e)}`"
