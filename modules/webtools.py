"""
Web Tools Module
Website vulnerability scanner, subdomain enumeration, tech detection, email security
"""

import asyncio
import socket
import re
from typing import Optional

import aiohttp


SENSITIVE_PATHS = [
    '/admin', '/administrator', '/.env', '/.env.backup', '/.git',
    '/.git/config', '/wp-admin', '/wp-login.php', '/phpmyadmin',
    '/config.php', '/backup', '/backup.zip', '/db.sql',
    '/robots.txt', '/.htaccess', '/server-status', '/actuator',
    '/actuator/health', '/swagger-ui.html', '/api/v1',
]


async def vuln_scan(url: str) -> str:
    """Comprehensive website vulnerability scanner with A-F grading"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    result = f"🔍 *Vulnerability Scan:* `{url}`\n\n"
    score = 100
    issues = []
    timeout = aiohttp.ClientTimeout(total=10)

    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:

            # Main request
            try:
                async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
                    headers = resp.headers
                    html = await resp.text(errors='ignore')
                    final_url = str(resp.url)
            except Exception as e:
                return result + f"❌ *Connection failed:* `{str(e)}`"

            # --- Security Headers ---
            result += "🛡 *Security Headers:*\n"
            header_checks = {
                'Strict-Transport-Security': ('HSTS', 10),
                'Content-Security-Policy': ('CSP', 15),
                'X-Frame-Options': ('X-Frame-Options', 10),
                'X-Content-Type-Options': ('X-Content-Type-Options', 5),
                'Referrer-Policy': ('Referrer-Policy', 5),
                'Permissions-Policy': ('Permissions-Policy', 5),
            }
            for header, (name, penalty) in header_checks.items():
                if header in headers:
                    result += f"├ ✅ {name}\n"
                else:
                    result += f"├ ❌ {name} — missing\n"
                    score -= penalty
                    issues.append(f"Missing {name}")

            # --- Server Info Disclosure ---
            result += "\n📡 *Server Info Disclosure:*\n"
            server = headers.get('Server', '')
            x_powered = headers.get('X-Powered-By', '')
            if server:
                result += f"├ ⚠️ Server exposed: `{server}`\n"
                score -= 5
                issues.append(f"Server header reveals version info: {server}")
            else:
                result += "├ ✅ Server header hidden\n"
            if x_powered:
                result += f"├ ⚠️ X-Powered-By exposed: `{x_powered}`\n"
                score -= 5
                issues.append(f"X-Powered-By reveals: {x_powered}")
            else:
                result += "├ ✅ X-Powered-By hidden\n"

            # --- Cookie Security ---
            result += "\n🍪 *Cookie Security:*\n"
            cookies_raw = resp.headers.getall('Set-Cookie', [])
            if cookies_raw:
                cookie_issues = 0
                for cookie in cookies_raw:
                    c_lower = cookie.lower()
                    if 'httponly' not in c_lower:
                        cookie_issues += 1
                    if 'secure' not in c_lower:
                        cookie_issues += 1
                    if 'samesite' not in c_lower:
                        cookie_issues += 1
                if cookie_issues == 0:
                    result += "├ ✅ Cookies properly secured\n"
                else:
                    result += f"├ ⚠️ {len(cookies_raw)} cookie(s) missing HttpOnly/Secure/SameSite flags\n"
                    score -= 10
                    issues.append("Cookie security flags missing")
            else:
                result += "├ ℹ️ No cookies set on main response\n"

            # --- CORS Misconfiguration ---
            result += "\n🌐 *CORS Configuration:*\n"
            acao = headers.get('Access-Control-Allow-Origin', '')
            if acao == '*':
                result += "├ ⚠️ CORS wildcard (`*`) — any origin allowed\n"
                score -= 10
                issues.append("CORS misconfiguration: wildcard origin")
            elif acao:
                result += f"├ ✅ CORS restricted to: `{acao}`\n"
            else:
                result += "├ ✅ No permissive CORS headers\n"

            # --- HTTP Methods ---
            result += "\n🔧 *HTTP Methods:*\n"
            try:
                async with session.options(url, timeout=aiohttp.ClientTimeout(total=5)) as opt_resp:
                    allow = opt_resp.headers.get('Allow', '')
                    if allow:
                        dangerous = [m for m in ['PUT', 'DELETE', 'TRACE', 'CONNECT'] if m in allow]
                        if dangerous:
                            result += f"├ ⚠️ Dangerous methods allowed: `{', '.join(dangerous)}`\n"
                            score -= 10
                            issues.append(f"Dangerous HTTP methods enabled: {', '.join(dangerous)}")
                        else:
                            result += f"├ ✅ Methods: `{allow}`\n"
                    else:
                        result += "├ ℹ️ Could not determine allowed methods\n"
            except Exception:
                result += "├ ℹ️ OPTIONS request skipped\n"

            # --- Clickjacking ---
            result += "\n🖱 *Clickjacking Protection:*\n"
            xfo = headers.get('X-Frame-Options', '')
            csp = headers.get('Content-Security-Policy', '')
            if xfo or ('frame-ancestors' in csp):
                result += "├ ✅ Protected against clickjacking\n"
            else:
                result += "├ ❌ No clickjacking protection\n"
                score -= 10
                issues.append("No clickjacking protection (missing X-Frame-Options or CSP frame-ancestors)")

            # --- SSL/HTTPS ---
            result += "\n🔐 *SSL/HTTPS:*\n"
            if final_url.startswith('https://'):
                result += "├ ✅ HTTPS enforced\n"
            else:
                result += "├ ❌ Not using HTTPS\n"
                score -= 20
                issues.append("HTTPS not used or not enforced")

            # --- Sensitive Paths ---
            result += "\n🗂 *Sensitive Paths Check:*\n"
            found_paths = []

            async def check_path(path):
                try:
                    check_url = url.rstrip('/') + path
                    async with session.get(
                        check_url,
                        timeout=aiohttp.ClientTimeout(total=3),
                        allow_redirects=False
                    ) as r:
                        if r.status in (200, 301, 302, 403):
                            return (path, r.status)
                except Exception:
                    pass
                return None

            path_results = await asyncio.gather(*[check_path(p) for p in SENSITIVE_PATHS])
            for pr in path_results:
                if pr:
                    path, status = pr
                    if status == 200:
                        found_paths.append(f"`{path}` → {status} ⚠️ EXPOSED")
                        score -= 5
                        issues.append(f"Sensitive path accessible: {path}")
                    elif status in (301, 302):
                        found_paths.append(f"`{path}` → {status} (redirect)")
                    elif status == 403:
                        found_paths.append(f"`{path}` → {status} (exists, forbidden)")

            if found_paths:
                for fp in found_paths[:10]:
                    result += f"├ {fp}\n"
            else:
                result += "├ ✅ No sensitive paths found\n"

    except Exception as e:
        return result + f"❌ *Scan error:* `{str(e)}`"

    # --- Grade Calculation ---
    score = max(0, score)
    if score >= 90:
        grade, grade_emoji = "A", "🟢"
    elif score >= 75:
        grade, grade_emoji = "B", "🟡"
    elif score >= 60:
        grade, grade_emoji = "C", "🟠"
    elif score >= 40:
        grade, grade_emoji = "D", "🔴"
    else:
        grade, grade_emoji = "F", "💀"

    result += f"\n{'='*30}\n"
    result += f"📊 *Security Score:* {score}/100\n"
    result += f"{grade_emoji} *Grade:* *{grade}*\n"

    if issues:
        result += f"\n⚠️ *Issues Found ({len(issues)}):*\n"
        for issue in issues[:8]:
            result += f"├ {issue}\n"

    return result


async def find_subdomains(domain: str) -> str:
    """Find subdomains via crt.sh, resolve IPs, check which are alive"""
    result = f"🔭 *Subdomain Enumeration:* `{domain}`\n\n"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f'https://crt.sh/?q=%.{domain}&output=json',
                timeout=aiohttp.ClientTimeout(total=25),
                headers={'User-Agent': 'Mozilla/5.0'}
            ) as resp:
                if resp.status != 200:
                    return result + f"❌ crt.sh returned status {resp.status}"
                data = await resp.json(content_type=None)

        # Extract unique subdomains
        subdomains = set()
        for entry in data:
            name = entry.get('name_value', '')
            for sub in name.split('\n'):
                sub = sub.strip().lower()
                if sub.endswith(f'.{domain}') or sub == domain:
                    if '*' not in sub:
                        subdomains.add(sub)

        if not subdomains:
            return result + "⚠️ No subdomains found in crt.sh certificate transparency logs"

        result += f"📋 *Found {len(subdomains)} unique subdomains in CT logs*\n\n"

        # Check which are alive
        async def check_subdomain(sub):
            try:
                loop = asyncio.get_event_loop()
                ip = await loop.run_in_executor(None, socket.gethostbyname, sub)
                try:
                    connector = aiohttp.TCPConnector(ssl=False)
                    async with aiohttp.ClientSession(connector=connector) as s:
                        async with s.get(
                            f'https://{sub}',
                            timeout=aiohttp.ClientTimeout(total=3),
                            allow_redirects=False
                        ) as r:
                            return (sub, ip, r.status, True)
                except Exception:
                    return (sub, ip, None, True)
            except Exception:
                return (sub, None, None, False)

        subs_list = sorted(list(subdomains))[:30]
        check_results = await asyncio.gather(*[check_subdomain(s) for s in subs_list])

        alive = [(s, ip, st) for s, ip, st, resolves in check_results if resolves]
        dead = [s for s, ip, st, resolves in check_results if not resolves]

        result += f"🟢 *Alive / Resolving ({len(alive)}):*\n"
        for sub, ip, status in alive[:20]:
            status_str = f" [{status}]" if status else ""
            result += f"├ `{sub}`\n│  IP: `{ip}`{status_str}\n"

        if dead:
            result += f"\n🔴 *Not Resolving ({len(dead)}):*\n"
            for sub in dead[:8]:
                result += f"├ `{sub}`\n"

        if len(subdomains) > 30:
            result += f"\n⚠️ Showing 30 of {len(subdomains)} total subdomains"

    except Exception as e:
        result += f"❌ *Error:* `{str(e)}`"

    return result


async def tech_detect(url: str) -> str:
    """Detect web technologies from HTTP headers and HTML content"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    result = f"🔬 *Technology Detection:* `{url}`\n\n"

    # Signature definitions: header-based and HTML-based patterns
    signatures = [
        # Web Servers
        ('nginx',          'Web Server',   [('Server', r'nginx')],          None),
        ('Apache',         'Web Server',   [('Server', r'Apache')],         None),
        ('IIS',            'Web Server',   [('Server', r'IIS')],            None),
        ('LiteSpeed',      'Web Server',   [('Server', r'LiteSpeed')],      None),
        ('Caddy',          'Web Server',   [('Server', r'Caddy')],          None),
        # Languages
        ('PHP',            'Language',     [('X-Powered-By', r'PHP'), ('Set-Cookie', r'PHPSESSID')], r'\.php'),
        ('ASP.NET',        'Framework',    [('X-Powered-By', r'ASP'), ('X-AspNet-Version', r'.')],   None),
        ('Node.js',        'Runtime',      [('X-Powered-By', r'Express|node')],                      None),
        # CMS
        ('WordPress',      'CMS',          [],   r'wp-content|wp-includes|WordPress'),
        ('Joomla',         'CMS',          [],   r'Joomla|/components/com_'),
        ('Drupal',         'CMS',          [('X-Generator', r'Drupal')],    r'Drupal'),
        ('Magento',        'CMS',          [],   r'Mage\.Cookies|/skin/frontend/'),
        # JS Frameworks
        ('React',          'JS Framework', [],   r'react\.js|react\.min\.js|ReactDOM|__REACT'),
        ('Next.js',        'JS Framework', [('X-Powered-By', r'Next\.js')], r'__NEXT_DATA__'),
        ('Angular',        'JS Framework', [],   r'ng-version|angular\.min\.js|ng-app'),
        ('Vue.js',         'JS Framework', [],   r'vue\.js|vue\.min\.js|__vue__'),
        ('Nuxt.js',        'JS Framework', [],   r'__nuxt|nuxt\.js'),
        ('jQuery',         'JS Library',   [],   r'jquery\.js|jquery\.min\.js|jquery-\d'),
        # CDN / Cloud
        ('Cloudflare',     'CDN',          [('CF-RAY', r'.'), ('Server', r'cloudflare')], None),
        ('AWS CloudFront', 'CDN',          [('X-Amz-Cf-Id', r'.')],         None),
        ('Fastly',         'CDN',          [('X-Served-By', r'cache')],     None),
        ('Google Cloud',   'Cloud',        [('Via', r'Google Frontend')],   None),
    ]

    detected = {}

    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            ) as resp:
                headers = resp.headers
                html = await resp.text(errors='ignore')
                html_check = html[:60000]

        for tech, category, header_sigs, html_pattern in signatures:
            found = False
            for header_name, pattern in header_sigs:
                val = headers.get(header_name, '')
                if val and re.search(pattern, val, re.IGNORECASE):
                    found = True
                    break
            if not found and html_pattern:
                if re.search(html_pattern, html_check, re.IGNORECASE):
                    found = True
            if found:
                detected.setdefault(category, []).append(tech)

        cat_emojis = {
            'Web Server': '🖥',
            'Language': '💻',
            'Framework': '⚙️',
            'Runtime': '🟢',
            'CMS': '📝',
            'JS Framework': '⚛️',
            'JS Library': '📚',
            'CDN': '☁️',
            'Cloud': '🌩',
        }

        if detected:
            for cat, techs in detected.items():
                emoji = cat_emojis.get(cat, '🔧')
                result += f"{emoji} *{cat}:*\n"
                for tech in techs:
                    result += f"├ {tech}\n"
                result += "\n"
        else:
            result += "⚠️ No known technologies detected\n\n"

        result += "📋 *Raw Headers:*\n"
        result += f"├ Server: `{headers.get('Server', 'hidden')}`\n"
        result += f"├ X-Powered-By: `{headers.get('X-Powered-By', 'hidden')}`\n"
        result += f"├ Content-Type: `{headers.get('Content-Type', 'N/A')}`\n"
        cf_ray = headers.get('CF-RAY', '')
        if cf_ray:
            result += f"├ CF-RAY: `{cf_ray}`\n"

    except Exception as e:
        result += f"❌ *Error:* `{str(e)}`"

    return result


async def email_security_check(domain: str) -> str:
    """Check SPF, DKIM, DMARC records and rate email security A-F"""
    result = f"📧 *Email Security Check:* `{domain}`\n\n"
    score = 0

    try:
        import dns.resolver
    except ImportError:
        return result + "❌ dnspython not installed. Install with: `pip install dnspython`"

    import dns.resolver

    loop = asyncio.get_event_loop()

    # --- SPF ---
    result += "📋 *SPF (Sender Policy Framework):*\n"
    try:
        txt_records = await loop.run_in_executor(
            None, lambda: list(dns.resolver.resolve(domain, 'TXT'))
        )
        spf_record = None
        for record in txt_records:
            txt = record.to_text().strip('"')
            if txt.startswith('v=spf1'):
                spf_record = txt
                break

        if spf_record:
            result += f"├ ✅ SPF record found\n"
            result += f"├ `{spf_record[:100]}`\n"
            score += 30
            if '-all' in spf_record:
                result += "├ ✅ Strict policy (`-all`)\n"
                score += 10
            elif '~all' in spf_record:
                result += "├ ⚠️ Soft fail (`~all`) — consider `-all`\n"
                score += 5
            elif '+all' in spf_record:
                result += "├ 🚨 Pass-all (`+all`) — anyone can spoof!\n"
                score -= 15
            else:
                result += "├ ⚠️ Weak or neutral policy\n"
        else:
            result += "├ ❌ No SPF record — domain can be spoofed\n"
    except Exception as e:
        result += f"├ ❌ Lookup error: `{str(e)}`\n"

    # --- DMARC ---
    result += "\n🛡 *DMARC (Domain-based Message Authentication):*\n"
    try:
        dmarc_records = await loop.run_in_executor(
            None, lambda: list(dns.resolver.resolve(f'_dmarc.{domain}', 'TXT'))
        )
        dmarc_found = False
        for record in dmarc_records:
            txt = record.to_text().strip('"')
            if txt.startswith('v=DMARC1'):
                dmarc_found = True
                result += f"├ ✅ DMARC record found\n"
                result += f"├ `{txt[:120]}`\n"
                score += 30
                if 'p=reject' in txt:
                    result += "├ ✅ Policy: reject (strongest)\n"
                    score += 10
                elif 'p=quarantine' in txt:
                    result += "├ ⚠️ Policy: quarantine (medium)\n"
                    score += 5
                elif 'p=none' in txt:
                    result += "├ ⚠️ Policy: none (monitoring only — not enforced)\n"
                break
        if not dmarc_found:
            result += "├ ❌ No DMARC record found\n"
    except Exception:
        result += "├ ❌ No DMARC record found\n"

    # --- DKIM ---
    result += "\n🔑 *DKIM (DomainKeys Identified Mail):*\n"
    dkim_selectors = ['default', 'google', 'k1', 'mail', 'dkim', 'selector1', 'selector2', 'smtp']
    dkim_found = False
    for selector in dkim_selectors:
        try:
            dkim_host = f'{selector}._domainkey.{domain}'
            await loop.run_in_executor(
                None, lambda h=dkim_host: dns.resolver.resolve(h, 'TXT')
            )
            result += f"├ ✅ DKIM found (selector: `{selector}`)\n"
            score += 20
            dkim_found = True
            break
        except Exception:
            pass
    if not dkim_found:
        result += "├ ⚠️ DKIM not detected with common selectors\n"
        result += "├ Note: Selector names vary by mail provider\n"

    # --- MTA-STS ---
    result += "\n🔒 *MTA-STS (Mail Transfer Security):*\n"
    try:
        await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(f'_mta-sts.{domain}', 'TXT')
        )
        result += "├ ✅ MTA-STS configured\n"
        score += 10
    except Exception:
        result += "├ ⚠️ No MTA-STS record\n"

    # --- BIMI ---
    result += "\n🖼 *BIMI (Brand Indicators):*\n"
    try:
        await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(f'default._bimi.{domain}', 'TXT')
        )
        result += "├ ✅ BIMI record found\n"
        score += 5
    except Exception:
        result += "├ ℹ️ No BIMI record\n"

    # --- Grade ---
    score = min(score, 100)
    if score >= 80:
        grade, grade_emoji, verdict = "A", "🟢", "Excellent"
    elif score >= 60:
        grade, grade_emoji, verdict = "B", "🟡", "Good"
    elif score >= 40:
        grade, grade_emoji, verdict = "C", "🟠", "Fair"
    elif score >= 20:
        grade, grade_emoji, verdict = "D", "🔴", "Poor"
    else:
        grade, grade_emoji, verdict = "F", "💀", "Very Poor — easily spoofed"

    result += f"\n{'='*28}\n"
    result += f"📊 *Score:* {score}/100\n"
    result += f"{grade_emoji} *Grade:* *{grade}* — {verdict}\n"

    return result
