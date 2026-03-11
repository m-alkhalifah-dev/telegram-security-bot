"""
Web Scanning Module
Website crawling, JS analysis, CORS testing, WAF detection,
deep header analysis, robots.txt/sitemap analysis
"""

import asyncio
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp

_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'


async def crawl_website(url: str, max_pages: int = 25) -> str:
    """Spider a website: find links, forms, inputs, hidden fields, comments, JS files"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    result = f"🕷 *Website Crawler:* `{url}`\n\n"
    base_domain = urlparse(url).netloc
    visited: Set[str] = set()
    to_visit = [url]
    all_links: Set[str] = set()
    external_links: Set[str] = set()
    forms: List[dict] = []
    js_files: Set[str] = set()
    comments: List[str] = []
    hidden_fields: List[str] = []
    emails_found: Set[str] = set()

    connector = aiohttp.TCPConnector(ssl=False)
    timeout = aiohttp.ClientTimeout(total=8)

    try:
        async with aiohttp.ClientSession(
            connector=connector,
            headers={'User-Agent': _UA}
        ) as session:
            while to_visit and len(visited) < max_pages:
                current_url = to_visit.pop(0)
                if current_url in visited:
                    continue
                visited.add(current_url)

                try:
                    async with session.get(current_url, timeout=timeout, allow_redirects=True) as resp:
                        ct = resp.headers.get('Content-Type', '')
                        if 'text/html' not in ct:
                            continue
                        html = await resp.text(errors='ignore')
                except Exception:
                    continue

                # Links and src attributes
                for match in re.findall(r'(?:href|src)=["\']([^"\']+)["\']', html, re.IGNORECASE):
                    abs_url = urljoin(current_url, match)
                    parsed = urlparse(abs_url)
                    if parsed.netloc == base_domain:
                        if abs_url not in visited:
                            to_visit.append(abs_url)
                        all_links.add(abs_url)
                    elif parsed.netloc:
                        external_links.add(abs_url)
                    if re.search(r'\.js(\?|$)', match):
                        js_files.add(urljoin(current_url, match))

                # Forms
                for form_html in re.findall(r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL):
                    action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                    method = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                    inputs = re.findall(r'<input[^>]*>', form_html, re.IGNORECASE)
                    forms.append({
                        'action': action.group(1) if action else current_url,
                        'method': (method.group(1).upper() if method else 'GET'),
                        'fields': len(inputs),
                        'url': current_url,
                    })
                    for h in re.findall(r'<input[^>]+type=["\']hidden["\'][^>]*>', form_html, re.IGNORECASE):
                        nm = re.search(r'name=["\']([^"\']*)["\']', h, re.IGNORECASE)
                        if nm:
                            hidden_fields.append(f"{nm.group(1)} @ {current_url}")

                # HTML comments
                for c in re.findall(r'<!--(.*?)-->', html, re.DOTALL):
                    c = c.strip()
                    if len(c) > 10 and not c.startswith('[if'):
                        comments.append(c[:100])

                # Emails
                for em in re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', html):
                    emails_found.add(em)
    except Exception as e:
        result += f"❌ *Crawler error:* `{str(e)}`\n"
        return result

    result += "📊 *Crawl Summary:*\n"
    result += f"├ Pages visited:    {len(visited)}\n"
    result += f"├ Internal links:   {len(all_links)}\n"
    result += f"├ External links:   {len(external_links)}\n"
    result += f"├ Forms found:      {len(forms)}\n"
    result += f"├ JS files found:   {len(js_files)}\n"
    result += f"├ HTML comments:    {len(comments)}\n"
    result += f"├ Hidden fields:    {len(hidden_fields)}\n"
    result += f"└ Emails found:     {len(emails_found)}\n\n"

    if forms:
        result += "📝 *Forms:*\n"
        for f in forms[:6]:
            result += f"├ {f['method']} `{f['action'][:55]}`  ({f['fields']} fields)\n"
        result += "\n"

    if hidden_fields:
        result += "🔒 *Hidden Form Fields:*\n"
        for hf in hidden_fields[:8]:
            result += f"├ `{hf[:70]}`\n"
        result += "\n"

    if js_files:
        result += f"📜 *JavaScript Files ({len(js_files)}):*\n"
        for js in list(js_files)[:10]:
            result += f"├ `{js[:80]}`\n"
        result += "\n"

    if comments:
        result += f"💬 *HTML Comments (sample):*\n"
        for c in comments[:5]:
            result += f"├ `{c[:80]}`\n"
        result += "\n"

    if emails_found:
        result += "📧 *Emails Found:*\n"
        for em in list(emails_found)[:5]:
            result += f"├ `{em}`\n"

    if external_links:
        result += f"\n🌐 *External Links (sample):*\n"
        for el in list(external_links)[:5]:
            result += f"├ `{el[:80]}`\n"

    return result


_SECRET_PATTERNS: List[Tuple[str, str]] = [
    (r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']{8,50})["\']',             'API Key'),
    (r'(?i)(?:secret[_-]?key|client_secret)\s*[:=]\s*["\']([^"\']{8,50})["\']',   'Secret Key'),
    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,40})["\']',             'Password'),
    (r'(?i)(?:access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*["\']([^"\']{8,})["\']', 'Auth Token'),
    (r'AKIA[A-Z0-9]{16}',                                                            'AWS Access Key'),
    (r'(?i)(?:database_url|db[_-]?url|mongo[_-]?uri)\s*[:=]\s*["\']([^"\']{8,})["\']', 'DB URL'),
    (r'(?i)(?:private[_-]?key)\s*[:=]\s*["\']([^"\']{8,})["\']',                  'Private Key'),
    (r'"[^"]*/(api|v\d|graphql|rest)/[^"<>\s]{3,60}"',                             'API Endpoint'),
]


async def js_scan(url: str) -> str:
    """Extract and analyze JS files for API keys, endpoints, tokens, credentials"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    result = f"🔬 *JavaScript Security Scan:* `{url}`\n\n"
    js_urls: Set[str] = set()

    connector = aiohttp.TCPConnector(ssl=False)
    try:
        async with aiohttp.ClientSession(connector=connector, headers={'User-Agent': _UA}) as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as resp:
                html = await resp.text(errors='ignore')

            for js in re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', html, re.IGNORECASE):
                js_urls.add(urljoin(url, js))

            inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL)
            result += f"📜 Found *{len(js_urls)}* external JS files + *{len(inline_scripts)}* inline scripts\n\n"

            all_findings: Dict[str, List[Tuple[str, str]]] = {}
            endpoints: Set[str] = set()

            for js_url in list(js_urls)[:12]:
                try:
                    async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=6)) as jr:
                        content = await jr.text(errors='ignore')
                    findings = _scan_js_content(content)
                    if findings:
                        all_findings[js_url] = findings
                    for ep in re.findall(r'"(/(?:api|v\d+|graphql|rest)[^"<>\s]{0,60})"', content):
                        endpoints.add(ep)
                except Exception:
                    pass

            inline_findings: List[Tuple[str, str]] = []
            for script in inline_scripts[:5]:
                inline_findings.extend(_scan_js_content(script))

            if all_findings or inline_findings:
                result += "🚨 *Potential Secrets / Sensitive Data Found:*\n\n"
                for file_url, findings in all_findings.items():
                    fname = file_url.split('/')[-1][:40]
                    result += f"📄 *{fname}:*\n"
                    for ftype, fval in findings[:4]:
                        masked = fval[:15] + '...' if len(fval) > 15 else fval
                        result += f"├ [{ftype}] `{masked}`\n"
                    result += "\n"
                if inline_findings:
                    result += "📌 *Inline Script Findings:*\n"
                    for ftype, fval in inline_findings[:6]:
                        masked = fval[:20] + '...' if len(fval) > 20 else fval
                        result += f"├ [{ftype}] `{masked}`\n"
            else:
                result += "✅ *No obvious secrets or credentials found in JS files*\n"

            if endpoints:
                result += f"\n🔗 *API Endpoints Found ({len(endpoints)}):*\n"
                for ep in list(endpoints)[:10]:
                    result += f"├ `{ep[:70]}`\n"

    except Exception as e:
        result += f"❌ *Error:* `{str(e)}`"

    return result


def _scan_js_content(content: str) -> List[Tuple[str, str]]:
    findings = []
    for pattern, label in _SECRET_PATTERNS:
        for match in re.findall(pattern, content)[:2]:
            value = match if isinstance(match, str) else (match[-1] if match else '')
            if value and len(value) > 4:
                findings.append((label, value))
    return findings


async def cors_test(url: str) -> str:
    """Deep CORS misconfiguration testing with multiple origins"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    result = f"🌐 *CORS Misconfiguration Test:* `{url}`\n\n"
    host = urlparse(url).netloc

    test_origins = [
        ('https://evil.com',                 'Arbitrary external domain'),
        ('https://attacker.com',             'Generic attacker domain'),
        ('null',                             'Null origin (sandboxed iframe)'),
        (f'https://evil.{host}',             'Subdomain of target'),
        (f'https://{host}.evil.com',         'Target as subdomain of evil'),
        ('https://localhost',                'Localhost'),
        ('http://127.0.0.1',                 'Loopback IP'),
    ]

    vulnerabilities = []
    connector = aiohttp.TCPConnector(ssl=False)

    async def test_one(origin, desc):
        try:
            async with aiohttp.ClientSession(connector=connector) as s:
                async with s.options(
                    url,
                    headers={
                        'Origin': origin,
                        'Access-Control-Request-Method': 'GET',
                        'User-Agent': _UA,
                    },
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    return (
                        origin, desc,
                        resp.headers.get('Access-Control-Allow-Origin', ''),
                        resp.headers.get('Access-Control-Allow-Credentials', ''),
                        resp.headers.get('Access-Control-Allow-Methods', ''),
                    )
        except Exception:
            return (origin, desc, '', '', '')

    results = await asyncio.gather(*[test_one(o, d) for o, d in test_origins])

    result += "🧪 *Test Results:*\n\n"
    for origin, desc, acao, acac, acam in results:
        if not acao:
            result += f"├ `{origin[:40]}`\n│  → No CORS response\n\n"
            continue

        vuln = False
        detail = ""
        if acao == '*':
            vuln, detail = True, "Wildcard — any origin allowed"
        elif acao == origin:
            vuln, detail = True, "Reflects arbitrary origin"
        elif 'null' in acao and origin == 'null':
            vuln, detail = True, "Allows null origin"

        if vuln and acac.lower() == 'true':
            detail += " + credentials=true → CRITICAL"

        if vuln:
            vulnerabilities.append((origin, detail))
            result += f"├ 🚨 `{origin[:40]}`\n"
            result += f"│  ACAO: `{acao}` | Creds: `{acac or 'false'}`\n"
            result += f"│  ⚠️ {detail}\n\n"
        else:
            result += f"├ ✅ `{origin[:40]}`\n│  ACAO: `{acao[:40]}`\n\n"

    result += "━━━━━━━━━━\n"
    if vulnerabilities:
        result += f"🚨 *{len(vulnerabilities)} CORS misconfiguration(s) detected*\n"
        result += "💥 Attackers can make cross-origin requests and read responses.\n"
        if any('CRITICAL' in v[1] for v in vulnerabilities):
            result += "🔴 *CRITICAL: Credentials allowed — session hijacking possible!*\n"
    else:
        result += "✅ *No CORS misconfigurations found*\n"

    return result


_WAF_SIGS = [
    ('Server',               r'cloudflare',       'Cloudflare'),
    ('CF-RAY',               r'.',                 'Cloudflare'),
    ('Server',               r'AkamaiGHost',       'Akamai'),
    ('X-Check-Cacheable',    r'.',                 'Akamai'),
    ('X-Amzn-Trace-Id',      r'.',                 'AWS WAF'),
    ('X-SucuriRequestId',    r'.',                 'Sucuri'),
    ('Server',               r'Incapsula',         'Imperva Incapsula'),
    ('X-Iinfo',              r'.',                 'Imperva Incapsula'),
    ('Set-Cookie',           r'BIGipServer',       'F5 BIG-IP'),
    ('Set-Cookie',           r'TS[0-9a-f]{8}=',   'F5 BIG-IP ASM'),
    ('X-Distil-CS',          r'.',                 'Distil Networks'),
    ('Server',               r'DDoS-Guard',        'DDoS-Guard'),
]

_WAF_BODY_SIGS = {
    'Cloudflare':  r'cloudflare|__cf_chl',
    'Sucuri':      r'Sucuri|sucuri\.net',
    'Akamai':      r'Reference\s+#\d|akamai',
    'Imperva':     r'Incapsula incident',
    'AWS WAF':     r'AWS WAF|Request blocked',
    'ModSecurity': r'ModSecurity|mod_security',
}


async def waf_detect(url: str) -> str:
    """Detect WAF presence and identify vendor"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    result = f"🛡 *WAF Detection:* `{url}`\n\n"
    detected: Set[str] = set()
    connector = aiohttp.TCPConnector(ssl=False)

    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                url,
                headers={'User-Agent': _UA},
                timeout=aiohttp.ClientTimeout(total=8),
                allow_redirects=True
            ) as resp:
                normal_headers = dict(resp.headers)
                normal_status = resp.status

        result += f"📡 *Normal request:* HTTP {normal_status}\n\n"
        result += "🔍 *Header-based detection:*\n"

        for hname, pattern, waf in _WAF_SIGS:
            val = normal_headers.get(hname, '')
            if val and re.search(pattern, val, re.IGNORECASE):
                detected.add(waf)
                result += f"├ ✅ `{hname}` → *{waf}*\n"

        if not detected:
            result += "├ No WAF signatures in normal headers\n"

        # Send a malicious-looking request
        evil_url = url + ("&" if "?" in url else "?") + "id=<script>alert(1)</script>"
        result += "\n🧪 *Attack simulation:*\n"
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    evil_url,
                    headers={'User-Agent': _UA},
                    timeout=aiohttp.ClientTimeout(total=5),
                    allow_redirects=False
                ) as bad_resp:
                    bad_status = bad_resp.status
                    bad_headers = dict(bad_resp.headers)
                    bad_body = await bad_resp.text(errors='ignore')

            if bad_status in (403, 406, 429, 503):
                result += f"├ ⚠️ Request blocked: HTTP {bad_status} — WAF likely active\n"
                for waf_name, pattern in _WAF_BODY_SIGS.items():
                    if re.search(pattern, bad_body, re.IGNORECASE):
                        detected.add(waf_name)
                        result += f"├ ✅ Confirmed via response body: *{waf_name}*\n"
                for hname, pattern, waf in _WAF_SIGS:
                    val = bad_headers.get(hname, '')
                    if val and re.search(pattern, val, re.IGNORECASE):
                        detected.add(waf)
            elif bad_status == normal_status:
                result += f"├ ℹ️ Request not blocked (HTTP {bad_status}) — WAF may be absent\n"
            else:
                result += f"├ ℹ️ Different response: HTTP {bad_status} (normal was {normal_status})\n"
        except asyncio.TimeoutError:
            result += "├ ⚠️ Request timed out — possible WAF blocking\n"

    except Exception as e:
        return result + f"❌ *Error:* `{str(e)}`"

    result += "\n━━━━━━━━━━\n"
    if detected:
        result += f"🛡 *WAF Detected:* {', '.join(detected)}\n"
    else:
        result += "❓ *No WAF definitively detected*\n"
        result += "Site may have no WAF, or uses a custom/unknown solution.\n"

    return result


_HEADER_INFO = {
    'Strict-Transport-Security': ('HSTS',                  True,  'Forces HTTPS, prevents downgrade attacks',                   'Strict-Transport-Security: max-age=31536000; includeSubDomains'),
    'Content-Security-Policy':   ('CSP',                   True,  'Controls resources loaded, prevents XSS',                    'Add a Content-Security-Policy header'),
    'X-Frame-Options':           ('X-Frame-Options',       True,  'Prevents clickjacking',                                      'X-Frame-Options: DENY'),
    'X-Content-Type-Options':    ('X-Content-Type-Options',True,  'Prevents MIME sniffing',                                     'X-Content-Type-Options: nosniff'),
    'Referrer-Policy':           ('Referrer-Policy',       False, 'Controls referrer header sent to other sites',               'Referrer-Policy: strict-origin-when-cross-origin'),
    'Permissions-Policy':        ('Permissions-Policy',    False, 'Controls browser features (camera, mic, etc.)',              'Permissions-Policy: geolocation=(), camera=()'),
    'Server':                    ('Server (disclosure)',   False, 'Reveals server software — should be hidden',                 'Remove or obscure the Server header'),
    'X-Powered-By':              ('X-Powered-By (disclosure)', False, 'Reveals backend tech — should be hidden',               'Remove X-Powered-By header'),
    'Access-Control-Allow-Origin': ('CORS',                False, 'Defines allowed cross-origin requests',                     'Restrict to specific trusted origins only'),
    'Cache-Control':             ('Cache-Control',         False, 'Controls caching — sensitive pages should not be cached',   'Cache-Control: no-store for sensitive pages'),
}


async def header_check(url: str) -> str:
    """Deep HTTP header security analysis with recommendations"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    result = f"📋 *HTTP Header Analysis:* `{url}`\n\n"
    connector = aiohttp.TCPConnector(ssl=False)

    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                url,
                headers={'User-Agent': _UA},
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=True
            ) as resp:
                headers = dict(resp.headers)
                status = resp.status
                final_url = str(resp.url)

        result += f"📡 *Response:* HTTP {status}\n"
        result += f"🔗 *Final URL:* `{final_url[:70]}`\n\n"
        result += "🛡 *Security Header Analysis:*\n\n"

        missing_critical = []
        for hname, (label, is_critical, description, fix) in _HEADER_INFO.items():
            val = headers.get(hname, '')
            if val:
                warn = hname in ('Server', 'X-Powered-By', 'Access-Control-Allow-Origin')
                emoji = "⚠️" if warn else "✅"
                result += f"{emoji} *{label}*\n"
                result += f"├ Value: `{val[:80]}`\n"
                result += f"└ {description}\n\n"
            else:
                if is_critical:
                    missing_critical.append(label)
                    result += f"❌ *{label}* — MISSING (important)\n"
                else:
                    result += f"⚠️ *{label}* — not set\n"
                result += f"└ Recommendation: {fix}\n\n"

        result += "📊 *All Response Headers:*\n"
        for key, val in headers.items():
            result += f"├ `{key}`: `{val[:60]}`\n"

        if missing_critical:
            result += f"\n🔴 *Missing Critical Headers:* {', '.join(missing_critical)}\n"

    except Exception as e:
        result += f"❌ *Error:* `{str(e)}`"

    return result


async def robots_check(url: str) -> str:
    """Fetch and analyze robots.txt and sitemap.xml"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    result = f"🤖 *Robots.txt & Sitemap:* `{base}`\n\n"

    connector = aiohttp.TCPConnector(ssl=False)
    interesting_kw = ['admin', 'api', 'backup', 'config', 'dev', 'debug',
                      'private', 'secret', 'internal', 'staging', 'test', '.env', 'wp-']

    async with aiohttp.ClientSession(connector=connector, headers={'User-Agent': _UA}) as session:

        # robots.txt
        result += "📄 *robots.txt:*\n"
        try:
            async with session.get(f'{base}/robots.txt', timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    robots = await resp.text(errors='ignore')
                    disallowed = re.findall(r'Disallow:\s*(.+)', robots, re.IGNORECASE)
                    allowed    = re.findall(r'Allow:\s*(.+)',    robots, re.IGNORECASE)
                    sitemaps   = re.findall(r'Sitemap:\s*(.+)',  robots, re.IGNORECASE)

                    result += f"├ Status: ✅ Found ({len(robots)} bytes)\n"
                    result += f"├ Disallowed: {len(disallowed)} paths\n"
                    result += f"├ Allowed: {len(allowed)} paths\n"
                    result += f"└ Sitemaps referenced: {len(sitemaps)}\n\n"

                    if disallowed:
                        result += "🚫 *Disallowed Paths:*\n"
                        for p in disallowed[:20]:
                            p = p.strip()
                            if p and p != '/':
                                result += f"├ `{p}`\n"
                        result += "\n"

                    interesting = [p.strip() for p in disallowed if any(kw in p.lower() for kw in interesting_kw)]
                    if interesting:
                        result += "🎯 *Interesting Disallowed Paths:*\n"
                        for p in interesting[:10]:
                            result += f"├ ⚠️ `{p}`\n"
                        result += "\n"

                    if sitemaps:
                        result += "🗺 *Sitemaps:*\n"
                        for sm in sitemaps[:5]:
                            result += f"├ `{sm.strip()}`\n"
                        result += "\n"
                else:
                    result += f"├ HTTP {resp.status} — not found\n\n"
        except Exception as e:
            result += f"├ Error: `{str(e)[:60]}`\n\n"

        # sitemap.xml
        result += "🗺 *sitemap.xml:*\n"
        found_sitemap = False
        for path in ['/sitemap.xml', '/sitemap_index.xml', '/sitemap-index.xml']:
            try:
                async with session.get(f'{base}{path}', timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        content = await resp.text(errors='ignore')
                        urls_in_sitemap = re.findall(r'<loc>(.*?)</loc>', content, re.IGNORECASE)
                        result += f"├ Found at: `{path}`\n"
                        result += f"├ URLs listed: {len(urls_in_sitemap)}\n\n"
                        result += "*Sample URLs:*\n"
                        for u in urls_in_sitemap[:10]:
                            result += f"├ `{u.strip()[:80]}`\n"
                        if len(urls_in_sitemap) > 10:
                            result += f"└ ...and {len(urls_in_sitemap) - 10} more\n"
                        found_sitemap = True
                        break
            except Exception:
                pass

        if not found_sitemap:
            result += "├ No sitemap found at standard locations\n"

    return result
