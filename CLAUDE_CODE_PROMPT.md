## Claude Code Prompt - Copy and paste this to Claude Code

---

I have a Telegram security bot on my Raspberry Pi 5 at `/home/pi/Desktop/telegram-security-bot/`. Read the CLAUDE.md file first to understand the project.

I want you to add these new features to the bot. Follow the existing code patterns and architecture:

### 1. Website Vulnerability Scanner (/vulnscan [URL])
Add a comprehensive website security scanner that checks for:
- Missing security headers (X-Frame-Options, CSP, HSTS, etc.) with explanations of each risk
- Open sensitive paths (/admin, /login, /.env, /.git, /wp-admin, /phpmyadmin, /backup, etc.)
- Server information disclosure (version leaks in headers)
- Cookie security (HttpOnly, Secure, SameSite flags)
- CORS misconfiguration check
- Directory listing detection
- HTTP methods allowed (check for dangerous ones like PUT, DELETE, TRACE)
- Clickjacking vulnerability check
- SSL/TLS issues (weak ciphers, expired cert, etc.)
- Give a final security score (A to F grade) with summary of findings
- Output a clean formatted Telegram report

### 2. Subdomain Finder (/subdomains [domain])
- Use crt.sh API to find subdomains
- Show IP for each subdomain
- Check which ones are alive (respond to HTTP)

### 3. Technology Detector (/techdetect [URL])
- Detect web technologies (CMS, frameworks, servers, programming languages)
- Check response headers, meta tags, and common fingerprints
- Detect: WordPress, Joomla, Drupal, React, Angular, Vue, Laravel, Django, nginx, Apache, IIS, PHP, Node.js, etc.

### 4. Email Security Check (/emailsec [domain])
- Check SPF record
- Check DKIM
- Check DMARC policy
- Rate the email security

### 5. Speed Test (/speedtest)
- Run internet speed test on the Pi
- Show download, upload, and ping

### 6. Daily Auto Report (/dailyreport on/off)
- Automatic daily summary sent at a configurable time
- Include: system health, network changes, any alerts from the day

### 7. Shodan-style IP Lookup (/iplookup [IP])
- Use free APIs (ip-api, ipinfo, abuseipdb free tier if available)
- Show: location, ISP, open ports if available, abuse reports, threat score

### 8. Password Strength Checker (/passcheck [password])
- Check password strength
- Check length, complexity, common patterns
- Check against common password lists
- Give suggestions to improve

### 9. Hash Lookup (/hash [hash_value])
- Identify hash type (MD5, SHA1, SHA256, etc.)
- Try to look it up in free hash databases

### 10. Network Bandwidth Monitor (/bandwidth)
- Show current network usage (upload/download rates)
- Show bandwidth usage over time

### Rules:
- Follow the CLAUDE.md conventions exactly
- All strings in ENGLISH only (no Arabic - terminal can't render it)
- Add new dependencies to requirements.txt
- Register all new commands in bot.py (handler + BotCommand list + start/help messages)
- Use async functions, proper error handling, and Telegram Markdown formatting
- Create new module files as needed (e.g., modules/vulnscan.py, modules/tools.py)
- Keep the @authorized_only decorator on all commands
- Test that imports work correctly

---
