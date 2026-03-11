# ============================================================
# config.example.py — copy this to config.py and fill in your values
# cp config.example.py config.py
# ============================================================

BOT_VERSION = "2.0.0"

# ── Telegram ──────────────────────────────────────────────────────────────────
# Get your token from @BotFather on Telegram
BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"

# Your personal Telegram Chat ID (from @userinfobot)
ALLOWED_CHAT_IDS = [123456789]

# ── Network monitoring ────────────────────────────────────────────────────────
SCAN_INTERVAL    = 300             # Seconds between auto-scans (300 = 5 min)
NETWORK_INTERFACE = "wlan0"        # wlan0 = WiFi, eth0 = Ethernet
NETWORK_RANGE    = "192.168.1.0/24"  # Your local subnet

# ── File paths ────────────────────────────────────────────────────────────────
KNOWN_DEVICES_FILE = "data/known_devices.json"
DB_FILE            = "data/history.db"

# ── AbuseIPDB (optional) ──────────────────────────────────────────────────────
# Free API key from https://www.abuseipdb.com/
# Leave empty to use the ip-api.com fallback
ABUSEIPDB_API_KEY = ""

# ── Web Dashboard ─────────────────────────────────────────────────────────────
DASHBOARD_ENABLED    = True
DASHBOARD_HOST       = "0.0.0.0"   # Listen on all interfaces
DASHBOARD_PORT       = 5000
DASHBOARD_USER       = "admin"
DASHBOARD_PASS       = "changeme"  # Change this!
DASHBOARD_SECRET_KEY = "change-this-to-a-random-string-before-production"
