# CLAUDE.md - Telegram Security Bot

## Project Overview
This is a Telegram security bot running on Raspberry Pi 5 (8GB RAM, Raspberry Pi OS).
The bot provides cybersecurity tools via Telegram commands. It's owned by Mohammed, a networking & security student.

## Project Location
`/home/pi/Desktop/telegram-security-bot/`

## Tech Stack
- Python 3 with python-telegram-bot v20.7
- asyncio-based architecture
- Runs on Raspberry Pi 5 via systemd service
- Libraries: psutil, python-nmap, scapy, aiohttp, python-whois, dnspython

## Project Structure
```
telegram-security-bot/
├── bot.py                  # Main bot file - all command handlers registered here
├── config.py               # BOT_TOKEN, ALLOWED_CHAT_IDS, network settings
├── requirements.txt        # Python dependencies
├── setup.sh                # Installation script
├── security-bot.service    # systemd service file
├── modules/
│   ├── __init__.py
│   ├── system.py           # System monitoring (CPU, RAM, temp, processes)
│   ├── network.py          # Network tools (ping, portscan, checksite, ssl, myip)
│   ├── monitor.py          # Network monitor (ARP scan, device tracking, alerts)
│   └── analysis.py         # Domain analysis (whois, dns, geoip, reverse dns)
└── data/
    └── known_devices.json  # Known devices database
```

## Architecture Pattern
- Each module in `modules/` contains async functions that return formatted Markdown strings
- `bot.py` imports these functions and wraps them in command handlers
- All handlers use `@authorized_only` decorator for security
- NetworkMonitor is a class with state (known devices, current devices)
- Background monitoring runs via asyncio.create_task()

## How to Add a New Command
1. Create the function in the appropriate module (or create a new module)
2. Import it in `bot.py`
3. Create a command handler function with `@authorized_only` decorator
4. Register it with `app.add_handler(CommandHandler("name", handler_func))`
5. Add it to the BotCommand list in `post_init()` function
6. Add it to the /start and /help messages

## Coding Conventions
- All functions are async
- Return formatted Telegram Markdown strings
- Use emojis for visual feedback
- Comments in English (terminal doesn't render Arabic well)
- Error handling with try/except in every function
- Loading messages before long operations ("Processing..." type messages)

## Config Notes
- BOT_TOKEN and ALLOWED_CHAT_IDS are in config.py
- NETWORK_RANGE should match the local network (default: 192.168.1.0/24)
- Bot only responds to whitelisted Chat IDs

## Important
- Keep all comments and strings in ENGLISH (Arabic breaks in the Pi terminal)
- Use Telegram Markdown formatting (*bold*, `code`, etc.)
- Always add proper error handling
- Test each command independently
- Add new pip packages to requirements.txt
- Some network commands need sudo (arp-scan, nmap)

## Current Commands
/start, /help, /status, /processes, /myip, /ping, /portscan, 
/checksite, /ssl, /scan, /devices, /approve, /approve_all, 
/monitor, /whois, /dns, /geoip, /report
