"""
موديول مراقبة الشبكة - Network Monitor Module
يراقب الأجهزة المتصلة بشبكتك ويرسل تنبيهات
"""

import json
import os
import asyncio
import subprocess
import logging
from datetime import datetime
from typing import Dict, Optional

from config import KNOWN_DEVICES_FILE, NETWORK_RANGE, SCAN_INTERVAL

logger = logging.getLogger(__name__)


class NetworkMonitor:
    """يراقب الشبكة المحلية ويكشف الأجهزة الجديدة"""

    def __init__(self):
        self.known_devices: Dict[str, dict] = {}
        self.current_devices: Dict[str, dict] = {}
        self.is_running = False
        self._load_known_devices()

    def _load_known_devices(self):
        """يحمّل الأجهزة المعروفة من الملف"""
        try:
            if os.path.exists(KNOWN_DEVICES_FILE):
                with open(KNOWN_DEVICES_FILE, 'r') as f:
                    self.known_devices = json.load(f)
                logger.info(f"تم تحميل {len(self.known_devices)} جهاز معروف")
        except Exception as e:
            logger.error(f"خطأ في تحميل الأجهزة: {e}")
            self.known_devices = {}

    def _save_known_devices(self):
        """يحفظ الأجهزة المعروفة في الملف"""
        try:
            os.makedirs(os.path.dirname(KNOWN_DEVICES_FILE), exist_ok=True)
            with open(KNOWN_DEVICES_FILE, 'w') as f:
                json.dump(self.known_devices, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"خطأ في حفظ الأجهزة: {e}")

    async def scan_network(self) -> Dict[str, dict]:
        """يسوي ARP scan للشبكة المحلية"""
        devices = {}

        try:
            # استخدام arp-scan لو موجود
            process = await asyncio.create_subprocess_exec(
                'sudo', 'arp-scan', '--localnet', '--retry=2',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                for line in stdout.decode().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 3 and '.' in parts[0]:
                        ip = parts[0].strip()
                        mac = parts[1].strip().upper()
                        vendor = parts[2].strip() if len(parts) > 2 else "Unknown"
                        devices[mac] = {
                            'ip': ip,
                            'mac': mac,
                            'vendor': vendor,
                            'last_seen': datetime.now().isoformat()
                        }
            else:
                # فولباك: استخدام nmap
                devices = await self._nmap_scan()

        except FileNotFoundError:
            # لو arp-scan مو موجود، يستخدم nmap
            devices = await self._nmap_scan()
        except Exception as e:
            logger.error(f"خطأ في السكان: {e}")
            # فولباك أخير: استخدام arp table
            devices = await self._arp_table_scan()

        self.current_devices = devices
        return devices

    async def _nmap_scan(self) -> Dict[str, dict]:
        """سكان باستخدام nmap"""
        devices = {}
        try:
            process = await asyncio.create_subprocess_exec(
                'nmap', '-sn', NETWORK_RANGE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()

            current_ip = None
            for line in stdout.decode().split('\n'):
                if 'Nmap scan report for' in line:
                    parts = line.split()
                    current_ip = parts[-1].strip('()')
                elif 'MAC Address:' in line and current_ip:
                    parts = line.split()
                    mac = parts[2].upper()
                    vendor = ' '.join(parts[3:]).strip('()')
                    devices[mac] = {
                        'ip': current_ip,
                        'mac': mac,
                        'vendor': vendor,
                        'last_seen': datetime.now().isoformat()
                    }
                    current_ip = None
        except Exception as e:
            logger.error(f"خطأ في nmap scan: {e}")
        return devices

    async def _arp_table_scan(self) -> Dict[str, dict]:
        """سكان باستخدام جدول ARP (فولباك أخير)"""
        devices = {}
        try:
            # أولاً نسوي ping sweep
            process = await asyncio.create_subprocess_shell(
                f'for i in $(seq 1 254); do ping -c 1 -W 1 {NETWORK_RANGE.rsplit(".", 1)[0]}.$i &>/dev/null & done; wait',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()

            # بعدها نقرأ جدول ARP
            process = await asyncio.create_subprocess_exec(
                'arp', '-a',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()

            for line in stdout.decode().split('\n'):
                if 'ether' in line or ':' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if ':' in part and len(part) == 17:  # MAC address
                            mac = part.upper()
                            # البحث عن IP
                            ip = "Unknown"
                            for p in parts:
                                if '.' in p and p[0].isdigit():
                                    ip = p.strip('()')
                                    break
                            devices[mac] = {
                                'ip': ip,
                                'mac': mac,
                                'vendor': 'Unknown',
                                'last_seen': datetime.now().isoformat()
                            }
        except Exception as e:
            logger.error(f"خطأ في ARP scan: {e}")
        return devices

    async def check_new_devices(self) -> list:
        """يفحص إذا فيه أجهزة جديدة"""
        devices = await self.scan_network()
        new_devices = []

        for mac, info in devices.items():
            if mac not in self.known_devices:
                new_devices.append(info)

        return new_devices

    def approve_device(self, mac: str, name: str = "") -> bool:
        """يضيف جهاز للقائمة المعروفة"""
        mac = mac.upper()
        if mac in self.current_devices:
            device = self.current_devices[mac].copy()
            device['name'] = name
            device['approved_at'] = datetime.now().isoformat()
            self.known_devices[mac] = device
            self._save_known_devices()
            return True
        return False

    def approve_all_current(self) -> int:
        """يضيف كل الأجهزة الحالية للقائمة المعروفة"""
        count = 0
        for mac, info in self.current_devices.items():
            if mac not in self.known_devices:
                device = info.copy()
                device['approved_at'] = datetime.now().isoformat()
                self.known_devices[mac] = device
                count += 1
        self._save_known_devices()
        return count

    def remove_device(self, mac: str) -> bool:
        """يشيل جهاز من القائمة المعروفة"""
        mac = mac.upper()
        if mac in self.known_devices:
            del self.known_devices[mac]
            self._save_known_devices()
            return True
        return False

    def get_devices_list(self) -> str:
        """يرجع قائمة الأجهزة المتصلة حالياً"""
        if not self.current_devices:
            return "📡 لم يتم سكان الشبكة بعد. استخدم /scan أولاً"

        result = f"📡 *الأجهزة المتصلة بالشبكة ({len(self.current_devices)}):*\n\n"

        for mac, info in self.current_devices.items():
            is_known = mac in self.known_devices
            name = self.known_devices.get(mac, {}).get('name', '')
            status = "✅" if is_known else "⚠️ جديد"

            result += f"{status} *{name or info.get('vendor', 'Unknown')}*\n"
            result += f"├ IP: `{info['ip']}`\n"
            result += f"├ MAC: `{info['mac']}`\n"
            result += f"└ الشركة: {info.get('vendor', 'Unknown')}\n\n"

        known_count = sum(1 for mac in self.current_devices if mac in self.known_devices)
        unknown_count = len(self.current_devices) - known_count

        result += f"📊 *ملخص:* {known_count} معروف | {unknown_count} جديد"
        return result

    def format_alert(self, device: dict) -> str:
        """ينسّق تنبيه جهاز جديد"""
        return f"""
🚨 *تنبيه: جهاز جديد على الشبكة!*

📡 *IP:* `{device['ip']}`
🔑 *MAC:* `{device['mac']}`
🏭 *الشركة:* {device.get('vendor', 'Unknown')}
🕐 *الوقت:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

استخدم `/approve {device['mac']}` لإضافته للأجهزة المعروفة
أو `/approve_all` لإضافة كل الأجهزة الحالية
"""
