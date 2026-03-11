"""
موديول النظام - System Module
يعطيك معلومات عن حالة الراسبيري باي
"""

import psutil
import platform
import datetime
import socket


def get_system_status() -> str:
    """يرجع حالة النظام كاملة"""

    # معلومات CPU
    cpu_percent = psutil.cpu_percent(interval=1)
    cpu_count = psutil.cpu_count()

    # معلومات الرام
    ram = psutil.virtual_memory()
    ram_used = ram.used / (1024 ** 3)  # تحويل لـ GB
    ram_total = ram.total / (1024 ** 3)
    ram_percent = ram.percent

    # معلومات التخزين
    disk = psutil.disk_usage('/')
    disk_used = disk.used / (1024 ** 3)
    disk_total = disk.total / (1024 ** 3)
    disk_percent = disk.percent

    # الحرارة (خاص بالراسبيري باي)
    temp = get_cpu_temperature()

    # مدة التشغيل
    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.datetime.now() - boot_time

    # اسم الجهاز و IP المحلي
    hostname = socket.gethostname()
    local_ip = get_local_ip()

    status = f"""
🖥 *حالة النظام - System Status*

🏷 *الجهاز:* `{hostname}`
🌐 *IP المحلي:* `{local_ip}`
💻 *النظام:* `{platform.system()} {platform.release()}`

📊 *المعالج (CPU):*
├ الاستخدام: {cpu_percent}%
├ عدد الأنوية: {cpu_count}
└ الحرارة: {temp}

🧠 *الذاكرة (RAM):*
├ المستخدم: {ram_used:.1f} GB / {ram_total:.1f} GB
└ النسبة: {ram_percent}%

💾 *التخزين:*
├ المستخدم: {disk_used:.1f} GB / {disk_total:.1f} GB
└ النسبة: {disk_percent}%

⏱ *مدة التشغيل:* {format_uptime(uptime)}
"""
    return status


def get_cpu_temperature() -> str:
    """يقرأ حرارة المعالج"""
    try:
        temps = psutil.sensors_temperatures()
        if 'cpu_thermal' in temps:
            temp = temps['cpu_thermal'][0].current
            emoji = "🟢" if temp < 60 else "🟡" if temp < 75 else "🔴"
            return f"{emoji} {temp:.1f}°C"
        # لو ما لقى cpu_thermal، يدور على أي حساس
        for name, entries in temps.items():
            if entries:
                temp = entries[0].current
                emoji = "🟢" if temp < 60 else "🟡" if temp < 75 else "🔴"
                return f"{emoji} {temp:.1f}°C"
    except Exception:
        pass

    # محاولة قراءة مباشرة من ملف الراسبيري باي
    try:
        with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
            temp = int(f.read().strip()) / 1000
            emoji = "🟢" if temp < 60 else "🟡" if temp < 75 else "🔴"
            return f"{emoji} {temp:.1f}°C"
    except Exception:
        return "⚪ غير متوفر"


def get_local_ip() -> str:
    """يرجع الـ IP المحلي"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "غير متوفر"


def format_uptime(uptime: datetime.timedelta) -> str:
    """ينسّق مدة التشغيل بشكل مقروء"""
    days = uptime.days
    hours, remainder = divmod(uptime.seconds, 3600)
    minutes, _ = divmod(remainder, 60)

    parts = []
    if days > 0:
        parts.append(f"{days} يوم")
    if hours > 0:
        parts.append(f"{hours} ساعة")
    if minutes > 0:
        parts.append(f"{minutes} دقيقة")

    return " و ".join(parts) if parts else "أقل من دقيقة"


def get_top_processes(n: int = 5) -> str:
    """يرجع أعلى العمليات استهلاكاً"""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            info = proc.info
            processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # ترتيب حسب استهلاك CPU
    processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
    top = processes[:n]

    result = "📋 *أعلى العمليات استهلاكاً:*\n\n"
    for i, proc in enumerate(top, 1):
        name = proc.get('name', 'Unknown')
        cpu = proc.get('cpu_percent', 0)
        mem = proc.get('memory_percent', 0)
        pid = proc.get('pid', 0)
        result += f"{i}. `{name}` (PID: {pid})\n"
        result += f"   CPU: {cpu:.1f}% | RAM: {mem:.1f}%\n"

    return result
