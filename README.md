# 🤖 بوت التلقرام الأمني - Telegram Security Bot

بوت تلقرام يشتغل على الراسبيري باي، يساعدك في مراقبة شبكتك وفحص المواقع والأجهزة.

---

## 📋 المميزات

### مراقبة النظام
- حالة CPU, RAM, حرارة, تخزين
- أعلى العمليات استهلاكاً
- IP العام مع معلومات جغرافية

### أدوات الشبكة
- Ping لأي هوست
- فحص البورتات المفتوحة
- فحص حالة المواقع + الهيدرز الأمنية
- فحص شهادات SSL

### مراقبة الشبكة المحلية
- اكتشاف الأجهزة المتصلة
- تنبيهات فورية عند دخول جهاز جديد
- إدارة قائمة الأجهزة المعروفة

### تحليل الدومينات
- WHOIS lookup
- سجلات DNS كاملة
- موقع جغرافي لأي IP
- تقارير شاملة

---

## 🚀 التثبيت

### 1. انسخ المشروع على الراسبيري باي
```bash
# انسخ المجلد كامل على الراسبيري باي
scp -r telegram-security-bot/ pi@RASPBERRY_PI_IP:/home/pi/
```

### 2. شغّل سكربت التثبيت
```bash
cd telegram-security-bot
chmod +x setup.sh
./setup.sh
```

### 3. اسوي بوت جديد بتلقرام
1. روح **@BotFather** بتلقرام
2. ارسل `/newbot`
3. اختار اسم للبوت
4. انسخ التوكن

### 4. اعرف الـ Chat ID حقك
1. روح **@userinfobot** بتلقرام
2. ارسل أي رسالة
3. انسخ الرقم (Chat ID)

### 5. عدّل الإعدادات
```bash
nano config.py
```
- حط التوكن في `BOT_TOKEN`
- حط الـ Chat ID في `ALLOWED_CHAT_IDS`
- عدّل `NETWORK_RANGE` حسب شبكتك

### 6. شغّل البوت
```bash
python3 bot.py
```

---

## 🔄 تشغيل تلقائي مع كل ريستارت

```bash
# عدّل المسار في الملف لو لازم
nano security-bot.service

# انسخ الملف وفعّله
sudo cp security-bot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable security-bot
sudo systemctl start security-bot

# تأكد إنه شغال
sudo systemctl status security-bot
```

---

## 📱 الأوامر المتاحة

| الأمر | الوصف |
|-------|-------|
| `/start` | رسالة ترحيب |
| `/help` | المساعدة |
| `/status` | حالة النظام |
| `/processes` | أعلى العمليات |
| `/myip` | IP العام |
| `/ping [host]` | عمل Ping |
| `/portscan [IP]` | فحص البورتات |
| `/checksite [URL]` | فحص موقع |
| `/ssl [domain]` | فحص SSL |
| `/scan` | سكان الشبكة |
| `/devices` | الأجهزة المتصلة |
| `/approve [MAC]` | تأكيد جهاز |
| `/approve_all` | تأكيد كل الأجهزة |
| `/monitor` | تشغيل/إيقاف المراقبة |
| `/whois [domain]` | معلومات WHOIS |
| `/dns [domain]` | سجلات DNS |
| `/geoip [IP]` | موقع جغرافي |
| `/report [domain]` | تقرير شامل |

---

## ⚠️ تنبيهات أمنية

- **لا تشارك التوكن** مع أي شخص
- **لا تسوي سكان** لشبكات أو أجهزة غير شبكتك
- البوت محمي بالـ **Chat ID** — ما يرد إلا عليك أنت
- استخدم الأدوات لأغراض **تعليمية وحماية شبكتك فقط**

---

## 📁 هيكل المشروع

```
telegram-security-bot/
├── bot.py                  # الملف الرئيسي
├── config.py               # الإعدادات
├── requirements.txt        # المكتبات المطلوبة
├── setup.sh                # سكربت التثبيت
├── security-bot.service    # ملف التشغيل التلقائي
├── README.md               # هذا الملف
├── modules/
│   ├── __init__.py
│   ├── system.py           # أوامر النظام
│   ├── network.py          # أوامر الشبكة
│   ├── monitor.py          # مراقبة الشبكة
│   └── analysis.py         # أدوات التحليل
└── data/
    └── known_devices.json  # الأجهزة المعروفة
```
