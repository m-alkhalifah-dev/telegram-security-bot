#!/bin/bash
# ============================================
# سكربت تثبيت بوت التلقرام الأمني
# Telegram Security Bot - Setup Script
# ============================================

echo "🤖 جاري تثبيت بوت الأمان..."
echo "========================================"

# تحديث النظام
echo "📦 تحديث النظام..."
sudo apt update && sudo apt upgrade -y

# تثبيت الأدوات المطلوبة
echo "🔧 تثبيت الأدوات..."
sudo apt install -y python3 python3-pip nmap arp-scan net-tools

# تثبيت مكتبات بايثون
echo "🐍 تثبيت مكتبات بايثون..."
pip3 install -r requirements.txt --break-system-packages

echo ""
echo "========================================"
echo "✅ تم التثبيت بنجاح!"
echo ""
echo "📝 الخطوات التالية:"
echo "1. روح @BotFather بتلقرام واسوي بوت جديد"
echo "2. انسخ التوكن وحطه في config.py"
echo "3. روح @userinfobot واعرف الـ Chat ID حقك"
echo "4. حط الـ Chat ID في config.py"
echo "5. شغّل البوت: python3 bot.py"
echo ""
echo "🔒 لتشغيل البوت تلقائي مع كل ريستارت:"
echo "   sudo cp security-bot.service /etc/systemd/system/"
echo "   sudo systemctl enable security-bot"
echo "   sudo systemctl start security-bot"
echo "========================================"
