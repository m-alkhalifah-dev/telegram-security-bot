#!/bin/bash
case "$1" in
  start)
    echo "Starting bot..."
    cd /home/pi/Desktop/telegram-security-bot
    python3 bot.py &
    echo $! > /tmp/secbot.pid
    echo "Starting dashboard..."
    python3 dashboard.py &
    echo $! > /tmp/secdash.pid
    echo "Both running!"
    ;;
  stop)
    kill $(cat /tmp/secbot.pid) 2>/dev/null
    kill $(cat /tmp/secdash.pid) 2>/dev/null
    echo "Stopped."
    ;;
  status)
    ps aux | grep -E "bot.py|dashboard.py" | grep -v grep
    ;;
  restart)
    $0 stop
    sleep 2
    $0 start
    ;;
  *)
    echo "Usage: ./run.sh start|stop|status|restart"
    ;;
esac
