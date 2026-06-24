#!/bin/bash
set -e
cd /opt/juice-shop
node build/app.js > /var/log/juice-shop.log 2>&1 &
JUICESHOP_PID=$!
echo "[entrypoint] juice-shop pid=$JUICESHOP_PID"
# wait for juice-shop to be ready
for i in $(seq 1 60); do
    if curl -s -f http://localhost:3000/ > /dev/null 2>&1; then
        echo "[entrypoint] juice-shop ready after ${i}s"
        break
    fi
    sleep 1
done
tail -f /dev/null
