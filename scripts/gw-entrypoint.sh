#!/bin/sh
set -eu

echo "[IPsec] Starting charon..."
/usr/local/libexec/ipsec/charon &

echo "[IPsec] Waiting for VICI socket..."

i=0
while [ ! -S /var/run/charon.vici ]; do
    i=$((i + 1))

    if [ "$i" -ge 30 ]; then
        echo "[IPsec] ERROR: VICI socket did not become ready"
        exit 1
    fi

    sleep 1
done

echo "[IPsec] VICI socket ready"

echo "[IPsec] Loading StrongSwan configuration..."
swanctl --load-all

echo "[IPsec] StrongSwan ready"

exec sleep infinity
