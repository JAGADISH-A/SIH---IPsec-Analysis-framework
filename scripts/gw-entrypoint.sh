#!/bin/sh
set -eu

echo "[IPsec] Starting charon..."
/usr/local/libexec/ipsec/charon &

echo "[IPsec] Waiting for VICI to become ready..."

i=0
while true; do
    if swanctl --list-conns >/dev/null 2>&1; then
        break
    fi

    i=$((i + 1))

    if [ "$i" -ge 30 ]; then
        echo "[IPsec] ERROR: VICI did not become ready"
        exit 1
    fi

    sleep 1
done

echo "[IPsec] VICI is ready"

echo "[IPsec] Loading StrongSwan configuration..."
swanctl --load-all

echo "[IPsec] StrongSwan ready"

exec sleep infinity
