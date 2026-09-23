#!/bin/sh
set -eu

echo "[IPsec] Starting charon..."
/usr/lib/ipsec/charon &

echo "[IPsec] Waiting for VICI..."

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

# Observation lifecycle: start the eBPF/XDP packet observer on the IPsec link
# (eth1).  The binary is staged into the image by the transport Dockerfile.
# Monitoring must never block IPsec startup, hence a soft failure path.
if command -v xdp_monitor >/dev/null 2>&1; then
    xdp_monitor eth1 --json > /var/log/xdp_monitor.jsonl 2> /var/log/xdp_monitor.err &
    sleep 1
    if kill -0 "$!" 2>/dev/null; then
        echo "[IPsec] xdp_monitor started (pid $!; generic/SKB XDP on eth1)"
    else
        echo "[IPsec] WARNING: xdp_monitor exited immediately; see /var/log/xdp_monitor.err"
    fi
else
    echo "[IPsec] WARNING: xdp_monitor not installed in this image"
fi

exec sleep infinity
