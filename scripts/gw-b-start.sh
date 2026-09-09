#!/bin/sh

set -e

echo "[GW-B] Starting charon..."

/usr/local/libexec/ipsec/charon &

sleep 2

echo "[GW-B] Loading StrongSwan configuration..."

swanctl --load-all

echo "[GW-B] Ready."

exec sleep infinity
