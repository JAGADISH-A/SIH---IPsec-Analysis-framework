#!/bin/sh

set -e

echo "[GW-A] Starting charon..."

/usr/local/libexec/ipsec/charon &

sleep 2

echo "[GW-A] Loading StrongSwan configuration..."

swanctl --load-all

echo "[GW-A] Ready."

exec sleep infinity
