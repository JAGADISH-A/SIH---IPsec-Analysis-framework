#!/bin/sh
set -e

ip addr add 10.10.2.10/24 dev eth1
ip route add 10.10.1.0/24 via 10.10.2.1

echo "[HOST-B] 10.10.2.10/24 configured"

exec sleep infinity
