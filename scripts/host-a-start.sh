#!/bin/sh
set -e

ip addr add 10.10.1.10/24 dev eth1
ip route add 10.10.2.0/24 via 10.10.1.1

echo "[HOST-A] 10.10.1.10/24 configured"

exec sleep infinity
