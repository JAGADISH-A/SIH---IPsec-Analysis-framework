#!/usr/bin/env bash
# ==========================================================================
# VPN Testbed - Topology Setup
# SIH26160 - AI-Powered IPsec VPN Protocol Analyzer (NTRO)
#
# Builds: LAN-A -- GW-A ===IPsec=== GW-B -- LAN-B
#
# Run inside the Ubuntu Server VM (not on your host desktop).
# Requires: bash, iproute2 (both installed by default on Ubuntu Server)
#
# Usage:
#   chmod +x setup_topology.sh
#   sudo ./setup_topology.sh
# ==========================================================================
set -euo pipefail

# Must run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Run this with sudo."
    exit 1
fi

echo "=== Cleaning up any previous topology first ==="
for ns in lan-a gw-a gw-b lan-b; do
    ip netns del "$ns" 2>/dev/null || true
done

echo "=== Creating namespaces ==="
ip netns add lan-a
ip netns add gw-a
ip netns add gw-b
ip netns add lan-b

echo "=== Bringing up loopback in each namespace ==="
for ns in lan-a gw-a gw-b lan-b; do
    ip netns exec "$ns" ip link set lo up
done

# --------------------------------------------------------------------------
# Link 1: lan-a <-> gw-a   (10.10.1.0/24, IPv6: fd00:1::/64)
# --------------------------------------------------------------------------
echo "=== Wiring lan-a <-> gw-a ==="
ip link add veth-lanA-h type veth peer name veth-lanA-g
ip link set veth-lanA-h netns lan-a
ip link set veth-lanA-g netns gw-a

ip netns exec lan-a ip addr add 10.10.1.10/24 dev veth-lanA-h
ip netns exec lan-a ip -6 addr add fd00:1::10/64 dev veth-lanA-h
ip netns exec lan-a ip link set veth-lanA-h up

ip netns exec gw-a ip addr add 10.10.1.1/24 dev veth-lanA-g
ip netns exec gw-a ip -6 addr add fd00:1::1/64 dev veth-lanA-g
ip netns exec gw-a ip link set veth-lanA-g up

# lan-a default route via gw-a
ip netns exec lan-a ip route add default via 10.10.1.1
ip netns exec lan-a ip -6 route add default via fd00:1::1

# --------------------------------------------------------------------------
# Link 2: gw-a <-> gw-b   ("WAN" / untrusted link, 192.168.50.0/30, IPv6: fd00:50::/64)
# --------------------------------------------------------------------------
echo "=== Wiring gw-a <-> gw-b (simulated WAN) ==="
ip link add veth-wanA type veth peer name veth-wanB
ip link set veth-wanA netns gw-a
ip link set veth-wanB netns gw-b

ip netns exec gw-a ip addr add 192.168.50.1/30 dev veth-wanA
ip netns exec gw-a ip -6 addr add fd00:50::1/64 dev veth-wanA
ip netns exec gw-a ip link set veth-wanA up

ip netns exec gw-b ip addr add 192.168.50.2/30 dev veth-wanB
ip netns exec gw-b ip -6 addr add fd00:50::2/64 dev veth-wanB
ip netns exec gw-b ip link set veth-wanB up

# --------------------------------------------------------------------------
# Link 3: gw-b <-> lan-b   (10.10.2.0/24, IPv6: fd00:2::/64)
# --------------------------------------------------------------------------
echo "=== Wiring gw-b <-> lan-b ==="
ip link add veth-lanB-h type veth peer name veth-lanB-g
ip link set veth-lanB-h netns lan-b
ip link set veth-lanB-g netns gw-b

ip netns exec lan-b ip addr add 10.10.2.10/24 dev veth-lanB-h
ip netns exec lan-b ip -6 addr add fd00:2::10/64 dev veth-lanB-h
ip netns exec lan-b ip link set veth-lanB-h up

ip netns exec gw-b ip addr add 10.10.2.1/24 dev veth-lanB-g
ip netns exec gw-b ip -6 addr add fd00:2::1/64 dev veth-lanB-g
ip netns exec gw-b ip link set veth-lanB-g up

# lan-b default route via gw-b
ip netns exec lan-b ip route add default via 10.10.2.1
ip netns exec lan-b ip -6 route add default via fd00:2::1

# --------------------------------------------------------------------------
# Gateway routing: each gateway needs a route to the OTHER LAN via the WAN link.
# This is the "plaintext" path — IPsec policies (added later by strongSwan)
# intercept and encrypt traffic matching these routes.
# --------------------------------------------------------------------------
echo "=== Adding gateway cross-routes ==="
ip netns exec gw-a ip route add 10.10.2.0/24 via 192.168.50.2
ip netns exec gw-a ip -6 route add fd00:2::/64 via fd00:50::2

ip netns exec gw-b ip route add 10.10.1.0/24 via 192.168.50.1
ip netns exec gw-b ip -6 route add fd00:1::/64 via fd00:50::1

# --------------------------------------------------------------------------
# Enable IP forwarding on both gateways (they route between LAN and WAN sides)
# --------------------------------------------------------------------------
echo "=== Enabling forwarding on gateways ==="
ip netns exec gw-a sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec gw-a sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
ip netns exec gw-b sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec gw-b sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null

echo ""
echo "=== Topology built successfully ==="
echo ""
echo "  lan-a  (10.10.1.10, fd00:1::10)"
echo "    |"
echo "  gw-a   (LAN: 10.10.1.1/fd00:1::1 | WAN: 192.168.50.1/fd00:50::1)"
echo "    |  <- IPsec goes here, between gw-a and gw-b ->"
echo "  gw-b   (WAN: 192.168.50.2/fd00:50::2 | LAN: 10.10.2.1/fd00:2::1)"
echo "    |"
echo "  lan-b  (10.10.2.10, fd00:2::10)"
echo ""
echo "Sanity test (should work, unencrypted, before strongSwan is configured):"
echo "  sudo ip netns exec lan-a ping -c 3 10.10.2.10"
echo ""
echo "To watch this traffic in the clear on the WAN link:"
echo "  sudo ip netns exec gw-a tcpdump -i veth-wanA -n"
