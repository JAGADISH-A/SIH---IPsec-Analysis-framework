#!/usr/bin/env bash
#
# wan-tap-setup.sh - passive middle-link mirror for the ipsec lab WAN segment.
#
# The lab WAN is now a transparent L2 segment: Linux bridge `br-wan` created in
# the HOST (root) network namespace by scripts/deploy-ipsec.sh. Its members are
#
#   br-wan:eth1  <-  clab-ipsec-gw-a:eth2   (192.168.100.1)
#   br-wan:eth2  <-  clab-ipsec-gw-b:eth2   (192.168.100.2)
#   br-wan:eth3  <-  clab-ipsec-sensor:eth1 (passive mirror listener)
#
# This script installs an explicit L2 SPAN-style mirror on the two dataplane
# bridge members (ingress side) that copies BOTH directions into the
# sensor-facing member br-wan:eth3:
#
#   gw-a -> gw-b : tc mirred mirror of ingress on br-wan:eth1
#   gw-b -> gw-a : tc mirred mirror of ingress on br-wan:eth2
#
# The mirror is copy-only (`mirred egress mirror`). It never redirects, drops,
# or alters the original frames: gw-a <-> gw-b continues directly through the
# bridge. The sensor-facing interface is receive-only from the WAN dataplane's
# perspective (sensor has no IP, no routes, forwarding disabled, charon not
# running).
#
# Idempotent: safe to re-run after every deploy / container re-create.
# Fail-safe: exits non-zero (without touching the dataplane) if the topology
# is not where the script expects it to be.
#
# Run with root privileges:
#   sudo ./scripts/wan-tap-setup.sh
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BRIDGE="br-wan"
PREFIX="clab-ipsec"
MTU=9500

# gw-a:eth2 / gw-b:eth2 / sensor:eth1 names inside the containers.
declare -r NODES=(
    "gw-a:eth2"
    "gw-b:eth2"
    "sensor:eth1"
)

die() { echo "ERROR: $*" >&2; exit 1; }

# --- locate the root-netns bridge member that is the peer of a container iface
# Each lab data link is a veth pair wrapping the container netns and the root
# netns. We derive the root-side device from the container-side peer ifindex so
# we never assume where the segment lives.
root_member() { # $1 container iface e.g. gw-a:eth2 -> prints root netns dev
    local node="${1%%:*}" ifc="${1##*:}"
    local container="$PREFIX-$node"
    local peer_idx dev

    peer_idx=$(docker exec "$container" ip -o link show "$ifc" 2>/dev/null \
        | sed -nE 's/^[0-9]+: .*@if([0-9]+):.*/\1/p')
    [ -n "$peer_idx" ] || die "$container:$ifc not found or has no peer"

    dev=$(ip -j link | jq -r --argjson i "$peer_idx" \
        '.[] | select(.ifindex == $i) | .ifname' 2>/dev/null)
    [ -n "$dev" ] && [ "$dev" != "null" ] || \
        die "no root-netns device with ifindex $peer_idx (peer of $container:$ifc)"
    printf '%s' "$dev"
}

echo "== [$BRIDGE] passive middle-link mirror provisioning =="

# --- 0. all lab containers up
for n in gw-a gw-b sensor; do
    docker inspect -f '{{.State.Running}}' "$PREFIX-$n" 2>/dev/null \
        | grep -q '^true' || die "container $PREFIX-$n is not running"
done

# --- 1. bridge must exist in the ROOT netns (this is where the segment lives)
ip link show "$BRIDGE" >/dev/null 2>&1 || \
    die "bridge $BRIDGE not found in the root netns - run scripts/deploy-ipsec.sh deploy first"
bri_idx=$(ip -j link | jq -r --arg b "$BRIDGE" '.[] | select(.ifname==$b) | .ifindex')
[ -n "$bri_idx" ] && [ "$bri_idx" != "null" ] || die "could not resolve ifindex of $BRIDGE"

# --- 2. resolve the three root-side members and prove they live on br-wan
# `ip -j link` reports a device's "master" either as the bridge NAME ("br-wan")
# or as the master's ifindex, depending on the iproute2 version. Normalize to a
# name and compare against $BRIDGE so the check holds on both representations.
declare -A DEV
for spec in "${NODES[@]}"; do
    node=${spec%%:*} ifc=${spec##*:}
    dev=$(root_member "$spec")
    master=$(ip -j link | jq -r --arg d "$dev" \
        '.[] | select(.ifname==$d) | .master // empty' 2>/dev/null)
    dev_idx=$(ip -j link | jq -r --arg d "$dev" '.[] | select(.ifname==$d) | .ifindex' 2>/dev/null)
    [ "$dev_idx" != "null" ] || die "cannot resolve ifindex of root dev $dev"
    if [ -n "$master" ] && [[ "$master" =~ ^[0-9]+$ ]]; then
        master=$(ip -j link | jq -r --argjson i "$master" \
            '.[] | select(.ifindex == $i) | .ifname // empty' 2>/dev/null)
    fi
    [ -n "$master" ] && [ "$master" = "$BRIDGE" ] || \
        die "$node:$ifc peer '$dev' (ifindex $dev_idx) is not enslaved to '$BRIDGE' (master='$master')"
    DEV[$node]=$dev
    echo "  $node:$ifc  ->  root netns '$dev' ensl. $BRIDGE (ifindex $dev_idx)"
done

DA=${DEV[gw-a]}   # mirrors gw-a -> gw-b (source of WAN traffic from gw-a)
DB=${DEV[gw-b]}   # mirrors gw-b -> gw-a
DS=${DEV[sensor]} # sensor-facing member (receives BOTH mirrored directions)

[ "$DA" != "$DS" ] && [ "$DB" != "$DS" ] || die "mirror source/target resolved to the same device"

# --- 3. keep the mirror path at WAN MTU (>=9500) - copies of 9500 MTU frames
#        must not be clamped anywhere on the sensor path.
for d in "$DA" "$DB" "$DS"; do
    ip link set dev "$d" mtu "$MTU"
done
docker exec "$PREFIX-sensor" ip link set dev eth1 mtu "$MTU"

# --- 4. explicit L2 mirror (SPAN semantics) - copy only, BOTH directions
mirror_into_sensor() { # $1 source bridge member -> copies its ingress to $DS
    local src="$1"
    # idempotent: drop any existing clsact/filters, then re-add cleanly
    tc qdisc del dev "$src" clsact 2>/dev/null || true
    tc qdisc add dev "$src" clsact
    tc filter add dev "$src" ingress prio 1 protocol all matchall \
        action mirred egress mirror dev "$DS"
    echo "  [mirror] ingress of $src  ->  mirror copy -> $DS"
}

mirror_into_sensor "$DA"   # direction: gw-a -> gw-b
mirror_into_sensor "$DB"   # direction: gw-b -> gw-a

# --- 5. verify
echo
echo "== [$BRIDGE] verification =="
echo "-- bridge members --"
bridge link show master "$BRIDGE"

echo
echo "-- sensor-facing member state (receive-only, copies land here) --"
ip -d link show "$DS"
docker exec "$PREFIX-sensor" ip -d link show eth1 | sed -n '1,2p'
docker exec "$PREFIX-sensor" sh -c '
    echo "  sensor IPv4 addrs: $(ip -4 -o addr show eth1 | wc -l)"
    echo "  sensor IPv6 addrs: $(ip -6 -o addr show eth1 scope global | wc -l)"
    echo "  ip_forward: $(cat /proc/sys/net/ipv4/ip_forward)"
    echo "  charon running: $(pgrep -c charon 2>/dev/null || echo 0)"
'

echo
echo "-- mirror filters (tc, root netns) --"
for d in "$DA" "$DB"; do
    echo "[$d]"
    tc -s filter show dev "$d" ingress
done

echo
echo "== [$BRIDGE] mirror ready =="
echo "  capture BOTH directions on the sensor interface:"
echo "    docker exec $PREFIX-sensor tcpdump -en -i eth1"