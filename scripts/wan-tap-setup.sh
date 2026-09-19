#!/usr/bin/env bash
#
# wan-tap-setup.sh - passive GW-A WAN-side mirror feeding the XDP sensor.
#
# The observation point for the live XDP sensor is moved from the br-wan
# middle-link (both dataplane members) to the WAN-facing side of GW-A only:
#
#     GW-A eth2 (192.168.100.1)
#       |  copy-only passive mirror (tc mirred ... mirror)
#       v
#     br-wan:eth1 = root-netns peer of gw-a:eth2  (source hook: ingress + egress)
#       |  mirred copies -> br-wan:eth3
#       v
#     clab-ipsec-sensor:eth1  (dedicated sink; XDP/eBPF reads it)
#
# Mirror source hook: the root-netns bridge member `br-wan:eth1`, which is the
# peer veth of `gw-a:eth2`.  Because that member sits on the WAN side of GW-A:
#
#   ingress on br-wan:eth1  == frames GW-A transmits toward the WAN (A -> B)
#   egress  on br-wan:eth1  == frames the WAN delivers toward GW-A (B -> A)
#
# Both hooks are mirrored copy-only into the sensor-facing member `br-wan:eth3`
# (SPAN semantics).  The XFRM/plaintext question is unchanged from the previous
# middle-link tap: these frames are the encrypted ESP payloads on the wire; any
# plaintext artifacts can only appear INSIDE gw-a's netns and are intentionally
# not part of this feed (verified empirically in the validation report).
#
# The mirror is copy-only (`mirred egress mirror`). It never redirects, drops,
# or alters the original frames: gw-a <-> gw-b continues directly through the
# bridge.  The sensor-facing member is a dedicated sink:
#
#   - isolated on, learning off, flood off, mcast_flood off, bcast_flood off
#     so the bridge NEVER floods/forwards dataplane frames to it (sensor only
#     ever sees the explicit mirred copies - no duplicates, no re-injection);
#   - sensor has no IP, no routes, forwarding disabled, charon not running.
#
# The gw-b leg (br-wan:eth2) carries NO mirror anymore; any leftover clsact
# from the previous middle-link provisioning is removed.
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

echo "== [$BRIDGE] GW-A WAN-side mirror provisioning =="

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

DA=${DEV[gw-a]}   # WAN-side observation point (peer of gw-a:eth2) - mirror source
DB=${DEV[gw-b]}   # no mirror on this leg anymore (cleanup target)
DS=${DEV[sensor]} # sensor-facing sink member (receives the mirrored copies)

[ "$DA" != "$DS" ] && [ "$DB" != "$DS" ] || die "mirror source/target resolved to the same device"

# --- 3. keep the mirror path at WAN MTU (>=9500) - copies of 9500 MTU frames
#        must not be clamped anywhere on the sensor path.
for d in "$DA" "$DB" "$DS"; do
    ip link set dev "$d" mtu "$MTU"
done
docker exec "$PREFIX-sensor" ip link set dev eth1 mtu "$MTU"

# --- 4. sensor member becomes a dedicated sink: isolated + all floods/learning
#        disabled so the ONLY frames it ever receives are the explicit mirred
#        copies below (no bridge flood duplicates, no re-injection possible).
#        (Empirically verified that `isolated on` alone does NOT stop floods;
#        the flood/learning flags must be off too.)
bridge link set dev "$DS" isolated on
bridge link set dev "$DS" learning off
bridge link set dev "$DS" flood off
bridge link set dev "$DS" mcast_flood off
bridge link set dev "$DS" bcast_flood off

# --- 5. explicit GW-A WAN-side mirror (SPAN semantics) - copy only, BOTH
#        directions from the single WAN-side hook at GW-A.
#
#        ingress on DA  == GW-A -> WAN  (A -> B)
#        egress  on DA  == WAN  -> GW-A (B -> A)
mirror_into_sensor() { # $1 source bridge member -> copies ing+eg to $DS
    local src="$1"
    # idempotent: drop any existing clsact/filters, then re-add cleanly
    tc qdisc del dev "$src" clsact 2>/dev/null || true
    tc qdisc add dev "$src" clsact
    tc filter add dev "$src" ingress prio 1 protocol all matchall \
        action mirred egress mirror dev "$DS"
    tc filter add dev "$src" egress prio 1 protocol all matchall \
        action mirred egress mirror dev "$DS"
    echo "  [mirror] ingress+egress of $src  ->  mirror copies -> $DS"
}

# --- 6. remove the old gw-b leg mirror (previous middle-link deployment)
if tc qdisc show dev "$DB" | grep -q clsact; then
    tc qdisc del dev "$DB" clsact 2>/dev/null || \
        die "could not remove leftover clsact on $DB (old middle-link mirror)"
    echo "  [cleanup] removed old middle-link mirror on $DB"
fi

mirror_into_sensor "$DA"   # GW-A WAN-side; captures A->B (ingress) and B->A (egress)

# --- 7. verify
echo
echo "== [$BRIDGE] verification =="
echo "-- bridge members --"
bridge -d link show master "$BRIDGE"

echo
echo "-- sensor-facing member state (dedicated sink, receive-only) --"
ip -d link show "$DS" | sed -n '1,3p'
docker exec "$PREFIX-sensor" ip -d link show eth1 | sed -n '1,2p'
docker exec "$PREFIX-sensor" sh -c '
    echo "  sensor IPv4 addrs: $(ip -4 -o addr show eth1 | wc -l)"
    echo "  sensor IPv6 addrs: $(ip -6 -o addr show eth1 scope global | wc -l)"
    echo "  ip_forward: $(cat /proc/sys/net/ipv4/ip_forward)"
    echo "  charon running: $(pgrep -c charon 2>/dev/null || echo 0)"
'

echo
echo "-- mirror filters (tc, root netns) --"
echo "[$DA] (GW-A WAN-side observation point)"
tc -s filter show dev "$DA" 2>/dev/null

echo
echo "-- no mirror filters on the gw-b leg --"
if tc qdisc show dev "$DB" | grep -q clsact; then
    echo "WARNING: $DB still has a clsact qdisc - expected none"
else
    echo "[$DB] clean (no clsact / no mirror)"
fi

echo
echo "== [$BRIDGE] mirror ready =="
echo "  capture BOTH directions on the sensor interface:"
echo "    docker exec $PREFIX-sensor tcpdump -en -i eth1"
echo "  (the audit tap on gw-a eth2 is unaffected)"