#!/usr/bin/env bash
#
# status.sh - concise health report for the IPsec tunnel testbed.
#
#   Docker / Containerlab / lab state / node states / interfaces
#   GW-A observation mirror / IPsec SA / connectivity / audit tap / sensor / XDP
#
# Read-only. Exit code 0 = shell + core dependency state usable, 1 = Docker or
# Containerlab unusable (cannot evaluate), 2 = not deployed (clean).
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR" || exit 1

OK="OK"
WARN="WARN"
FAIL="FAIL"
STOPPED="STOPPED"

now() { date '+%Y-%m-%d %H:%M:%S'; }

echo "=========================================================================="
echo " IPsec testbed status  ($(now))"
echo "=========================================================================="
echo

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------
if docker info >/dev/null 2>&1; then
    printf '%-12s %s\n' "docker" "[$OK] daemon running"
else
    printf '%-12s %s\n' "docker" "[$FAIL] daemon NOT usable (start Docker / docker group)"
    exit 1
fi

# ---------------------------------------------------------------------------
# Containerlab
# ---------------------------------------------------------------------------
if containerlab version >/dev/null 2>&1; then
    clab_ver="$(containerlab version 2>/dev/null | grep -m1 ':' | tr -d ' ')"
    printf '%-12s %s\n' "containerlab" "[$OK] ${clab_ver:-version unknown}"
else
    printf '%-12s %s\n' "containerlab" "[$FAIL] not available - run ./scripts/install.sh"
    exit 1
fi

# ---------------------------------------------------------------------------
# Lab state (containerlab inspect is read-only)
# ---------------------------------------------------------------------------
if containerlab inspect -t topology/tunnel/ipsec.clab.yml >/dev/null 2>&1 && \
   containerlab inspect -t topology/tunnel/ipsec.clab.yml 2>/dev/null | grep -q "running"; then
    printf '%-12s %s\n' "lab" "[$OK] deployed (running)"
    deployed=1
elif docker ps --format '{{.Names}}' 2>/dev/null | grep -q "clab-ipsec-"; then
    printf '%-12s %s\n' "lab" "[$OK] nodes present"
    deployed=1
else
    printf '%-12s %s\n' "lab" "[$STOPPED] not deployed (run ./scripts/run.sh)"
    exit 2
fi

printf '%s\n' "--------------------------------------------------------------"

# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------
echo "Nodes:"
for node in clab-ipsec-host-a clab-ipsec-gw-a clab-ipsec-gw-b clab-ipsec-host-b clab-ipsec-sensor; do
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$node"; then
        printf '  %-22s %s\n' "$node" "[$OK] running"
    elif docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$node"; then
        printf '  %-22s %s\n' "$node" "[$STOPPED] created but down"
    else
        printf '  %-22s %s\n' "$node" "[$FAIL] absent"
    fi
done

printf '%s\n' "--------------------------------------------------------------"

# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------
iface() { # <node> <iface> <label>
    if docker exec "$1" ip -br link show "$2" >/dev/null 2>&1; then
        state="$(docker exec "$1" ip -br link show "$2" 2>/dev/null | awk '{print $2}')"
        printf '  %-12s %-6s %-10s [%s %s]\n' "$1" "$2" "$3" "$OK" "$state"
    else
        printf '  %-12s %-6s %-10s [%s]\n' "$1" "$2" "$3" "$FAIL"
    fi
}
echo "Interfaces:"
iface clab-ipsec-gw-a eth1        "LAN-A"
iface clab-ipsec-gw-a eth2        "WAN"
iface clab-ipsec-gw-a eth3        "observation feed"
iface clab-ipsec-gw-a audit-tap0  "audit tap"
iface clab-ipsec-sensor eth1      "mirror sink"

printf '%s\n' "--------------------------------------------------------------"

# ---------------------------------------------------------------------------
# GW-A observation mirror
# ---------------------------------------------------------------------------
ingress="$(docker exec clab-ipsec-gw-a tc filter show dev eth2 ingress 2>/dev/null | grep -c mirred)"
egress="$(docker exec clab-ipsec-gw-a tc filter show dev eth2 egress 2>/dev/null | grep -c mirred)"
if [ "${ingress:-0}" -ge 1 ] && [ "${egress:-0}" -ge 1 ]; then
    printf '%-16s [%s] gw-a eth2 mirror ingress=%s egress=%s (audit-tap0 + eth3 -> sensor)\n' "observation" "$OK" "${ingress:-0}" "${egress:-0}"
else
    printf '%-16s [%s] gw-a eth2 mirror ingress=%s egress=%s\n' "observation" "$FAIL" "${ingress:-0}" "${egress:-0}"
fi

# ---------------------------------------------------------------------------
# Sensor posture + IPsec expired counters before a probe
# ---------------------------------------------------------------------------
ip_fwd="$(docker exec clab-ipsec-sensor sysctl -n net.ipv4.ip_forward 2>/dev/null)"
if [ -z "$ip_fwd" ]; then
    printf '%-16s [%s] sensor DOWN / no sysctl\n' "sensor" "$FAIL"
else
    [ "$ip_fwd" = "0" ] && s_tag="$OK" || s_tag="$WARN"
    printf '%-16s [%s] sensor ip_forward=%s (0 = passive sink)\n' "sensor" "$s_tag" "$ip_fwd"
fi

# ---------------------------------------------------------------------------
# IPsec SA
# ---------------------------------------------------------------------------
if docker exec clab-ipsec-gw-a swanctl --list-sas 2>/dev/null | grep -q "ESTABLISHED"; then
    sa_summary="$(docker exec clab-ipsec-gw-a swanctl --list-sas 2>/dev/null | grep "ESTABLISHED" | head -1 | sed 's/^[[:space:]]*//')"
    printf '%-16s [%s] %s\n' "ipsec sa" "$OK" "$sa_summary"
else
    printf '%-16s [%s] no ESTABLISHED SA (initiate via run.sh or swanctl)\n' "ipsec sa" "$FAIL"
fi

# ---------------------------------------------------------------------------
# Connectivity probe
# ---------------------------------------------------------------------------
ping_out="$(docker exec clab-ipsec-host-a ping -c 3 -W 1 10.10.2.10 2>&1)"
if printf '%s\n' "$ping_out" | grep -q "0% packet loss"; then
    printf '%-16s [%s] host-a -> 10.10.2.10  3/3\n' "connectivity" "$OK"
elif printf '%s\n' "$ping_out" | grep -q "100% packet loss"; then
    printf '%-16s [%s] host-a -> 10.10.2.10  no reply\n' "connectivity" "$FAIL"
else
    printf '%-16s [%s] host-a -> 10.10.2.10  partially degraded (check SA + xfrm)\n' "connectivity" "$WARN"
fi

# ---------------------------------------------------------------------------
# XDP on the sensor
# ---------------------------------------------------------------------------
if docker exec clab-ipsec-sensor pgrep -x xdp_monitor >/dev/null 2>&1; then
    printf '%-16s [%s] xdp_monitor RUNNING on eth1 (attached in generic/SKB mode)\n' "xdp" "$OK"
else
    printf '%-16s [%s] xdp_monitor not running (start: docker exec clab-ipsec-sensor /usr/sbin/xdp_monitor eth1 --json)\n' "xdp" "$WARN"
fi

printf '%s\n' "--------------------------------------------------------------"
echo "Bridges (root ns):"
members="$( [ -d /sys/class/net/br-wan/brif ] && ls /sys/class/net/br-wan/brif/ | tr '\n' ' ' )"
if [ -n "$members" ]; then
    printf '  %-12s members: %s\n' "br-wan" "$members"
    printf '%s' "$members" | grep -q "sensor" && printf '  %-12s [%s] sensor must NOT be a member\n' "br-wan" "$FAIL" || true
else
    printf '  %-12s not present/unreadable\n' "br-wan"
fi
printf '%s\n' "--------------------------------------------------------------"
echo "Next:  ./scripts/status.sh any time | ./scripts/run.sh (redeploy+re-verify) | ./scripts/stop.sh"
exit 0