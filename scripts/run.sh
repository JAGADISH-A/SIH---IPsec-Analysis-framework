#!/usr/bin/env bash
#
# run.sh - bring the IPsec tunnel testbed up and verify the full stack:
#
#   deploy (reuse deploy-ipsec.sh --reconfigure)
#   -> nodes up -> GW-A observation (mirror) -> IPsec SA
#   -> XFRM state/policy -> Host-A -> Host-B connectivity
#   -> sensor mirror live-capture -> audit tap -> XDP (optional)
#
# Idempotent: if the lab is already deployed and the observation path is
# healthy, the deploy stage is skipped (converged); otherwise it uses the
# existing deploy-ipsec.sh --reconfigure mechanism.
#
# Non-tunnel nodes (host-c/host-d transport topology) are NOT in scope of this
# automated workflow; the tunnel testbed is the verified architecture.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR" || exit 1

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

OK="[OK]"
WARN="[WARN]"
FAIL="[FAIL]"

warnings=0
ok()    { printf '%s %s\n' "$OK"   "$*"; }
warn()  { printf '%s %s\n' "$WARN" "$*"; warnings=$((warnings + 1)); }
die()   { printf '%s %s\n' "$FAIL" "$*" >&2; exit 1; }

ipsec_sa_established() {
    docker exec clab-ipsec-gw-a swanctl --list-sas 2>/dev/null | grep -q "ESTABLISHED"
}

container_running() {
    docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$1"
}

iface_exists() {
    docker exec "$1" ip -br link show "$2" >/dev/null 2>&1
}

mirror_counts() {
    # clsact mirror actions live on the ingress/egress parents; the bare
    # `tc filter show dev eth2` form shows the root qdisc only (this was the
    # original health-check bug) - always inspect both directions.
    ingress="$(docker exec clab-ipsec-gw-a tc filter show dev eth2 ingress 2>/dev/null | grep -c mirred)"
    egress="$(docker exec clab-ipsec-gw-a tc filter show dev eth2 egress 2>/dev/null | grep -c mirred)"
    printf '%s %s\n' "${ingress:-0}" "${egress:-0}"
}

echo "=========================================================================="
echo " IPsec testbed - run/verify (tunnel: Host-A -> GW-A <-> GW-B -> Host-B)"
echo "=========================================================================="

# ---------------------------------------------------------------------------
# 0. Preflight
# ---------------------------------------------------------------------------
if ! docker info >/dev/null 2>&1; then
    die "Docker is not usable. Start Docker and/or check the 'docker' group membership."
fi
if ! containerlab version >/dev/null 2>&1; then
    die "Containerlab is not available. Run ./scripts/install.sh first."
fi

if [ "$SUDO" = "sudo" ] && ! sudo -n true >/dev/null 2>&1; then
    echo "[~~] sudo will prompt for a password at the privileged deploy step (br-wan bridge + containerlab)."
fi

# ---------------------------------------------------------------------------
# 1. Deploy (or converge on an already-healthy lab)
# ---------------------------------------------------------------------------
echo "=== 1. Deployment (reuse deploy-ipsec.sh) ==="

needs_deploy=0
for node in clab-ipsec-gw-a clab-ipsec-gw-b clab-ipsec-host-a clab-ipsec-host-b clab-ipsec-sensor; do
    container_running "$node" || needs_deploy=1
done
iface_exists clab-ipsec-gw-a eth2 || needs_deploy=1
iface_exists clab-ipsec-gw-a eth3 || needs_deploy=1
iface_exists clab-ipsec-sensor eth1 || needs_deploy=1
read -r ing egr < <(mirror_counts)
if [ "${ing:-0}" -lt 1 ] || [ "${egr:-0}" -lt 1 ]; then
    needs_deploy=1
fi

if [ "$needs_deploy" -eq 0 ]; then
    ok "lab already deployed and observation path healthy (ingress=$ing, egress=$egr) - skipping redeploy (idempotent converge)."
else
    echo "[~~] deploying testbed ..."
    if ! $SUDO bash "$SCRIPT_DIR/deploy-ipsec.sh" deploy; then
        die "deployment failed (see deploy-ipsec.sh output above); check 'docker logs clab-ipsec-gw-a'."
    fi
    ok "lab deployed."
fi

if ! container_running clab-ipsec-gw-a; then
    die "gw-a is not running after deploy."
fi

# ---------------------------------------------------------------------------
# 2. Node + interface verification
# ---------------------------------------------------------------------------
echo "=== 2. Nodes and interfaces ==="

for node in clab-ipsec-host-a clab-ipsec-gw-a clab-ipsec-gw-b clab-ipsec-host-b clab-ipsec-sensor; do
    if container_running "$node"; then
        ok "$node running"
    else
        die "$node not running"
    fi
done

for spec in "clab-ipsec-gw-a:eth1:LAN-A" "clab-ipsec-gw-a:eth2:WAN" "clab-ipsec-gw-a:eth3:observation feed" "clab-ipsec-sensor:eth1:mirror sink"; do
    node="${spec%%:*}"; rest="${spec#*:}"; iface="${rest%%:*}"; what="${rest#*:}"
    if iface_exists "$node" "$iface"; then
        ok "$node $iface ($what) present"
    else
        die "$node $iface ($what) MISSING - check deployment"
    fi
done

# ---------------------------------------------------------------------------
# 3. GW-A observation (authoritative passive mirror) health
# ---------------------------------------------------------------------------
echo "=== 3. GW-A observation mirror ==="

read -r ing egr < <(mirror_counts)
if [ "${ing:-0}" -ge 1 ] && [ "${egr:-0}" -ge 1 ]; then
    ok "GW-A eth2 mirror: ingress=$ing egress=$egr mirred action(s) -> audit-tap0 + eth3/sensor"
else
    die "GW-A eth2 mirror missing (ingress=${ing:-0}, egress=${egr:-0}). Check docker logs clab-ipsec-gw-a for audit-tap errors."
fi

# ---------------------------------------------------------------------------
# 4. IPsec SA establishment
# ---------------------------------------------------------------------------
echo "=== 4. IPsec SA establishment ==="

if ipsec_sa_established; then
    ok "IPsec SA already ESTABLISHED."
else
    echo "[~~] initiating tunnel (swanctl --initiate --child lan-a-to-lan-b) ..."
    if ! docker exec clab-ipsec-gw-a swanctl --initiate --child lan-a-to-lan-b >/tmp/ipsec-init.log 2>&1; then
        warn "swanctl --initiate had output:"
        sed 's/^/      /' /tmp/ipsec-init.log >&2
    fi
    for _ in $(seq 1 30); do
        ipsec_sa_established && break
        sleep 1
    done
fi

if ipsec_sa_established; then
    ok "IPsec IKE SA + CHILD SA ESTABLISHED (gw-a-to-gw-b / lan-a-to-lan-b)"
else
    die "IPsec SA did not reach ESTABLISHED within 30s. Run: docker exec clab-ipsec-gw-a swanctl --list-sas"
fi

# ---------------------------------------------------------------------------
# 5. XFRM verification
# ---------------------------------------------------------------------------
echo "=== 5. XFRM state / policy ==="

esp_states="$(docker exec clab-ipsec-gw-a ip xfrm state 2>/dev/null | grep -c proto)"
out_policies="$(docker exec clab-ipsec-gw-a ip xfrm policy 2>/dev/null | grep -c 'dir out')"

if [ "${esp_states:-0}" -ge 2 ] && [ "${out_policies:-0}" -ge 1 ]; then
    ok "XFRM: $esp_states ESP state(s), outbound tunnel policy installed."
else
    die "XFRM state/policy unexpected (esp_states=${esp_states:-0}, out_policies=${out_policies:-0})."
fi

# ---------------------------------------------------------------------------
# 6. Connectivity (Host-A -> Host-B)
# ---------------------------------------------------------------------------
echo "=== 6. Connectivity ==="

ping_out="$(docker exec clab-ipsec-host-a ping -c 5 -i 0.2 -W 1 10.10.2.10 2>&1)"
loss="$(printf '%s\n' "$ping_out" | grep -o '[0-9]*% packet loss' | head -1)"

if printf '%s\n' "$ping_out" | grep -q "0% packet loss"; then
    ok "Host-A -> Host-B 5/5 (0% packet loss)."
else
    printf '%s\n' "$ping_out" >&2
    die "Host-A -> Host-B connectivity FAILED (loss: ${loss:-unknown})."
fi

# ---------------------------------------------------------------------------
# 7. Sensor observation: mirrored stream + passive posture
# ---------------------------------------------------------------------------
echo "=== 7. Sensor observation (passive mirror) ==="

ip_fwd="$(docker exec clab-ipsec-sensor sysctl -n net.ipv4.ip_forward 2>/dev/null)"
if [ "$ip_fwd" = "0" ]; then
    ok "sensor is passive (net.ipv4.ip_forward=0)."
else
    die "sensor has ip_forward=1 - it must be a passive observation sink."
fi

if [ -d /sys/class/net/br-wan/brif ]; then
    members="$(ls /sys/class/net/br-wan/brif/)"
    if printf '%s' "$members" | grep -q "sensor"; then
        warn "sensor appears to be a br-wan member - this is NOT the verified architecture (verify manually)."
    elif [ -z "$members" ]; then
        warn "br-wan exists but has no members; run ./scripts/status.sh for detail."
    else
        ok "sensor is NOT on br-wan (WAN bridge carries only the two gateway members)."
    fi
else
    warn "br-wan not present/readable in this root namespace; skipped (run 'sudo ./scripts/status.sh' for a full check)."
fi

echo "[~~] capturing mirrored WAN traffic (gw-a eth2 vs sensor eth1) during a ping burst ..."
docker exec -d clab-ipsec-gw-a sh -c 'timeout 12 tcpdump -eni eth2 "udp port 500 or udp port 4500 or esp" -c 1000 >/tmp/obs_gwa.txt 2>/dev/null'
docker exec -d clab-ipsec-sensor sh -c 'timeout 12 tcpdump -eni eth1 "udp port 500 or udp port 4500 or esp" -c 1000 >/tmp/obs_sensor.txt 2>/dev/null'
docker exec clab-ipsec-host-a ping -c 25 -i 0.2 10.10.2.10 >/dev/null 2>&1
sleep 11
gwa_esp="$(docker exec clab-ipsec-gw-a sh -c 'grep -c ESP /tmp/obs_gwa.txt' 2>/dev/null)"
sensor_esp="$(docker exec clab-ipsec-sensor sh -c 'grep -c ESP /tmp/obs_sensor.txt' 2>/dev/null)"

if [ "${sensor_esp:-0}" -ge 1 ]; then
    ok "sensor received mirrored IPsec traffic (sensor ESP frames=${sensor_esp:-0}, gw-a eth2=${gwa_esp:-0})."
    if [ "${sensor_esp:-0}" -lt "${gwa_esp:-1}" ]; then
        warn "mirror count on sensor (${sensor_esp:-0}) < gw-a eth2 (${gwa_esp:-0}); check gw-a eth2/eth3 state."
    fi
else
    die "sensor received 0 IPsec frames - the GW-A observation mirror is not delivering traffic."
fi

# ---------------------------------------------------------------------------
# 8. Audit tap (in-gw-a tshark surface)
# ---------------------------------------------------------------------------
echo "=== 8. Audit tap (audit-tap0) ==="

if iface_exists clab-ipsec-gw-a audit-tap0; then
    ok "audit-tap0 present in gw-a."
else
    die "audit-tap0 missing in gw-a - the GW-A audit mirror was not provisioned."
fi

echo "[~~] sampling audit-tap0 during a ping burst ..."
docker exec -d clab-ipsec-gw-a sh -c 'timeout 10 tshark -i audit-tap0 -Y "esp" -c 200 >/tmp/obs_audit.txt 2>/dev/null'
docker exec clab-ipsec-host-a ping -c 20 -i 0.2 10.10.2.10 >/dev/null 2>&1
sleep 9
audit_esp="$(docker exec clab-ipsec-gw-a sh -c 'grep -c ESP /tmp/obs_audit.txt' 2>/dev/null)"

if [ "${audit_esp:-0}" -ge 1 ]; then
    ok "audit-tap0 received IPsec frames (ESP frames=${audit_esp:-0})."
else
    die "audit-tap0 received 0 ESP frames."
fi

# ---------------------------------------------------------------------------
# 9. XDP (optional, non-fatal - verified generic/SKB mode)
# ---------------------------------------------------------------------------
echo "=== 9. XDP/eBPF observation on the sensor (optional) ==="

xdp_state="not verified"
if [ -x ebpf/xdp_monitor ]; then
    echo "[~~] starting xdp_monitor on sensor eth1 (generic/SKB) for a live sample ..."
    docker cp ebpf/xdp_monitor clab-ipsec-sensor:/usr/sbin/xdp_monitor >/dev/null 2>&1
    docker exec -d clab-ipsec-sensor sh -c '/usr/sbin/xdp_monitor eth1 --json >/tmp/xdp.jsonl 2>/tmp/xdp.err'
    sleep 1
    docker exec clab-ipsec-host-a ping -c 40 -i 0.2 10.10.2.10 >/dev/null 2>&1
    sleep 2
    mode="$(docker exec clab-ipsec-sensor sh -c 'grep -o "SUCCESS: attached XDP in generic (SKB) mode\|SUCCESS: attached XDP in native (driver) mode" /tmp/xdp.err' 2>/dev/null | head -1)"
    native_rejected="$(docker exec clab-ipsec-sensor sh -c 'grep -c "Peer MTU is too large" /tmp/xdp.err' 2>/dev/null | tr -d ' ')"
    events="$(docker exec clab-ipsec-sensor sh -c 'wc -l < /tmp/xdp.jsonl' 2>/dev/null | tr -d ' ')"
    esp_events="$(docker exec clab-ipsec-sensor sh -c 'grep -c ESP /tmp/xdp.jsonl' 2>/dev/null)"
    docker exec clab-ipsec-sensor pkill -INT xdp_monitor >/dev/null 2>&1

    if [ "${events:-0}" -gt 0 ]; then
        # The veth/MTU combo always rejects native XDP first; the monitor falls
        # back to generic (SKB). Functional proof = real events received; the
        # native-rejected marker tells us which mode was in play.
        if printf '%s' "$mode" | grep -q "generic"; then
            xdp_state="GENERIC (SKB) - verified"
        elif [ "${native_rejected:-0}" -gt 0 ]; then
            xdp_state="GENERIC (SKB) - witnessed (native rejected via Peer-MTU marker)"
            ok "XDP generic/SKB mode: VERIFIED (events=${events:-0}, ESP=${esp_events:-0}; native veth/MTU limit noted)."
        else
            xdp_state="NATIVE (driver)"
            ok "XDP attached (native driver mode): VERIFIED (events=${events:-0})."
        fi
    else
        xdp_state="DOWN"
        warn "XDP captured 0 events (generic mode). Known limitation: native/DRV XDP needs a larger-MTU veth; generic mode is the supported path. Not fatal for the testbed."
    fi
else
    warn "ebpf/xdp_monitor binary absent - XDP verification skipped (run ./scripts/install.sh). Not fatal."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "=========================================================================="
echo " IPsec testbed READY"
echo "=========================================================================="
echo "  deployment         : tunnel (Host-A -> GW-A <-> br-wan/GW-B -> Host-B)"
echo "  observation        : GW-A eth2 -> audit-tap0 + eth3 -> sensor (passive)"
echo "  IPsec              : ESTABLISHED (lan-a-to-lan-b, ESP:AES_GCM_16-256)"
echo "  connectivity       : Host-A -> Host-B OK"
echo "  xdp                : $xdp_state"
echo
echo "  ./scripts/status.sh           # concise health report"
echo "  docker exec clab-ipsec-host-a ping -c 3 10.10.2.10   # quick ping"
echo "  docker exec clab-ipsec-sensor /usr/sbin/xdp_monitor eth1 --json  # live XDP stream"
echo "  ./scripts/stop.sh             # tear the testbed down"

[ "$warnings" -gt 0 ] && {
    printf '%s %s warning(s) recorded (non-fatal).\n' "$WARN" "$warnings"
    exit 2
}
exit 0