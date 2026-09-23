#!/usr/bin/env bash
#
# deploy-ipsec.sh - deploy/provision the ipsec lab with GW-A passive observation.
#
# Usage:
#   sudo ./scripts/deploy-ipsec.sh deploy     # create WAN bridge + deploy the lab
#   sudo ./scripts/deploy-ipsec.sh destroy    # containerlab destroy + remove WAN bridge
#
# Why a wrapper?  Containerlab's `kind: bridge` does NOT create the bridge for
# you (containerlab docs): `br-wan` must already exist in the root netns before
# `containerlab deploy` enslaves the endpoints.  This wrapper creates it first,
# then deploys the (unchanged) topology.
#
# Monitoring architecture:  GW-A is the AUTHORITATIVE observation point.  The
# WAN bridge `br-wan` is pure dataplane - exactly the two gateway members
# (gw-a:eth2, gw-b:eth2), no sensor member.  Passive observation is provisioned
# INSIDE gw-a at container start (gw-entrypoint.sh -> audit-tap-setup.sh): it
# mirrors gw-a:eth2 (WAN side, sees IKE + ESP both directions) copy-only into
# the in-container audit tap (audit-tap0) and into gw-a:eth3, a direct veth
# feed to the passive sensor (sensor:eth1).  The sensor is a sink only and is
# never inline with the WAN segment.  There is no br-wan mirror tap script.
#
# Why --reconfigure (forced fresh deploy)?  Since containerlab 0.79, `deploy`
# CONVERGES an already-deployed lab in place (same reconcile engine as `apply`).
# `br-wan` is a root-namespace bridge that containerlab treats as externally
# managed and therefore refuses to recreate; reconciling the new topology
# against the previous deployment fails with
#   "Node br-wan is externally managed and cannot be recreate for config drift: Kind"
# `--reconfigure` is containerlab's documented remedy for such externally
# managed nodes: it destroys the previous lab and redeploys from scratch.
# br-wan itself is never destroyed by containerlab (bridge.Delete() is a no-op),
# so it survives the reconfigure and this wrapper re-ensures it before deploy.
#
# The raw containerlab workflow still works once a stale deployment is removed:
#   sudo ip link add br-wan type bridge && sudo ip link set br-wan up
#   sudo containerlab destroy -t topology/tunnel/ipsec.clab.yml --cleanup
#   sudo containerlab deploy -t topology/tunnel/ipsec.clab.yml
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOPO="$ROOT_DIR/topology/tunnel/ipsec.clab.yml"
BRIDGE="br-wan"
ACTION="${1:-deploy}"

usage() {
    echo "usage: $0 [deploy|destroy]" >&2
    exit 2
}

ensure_bridge() {
    if ! ip link show "$BRIDGE" >/dev/null 2>&1; then
        echo "[deploy] creating WAN L2 segment bridge $BRIDGE (root netns)"
        ip link add "$BRIDGE" type bridge
    fi
    ip link set "$BRIDGE" up
    echo "[deploy] $BRIDGE ready at $(ip -o link show "$BRIDGE" | awk '{print $1}' | tr -d ':')"
}

case "$ACTION" in
    deploy)
        ensure_bridge
        echo "[deploy] containerlab deploy --reconfigure: $(basename "$TOPO")"
        containerlab deploy --reconfigure -t "$TOPO"
        # GW-A observation is provisioned inside gw-a by its entrypoint
        # (mirror eth2 -> audit-tap0 + sensor feed eth3).  Health-check it here
        # so a missing observation path is surfaced early; the dataplane is NOT
        # affected either way.
        gw_a="clab-ipsec-gw-a"
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$gw_a"; then
            echo "[deploy] checking GW-A observation provisioning (${gw_a})"
            # clsact mirrors are attached on the ingress (ffff:fff1) and egress
            # (ffff:fff2) parents; `tc filter show dev eth2` alone shows the root
            # qdisc and lists nothing.  Inspect both directions explicitly.
            ingress="$(docker exec "$gw_a" tc filter show dev eth2 ingress 2>/dev/null | grep -c mirred || true)"
            egress="$(docker exec "$gw_a" tc filter show dev eth2 egress 2>/dev/null | grep -c mirred || true)"
            if [ "${ingress:-0}" -lt 1 ] || [ "${egress:-0}" -lt 1 ]; then
                echo "[deploy] WARNING: eth2 mirror missing filters (ingress=${ingress:-0}, egress=${egress:-0}); check gw-a audit-tap logs" >&2
            else
                echo "[deploy] GW-A observation ready: eth2 mirror -> audit-tap0 + eth3 (ingress=${ingress:-0}, egress=${egress:-0} mirred action(s))"
            fi
        else
            echo "[deploy] WARNING: $gw_a container not present; observation not checked" >&2
        fi
        echo
        echo "[deploy] DONE. Lab up, observation on the GW-A side. Validate with:"
        echo "    docker exec clab-ipsec-host-a ping -c 3 10.10.2.10"
        echo "    # PCAP at the observation point (highest fidelity, inside GW-A):"
        echo "    docker exec clab-ipsec-gw-a tcpdump -en -i eth2 udp port 500 or udp port 4500 or esp"
        echo "    # Mirrored stream as seen by the passive sensor:"
        echo "    docker exec clab-ipsec-sensor tcpdump -en -i eth1 udp port 500 or udp port 4500 or esp"
        echo "    # XDP/eBPF observation on the sensor feed (manual; optional):"
        echo "    docker cp ebpf/xdp_monitor clab-ipsec-sensor:/usr/sbin/xdp_monitor"
        echo "    docker exec clab-ipsec-sensor /usr/sbin/xdp_monitor eth1 --json"
        ;;
    destroy)
        echo "[deploy] containerlab destroy: $(basename "$TOPO")"
        containerlab destroy -t "$TOPO" --cleanup
        # Remove the WAN bridge ONLY if this lab is its last user.  An unrelated
        # bridge/reuse of the name must never be destroyed by accident.
        if ip link show "$BRIDGE" >/dev/null 2>&1; then
            members=$(bridge link show master "$BRIDGE" 2>/dev/null | grep -vc '^$' || true)
            if [ "$members" -eq 0 ]; then
                ip link del "$BRIDGE"
                echo "[deploy] destroyed (lab + $BRIDGE)"
            else
                echo "[deploy] lab destroyed; $BRIDGE still has $members member(s) - not deleting (shared/in-use)"
            fi
        else
            echo "[deploy] destroyed (lab; $BRIDGE not present)"
        fi
        ;;
    *)
        usage
        ;;
esac