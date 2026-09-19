#!/usr/bin/env bash
#
# deploy-ipsec.sh - deploy/provision the ipsec lab with the passive WAN mirror.
#
# Usage:
#   sudo ./scripts/deploy-ipsec.sh deploy     # create WAN bridge + deploy + mirror
#   sudo ./scripts/deploy-ipsec.sh destroy    # containerlab destroy + remove WAN bridge
#
# Why a wrapper?  Containerlab's `kind: bridge` does NOT create the bridge for
# you (containerlab docs): `br-wan` must already exist in the root netns before
# `containerlab deploy` enslaves the endpoints.  This wrapper creates it first,
# deploys the (unchanged) topology, provisions the passive mirror and validates
# it.  A mirror failure aborts the wrapper (non-zero) but leaves the lab up and
# the gw-a <-> gw-b dataplane untouched.
#
# Observation point:  the mirror observation point is the WAN-facing side of
# GW-A — specifically the root-netns peer of gw-a:eth2 (br-wan:eth1).  Both
# ingress (A -> B) and egress (B -> A) on that single member are mirrored
# copy-only into the sensor-facing member br-wan:eth3.  The old middle-link
# mirror (mirrored ingress on BOTH gw-a and gw-b dataplane members) was
# removed during the WAN-side migration; see wan-tap-setup.sh header for
# details.
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
#   sudo ./scripts/wan-tap-setup.sh
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOPO="$ROOT_DIR/topology/tunnel/ipsec.clab.yml"
WAN_TAP="$ROOT_DIR/scripts/wan-tap-setup.sh"
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
        echo "[deploy] provisioning passive WAN mirror"
        "$WAN_TAP"
        echo
        echo "[deploy] DONE. Lab up, mirror up. Validate with:"
        echo "    docker exec clab-ipsec-host-a ping -c 3 10.10.2.10"
        echo "    docker exec clab-ipsec-sensor tcpdump -en -i eth1"
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