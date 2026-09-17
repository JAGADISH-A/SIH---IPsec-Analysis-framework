#!/bin/sh
# Idempotent passive-observation provisioning for the IPsec audit layer.
#
# Runs inside the gateway's network namespace and creates a *copy* path only:
#
#     <mirror_iface> --tc mirred(mirror ing+eg)--> audit-mir <--> audit-tap0 (veth)
#
# `tc mirred ... egress mirror` merely duplicates frames into the sink veth;
# the original frame continues on the wire unchanged, so the IPsec
# forwarding topology is never altered and the observation point is strictly
# passive.  Read the observation interface with TShark/tcpdump:
#
#     tshark  -i audit-tap0 -Y "esp or isakmp" -T json
#     tcpdump -ni audit-tap0 esp or udp port 500 or udp port 4500
#
# A veth pair is used rather than a tun/tap device because AF_PACKET
# consumers (dumpcap/tshark/tcpdump) only receive packets on a tun/tap when
# some process holds /dev/net/tun open (without it the device stays
# NO-CARRIER and `mirred` transmissions are dropped).  A veth sink is
# self-carrier and needs no helper process.
#
# Usage: audit-tap-setup.sh [MIRROR_IFACE]
#   MIRROR_IFACE  interface to mirror (default: $AUDIT_TAP_IFACE, else eth2)
set -eu

MIRROR_IFACE="${1:-${AUDIT_TAP_IFACE:-eth2}}"
SINK="audit-mir"
TAP="audit-tap0"

# Containerlab trophies interfaces (eth1/eth2/...) asynchronously; wait a bit
# before bailing out so entrypoint provisioning succeeds on first boot.
WAIT_S="${AUDIT_TAP_WAIT_S:-15}"
i=0
while [ ! -e "/sys/class/net/${MIRROR_IFACE}" ] && [ "${i}" -lt "${WAIT_S}" ]; do
    sleep 1
    i=$((i + 1))
done
if [ ! -e "/sys/class/net/${MIRROR_IFACE}" ]; then
    echo "[audit-tap] ERROR: interface ${MIRROR_IFACE} does not exist (waited ${WAIT_S}s)" >&2
    exit 1
fi

# Deterministic state: drop any leftover observation devices from an earlier
# lifecycle, then (re)create the pair fresh.
ip link del "${TAP}" 2>/dev/null || true
ip link del "${SINK}" 2>/dev/null || true

ip link add "${SINK}" type veth peer name "${TAP}"
ip link set "${SINK}" up
ip link set "${TAP}" up

# clsact enables both ingress and egress classification in one qdisc.
tc qdisc del dev "${MIRROR_IFACE}" clsact 2>/dev/null || true
tc qdisc add dev "${MIRROR_IFACE}" clsact

# Passive copy filters (strictly mirror, never redirect).
tc filter add dev "${MIRROR_IFACE}" ingress prio 1 matchall \
    action mirred egress mirror dev "${SINK}"
tc filter add dev "${MIRROR_IFACE}" egress prio 1 matchall \
    action mirred egress mirror dev "${SINK}"

echo "[audit-tap] observation ready: ${MIRROR_IFACE} ing+eg -> ${SINK}; read via ${TAP}"