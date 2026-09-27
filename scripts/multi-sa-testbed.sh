#!/usr/bin/env bash
# Real multi-SA testbed: one gateway terminating TWO simultaneous IPsec SAs,
# both force-encapsulated so they share the same UDP/4500 transport.
#
# This uses plain Docker networks rather than containerlab because deploying
# containerlab needs root, and this scenario does not: it only needs three
# strongSwan gateways and three hosts on four L2 networks, which is exactly
# what the existing gateway/host images already provide.
#
#   msa-wan   192.168.100.0/24   gw-a .1   gw-b .2   gw-c .3
#   msa-lan-a 10.10.1.0/24       gw-a .1   host-a .10
#   msa-lan-b 10.10.2.0/24       gw-b .1   host-b .10
#   msa-lan-c 10.10.3.0/24       gw-c .1   host-c .10
#
# Usage:
#   scripts/multi-sa-testbed.sh up      bring the topology up and start the SAs
#   scripts/multi-sa-testbed.sh status  show SA/SPIs/window counters
#   scripts/multi-sa-testbed.sh capture <out.pcap>
#   scripts/multi-sa-testbed.sh down    tear everything down
set -euo pipefail

PREFIX=msa
GATEWAY_IMAGE=ipsec-test-gateway:6.0.3
HOST_IMAGE=ipsec-test-host:24.04
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TOPO="$HERE/topology/multi-sa"
CAPTURE_DIR="${CAPTURE_DIR:-$HERE/results/observed-state/multi-sa}"

net() { echo "${PREFIX}-$1"; }

wait_for_ip() {
    local container=$1 want=$2 tries=60
    while (( tries-- > 0 )); do
        if docker exec "$container" ip -4 -o addr show 2>/dev/null | grep -q " $want/"; then
            return 0
        fi
        sleep 0.5
    done
    echo "timed out waiting for $container to hold $want" >&2
    return 1
}

make_net() {
    local name=$1 subnet=$2 gateway=$3
    docker network inspect "$(net "$name")" >/dev/null 2>&1 || \
        docker network create --subnet "$subnet" --gateway "$gateway" \
            "$(net "$name")" >/dev/null
}

start_gateway() {
    local name=$1 wan_ip=$2 lan_net=$3 lan_ip=$4
    # Reuse the project's own gateway entrypoint and the same config path the
    # containerlab topology uses, so both deployments start charon identically.
    docker run -d --name "${PREFIX}-${name}" --privileged --cap-add NET_ADMIN \
        --sysctl net.ipv4.ip_forward=1 \
        -v "$HERE/scripts/gw-entrypoint.sh:/usr/local/bin/gw-entrypoint.sh:ro" \
        -v "$TOPO/${name}/swanctl:/usr/local/etc/swanctl" \
        --network "$(net wan)" --ip "$wan_ip" \
        --entrypoint /bin/sh "$GATEWAY_IMAGE" -c /usr/local/bin/gw-entrypoint.sh \
        >/dev/null
    docker network connect --ip "$lan_ip" "$lan_net" "${PREFIX}-${name}"
}

up() {
    echo "== clearing any stale containers from a previous run =="
    down >/dev/null 2>&1 || true

    echo "== networks =="
    # Each bridge takes .254 as its own gateway: Docker's default is the first
    # usable address, which would be the .1 this testbed assigns to a gateway
    # or host, and the container would refuse to start with
    # "Address already in use".
    make_net wan   192.168.100.0/24 192.168.100.254
    make_net lan-a 10.10.1.0/24     10.10.1.254
    make_net lan-b 10.10.2.0/24     10.10.2.254
    make_net lan-c 10.10.3.0/24     10.10.3.254

    echo "== gateways (privileged: charon needs TUN/xfrm) =="
    # Docker only accepts --ip for the network given to --network, so the LAN
    # side is attached afterwards with `docker network connect --ip`.
    start_gateway gw-a 192.168.100.1 "$(net lan-a)" 10.10.1.1
    start_gateway gw-b 192.168.100.2 "$(net lan-b)" 10.10.2.1
    start_gateway gw-c 192.168.100.3 "$(net lan-c)" 10.10.3.1

    echo "== hosts =="
    # NET_ADMIN so each host can install the route into the other LANs; without
    # it `ip route replace` returns EPERM and nothing is ever offered to the
    # tunnel, leaving both SAs idle.
    start_host host-a 10.10.1.10 "$(net lan-a)"
    start_host host-b 10.10.2.10 "$(net lan-b)"
    start_host host-c 10.10.3.10 "$(net lan-c)"

    wait_for_ip "${PREFIX}-gw-a" 192.168.100.1
    wait_for_ip "${PREFIX}-gw-b" 192.168.100.2
    wait_for_ip "${PREFIX}-gw-c" 192.168.100.3

    # The LAN hosts only know their own /24 by default, so route the other LANs
    # through the local gateway.  Without this nothing is ever offered to the
    # tunnel and the SAs stay idle.
    route_lan "${PREFIX}-host-a" 10.10.1.1 10.10.2.0/24 10.10.3.0/24
    route_lan "${PREFIX}-host-b" 10.10.2.1 10.10.1.0/24
    route_lan "${PREFIX}-host-c" 10.10.3.1 10.10.1.0/24

    echo "== waiting for both SAs to establish =="
    local tries=60
    while (( tries-- > 0 )); do
        if docker exec "${PREFIX}-gw-a" swanctl --list-sas 2>/dev/null \
                | grep -q "ESTABLISHED" \
           && [ "$(docker exec "${PREFIX}-gw-a" swanctl --list-sas 2>/dev/null \
                  | grep -c ESTABLISHED)" -ge 2 ]; then
            echo "both SAs established"
            status
            return 0
        fi
        sleep 1
    done
    echo "warning: both SAs did not establish; run 'status' for detail" >&2
    status
}

status() {
    echo
    echo "== gw-a SAs (two simultaneous, shared UDP/4500) =="
    docker exec "${PREFIX}-gw-a" swanctl --list-sas 2>/dev/null || true
    echo
    echo "== gw-a child SAs / installed SAs =="
    docker exec "${PREFIX}-gw-a" swanctl --list-sas --ike 2>/dev/null | grep -Ei "ESP|installed" || true
    echo
    echo "== gateway xfrm state (one SPI pair per SA) =="
    docker exec "${PREFIX}-gw-a" ip xfrm state 2>/dev/null | grep -E "^src|^dst" || true
    echo
    echo "== UDP/4500 sockets =="
    docker exec "${PREFIX}-gw-a" ss -lunp 2>/dev/null | grep 4500 || \
        docker exec "${PREFIX}-gw-a" netstat -lunp 2>/dev/null | grep 4500 || true
}

start_host() {
    local name=$1 ip=$2
    docker run -d --name "${PREFIX}-${name}" --cap-add NET_ADMIN \
        --network "$3" --ip "$ip" \
        --entrypoint sh "$HOST_IMAGE" -c 'ip link set lo up; sleep infinity' >/dev/null
}

route_lan() {
    local container=$1 via=$2
    shift 2
    for subnet in "$@"; do
        docker exec "$container" ip route replace "$subnet" via "$via" dev eth0 \
            2>/dev/null || true
    done
}

traffic() {
    # Two deliberately different profiles so a blended vector is obvious:
    #   SA to gw-b  -> small, regular ICMP echo at a high rate (host-b)
    #   SA to gw-c  -> large UDP datagrams at a low rate (host-c)
    # The host image has no nc, so the bulk sender is a short python3 one-liner.
    echo "== SA-1 (gw-a <-> gw-b): small-packet ICMP toward 10.10.2.10 =="
    docker exec -d "${PREFIX}-host-a" \
        ping -c 2000 -i 0.01 -s 56 10.10.2.10 >/dev/null
    echo "== SA-2 (gw-a <-> gw-c): large-packet UDP toward 10.10.3.10 =="
    docker exec -d "${PREFIX}-host-a" python3 -c '
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
payload = b"\0" * 1200
deadline = time.time() + 20
while time.time() < deadline:
    for _ in range(4):
        s.sendto(payload, ("10.10.3.10", 9999))
    time.sleep(0.04)
' >/dev/null
    echo "traffic started (both tunnels carry concurrent traffic)"
}

capture() {
    local out=${1:-$CAPTURE_DIR/multi-sa.pcap}
    mkdir -p "$(dirname "$out")"
    echo "capturing on gw-a (all UDP/4500 ESP + IKE) -> $out"
    # -d is required: without it `docker exec` blocks on tcpdump and the
    # sleep/stop/copy below would never run.
    docker exec -d "${PREFIX}-gw-a" \
        tcpdump -i any -s 0 -U -w /tmp/multi-sa.pcap 'udp port 4500 or udp port 500'
    sleep 1
    local seconds=${CAPTURE_SECONDS:-10}
    echo "capturing for ${seconds}s"
    sleep "$seconds"
    docker exec "${PREFIX}-gw-a" sh -c 'pkill -INT tcpdump; sleep 1' >/dev/null 2>&1 || true
    docker cp "${PREFIX}-gw-a:/tmp/multi-sa.pcap" "$out" >/dev/null
    echo "wrote $out ($(stat -c%s "$out") bytes)"
}

down() {
    for name in gw-a gw-b gw-c host-a host-b host-c; do
        docker rm -f "${PREFIX}-${name}" >/dev/null 2>&1 || true
    done
    for name in wan lan-a lan-b lan-c; do
        docker network rm "$(net "$name")" >/dev/null 2>&1 || true
    done
    echo "topology removed"
}

case "${1:-up}" in
    up) up ;;
    status) status ;;
    traffic) traffic ;;
    capture) capture "${2:-}" ;;
    down) down ;;
    *) echo "usage: $0 {up|status|traffic|capture [out.pcap]|down}" >&2; exit 2 ;;
esac
