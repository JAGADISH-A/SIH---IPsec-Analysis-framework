#!/bin/bash
#
# NAT node for the transport-NAT (NAT-T) topology.
#
# This node is the ONLY thing that makes the path a genuine NAT: it forwards
# between the LAN (eth1) and WAN (eth2) segments and MASQUERADEs host-c's
# source address onto the WAN address.  Nothing about the IPsec itself is
# faked here - strongSwan on the two hosts has to detect the address
# translation on its own (NATD_S_IP / NATD_D_IP) before it will switch IKE and
# ESP onto UDP/4500.  If this node stopped NATting, the topology would still
# work as plain IPsec but would report native protocol-50 ESP, not NAT-T.
#
# It also runs no observer and hosts no experiment: it is plain infrastructure.

set -e

echo "[NAT] Enabling IPv4 forwarding"
echo 1 > /proc/sys/net/ipv4/ip_forward

# Non-default policies are not relied upon; the rule is appended so the docker
# defaults this image ships with stay intact.
iptables -P FORWARD ACCEPT
iptables -t nat -A POSTROUTING -s 10.20.1.0/24 -o eth2 -j MASQUERADE

echo "[NAT] Active NAT rules:"
iptables -t nat -S POSTROUTING
echo "[NAT] Ready"

# Keep the container alive: containerlab runs this script as the node's PID 1
# (the image's own CMD is overridden by the topology), so exiting here would
# take the node - and every link hanging off it - down mid-deploy.
exec sleep infinity