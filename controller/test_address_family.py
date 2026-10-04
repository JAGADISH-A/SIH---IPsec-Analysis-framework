"""Address-family coverage for the swanctl configuration generator.

The tunnel and transport topologies are selected by ``address_family``, so the
generator has to emit the family's own addresses and selectors on BOTH peers.
A symmetric pair is the whole correctness argument for negotiation: the
initiator's ``remote_addrs`` and the responder's ``local_addrs`` must be the
same host, and their traffic selectors must be each other's.

These tests pin that for IPv4 and IPv6 across both modes, and pin the NAT axis
as IPv4-only so an IPv6 NAT sample stays an explicit error instead of being
silently generated from an absent topology entry.
"""

import ipaddress
import unittest

from controller.executor import generate_configs
from controller.topology import (
    NAT_TOPOLOGIES,
    TOPOLOGIES,
    container_name,
    deployment_key,
    resolve_topology,
)
from controller.traffic import runtime


BASE_CONFIG = {
    "ike": {"version": 2, "encryption": "aes256", "integrity": "sha256",
            "dh_group": "modp2048"},
    "esp": {"encryption": "aes128gcm16", "integrity": None,
            "dh_group": "modp4096", "pfs": True},
    "traffic": {"profile": "voip", "duration": 20},
}

FAMILIES = ("ipv4", "ipv6")


def generate(mode, address_family, nat=False, output_dir=None):
    config = dict(
        BASE_CONFIG,
        mode=mode,
        address_family=address_family,
        nat=nat,
    )
    return generate_configs(config)


class TestAddressFamilyTopology(unittest.TestCase):
    """Both declared families resolve for both modes."""

    def test_both_families_exist_for_both_modes(self):
        for mode in TOPOLOGIES:
            with self.subTest(mode=mode):
                self.assertEqual(sorted(TOPOLOGIES[mode]), ["ipv4", "ipv6"])

    def test_resolve_topology_returns_distinct_selectors_per_family(self):
        for mode in TOPOLOGIES:
            v4 = resolve_topology(mode, "ipv4")
            v6 = resolve_topology(mode, "ipv6")
            with self.subTest(mode=mode):
                self.assertNotEqual(v4["local"]["ts"], v6["local"]["ts"])
                self.assertNotEqual(v4["remote"]["ts"], v6["remote"]["ts"])

    def test_ipv6_tunnel_selectors_are_ipv6(self):
        # Tunnel mode carries IPv6 LAN traffic over the IPv4 WAN link, so the
        # selectors must be IPv6 prefixes while the endpoint addresses stay on
        # the IPv4 WAN side.
        topology = resolve_topology("tunnel", "ipv6")
        for side in ("local", "remote"):
            with self.subTest(side=side):
                self.assertIn(":", topology[side]["ts"])

    def test_ipv6_transport_endpoints_are_ipv6(self):
        # In transport mode the IPsec endpoints ARE the protected hosts, so
        # both the address and the selector must be IPv6.
        topology = resolve_topology("transport", "ipv6")
        for side in ("local", "remote"):
            with self.subTest(side=side):
                self.assertIn(":", topology[side]["ip"])
                self.assertIn(":", topology[side]["ts"])
                self.assertTrue(topology[side]["ts"].endswith("/128"))

    def test_unsupported_address_family_is_rejected(self):
        with self.assertRaises(ValueError):
            resolve_topology("tunnel", "ipv5")

    def test_container_names_do_not_depend_on_address_family(self):
        # ``wait_for_ipsec_ready()`` resolves its container names through the
        # IPv4 table. That is only correct because deployment keys and node
        # names are family-independent, so both families poll the very same
        # containers. Pin the invariant instead of threading the family into
        # the gate.
        for mode in TOPOLOGIES:
            with self.subTest(mode=mode):
                ipv4_node = resolve_topology(mode, "ipv4")["local"]["node"]
                ipv6_node = resolve_topology(mode, "ipv6")["local"]["node"]
                self.assertEqual(ipv4_node, ipv6_node)
                key = deployment_key(mode, nat=False)
                self.assertEqual(
                    container_name(key, ipv4_node),
                    container_name(key, ipv6_node),
                )
                self.assertEqual(key, deployment_key(mode, nat=False))


class TestNatAxisIsIpv4Only(unittest.TestCase):
    """NAT-T stays explicitly IPv4-only.

    ``NAT_TOPOLOGIES`` has a single key, so there is no IPv6 translator
    deployment to generate from. The requirement is that asking for one fails
    loudly instead of falling back to an IPv4 address table.
    """

    def test_nat_topologies_declare_only_transport_ipv4(self):
        self.assertEqual(sorted(NAT_TOPOLOGIES), [("transport", "ipv4")])

    def test_transport_ipv6_nat_is_rejected(self):
        with self.assertRaises(ValueError):
            resolve_topology("transport", "ipv6", nat=True)

    def test_tunnel_nat_is_rejected_for_every_family(self):
        for family in FAMILIES:
            with self.subTest(family=family):
                with self.assertRaises(ValueError):
                    deployment_key("tunnel", nat=True)

    def test_transport_ipv6_nat_has_no_traffic_endpoint(self):
        with self.assertRaises(ValueError):
            runtime("transport", "ipv6", nat=True)


class TestGeneratedConfigPerFamily(unittest.TestCase):
    """Both peers must agree, and the family must reach the wire."""

    def _assert_pair(self, mode, family, nat=False):
        local_file, remote_file = generate(mode, family, nat=nat)
        local_text = local_file.read_text(encoding="utf-8")
        remote_text = remote_file.read_text(encoding="utf-8")

        topology = resolve_topology(mode, family, nat=nat)
        a, b = topology["local"], topology["remote"]

        # Each side must point at the other host, never at itself. A peer
        # generated against itself is the failure that previously made every
        # non-NAT run answer IKE_SA_INIT with NO_PROPOSAL_CHOSEN.
        self.assertIn(f"id-1 = {a['id']}", local_text)
        self.assertIn(f"id-2 = {b['id']}", local_text)
        self.assertIn(f"id-1 = {b['id']}", remote_text)
        self.assertIn(f"id-2 = {a['id']}", remote_text)

        # The LAN-side peer always targets the peer's real address. The
        # WAN-side peer targets the address that actually arrives from the
        # other side, which under NAT is the masquerade address rather than
        # the topology table's LAN-side address.
        if nat:
            wan_addr = topology["nat"]["masquerade"]
            wan_ts = f"{wan_addr}/32"
        else:
            wan_addr = a["ip"]
            wan_ts = a["ts"]

        # Initiator's remote address == responder's local address.
        self.assertIn(f"local_addrs = {a['ip']}", local_text)
        self.assertIn(f"remote_addrs = {b['ip']}", local_text)
        self.assertIn(f"local_addrs = {b['ip']}", remote_text)
        self.assertIn(f"remote_addrs = {wan_addr}", remote_text)

        # Selectors must be mirrored, not duplicated.
        self.assertIn(f"local_ts = {a['ts']}", local_text)
        self.assertIn(f"remote_ts = {b['ts']}", local_text)
        self.assertIn(f"local_ts = {b['ts']}", remote_text)
        self.assertIn(f"remote_ts = {wan_ts}", remote_text)

        # The requested crypto must survive verbatim on both sides.
        for text in (local_text, remote_text):
            self.assertIn("proposals = aes256-sha256-modp2048", text)
            self.assertIn("esp_proposals = aes128gcm16-modp4096", text)
            self.assertIn(f"mode = {mode}", text)
        return local_text, remote_text

    def test_tunnel_ipv4(self):
        self._assert_pair("tunnel", "ipv4")

    def test_tunnel_ipv6(self):
        local_text, remote_text = self._assert_pair("tunnel", "ipv6")
        # IPv6 selectors on an IPv4 WAN link: the selectors must be v6, the
        # endpoint addresses must not.
        self.assertIn("local_ts = 2001:db8:1::/64", local_text)
        self.assertIn("remote_ts = 2001:db8:2::/64", local_text)
        self.assertIn("local_ts = 2001:db8:2::/64", remote_text)
        self.assertIn("remote_ts = 2001:db8:1::/64", remote_text)

    def test_transport_ipv4(self):
        self._assert_pair("transport", "ipv4")

    def test_transport_ipv6(self):
        local_text, remote_text = self._assert_pair("transport", "ipv6")
        self.assertIn("local_ts = 2001:db8:20::10/128", local_text)
        self.assertIn("remote_ts = 2001:db8:20::20/128", local_text)
        self.assertIn("local_ts = 2001:db8:20::20/128", remote_text)
        self.assertIn("remote_ts = 2001:db8:20::10/128", remote_text)
        # Transport mode also needs the IKE bypass connection, or the trap
        # policy deadlocks on the UDP/500 negotiation itself.
        self.assertIn("mode = pass", local_text)
        self.assertIn("dynamic[udp/500]", local_text)
        self.assertIn("mode = pass", remote_text)

    def test_transport_nat_ipv4(self):
        # The NAT peer is reached through the masquerade address, which is the
        # one case where the remote address is NOT the topology table's.
        local_text, remote_text = self._assert_pair("transport", "ipv4", nat=True)
        topology = resolve_topology("transport", "ipv4", nat=True)
        masquerade = topology["nat"]["masquerade"]
        self.assertIn(f"remote_addrs = {masquerade}", remote_text)
        self.assertIn("dynamic[udp/4500]", remote_text)


class TestTrafficEndpointsPerFamily(unittest.TestCase):
    """Traffic must actually target the family's addresses.

    Connectivity/traffic verification is only meaningful over IPv6 if the
    generator is pointed at an IPv6 destination, so the endpoint table is
    asserted per family rather than assumed.
    """

    def test_endpoints_follow_the_selected_family(self):
        for mode in ("tunnel", "transport"):
            for family in FAMILIES:
                endpoints = runtime(mode, family)
                expect_colon = family == "ipv6"
                with self.subTest(mode=mode, family=family):
                    for key in ("source_ip", "destination_ip"):
                        self.assertEqual(":" in endpoints[key], expect_colon)

    def test_endpoints_match_topology_traffic_selectors(self):
        # The traffic destination must live inside the peer's negotiated
        # selector, otherwise the tunnel carries traffic that its own policy
        # rejects and every trial fails as a black hole.
        for mode in ("tunnel", "transport"):
            for family in FAMILIES:
                topology = resolve_topology(mode, family)
                endpoints = runtime(mode, family)
                with self.subTest(mode=mode, family=family):
                    self.assertIn(
                        ipaddress.ip_address(endpoints["source_ip"]),
                        ipaddress.ip_network(topology["local"]["ts"]),
                    )
                    self.assertIn(
                        ipaddress.ip_address(endpoints["destination_ip"]),
                        ipaddress.ip_network(topology["remote"]["ts"]),
                    )


if __name__ == "__main__":
    unittest.main()