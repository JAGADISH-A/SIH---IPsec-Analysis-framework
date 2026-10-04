TOPOLOGIES = {
    "tunnel": {
        "ipv4": {
            "local": {
                "id": "gw-a",
                "ip": "192.168.100.1",
                "ts": "10.10.1.0/24",
                "node": "gw-a",
            },
            "remote": {
                "id": "gw-b",
                "ip": "192.168.100.2",
                "ts": "10.10.2.0/24",
                "node": "gw-b",
            },
        },
        "ipv6": {
            "local": {
                "id": "gw-a",
                "ip": "192.168.100.1",
                "ts": "2001:db8:1::/64",
                "node": "gw-a",
            },
            "remote": {
                "id": "gw-b",
                "ip": "192.168.100.2",
                "ts": "2001:db8:2::/64",
                "node": "gw-b",
            },
        },
    },

    "transport": {
        "ipv4": {
            "local": {
                "id": "host-c",
                "ip": "10.20.1.10",
                "ts": "10.20.1.10/32",
                "node": "host-c",
            },
            "remote": {
                "id": "host-d",
                "ip": "10.20.1.20",
                "ts": "10.20.1.20/32",
                "node": "host-d",
            },
        },
        "ipv6": {
            "local": {
                "id": "host-c",
                "ip": "2001:db8:20::10",
                "ts": "2001:db8:20::10/128",
                "node": "host-c",
            },
            "remote": {
                "id": "host-d",
                "ip": "2001:db8:20::20",
                "ts": "2001:db8:20::20/128",
                "node": "host-d",
            },
        },
    },
}


# NAT-T deployments of the same two IPsec modes.
#
# ``mode`` stays ``transport``/``tunnel`` - NAT is a property of the *path*, not
# a third encapsulation mode, so nothing downstream (comparison, risk, XAI,
# evidence) needs a new branch.  What changes is the addressing: the peers sit
# on opposite sides of a real network address translator, so each host's idea
# of its peer's address differs.
#
# ``masquerade`` is the address the NAT node SNATs the LAN prefix onto.  The
# LAN-side peer keeps pointing at the WAN-side peer's real address; the
# WAN-side peer must point at the MASQUERADE address, because that is what
# actually arrives from the LAN side.
NAT_TOPOLOGIES = {
    ("transport", "ipv4"): {
        "local": {
            "id": "host-c",
            "ip": "10.20.1.10",
            "ts": "10.20.1.10/32",
            "node": "host-c",
        },
        "remote": {
            "id": "host-d",
            "ip": "10.30.1.20",
            "ts": "10.30.1.20/32",
            "node": "host-d",
        },
        "nat": {
            "masquerade": "10.30.1.1",
            "lan_prefix": "10.20.1.0/24",
            "wan_prefix": "10.30.1.0/24",
            "node": "nat",
        },
    },
}


def deployment_key(mode, nat=False):
    """Return the deployment directory/container-lab key for a sample.

    ``mode`` alone identifies the IPsec encapsulation; ``nat`` adds the
    translator to the path.  The key doubles as the topology directory name
    (``topology/<key>/ipsec.clab.yml``) and the containerlab lab name, so
    ``transport`` -> ``ipsec-transport`` and ``transport``+NAT ->
    ``ipsec-transport-nat`` stay distinct labs that are never co-resident.
    """
    if not nat:
        if mode not in TOPOLOGIES:
            raise ValueError(f"Unsupported mode: {mode}")
        return mode
    if (mode, "ipv4") not in NAT_TOPOLOGIES:
        raise ValueError(
            f"No NAT deployment is defined for mode {mode!r}; a NAT path is "
            "only implemented where a real translator can be provisioned."
        )
    return f"{mode}-nat"


def resolve_topology(mode, address_family, nat=False):
    """Return the endpoint table for a sample, honouring the NAT axis."""
    if nat:
        key = (mode, address_family)
        if key not in NAT_TOPOLOGIES:
            raise ValueError(
                f"No NAT deployment is defined for mode {mode!r} / address "
                f"family {address_family!r}."
            )
        return NAT_TOPOLOGIES[key]

    if mode not in TOPOLOGIES:
        raise ValueError(f"Unsupported mode: {mode}")
    topology = TOPOLOGIES[mode]
    if address_family not in topology:
        raise ValueError(
            f"Unsupported address family '{address_family}' for {mode}"
        )
    return topology[address_family]


#: Containerlab lab name per deployment key.
#:
#: A containerlab container is always ``clab-<lab name>-<node>``, where the lab
#: name is the ``name:`` field of the topology file, NOT the deployment key.
#: The key and the lab name coincide for ``transport`` and ``transport-nat``
#: (``ipsec-transport`` / ``ipsec-transport-nat``), but the base tunnel lab is
#: named ``ipsec`` and so its containers carry no ``tunnel`` segment. The
#: unprefixed tunnel naming is the convention the rest of the controller already
#: assumes (see ``controller/capture.py`` and ``controller/timing.py``, which map
#: tunnel to ``clab-ipsec-gw-a`` and ``clab-ipsec-sensor``).
LAB_NAMES = {
    "tunnel": "ipsec",
    "transport": "ipsec-transport",
    "transport-nat": "ipsec-transport-nat",
}


def container_name(key, node):
    """Containerlab container name for a node in a given deployment."""
    return f"clab-{LAB_NAMES.get(key, f'ipsec-{key}')}-{node}"
