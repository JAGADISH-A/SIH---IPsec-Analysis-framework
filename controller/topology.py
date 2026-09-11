TOPOLOGIES = {
    "tunnel": {
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

    "transport": {
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
}
