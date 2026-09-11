CONFIG = {
    "mode": "tunnel",
    "address_family": "ipv4",

    "ike": {
        "version": 2,
        "encryption": "aes256",
        "integrity": "sha256",
        "dh_group": "modp2048",
    },

    "esp": {
        "encryption": "aes256cbc",
        "integrity": "sha256",
        "dh_group": "modp2048",
        "pfs": True,
    },
}