CONFIG = {
    "mode": "tunnel",
    "address_family": "ipv4",
    # NAT is an orthogonal property of the *path*, not an IPsec encapsulation
    # mode.  False keeps the existing direct deployments byte-identical; True
    # routes the sample through a real network address translator, where
    # strongSwan must detect the translation and switch to UDP encapsulation.
    "nat": False,

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