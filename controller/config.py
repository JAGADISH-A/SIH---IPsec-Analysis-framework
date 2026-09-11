CONFIG = {
    "mode": "transport",

    "ike": {
        "version": 2,
        "encryption": "aes256",
        "integrity": "sha256",
        "dh_group": "modp2048",
    },

    "esp": {
        "encryption": "aes128gcm16",
        "dh_group": "modp2048",
        "pfs": False,
    },
}
