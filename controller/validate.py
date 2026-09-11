SUPPORTED_MODES = {
    "tunnel",
    "transport",
}

SUPPORTED_IKE_ENCRYPTION = {
    "aes128",
    "aes256",
}

SUPPORTED_IKE_INTEGRITY = {
    "sha256",
    "sha384",
    "sha512",
}

SUPPORTED_DH_GROUPS = {
    "modp2048",
    "modp3072",
    "modp4096",
}

SUPPORTED_ESP = {
    "aes128gcm16",
    "aes256gcm16",
}


def validate_config(config):
    mode = config["mode"]

    if mode not in SUPPORTED_MODES:
        raise ValueError(f"Unsupported mode: {mode}")

    ike = config["ike"]
    esp = config["esp"]

    if ike["version"] != 2:
        raise ValueError("Only IKEv2 is currently supported")

    if ike["encryption"] not in SUPPORTED_IKE_ENCRYPTION:
        raise ValueError(
            f"Unsupported IKE encryption: {ike['encryption']}"
        )

    if ike["integrity"] not in SUPPORTED_IKE_INTEGRITY:
        raise ValueError(
            f"Unsupported IKE integrity: {ike['integrity']}"
        )

    if ike["dh_group"] not in SUPPORTED_DH_GROUPS:
        raise ValueError(
            f"Unsupported IKE DH group: {ike['dh_group']}"
        )

    if esp["encryption"] not in SUPPORTED_ESP:
        raise ValueError(
            f"Unsupported ESP encryption: {esp['encryption']}"
        )

    if esp["dh_group"] not in SUPPORTED_DH_GROUPS:
        raise ValueError(
            f"Unsupported ESP DH group: {esp['dh_group']}"
        )

    if not isinstance(esp["pfs"], bool):
        raise ValueError("PFS must be True or False")

    return True
