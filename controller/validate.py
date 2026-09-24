SUPPORTED_MODES = {"tunnel", "transport"}

SUPPORTED_ADDRESS_FAMILIES = {"ipv4", "ipv6"}

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
    "aes128cbc",
    "aes256cbc",
}

SUPPORTED_ESP_INTEGRITY = {
    "sha256",
    "sha384",
    "sha512",
}


def validate_config(config):
    if config["mode"] not in SUPPORTED_MODES:
        raise ValueError(
            f"Unsupported mode: {config['mode']}"
        )

    if config["address_family"] not in SUPPORTED_ADDRESS_FAMILIES:
        raise ValueError(
            f"Unsupported address family: {config['address_family']}"
        )

    ike = config["ike"]
    esp = config["esp"]

    # IKE version
    if ike["version"] not in {1, 2}:
        raise ValueError("IKE version must be 1 or 2")

    # IKE encryption
    if ike["encryption"] not in SUPPORTED_IKE_ENCRYPTION:
        raise ValueError(
            f"Unsupported IKE encryption: {ike['encryption']}"
        )

    # IKE integrity
    if ike["integrity"] not in SUPPORTED_IKE_INTEGRITY:
        raise ValueError(
            f"Unsupported IKE integrity: {ike['integrity']}"
        )

    # IKE DH group
    if ike["dh_group"] not in SUPPORTED_DH_GROUPS:
        raise ValueError(
            f"Unsupported IKE DH group: {ike['dh_group']}"
        )

    # ESP encryption
    if esp["encryption"] not in SUPPORTED_ESP:
        raise ValueError(
            f"Unsupported ESP encryption: {esp['encryption']}"
        )

    # ESP integrity
    if esp["encryption"] in {"aes128cbc", "aes256cbc"}:
        if esp["integrity"] not in SUPPORTED_ESP_INTEGRITY:
            raise ValueError(
                "CBC ESP requires an integrity algorithm"
            )
    else:
        if esp["integrity"] is not None:
            raise ValueError(
                "GCM ESP must not specify a separate integrity algorithm"
            )

    # ESP DH group
    if esp["dh_group"] not in SUPPORTED_DH_GROUPS:
        raise ValueError(
            f"Unsupported ESP DH group: {esp['dh_group']}"
        )

    # PFS
    if not isinstance(esp["pfs"], bool):
        raise ValueError("PFS must be true or false")

    return True
