from pathlib import Path

PSK = "test-ipsec-psk-2026"


def generate_swanctl_config(config, local, remote):
    ike = config["ike"]
    esp = config["esp"]

    connection_name = f"{local['id']}-to-{remote['id']}"

    # IKE proposal
    ike_proposal = (
        f"{ike['encryption']}-"
        f"{ike['integrity']}-"
        f"{ike['dh_group']}"
    )

    # ESP proposal
    if esp["encryption"] in {"aes128cbc", "aes256cbc"}:
        esp_cipher = esp["encryption"].replace("cbc", "")
        esp_proposal = f"{esp_cipher}-{esp['integrity']}"
    else:
        esp_proposal = esp["encryption"]

    # Add DH group to ESP proposal when PFS is enabled
    if esp["pfs"]:
        esp_proposal += f"-{esp['dh_group']}"

    # In transport mode the traffic selectors are the tunnel endpoint
    # addresses themselves, so a trap policy would also match the IKE
    # (UDP 500/4500) traffic sent to the peer, deadlocking negotiation.
    # Defer the install to the explicit swanctl --initiate and bypass IKE.
    transport = config["mode"] == "transport"
    start_action = "none" if transport else "trap"

    bypass = ""
    if transport:
        bypass = f"""
    {connection_name}-ike-bypass {{
        version = {ike['version']}
        local_addrs = {local['ip']}
        remote_addrs = {remote['ip']}

        children {{
            {connection_name}-ike-bypass {{
                mode = pass
                local_ts = dynamic[udp/500]
                remote_ts = dynamic[udp/500]
                start_action = trap
            }}
        }}
    }}
"""

    return f"""secrets {{
    ike-psk {{
        id-1 = {local['id']}
        id-2 = {remote['id']}
        secret = "{PSK}"
    }}
}}

connections {{
    {connection_name} {{
        version = {ike['version']}
        local_addrs = {local['ip']}
        remote_addrs = {remote['ip']}

        local {{
            auth = psk
            id = {local['id']}
        }}

        remote {{
            auth = psk
            id = {remote['id']}
        }}

        children {{
            {connection_name} {{
                mode = {config['mode']}
                local_ts = {local['ts']}
                remote_ts = {remote['ts']}
                esp_proposals = {esp_proposal}
                start_action = {start_action}
            }}
        }}

        proposals = {ike_proposal}
    }}
    {bypass}
}}
"""


def write_connection(config, local, remote, output_file):
    content = generate_swanctl_config(config, local, remote)
    Path(output_file).write_text(content)
