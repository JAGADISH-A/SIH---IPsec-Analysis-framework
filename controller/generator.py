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

    # On a NAT path strongSwan moves IKE from UDP/500 onto UDP/4500 as soon as
    # it detects the address translation.  The transport child's traffic
    # selector covers this host's own IKE traffic, so that retransmitted
    # negotiation would re-enter the child trap and deadlock on exactly the
    # CHILD SA that has to carry it.  The 4500 pass trap is therefore required
    # whenever a NAT is in the path; it is emitted only in that case so an
    # existing direct transport deployment keeps byte-identical output.
    nat_bypass = ""
    if transport and config.get("nat"):
        nat_bypass = f"""
    {connection_name}-ike-bypass-4500 {{
        version = {ike['version']}
        local_addrs = {local['ip']}
        remote_addrs = {remote['ip']}

        children {{
            {connection_name}-ike-bypass-4500 {{
                mode = pass
                local_ts = dynamic[udp/4500]
                remote_ts = dynamic[udp/4500]
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
    {bypass}{nat_bypass}
}}
"""


def write_connection(config, local, remote, output_file):
    content = generate_swanctl_config(config, local, remote)
    Path(output_file).write_text(content)
