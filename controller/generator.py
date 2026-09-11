from pathlib import Path


PSK = "test-ipsec-psk-2026"


def generate_swanctl_config(config, local, remote):
    ike = config["ike"]
    esp = config["esp"]

    connection_name = f"{local['id']}-to-{remote['id']}"

    ike_proposal = (
        f"{ike['encryption']}-"
        f"{ike['integrity']}-"
        f"{ike['dh_group']}"
    )

    esp_proposal = esp["encryption"]

    if esp["pfs"]:
        esp_proposal += f"-{esp['dh_group']}"

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

                start_action = trap
            }}
        }}

        proposals = {ike_proposal}
    }}
}}
"""


def write_connection(config, local, remote, output_file):
    content = generate_swanctl_config(
        config,
        local,
        remote,
    )

    Path(output_file).write_text(content)
