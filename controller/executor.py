import subprocess
import json
from pathlib import Path

from .config import CONFIG
from .topology import TOPOLOGIES
from .validate import validate_config
from .generator import write_connection


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def get_topology(mode, address_family):
    if mode not in TOPOLOGIES:
        raise ValueError(
            f"Unsupported mode: {mode}"
        )

    topology = TOPOLOGIES[mode]

    if address_family not in topology:
        raise ValueError(
            f"Unsupported address family '{address_family}' for {mode}"
        )

    return topology[address_family]


def run(command):
    print(f"$ {' '.join(command)}")

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
    )

    if result.stdout:
        print(result.stdout)

    if result.returncode != 0:
        if result.stderr:
            print(result.stderr)

        raise RuntimeError(
            f"Command failed with exit code {result.returncode}"
        )

    return result.stdout


def topology_file(mode):
    path = (
        PROJECT_ROOT
        / "topology"
        / mode
        / "ipsec.clab.yml"
    )

    if not path.exists():
        raise FileNotFoundError(
            f"Topology not found: {path}"
        )

    return path

def destroy(mode):
    topo = topology_file(mode)

    run([
        "sudo",
        "containerlab",
        "destroy",
        "-t",
        str(topo),
        "--cleanup",
    ])


def deploy(mode):
    topo = topology_file(mode)

    run([
        "sudo",
        "containerlab",
        "deploy",
        "-t",
        str(topo),
    ])


def reset_and_deploy(mode):
    print(f"\n=== Starting {mode} experiment ===\n")

    try:
        destroy(mode)
    except RuntimeError:
        pass

    deploy(mode)

    print(f"\n=== {mode} topology deployed ===\n")

def generate_configs(config):
    validate_config(config)

    mode = config["mode"]
    topology = get_topology(mode, config["address_family"])

    local = topology["local"]
    remote = topology["remote"]

    output_dir = (
        PROJECT_ROOT
        / "controller"
        / "generated"
        / mode
    )

    output_dir.mkdir(parents=True, exist_ok=True)

    local_file = output_dir / f"{local['id']}.conf"
    remote_file = output_dir / f"{remote['id']}.conf"

    write_connection(
        config,
        local,
        remote,
        local_file,
    )

    write_connection(
        config,
        remote,
        local,
        remote_file,
    )

    print(f"Generated: {local_file}")
    print(f"Generated: {remote_file}")

    return local_file, remote_file

def load_generated_configs(config):
    mode = config["mode"]

    topology = get_topology(mode, config["address_family"])

    local = topology["local"]
    remote = topology["remote"]

    local_file, remote_file = generate_configs(config)

    local_container = (
        f"clab-ipsec-transport-{local['node']}"
        if mode == "transport"
        else f"clab-ipsec-{local['node']}"
    )

    remote_container = (
        f"clab-ipsec-transport-{remote['node']}"
        if mode == "transport"
        else f"clab-ipsec-{remote['node']}"
    )

    local_tmp = f"/tmp/{local['id']}.conf"
    remote_tmp = f"/tmp/{remote['id']}.conf"

    print("\n=== Loading generated configurations ===\n")

    run([
        "sudo",
        "docker",
        "cp",
        str(local_file),
        f"{local_container}:{local_tmp}",
    ])

    run([
        "sudo",
        "docker",
        "cp",
        str(remote_file),
        f"{remote_container}:{remote_tmp}",
    ])

    run([
        "sudo",
        "docker",
        "exec",
        local_container,
        "swanctl",
        "--load-conns",
        "--file",
        local_tmp,
    ])

    run([
        "sudo",
        "docker",
        "exec",
        remote_container,
        "swanctl",
        "--load-conns",
        "--file",
        remote_tmp,
    ])

    print("\n=== Generated configurations loaded ===\n")

def initiate_ipsec(mode, address_family):
    topology = get_topology(mode, address_family)
    local = topology["local"]

    if mode == "tunnel":
        container = f"clab-ipsec-{local['node']}"
    elif mode == "transport":
        container = f"clab-ipsec-transport-{local['node']}"
    else:
        raise ValueError(f"Unsupported mode: {mode}")

    connection_name = f"{local['id']}-to-{topology['remote']['id']}"

    print("\n=== Initiating IPsec ===\n")

    run([
        "sudo",
        "docker",
        "exec",
        container,
        "swanctl",
        "--initiate",
        "--child",
        connection_name,
    ])


def test_connectivity(mode, address_family):
    if mode == "tunnel":
        source = "clab-ipsec-host-a"

        if address_family == "ipv4":
            destination = "10.10.2.10"
            ping_command = [
                "ping",
                "-c",
                "3",
                "-i",
                "0.2",
                "-W",
                "1",
                destination,
            ]
        elif address_family == "ipv6":
            destination = "2001:db8:2::10"
            ping_command = [
                "ping",
                "-6",
                "-c",
                "3",
                "-i",
                "0.2",
                "-W",
                "1",
                destination,
            ]
        else:
            raise ValueError(
                f"Unsupported address family: {address_family}"
            )
    elif mode == "transport":
        source = "clab-ipsec-transport-host-c"

        if address_family == "ipv4":
            destination = "10.20.1.20"
            ping_command = [
                "ping",
                "-c",
                "3",
                "-i",
                "0.2",
                "-W",
                "1",
                destination,
            ]
        elif address_family == "ipv6":
            destination = "2001:db8:20::20"
            ping_command = [
                "ping",
                "-6",
                "-c",
                "3",
                "-i",
                "0.2",
                "-W",
                "1",
                destination,
            ]
        else:
            raise ValueError(
                f"Unsupported address family: {address_family}"
            )
    else:
        raise ValueError(f"Unsupported mode: {mode}")

    print("\n=== Testing connectivity ===\n")

    output = run(
        ["sudo", "docker", "exec", source] + ping_command
    )

    packet_loss = None

    for line in output.splitlines():
        if "packet loss" in line:
            packet_loss = float(line.split("%")[0].split()[-1])
            break

    if packet_loss is None:
        raise RuntimeError("Could not determine packet loss")

    return {
        "packet_loss": packet_loss,
        "status": "PASS" if packet_loss == 0 else "FAIL",
    }
def verify_ipsec(mode, address_family):
    topology = get_topology(mode, address_family)

    local = topology["local"]

    source = (
        f"clab-ipsec-transport-{local['node']}"
        if mode == "transport"
        else f"clab-ipsec-{local['node']}"
    )

    print("\n=== Verifying IPsec SA ===\n")

    output = run([
        "sudo",
        "docker",
        "exec",
        source,
        "swanctl",
        "--list-sas",
    ])

    if "ESTABLISHED" not in output:
        raise RuntimeError("IKE SA is not established")

    if "INSTALLED" not in output:
        raise RuntimeError("CHILD SA is not installed")

    expected_mode = mode.upper()

    if expected_mode not in output:
        raise RuntimeError(
            f"Expected {expected_mode} IPsec SA not found"
        )

    print("IPsec SA verification: PASS")

    return {
      "ike_sa": "ESTABLISHED",
      "child_sa": "INSTALLED",
      "mode": expected_mode,
}

def run_experiment(config):
    mode = config["mode"]
    address_family = config["address_family"]

    validate_config(config)

    reset_and_deploy(mode)
    load_generated_configs(config)
    initiate_ipsec(mode, address_family)
    ipsec = verify_ipsec(mode, address_family)
    connectivity = test_connectivity(mode, address_family)


    result = {
        "status": (
            "PASS"
            if connectivity["status"] == "PASS"
            else "FAIL"
        ),
        "mode": mode,
        "address_family": address_family,
        "ike": config["ike"],
        "esp": config["esp"],
        "connectivity": connectivity,
        "ipsec": ipsec,
    }

    return result


if __name__ == "__main__":
    result = run_experiment(CONFIG)

    print("\n=== Experiment Result ===\n")
    print(json.dumps(result, indent=2))
