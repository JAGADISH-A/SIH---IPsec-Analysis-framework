import subprocess
import json
from pathlib import Path

from .config import CONFIG
from .topology import TOPOLOGIES
from .validate import validate_config
from .generator import write_connection
from . import traffic as traffic_mod


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

    # Destroy EVERY containerlab topology before deploying.  The run may have
    # kept a different-mode topology alive for reuse, or resumed over one.
    for m in ("tunnel", "transport"):
        try:
            destroy(m)
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


def terminate_sas(mode, address_family):
    """Terminate the current IKE/CHILD SAs on both gateway containers.

    Used by the Module-10 reuse path BEFORE reloading a new StrongSwan
    configuration: dropping the existing IKE/CHILD SAs guarantees that a
    stale negotiated proposal cannot survive a config-only reload (see the
    Module-9 design §4/§13 ordering).

    Container and connection naming follow the exact conventions already used
    by ``initiate_ipsec``/``verify_ipsec``/``load_generated_configs``.  A
    termination error is not fatal: an already-terminated or nonexistent SA
    must not make a valid reuse path fail (best-effort teardown).

    Only the explicit per-connection CHILD/IKE terminations are used; the
    unsupported ``swanctl --terminate --all`` form is deliberately never
    invoked.
    """
    topology = get_topology(mode, address_family)
    local = topology["local"]
    remote = topology["remote"]

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

    connection_name = f"{local['id']}-to-{topology['remote']['id']}"

    containers = [local_container, remote_container]

    print("\n=== Terminating existing IPsec SAs ===\n")

    for container in containers:
        for command in (
            ["--terminate", "--child", connection_name],
            ["--terminate", "--ike", connection_name],
        ):
            try:
                run([
                    "sudo",
                    "docker",
                    "exec",
                    container,
                    "swanctl",
                    *command,
                ])
            except RuntimeError:
                pass

    print("\n=== Existing IPsec SAs terminated ===\n")


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

def validate_traffic(traffic):
    profile = traffic["profile"]
    duration = traffic.get("duration", traffic_mod.DEFAULT_DURATION)

    if profile not in traffic_mod.PROFILES:
        raise ValueError(
            f"Unsupported traffic profile: {profile}"
        )

    if not isinstance(duration, (int, float)) or isinstance(duration, bool):
        raise ValueError("Traffic duration must be a number")

    lo, hi = traffic_mod.DURATION_RANGE
    if duration < lo or duration > hi:
        raise ValueError(
            f"Traffic duration must be between {lo} and {hi} seconds"
        )

    return profile, int(duration)


def run_traffic(config):
    mode = config["mode"]
    address_family = config["address_family"]
    profile, duration = validate_traffic(config["traffic"])

    runtime_ctx = traffic_mod.runtime(mode, address_family)

    print(f"\n=== Running traffic profile: {profile} ({duration}s) ===\n")

    source = runtime_ctx["source_container"]
    destination = runtime_ctx["destination_container"]
    dest_ip = runtime_ctx["destination_ip"]
    port = traffic_mod.DEFAULT_PORT

    traffic_mod.copy_trafficgen(source)
    traffic_mod.copy_trafficgen(destination)

    traffic_mod.start_receiver(
        destination, dest_ip, port=port, duration=duration + 10,
    )
    traffic_mod.wait_receiver(source, dest_ip, port=port)
    print("traffic listener ready")

    log, status = traffic_mod.run_sender(
        source, profile, dest_ip, port=port, duration=duration,
    )
    traffic_mod.stop_receiver(destination)

    stats = {"packets": None, "bytes": None, "seconds": None, "bitrate_bps": None}

    for line in log.splitlines():
        if line.startswith("STATS"):
            parts = dict(
                chunk.split("=", 1)
                for chunk in line.split()
                if "=" in chunk
            )
            stats = {
                "packets": int(parts["packets"]),
                "bytes": int(parts["bytes"]),
                "seconds": float(parts["seconds"]),
                "bitrate_bps": float(parts["bitrate"].rstrip("_bps")),
            }
            break

    packets_per_second = (
        round(stats["packets"] / stats["seconds"], 2)
        if stats["seconds"]
        else None
    )

    print(f"traffic status: {status} (packets={stats['packets']}, "
          f"bitrate={stats['bitrate_bps']}bps)")

    return {
        "status": status,
        "profile": profile,
        "duration": duration,
        "port": port,
        **stats,
        "packets_per_second": packets_per_second,
    }


def run_experiment(config, on_stage=None):
    mode = config["mode"]
    address_family = config["address_family"]

    validate_config(config)

    if "traffic" in config and config["traffic"] is not None:
        profile, duration = validate_traffic(config["traffic"])
    else:
        profile, duration = None, None

    def stage(stage):
        if on_stage is not None:
            on_stage(stage)

    stage("DEPLOY")
    reset_and_deploy(mode)
    stage("IPSEC")
    load_generated_configs(config)
    initiate_ipsec(mode, address_family)
    ipsec = verify_ipsec(mode, address_family)
    stage("CONNECTIVITY")
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

    if profile is not None:
        stage("TRAFFIC")
        traffic = run_traffic(config)
        result["traffic"] = traffic

        if traffic["status"] != "PASS":
            result["status"] = "FAIL"

    return result


if __name__ == "__main__":
    result = run_experiment(CONFIG)

    print("\n=== Experiment Result ===\n")
    print(json.dumps(result, indent=2))
