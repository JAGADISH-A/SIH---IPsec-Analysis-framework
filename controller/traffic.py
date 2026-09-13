"""Traffic generation orchestration for the IPsec testbed.

Handles the runtime mapping (which container is the sender / receiver),
copies scripts/trafficgen.py into the containers and drives the
generation for a traffic trial.
"""

import subprocess
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TRAFFIC_GEN = PROJECT_ROOT / "scripts" / "trafficgen.py"
DEFAULT_PORT = 20000


def runtime(mode, address_family):
    """Map mode + address family to the concrete sender/receiver endpoints.

    Container names and data-plane IPs are taken from the Containerlab
    topologies under topology/{mode}/ipsec.clab.yml.
    """
    if mode == "tunnel":
        if address_family == "ipv4":
            source = ("clab-ipsec-host-a", "10.10.1.10")
            destination = ("clab-ipsec-host-b", "10.10.2.10")
        elif address_family == "ipv6":
            source = ("clab-ipsec-host-a", "2001:db8:1::10")
            destination = ("clab-ipsec-host-b", "2001:db8:2::10")
        else:
            raise ValueError(f"Unsupported address family: {address_family}")
    elif mode == "transport":
        if address_family == "ipv4":
            source = ("clab-ipsec-transport-host-c", "10.20.1.10")
            destination = ("clab-ipsec-transport-host-d", "10.20.1.20")
        elif address_family == "ipv6":
            source = ("clab-ipsec-transport-host-c", "2001:db8:20::10")
            destination = ("clab-ipsec-transport-host-d", "2001:db8:20::20")
        else:
            raise ValueError(f"Unsupported address family: {address_family}")
    else:
        raise ValueError(f"Unsupported mode: {mode}")

    return {
        "source_container": source[0],
        "source_ip": source[1],
        "destination_container": destination[0],
        "destination_ip": destination[1],
    }


def copy_trafficgen(container):
    subprocess.run(
        ["sudo", "docker", "cp", str(TRAFFIC_GEN), f"{container}:/tmp/trafficgen.py"],
        check=True,
        capture_output=True,
    )


def start_receiver(container, target, port=DEFAULT_PORT, duration=45.0):
    """Start the echo/drain receiver on the destination host (detached)."""
    cmd = [
        "sudo", "docker", "exec", "-d", container,
        "python3", "/tmp/trafficgen.py",
        "--role", "recv",
        "--target", target,
        "--port", str(port),
        "--duration", str(int(duration)),
    ]
    subprocess.run(cmd, check=True, capture_output=True)


def run_sender(container, profile, target, port=DEFAULT_PORT, duration=30.0):
    """Run the traffic profile on the source host, blocking until done.

    Returns (traffic_log, status) where traffic_log is a string and
    status is "PASS" or "FAIL".
    """
    cmd = [
        "sudo", "docker", "exec", container,
        "python3", "/tmp/trafficgen.py",
        "--role", "send",
        "--profile", profile,
        "--target", target,
        "--port", str(port),
        "--duration", str(int(duration)),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=int(duration) + 30)
    log = (result.stdout or "") + (result.stderr or "")
    status = "PASS" if result.returncode == 0 else "FAIL"
    return log, status


def stop_receiver(container):
    # The [t] bracket avoids pkill matching its own sh -c command line.
    subprocess.run(
        ["sudo", "docker", "exec", container, "sh", "-c", "pkill -f '[t]rafficgen.py' || true"],
        capture_output=True,
    )


def wait_receiver(source_container, dest_ip, port=DEFAULT_PORT, timeout=15.0):
    """Wait until the listener on the destination is accepting connections.

    Probes from the source container (so the connection also traverses the
    same VPN path the traffic will use) and returns once a TCP connection to
    dest_ip:port succeeds.  Raises RuntimeError if the listener never becomes
    ready, so a trial fails cleanly instead of sending into a dead listener.
    """
    family = "AF_INET6" if ":" in dest_ip else "AF_INET"
    probe = (
        f"import socket; s=socket.socket(socket.{family}); "
        f"s.settimeout(1); s.connect((\"{dest_ip}\", {port})); print(\"OK\")"
    )
    deadline = time.time() + timeout
    while time.time() < deadline:
        res = subprocess.run(
            ["sudo", "docker", "exec", source_container, "python3", "-c", probe],
            capture_output=True,
            text=True,
        )
        if res.returncode == 0:
            return True
        time.sleep(0.5)
    raise RuntimeError(
        f"listener at {dest_ip}:{port} was not ready within {timeout:.0f}s"
    )