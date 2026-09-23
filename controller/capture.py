"""Packet capture orchestration for the IPsec testbed.

Captures the *encrypted* IPsec traffic only (ESP) on the WAN-facing
interface of each topology, where a traffic classifier would observe the
tunneled stream.

The container WAN endpoint was verified against the running Containerlab
topologies, not assumed:

  tunnel   -> clab-ipsec-gw-a, address 192.168.100.1 (WAN link between gateways)
  transport-> clab-ipsec-transport-host-c, address 10.20.1.10 (host-to-host link)
              or 2001:db8:20::10 for the IPv6 transport link.

The concrete interface name (eth1/eth2/...) is resolved from the live
container with `ip -j addr` before each capture, never hardcoded.

tcpdump runs inside the container on a Linux veth with software ESP, so
the encrypted packets are observed exactly as they cross the wire.
"""

import json
import subprocess
import time

# All testbed privileged subprocesses run under ``sudo -n`` (non-interactive).
# A web worker must never block on an interactive sudo prompt.
SUDO = ["sudo", "-n"]

CAPTURE_COMMAND_TIMEOUT = 120.0

# Canonical capture filter for the whole testbed (single source of truth).
#
# IKE (UDP 500/4500) is purposefully captured alongside ESP (and AH, when
# used) so a capture contains the full negotiation (IKE_SA_INIT / IKE_AUTH /
# CREATE_CHILD_SA) followed by encrypted data, not ESP alone.  The capture
# *location* is unchanged: only the outer/WAN interface is observed.  An
# ESP-only capture stays available as an explicit override for legacy / parity
# evidence.
DEFAULT_CAPTURE_FILTER = "udp port 500 or udp port 4500 or esp or ah"

# For every mode/family pair we know which container carries the WAN-facing
# interface and which *IP address* must be present on it.  The concrete
# interface name (eth1, eth2, ...) is never assumed: it is resolved from the
# live container with `ip -j addr` right before each capture.
CAPTURE_TARGETS = {
    ("tunnel", "ipv4"): ("clab-ipsec-gw-a", "192.168.100.1"),
    ("tunnel", "ipv6"): ("clab-ipsec-gw-a", "192.168.100.1"),
    ("transport", "ipv4"): ("clab-ipsec-transport-host-c", "10.20.1.10"),
    ("transport", "ipv6"): ("clab-ipsec-transport-host-c", "2001:db8:20::10"),
}


def capture_facing(mode, address_family):
    if (mode, address_family) not in CAPTURE_TARGETS:
        raise ValueError(f"No capture mapping for {mode}/{address_family}")
    return CAPTURE_TARGETS[(mode, address_family)]


def detect_capture_interface(container, wan_ip):
    """Return the live interface carrying `wan_ip` inside `container`.

    Validates what the topology actually has right now instead of trusting a
    hardcoded ethX name.  Raises RuntimeError if the address is not found.
    """
    out = subprocess.run(
        [*SUDO, "docker", "exec", container, "ip", "-j", "addr"],
        capture_output=True,
        text=True,
        check=True,
        timeout=CAPTURE_COMMAND_TIMEOUT,
    ).stdout
    try:
        ifaces = json.loads(out)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"could not parse `ip -j addr` on {container}: {exc}")
    for entry in ifaces:
        name = entry.get("ifname")
        for addr in entry.get("addr_info", []):
            if addr.get("local") == wan_ip:
                return name
    raise RuntimeError(
        f"interface carrying {wan_ip} not found on {container} "
        f"(interfaces: {[e.get('ifname') for e in ifaces]})"
    )


def start_capture(container, interface, remote_path, seconds, filter_expr=DEFAULT_CAPTURE_FILTER):
    """Start tcpdump inside the container, detached.

    tcpdump runs in the *foreground* of a `docker exec -d` session wrapped in
    `timeout` (so it self-terminates even if the controller dies) and writes a
    completion marker to `<remote_path>.done` when it has finished and flushed
    the pcap.

    Deliberately daemonized into a *new session* with `setsid`: when a second
    detached exec later starts (e.g. the traffic listener), Docker tears down
    the first exec's session as soon as its shell exits, which intermittently
    kills a plainly-backgrounded or foreground tcpdump. A `setsid` session
    cannot be killed by that teardown. The `.done` marker guarantees the pcap
    is fully flushed before it is copied out.
    """
    cmd = (
        f"rm -f {remote_path} {remote_path}.done; "
        f"setsid sh -c 'timeout {int(seconds)} tcpdump -ni {interface} -s0 "
        f"-w {remote_path} {filter_expr}; touch {remote_path}.done' "
        f"< /dev/null > /dev/null 2>&1 &"
    )
    subprocess.run(
        [*SUDO, "docker", "exec", "-d", container, "sh", "-c", cmd],
        check=True,
        capture_output=True,
        timeout=CAPTURE_COMMAND_TIMEOUT,
    )


def stop_capture(container, remote_path, wait=15):
    """Stop the capture early and wait for its pcap to flush.

    Since the capture now starts BEFORE the IKE initiation (see campaign.py),
    its ``timeout`` budget is much longer than the traffic window.  Rather
    than waiting out that whole budget, we SIGTERM tcpdump right after
    traffic ends: tcpdump flushes and closes the pcap on SIGTERM, the
    ``timeout`` wrapper then emits the ``.done`` marker, and the file is
    copied out intact.  The ``timeout`` wrapper remains as the
    controller-death failsafe.
    """
    subprocess.run(
        [*SUDO, "docker", "exec", container, "sh", "-c",
         "pkill -TERM tcpdump || true"],
        capture_output=True,
        text=True,
        timeout=CAPTURE_COMMAND_TIMEOUT,
    )
    for _ in range(wait * 2):
        if _done(container, remote_path):
            time.sleep(1.0)
            return True
        time.sleep(0.5)
    return False


def _done(container, remote_path):
    probe = subprocess.run(
        [*SUDO, "docker", "exec", container, "sh", "-c",
         f"test -f {remote_path}.done"],
        capture_output=True,
        text=True,
        timeout=CAPTURE_COMMAND_TIMEOUT,
    )
    return probe.returncode == 0


def copy_capture(container, remote_path, destination):
    subprocess.run(
        [*SUDO, "docker", "cp", f"{container}:{remote_path}", str(destination)],
        check=True,
        capture_output=True,
        timeout=CAPTURE_COMMAND_TIMEOUT,
    )