"""Passive observation / TAP provisioning for the IPsec audit layer.

The tunnel-mode WAN link in this testbed is a *container-to-container* veth
pair (``gw-a eth2 <-> gw-b eth2``) with no host-side termination, so the
host cannot observe the encrypted stream directly.  The observation surface
is therefore provisioned inside the source gateway's network namespace:

    gw-a eth2 --tc mirred(mirror ing+eg)--> audit-mir <--> audit-tap0
                                              (sink)         ^ read by tshark

``tc mirred`` ``egress mirror`` actions only *copy* frames into the sink
veth; the original frame keeps its path, so the IPsec forwarding topology is
untouched and the observation point is strictly passive.

Provisioning is idempotent and is executed either automatically at container
start (``scripts/gw-entrypoint.sh`` when ``AUDIT_TAP_IFACE`` is set, see the
tunnel topology) or on demand from the controller via ``provision_observation``
(which streams ``scripts/audit-tap-setup.sh`` into the container, so it works
even when the bind was not mounted).
"""

import subprocess
from pathlib import Path

from . import capture as capture_mod

SINK_IFACE = "audit-mir"
TAP_IFACE = "audit-tap0"
SETUP_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "audit-tap-setup.sh"

# Sentinel field names used by ``observation_status`` (kept as plain strings
# so the wrapped `sh` snippet stays readable).
_MARKERS = (
    "tap_present",
    "sink_present",
    "tap_operstate",
    "ingress_filters",
    "egress_filters",
    "ingress_sent",
    "egress_sent",
)


def _exec(container, *argv, check=True):
    result = subprocess.run(
        ["sudo", "docker", "exec", container, *argv],
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"docker exec {container} {' '.join(argv)} failed "
            f"(rc={result.returncode}): {result.stderr.strip()}"
        )
    return result


def observation_target(mode="tunnel", address_family="ipv4", wan_ip=None):
    """Return (container, wan_ip, mirror_iface) for the observation point.

    The container and its WAN address come from the verified capture mapping
    (``capture.py``); the concrete mirror interface (eth1/eth2/...) is
    resolved live, never hardcoded -- the same convention as
    ``capture.detect_capture_interface``.
    """
    container, cap_wan_ip = capture_mod.capture_facing(mode, address_family)
    wan_ip = wan_ip or cap_wan_ip
    mirror_iface = capture_mod.detect_capture_interface(container, wan_ip)
    return container, wan_ip, mirror_iface


def provision_observation(mode="tunnel", address_family="ipv4", wan_ip=None,
                          log=None):
    """Provision the passive mirror + observation interface (idempotent).

    Streams ``scripts/audit-tap-setup.sh`` into the gateway container and
    runs it with the resolved mirror interface.  Re-running is safe: the
    script re-creates deterministically.  Returns
    ``observation_status(...)``.
    """
    log = log or (lambda msg: None)
    container, wan_ip, mirror_iface = observation_target(mode, address_family, wan_ip)
    script = SETUP_SCRIPT.read_text(encoding="utf-8")
    result = subprocess.run(
        ["sudo", "docker", "exec", "-i", container, "sh", "-s", "--", mirror_iface],
        input=script,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"observation provisioning failed on {container} "
            f"(rc={result.returncode}): {result.stderr.strip()}"
        )
    log(f"[observation] {container}:{mirror_iface} provisioned ({result.stdout.strip()})")
    return observation_status(mode, address_family, wan_ip)


def observation_status(mode="tunnel", address_family="ipv4", wan_ip=None):
    """Read-only report of the observation surface inside the container.

    Returns a dict with the container/interface identity, tap presence and
    state, and the installed ``tc mirred`` filter counts + sent counters.
    """
    container, wan_ip, mirror_iface = observation_target(mode, address_family, wan_ip)
    probe = (
        f"echo container={container}; echo mirror_interface={mirror_iface}; "
        f"[ -e /sys/class/net/{TAP_IFACE} ] && echo tap_present=yes || echo tap_present=no; "
        f"[ -e /sys/class/net/{SINK_IFACE} ] && echo sink_present=yes || echo sink_present=no; "
        f"cat /sys/class/net/{TAP_IFACE}/operstate 2>/dev/null | sed 's/^/tap_operstate=/' || true; "
        f"tc filter show dev {mirror_iface} ingress 2>/dev/null | grep -c mirred "
        f"| sed 's/^/ingress_filters=/'; "
        f"tc filter show dev {mirror_iface} egress 2>/dev/null | grep -c mirred "
        f"| sed 's/^/egress_filters=/'; "
        f"tc -s filter show dev {mirror_iface} ingress 2>/dev/null | grep -o 'Sent [0-9]* bytes [0-9]* pkt' "
        f"| sed 's/^/ingress_sent=/' ; "
        f"tc -s filter show dev {mirror_iface} egress 2>/dev/null | grep -o 'Sent [0-9]* bytes [0-9]* pkt' "
        f"| sed 's/^/egress_sent=/'"
    )
    result = _exec(container, "sh", "-c", probe)
    status = {"container": container, "mirror_interface": mirror_iface,
              "tap_interface": TAP_IFACE, "sink_interface": SINK_IFACE}
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key not in _MARKERS and key not in ("container", "mirror_interface"):
            continue
        status[key] = value.strip()
    return status


def verify_observation(status):
    """Return the checks performed by the safety checklist.

    ``status`` is an ``observation_status`` dict; returns a dict of
    PASS/FAIL booleans used in validation reporting.
    """
    return {
        "tap_present": status.get("tap_present") == "yes",
        "sink_present": status.get("sink_present") == "yes",
        "tap_up": status.get("tap_operstate") == "up",
        "mirror_ingress_installed": int(status.get("ingress_filters", 0) or 0) >= 1,
        "mirror_egress_installed": int(status.get("egress_filters", 0) or 0) >= 1,
    }