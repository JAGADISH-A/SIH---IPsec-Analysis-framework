"""Live XDP/eBPF observation lifecycle for the IPsec testbed sensor.

Both topologies expose the same passive observation architecture and the same
shared live journal, so Packet Analysis never needs to know which mode produced
the packets:

  tunnel     gw-a:eth2 (WAN/IPsec side) is mirrored ingress+egress onto gw-a:eth3,
             a direct veth into ``clab-ipsec-sensor`` eth1
  transport  host-c:eth1 (host-to-host IPsec side) is mirrored ingress+egress
             onto host-c:eth2, a direct veth into ``clab-ipsec-transport-sensor``
             eth1

The mirrors are provisioned by ``scripts/audit-tap-setup.sh`` from the
authoritative host's entrypoint (``scripts/gw-entrypoint.sh`` /
``scripts/transport-entrypoint.sh``) and are pure copies: the IPsec data path is
never altered and the sensor is a sink, never an inline member.  The generic
(SKB-mode) ``ebpf/xdp_monitor`` binary turns the mirrored frames into one JSONL
event per packet, written to the shared live journal

    results/observed-state/xdp/live_events.jsonl

which is bind-mounted into the sensor at ``/opt/xdp-journal``.  The Sentinel
capture API tails that journal read-only (``correlation/api/capture_feed.py``);
it never writes it.

This module owns the *observer lifecycle* so observation is part of the
testbed lifecycle, not a manual side step:

    DEPLOY -> IPSEC -> ensure_xdp_monitor() -> CONNECTIVITY -> TRAFFIC

``ensure_xdp_monitor`` is the idempotent entry point.  It:

  * requires the sensor container, its ``eth1`` interface and the journal
    mount to be present;
  * reuses a running monitor that is already attached to the right interface
    AND already writing to the right journal (never spawns a second);
  * replaces a missing / foreign / stale monitor (kills the old one first, so
    no duplicate monitors can ever accumulate);
  * verifies the *actual process* survives in the sensor's process table
    before returning "live";
  * raises ``ObservationReadinessError`` when readiness cannot be guaranteed -
    live observation is never silently claimed while the testbed runs.

Only generic (SKB) mode is used: the lab's veth/MTU combination always
rejects native (driver) XDP first and falls back to generic, which
``scripts/run.sh`` step 9 proves with real captured events.  ``tcpdump`` stays
the dataset capture mechanism; XDP is specifically the live Sentinel
observation mechanism.
"""

import re
import subprocess
import time
from pathlib import Path

from .privileges import docker_prefix

# Legacy fixed prefix kept for tooling/docs that reference it; runtime docker
# calls resolve their prefix via ``docker_prefix()`` so the same path works on
# hosts where docker is group/rootless-reachable with no sudo (the lab only
# needs host root for ``containerlab``/``br-wan``, never for the sensor XDP
# monitor itself).
SUDO = ("sudo", "-n")

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SENSOR_CONTAINER = "clab-ipsec-sensor"
SENSOR_IFACE = "eth1"

# Per-mode passive sensor.  Both topologies expose the SAME observation
# architecture and the SAME shared live journal, so Packet Analysis is
# mode-agnostic: the only difference is which container carries the mirror
# sink interface.
#
#   tunnel    -> clab-ipsec-sensor           (mirror of gw-a:eth2 on gw-a:eth3)
#   transport -> clab-ipsec-transport-sensor (mirror of host-c:eth1 on host-c:eth2)
#
# The transport host is the authoritative observation point because in
# transport mode host-c/host-d are themselves the IPsec endpoints, so host-c's
# eth1 carries IKE + ESP for both directions.
SENSOR_TARGETS = {
    "tunnel": (SENSOR_CONTAINER, SENSOR_IFACE),
    "transport": ("clab-ipsec-transport-sensor", SENSOR_IFACE),
    # NAT-T deployment of the transport topology.  host-c is still the
    # authoritative observation point (its eth1 is an IPsec endpoint's
    # data-plane interface and therefore carries the IKE exchange and the
    # UDP/4500 ESP-in-UDP); the NAT node is infrastructure and is deliberately
    # NOT observed, so what the sensor sees is the pre-NAT wire as the sending
    # endpoint emitted it.
    "transport-nat": ("clab-ipsec-transport-nat-sensor", SENSOR_IFACE),
}

XDP_BINARY_HOST = PROJECT_ROOT / "ebpf" / "xdp_monitor"
XDP_BINARY_IN_CONTAINER = "/usr/sbin/xdp_monitor"

# Host + container side of the live-journal bind mount.  The host path is the
# exact directory BOTH topologies declare (topology/tunnel/ipsec.clab.yml on
# clab-ipsec-sensor, topology/transport/ipsec.clab.yml on
# clab-ipsec-transport-sensor) and the journal name the analytics capture API
# is pointed at via ANALYTICS_API_CAPTURE_FEED.
JOURNAL_DIRECTORY = PROJECT_ROOT / "results" / "observed-state" / "xdp"
MOUNT_DIR = "/opt/xdp-journal"
JOURNAL_FILE = "live_events.jsonl"
ERROR_FILE = "xdp.err"

OBSERVATION_COMMAND_TIMEOUT = 120.0
OBSERVATION_READY_TIMEOUT = 15.0
_POLL_INTERVAL = 0.25

# Attach markers emitted by ebpf/xdp_monitor on stderr.  The lab veth/MTU
# combo always rejects native first; generic (SKB) is the supported path.
_ATTACH_GENERIC = "SUCCESS: attached XDP in generic (SKB) mode"
_ATTACH_NATIVE = "SUCCESS: attached XDP in native (driver) mode"
_NATIVE_REJECTED = "Peer MTU is too large"
# The monitor's own periodic statistics block.  It is printed by the sampling
# loop, so it only appears once the program has opened the interface, attached
# and entered its poll loop -- and the first block is printed with ``total: 0``,
# before any packet exists.  That makes it the readiness signal that does not
# depend on traffic having started.
_SAMPLER_BLOCK = re.compile(r"^total\s+:\s+\d+\s*$", re.M)

# One-line sensor-side probe: for every xdp_monitor process report its pid,
# its argv and the target of its stdout fd (which reveals the journal the
# process actually redirects into -- the shell redirection is not part of the
# process argv, so the fd must be inspected, never assumed).
_PGREP = (
    "for p in $(pgrep -x xdp_monitor 2>/dev/null); do "
    "printf 'pid=%s cmd=%s out=%s\\n' \"$p\" "
    "\"$(tr '\\0' ' ' </proc/$p/cmdline 2>/dev/null)\" "
    "\"$(readlink /proc/$p/fd/1 2>/dev/null)\"; done"
)


class ObservationReadinessError(RuntimeError):
    """Live XDP observation could not be made ready on the passive sensor.

    Raised when the testbed is deployed but the observation path cannot be
    made live: the UI reports "IPsec testbed is running, but live XDP
    observation is unavailable" instead of pretending observation works.
    """


def journal_path(journal_dir=JOURNAL_DIRECTORY, journal_file=JOURNAL_FILE):
    """Host path of the live XDP journal (the analytics capture feed target)."""
    return Path(journal_dir) / journal_file


def journal_summary(journal_dir=JOURNAL_DIRECTORY, journal_file=JOURNAL_FILE):
    """Host-side snapshot of the live journal (exists, bytes, lines).

    Read-only: this function only ever *reads* the journal.  Growth is
    produced by the sensor-side xdp_monitor through the bind mount.
    """
    path = Path(journal_dir) / journal_file
    if not path.is_file():
        return {"exists": False, "bytes": 0, "lines": 0}
    data = path.read_bytes()
    return {"exists": True, "bytes": len(data), "lines": data.count(b"\n")}


def _docker(container, *argv, check=True, timeout=OBSERVATION_COMMAND_TIMEOUT):
    result = subprocess.run(
        [*docker_prefix(), "docker", "exec", container, *argv],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"docker exec {container} {' '.join(argv)} failed "
            f"(rc={result.returncode}): {result.stderr.strip()[-2000:]}"
        )
    return result


def _probe_ok(container, script):
    return _docker(container, "sh", "-c", script, check=False).returncode == 0


def _container_alive(container):
    return _docker(container, "true", check=False).returncode == 0


def monitor_processes(container):
    """Return [{pid, cmdline, stdout_target}] for every xdp_monitor process."""
    result = _docker(container, "sh", "-c", _PGREP, check=False)
    procs = []
    for line in result.stdout.splitlines():
        match = re.match(r"pid=(\d+) cmd=(.*) out=(.*)\Z", line)
        if match:
            procs.append({
                "pid": int(match.group(1)),
                "cmdline": match.group(2),
                "stdout_target": match.group(3),
            })
    return procs


def _is_our_monitor(proc, iface, journal_inside):
    """True when ``proc`` is attached to ``iface`` AND writes our journal."""
    cmdline = proc.get("cmdline", "")
    return (
        "xdp_monitor" in cmdline
        and iface in cmdline
        and proc.get("stdout_target") == journal_inside
    )


def _kill_all_monitors(container):
    _docker(
        container,
        "sh", "-c", "pkill -9 -x xdp_monitor 2>/dev/null; exit 0",
        check=False,
    )


def copy_binary(container):
    """Place ebpf/xdp_monitor into the sensor when the image lacks it.

    The tunnel sensor image does not ship the binary; the transport image
    stages it at build time (scripts/install.sh verifies the staged sha256),
    in which case this is never called.
    """
    subprocess.run(
        [*docker_prefix(), "docker", "cp", str(XDP_BINARY_HOST), f"{container}:{XDP_BINARY_IN_CONTAINER}"],
        check=True,
        capture_output=True,
        text=True,
        timeout=OBSERVATION_COMMAND_TIMEOUT,
    )


def _start_monitor(container, iface, mount_dir, journal_file, err_file,
                   timeout=OBSERVATION_COMMAND_TIMEOUT):
    """Start the monitor detached, writing through the journal bind mount.

    Mirror of the capture layer's hardened detached-exec pattern (setsid +
    fully redirected session) so the monitor survives docker's detached-exec
    session teardown.  ``>`` truncates the journal: a fresh deployment starts
    a clean live stream for the new experiment (the recorded historical
    journal under ``results/observed-state/live_events_full.jsonl`` is never
    touched).
    """
    journal = f"{mount_dir}/{journal_file}"
    err = f"{mount_dir}/{err_file}"
    cmd = (
        f"setsid sh -c '{XDP_BINARY_IN_CONTAINER} {iface} --json "
        f"> {journal} 2> {err}' < /dev/null > /dev/null 2>&1 &"
    )
    subprocess.run(
        [*docker_prefix(), "docker", "exec", "-d", container, "sh", "-c", cmd],
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _attach_evidence(container, err_file):
    """Best-effort read of the monitor's stderr attach markers."""
    result = _docker(container, "cat", err_file, check=False)
    text = result.stdout or ""
    return {
        "generic_mode": _ATTACH_GENERIC in text,
        "native_mode": _ATTACH_NATIVE in text,
        "native_rejected": _NATIVE_REJECTED in text,
        "sampler_running": bool(_SAMPLER_BLOCK.search(text)),
        "stderr": text[-2000:],
    }


def _liveness_proof(evidence, summary):
    """Proof the monitor is attached and able to deliver observations.

    Readiness is a property of the *sensor side*, never of the traffic: the
    monitor must have attached (generic or native marker) or at least entered
    its statistics/sampling loop, which it only does once the interface is open
    and the program is running.  The first statistics block is emitted with
    ``total: 0``, so this proof holds before a single packet has been observed.
    A non-empty journal is also accepted, because after the launch-time
    truncation the journal only ever holds events this monitor sampled.
    """
    return (
        evidence.get("generic_mode")
        or evidence.get("native_mode")
        or evidence.get("sampler_running")
        or summary["lines"] > 0
    )


def _await_liveness(container, err_inside, journal_dir, deadline):
    """Poll until the monitor proves it is attached and sampling."""
    while True:
        evidence = _attach_evidence(container, err_inside)
        summary = journal_summary(journal_dir)
        if _liveness_proof(evidence, summary):
            return evidence, summary
        if time.monotonic() >= deadline:
            return evidence, summary
        time.sleep(_POLL_INTERVAL)


def await_observation_evidence(container=SENSOR_CONTAINER,
                               journal_dir=JOURNAL_DIRECTORY,
                               baseline_lines=0, log=None,
                               timeout=OBSERVATION_READY_TIMEOUT):
    """Verify the live journal actually received observations.

    This is the *traffic* half of readiness and belongs after traffic has been
    generated, never before: before the traffic stage a correctly attached
    monitor legitimately has an empty journal.  Raises
    ``ObservationReadinessError`` when the monitor was ready but the journal
    still holds no new events after traffic, which is a real observation
    failure rather than a startup race.
    """
    log = log or (lambda msg: None)
    deadline = time.monotonic() + timeout
    while True:
        summary = journal_summary(journal_dir)
        if summary["lines"] > baseline_lines:
            log(f"live journal received {summary['lines'] - baseline_lines} "
                f"new observation(s) ({summary['lines']} total, "
                f"{summary['bytes']} bytes)")
            return summary
        if time.monotonic() >= deadline:
            break
        time.sleep(_POLL_INTERVAL)
    raise ObservationReadinessError(
        "IPsec testbed is running and xdp_monitor is attached, but the live "
        f"journal received no observations after traffic: journal "
        f"{journal_inside_path(journal_dir)} still holds {summary['lines']} "
        f"line(s)"
    )


def journal_inside_path(journal_dir=JOURNAL_DIRECTORY, journal_file=JOURNAL_FILE):
    """Sensor-side path of the live journal, for error messages."""
    return f"{MOUNT_DIR}/{journal_file}"


def ensure_xdp_monitor(container=SENSOR_CONTAINER, iface=SENSOR_IFACE,
                       mount_dir=MOUNT_DIR, journal_file=JOURNAL_FILE,
                       err_file=ERROR_FILE, journal_dir=JOURNAL_DIRECTORY,
                       log=None,
                       ready_timeout=OBSERVATION_READY_TIMEOUT):
    """Make the live XDP observation path ready (idempotent, duplicate-safe).

    Returns a readiness dict (``status == "live"``) or raises
    ``ObservationReadinessError``.  Never leaves more than one monitor running
    and never lies about readiness: "live" means the monitor process is
    attached to ``iface`` and able to write the expected live journal.  It
    deliberately does NOT require an already-observed packet -- at this point
    in the lifecycle the traffic stage has not run yet.  Use
    :func:`await_observation_evidence` after traffic to prove observations are
    actually arriving.
    """
    log = log or (lambda msg: None)
    journal_path(journal_dir).parent.mkdir(parents=True, exist_ok=True)
    journal_inside = f"{mount_dir}/{journal_file}"
    err_inside = f"{mount_dir}/{err_file}"

    if not _container_alive(container):
        raise ObservationReadinessError(
            "IPsec testbed is running, but live XDP observation is "
            f"unavailable: sensor container {container} is not up"
        )
    if not _probe_ok(container, f"test -e /sys/class/net/{iface}"):
        raise ObservationReadinessError(
            "IPsec testbed is running, but live XDP observation is "
            f"unavailable: interface {iface} is not present in {container}"
        )
    if not _probe_ok(container, f"test -d {mount_dir}"):
        raise ObservationReadinessError(
            "IPsec testbed is running, but live XDP observation is "
            f"unavailable: journal mount {mount_dir} is not reachable in {container}"
        )

    procs = monitor_processes(container)
    accepted = [p for p in procs if _is_our_monitor(p, iface, journal_inside)]

    if accepted:
        pid = accepted[0]["pid"]
        log(f"xdp_monitor already attached on {container}:{iface} (pid {pid}) "
            f"writing {journal_inside} -- reusing")
        deadline = time.monotonic() + ready_timeout
        evidence, summary = _await_liveness(container, err_inside,
                                            journal_dir, deadline)
        if not _liveness_proof(evidence, summary):
            raise ObservationReadinessError(
                "IPsec testbed is running, but live XDP observation is "
                f"unavailable: xdp_monitor pid {pid} on {container}:{iface} "
                "is running but never attached (no generic/native attach "
                "marker, the monitor's sampling loop never reported, and the "
                "journal is empty)"
            )
        return {
            "status": "live",
            "action": "reuse",
            "container": container,
            "interface": iface,
            "pid": pid,
            "journal": str(journal_path(journal_dir)),
            "attach": evidence,
            "journal_size": summary["bytes"],
            "journal_lines": summary["lines"],
        }

    if procs:
        log(f"replacing {len(procs)} non-matching xdp_monitor process(es) "
            f"on {container} (wrong interface/journal)")
        _kill_all_monitors(container)

    if not _probe_ok(container, f"test -x {XDP_BINARY_IN_CONTAINER}"):
        log(f"copying {XDP_BINARY_HOST.name} into {container}")
        try:
            copy_binary(container)
        except Exception as exc:
            raise ObservationReadinessError(
                "IPsec testbed is running, but live XDP observation is "
                f"unavailable: could not install xdp_monitor into {container} "
                f"({type(exc).__name__}: {exc})"
            ) from exc

    log(f"starting xdp_monitor on {container}:{iface} (generic/SKB) "
        f"-> {journal_inside}")
    try:
        _start_monitor(container, iface, mount_dir, journal_file, err_file)
    except Exception as exc:
        raise ObservationReadinessError(
            "IPsec testbed is running, but live XDP observation is "
            f"unavailable: xdp_monitor could not be started on {container} "
            f"({type(exc).__name__}: {exc})"
        ) from exc

    deadline = time.monotonic() + ready_timeout
    while True:
        procs = monitor_processes(container)
        alive = [p for p in procs if _is_our_monitor(p, iface, journal_inside)]
        if alive:
            pid = alive[0]["pid"]
            # The journal must exist and be writable in the container before
            # readiness is claimed: the monitor's shell redirection creates it,
            # so its presence is what makes the journal ready to receive
            # observations.  A zero-length journal is expected here.
            journal_ready = _probe_ok(container, f"test -f {journal_inside}") and \
                _probe_ok(container, f"test -w {journal_inside}")
            evidence, summary = _await_liveness(container, err_inside,
                                                journal_dir, deadline)
            if journal_ready and _liveness_proof(evidence, summary):
                log(f"xdp_monitor attached and sampling on {container}:{iface} "
                    f"(pid {pid}, generic={evidence['generic_mode']}, "
                    f"sampler={evidence['sampler_running']}, "
                    f"journal_lines={summary['lines']})")
                return {
                    "status": "live",
                    "action": "started",
                    "container": container,
                    "interface": iface,
                    "pid": pid,
                    "journal": str(journal_path(journal_dir)),
                    "attach": evidence,
                    "journal_size": summary["bytes"],
                    "journal_lines": summary["lines"],
                }
            log(f"xdp_monitor process is alive on {container}:{iface} "
                f"(pid {pid}) but has not attached yet "
                f"(no attach marker, sampler={evidence['sampler_running']}, "
                f"journal_ready={journal_ready}, "
                f"journal_lines={summary['lines']})")
        if time.monotonic() >= deadline:
            break
        time.sleep(_POLL_INTERVAL)

    raise ObservationReadinessError(
        "IPsec testbed is running, but live XDP observation is unavailable: "
        f"xdp_monitor did not attach on {container}:{iface} (no generic/native "
        "attach marker, its sampling loop never reported, and the live journal "
        f"is empty; journal {journal_inside})"
    )


def ensure_for_mode(mode, log=None, ready_timeout=OBSERVATION_READY_TIMEOUT,
                    nat=False):
    """Make the live XDP observation path ready for a deployed ``mode``.

    Resolves the mode's passive sensor from :data:`SENSOR_TARGETS` and reuses
    the single :func:`ensure_xdp_monitor` lifecycle; the journal, mount and
    error file are the shared ones for every mode.  Raises
    ``ObservationReadinessError`` for an unknown mode so a topology can never
    run without declaring its observation point.
    """
    key = f"{mode}-nat" if nat else mode
    if key not in SENSOR_TARGETS:
        raise ObservationReadinessError(
            "IPsec testbed is running, but live XDP observation is "
            f"unavailable: no XDP observation sensor is declared for "
            f"mode {mode!r} (known: {', '.join(sorted(SENSOR_TARGETS))})"
        )
    container, iface = SENSOR_TARGETS[key]
    return ensure_xdp_monitor(
        container=container, iface=iface, log=log, ready_timeout=ready_timeout,
    )
