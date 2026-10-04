"""Traffic generation orchestration for the IPsec testbed.

Handles the runtime mapping (which container is the sender / receiver),
copies the traffic generator into the containers and drives the
generation for a traffic trial.

Two interchangeable traffic-generator backends are supported:

  * ``builtin`` (default) -- drives ``scripts/trafficgen.py`` (pure
    Python, no dependencies) inside the endpoint containers.
  * ``ditg`` -- drives the D-ITG 2.8.1 platform binaries (``ITGSend`` /
    ``ITGRecv`` / ``ITGDec``) that are vendored under ``vendor/ditg/``.
    D-ITG binaries run inside the same endpoint containers; ``ITGRecv``
    is started detached on the destination, ``ITGSend`` runs to
    completion synchronously on the source.

The backend is selected with the ``IPSEC_TRAFFIC_GENERATOR`` environment
variable at first use (``builtin`` when unset) and can be overridden at
runtime with ``set_traffic_generator()``.  Every profile is expressed as a
deterministic model (fixed D-ITG seed per profile), and
``resolve_traffic_model()`` returns the canonical machine-readable
description of the traffic model that gets stored in ``metadata.jsonl``.

Both backends reproduce the same six profiles.  ICMP always uses the
builtin ``ping`` implementation regardless of backend (ITGSend ICMP flows
require a raw-socket receiver; plain ping is simpler and already
validated).
"""

import os
import subprocess
import time
from pathlib import Path

from .privileges import docker_prefix

# All testbed dataplane subprocesses must run non-interactively.  ``docker``
# calls resolve their prefix via ``docker_prefix()``: ``sudo -n`` when
# privileged sudo exists, bare docker when the socket is group/rootless-
# reachable (the containerlab lab needs no host root for in-container exec).
DOCKER_EXEC_TIMEOUT = 120.0


def _docker(args, **kwargs):
    return subprocess.run([*docker_prefix(), "docker"] + args, **kwargs)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TRAFFIC_GEN = PROJECT_ROOT / "scripts" / "trafficgen.py"
DEFAULT_PORT = 20000

PROFILES = ("voip", "video", "messaging", "email", "web", "icmp")
DEFAULT_DURATION = 30
DURATION_RANGE = (10, 120)

PROFILE_LABELS = {
    "icmp": "ICMP",
    "voip": "VoIP-like",
    "messaging": "Messaging-like",
    "email": "Email-like",
    "web": "Web-like",
    "video": "Video-like",
}

# ---------------------------------------------------------------------------
# Traffic-generator backend selection
# ---------------------------------------------------------------------------

GENERATOR_ENV = "IPSEC_TRAFFIC_GENERATOR"
SUPPORTED_GENERATORS = ("builtin", "ditg")

# D-ITG 2.8.1 (revision 1023), jbucar/ditg fork, built on glibc >= 2.38 so it
# runs inside the ubuntu:24.04 endpoint images.  See vendor/ditg/VERSION for
# the exact build provenance and the gcc-15 build fixes that were applied.
DITG_VERSION = "ditg-2.8.1-r1023"
DITG_DIR = PROJECT_ROOT / "vendor" / "ditg"
DITG_BINARIES = ("ITGSend", "ITGRecv", "ITGDec")
DITG_SEND_BIN = "/tmp/ITGSend"
DITG_RECV_BIN = "/tmp/ITGRecv"
DITG_SEND_LOG = "/tmp/ditg_send.log"
DITG_RECV_LOG = "/tmp/ditg_recv.log"

# D-ITG signalling channel is a fixed TCP port on the receiver
# (common/ITG.h DEFAULT_PORT_SIGNALING); the data port comes from -rp.
DITG_SIGNALING_PORT = 9000

# Fixed per-profile seeds keep every D-ITG generation reproducible
# (ITGSend -s accepts a double in (0, 1)).
DITG_SEEDS = {
    "voip": "0.1001",
    "video": "0.2002",
    "messaging": "0.3003",
    "email": "0.4004",
    "web": "0.5005",
}

# Deterministic D-ITG model per profile.  ``idt`` is (distribution-token,
# parameter(s)), ``ps`` is (size-token, parameter(s)) -- tokens are the
# verified ITGSend vocabulary: -C constant pkts/s, -c constant bytes.
# ``burst`` is (on_token, on_param, off_token, off_param) for -B.  These
# models reproduce the ESP-layer load of the builtin profiles: voip/video
# are exact CBR equivalents, messaging/email are alternating
# on/off-burst equivalents, web is a single-connection request stream.
DITG_PROFILES = {
    "voip": {
        "protocol": "UDP",
        "idt": ("C", 50),
        "ps": ("c", 160),
        "packet_rate": 50.0,
        "packet_size": 160,
        "burst": None,
    },
    "video": {
        "protocol": "UDP",
        "idt": ("C", 250),
        "ps": ("c", 1200),
        "packet_rate": 250.0,
        "packet_size": 1200,
        "burst": None,
    },
    "messaging": {
        "protocol": "UDP",
        "idt": ("C", 200),
        "ps": ("c", 110),
        "packet_rate": 200.0,
        "packet_size": 110,
        "burst": ("C", 1000, "C", 3000),
    },
    "email": {
        "protocol": "TCP",
        "idt": ("C", 5),
        "ps": ("c", 8192),
        "packet_rate": 5.0,
        "packet_size": 8192,
        "burst": ("C", 1000, "C", 1000),
        "nagle_off": True,
    },
    "web": {
        "protocol": "TCP",
        "idt": ("C", 2),
        "ps": ("c", 320),
        "packet_rate": 2.0,
        "packet_size": 320,
        "burst": None,
        "nagle_off": True,
    },
}

# Structural description of the builtin generator's profiles, kept in sync
# with scripts/trafficgen.py PROFILES.  Used only by resolve_traffic_model.
BUILTIN_PROFILES = {
    "voip": {
        "protocol": "udp", "packet_rate": 50.0, "packet_size": 160,
        "distribution": {"idt": "constant", "ps": "constant"}, "burst": None,
    },
    "video": {
        "protocol": "udp", "packet_rate": 250.0, "packet_size": 1200,
        "distribution": {"idt": "constant", "ps": "constant"}, "burst": None,
    },
    "messaging": {
        "protocol": "udp", "packet_rate": 50.0, "packet_size": 110,
        "distribution": {"idt": "bursty", "ps": "constant"},
        "burst": {"on_ms": 1000, "off_ms": 3000},
    },
    "email": {
        "protocol": "tcp", "packet_rate": 2.5, "packet_size": 8192,
        "distribution": {"idt": "bursty", "ps": "constant"},
        "burst": {"on_ms": 1000, "off_ms": 1000},
    },
    "web": {
        "protocol": "tcp", "packet_rate": 2.0, "packet_size": 320,
        "distribution": {"idt": "constant", "ps": "constant"}, "burst": None,
    },
}


_TRAFFIC_GENERATOR = None


def get_traffic_generator():
    """Return the active backend, initialised from IPSEC_TRAFFIC_GENERATOR."""
    global _TRAFFIC_GENERATOR
    if _TRAFFIC_GENERATOR is None:
        set_traffic_generator(os.environ.get(GENERATOR_ENV, "builtin"))
    return _TRAFFIC_GENERATOR


def set_traffic_generator(name):
    """Override the active traffic-generator backend (test seam / config)."""
    global _TRAFFIC_GENERATOR
    if name not in SUPPORTED_GENERATORS:
        raise ValueError(
            f"unsupported traffic generator {name!r}; "
            f"expected one of {SUPPORTED_GENERATORS}"
        )
    _TRAFFIC_GENERATOR = name
    return name


# ---------------------------------------------------------------------------
# Endpoint mapping (same source of truth used by runtime())
# ---------------------------------------------------------------------------

_ENDPOINTS = {
    "tunnel": {
        "ipv4": {
            "source_container": "clab-ipsec-host-a",
            "source_ip": "10.10.1.10",
            "destination_container": "clab-ipsec-host-b",
            "destination_ip": "10.10.2.10",
        },
        "ipv6": {
            "source_container": "clab-ipsec-host-a",
            "source_ip": "2001:db8:1::10",
            "destination_container": "clab-ipsec-host-b",
            "destination_ip": "2001:db8:2::10",
        },
    },
    "transport": {
        "ipv4": {
            "source_container": "clab-ipsec-transport-host-c",
            "source_ip": "10.20.1.10",
            "destination_container": "clab-ipsec-transport-host-d",
            "destination_ip": "10.20.1.20",
        },
        "ipv6": {
            "source_container": "clab-ipsec-transport-host-c",
            "source_ip": "2001:db8:20::10",
            "destination_container": "clab-ipsec-transport-host-d",
            "destination_ip": "2001:db8:20::20",
        },
    },
    # NAT-T deployment of the transport topology: host-c sends from its LAN
    # address and the destination is host-d's WAN address, reached only
    # through the translator.
    "transport-nat": {
        "ipv4": {
            "source_container": "clab-ipsec-transport-nat-host-c",
            "source_ip": "10.20.1.10",
            "destination_container": "clab-ipsec-transport-nat-host-d",
            "destination_ip": "10.30.1.20",
        },
    },
}


def runtime(mode, address_family, nat=False):
    """Map mode + address family (+ NAT axis) to sender/receiver endpoints.

    Container names and data-plane IPs are taken from the Containerlab
    topologies under topology/{deployment}/ipsec.clab.yml.  For a NAT sample the
    destination is the peer's address on the far side of the translator, which
    is what the traffic actually traverses.
    """
    key = f"{mode}-nat" if nat else mode
    try:
        return dict(_ENDPOINTS[key][address_family])
    except KeyError:
        raise ValueError(f"Unsupported mode/address family: {key}/{address_family}")


def _endpoint_container_for_ip(ip):
    """Map a known data-plane IP back to its endpoint container name."""
    for mode in _ENDPOINTS:
        for family in _ENDPOINTS[mode]:
            endpoints = _ENDPOINTS[mode][family]
            if endpoints["source_ip"] == ip:
                return endpoints["source_container"]
            if endpoints["destination_ip"] == ip:
                return endpoints["destination_container"]
    raise ValueError(f"no testbed endpoint known for IP {ip}")


# ---------------------------------------------------------------------------
# Traffic model resolution (deterministic, generator-aware)
# ---------------------------------------------------------------------------

def _model_base(profile, duration, port):
    return {
        "profile": profile,
        "duration": float(duration),
        "port": int(port),
        "deterministic": True,
    }


def resolve_traffic_model(profile, duration, port=DEFAULT_PORT):
    """Return the canonical description of the traffic model for one trial.

    The description depends only on the profile, the duration, the port and
    the *active* generator, so it is reproducible and safe to store as ground
    truth in ``metadata.jsonl``.  ICMP is always generated with plain ``ping``
    no matter which backend is active.
    """
    if profile not in PROFILES:
        raise ValueError(f"unknown traffic profile: {profile}")
    base = _model_base(profile, duration, port)

    if profile == "icmp":
        return {
            "generator": "ping",
            "version": "ping",
            **base,
            "protocol": "icmp",
            "distribution": {"idt": "constant", "ps": "constant"},
            "packet_rate": 5.0,
            "packet_size": 32,
            "burst": None,
            "seed": None,
        }

    generator = get_traffic_generator()
    if generator == "builtin":
        model = dict(BUILTIN_PROFILES[profile])
        return {
            "generator": "builtin",
            "version": "trafficgen.py",
            **base,
            "protocol": model["protocol"],
            "distribution": model["distribution"],
            "packet_rate": model["packet_rate"],
            "packet_size": model["packet_size"],
            "burst": model["burst"],
            "seed": None,
        }
    if generator == "ditg":
        params = DITG_PROFILES[profile]
        distribution = {"idt": "constant", "ps": "constant"}
        if params.get("burst"):
            distribution = {"idt": "on-off", "ps": "constant"}
        return {
            "generator": "ditg",
            "version": DITG_VERSION,
            **base,
            "protocol": params["protocol"],
            "distribution": distribution,
            "packet_rate": params["packet_rate"],
            "packet_size": params["packet_size"],
            "burst": (
                {"on_ms": params["burst"][1], "off_ms": params["burst"][3]}
                if params.get("burst")
                else None
            ),
            "seed": DITG_SEEDS[profile],
        }
    raise ValueError(f"unsupported traffic generator: {generator}")


# ---------------------------------------------------------------------------
# D-ITG command construction
# ---------------------------------------------------------------------------

def build_ditg_command(profile, target, port=DEFAULT_PORT, duration=DEFAULT_DURATION):
    """Return the in-container ITGSend argv for one D-ITG trial.

    Built from the verified D-ITG 2.8.1 CLI only (see ITGSend -h / the
    flowParser switch cases); the receiver log is requested with -x so
    ITGRecv writes a parseable receiver-side log, the sender writes its
    own log with -l.  ICMP is intentionally unsupported here because the
    testbed always uses the builtin ``ping`` path for ICMP.
    """
    if profile == "icmp":
        raise ValueError("D-ITG is not used for the icmp profile (ping is used)")
    if profile not in DITG_PROFILES:
        raise ValueError(f"unknown traffic profile: {profile}")
    params = DITG_PROFILES[profile]

    argv = [DITG_SEND_BIN, "-a", target]
    if params["protocol"] != "ICMP":
        argv += ["-rp", str(int(port))]
    argv += ["-T", params["protocol"]]
    argv += ["-C", str(params["idt"][1])]
    argv += ["-c", str(params["ps"][1])]
    if params.get("nagle_off"):
        argv += ["-D"]
    if params.get("burst"):
        argv += ["-B"] + [str(part) for part in params["burst"]]
    argv += ["-t", str(int(duration * 1000))]
    argv += ["-s", DITG_SEEDS[profile]]
    argv += ["-l", DITG_SEND_LOG, "-x", DITG_RECV_LOG]
    return argv


# ---------------------------------------------------------------------------
# Per-trial orchestration (backend-dispatching)
# ---------------------------------------------------------------------------

def _docker(args, **kwargs):
    return subprocess.run(["sudo", "docker"] + args, **kwargs)


def copy_trafficgen(container):
    """Copy the traffic generator payload into the endpoint container.

    The builtin payload (Python script) is always copied so the ``ping`` /
    ICMP path and the builtin fallback keep working; the D-ITG binaries are
    additionally copied when the D-ITG backend is active.
    """
    _docker(["cp", str(TRAFFIC_GEN), f"{container}:/tmp/trafficgen.py"],
            check=True, capture_output=True)
    if get_traffic_generator() == "ditg":
        for binary in DITG_BINARIES:
            source = DITG_DIR / binary
            if not source.is_file():
                raise FileNotFoundError(
                    f"D-ITG backend requested but {source} is missing; "
                    f"build with make in the ditg source tree and copy it here"
                )
            _docker(["cp", str(source), f"{container}:/tmp/{binary}"],
                    check=True, capture_output=True)


def start_receiver(container, target, port=DEFAULT_PORT, duration=45.0):
    """Start the receiver on the destination host (detached)."""
    if get_traffic_generator() == "ditg":
        _stop_ditg_receiver(container)
        _docker(["exec", "-d", container, DITG_RECV_BIN], check=True,
                capture_output=True)
        return
    cmd = [
        "exec", "-d", container,
        "python3", "/tmp/trafficgen.py",
        "--role", "recv",
        "--target", target,
        "--port", str(port),
        "--duration", str(int(duration)),
    ]
    _docker(cmd, check=True, capture_output=True)


def run_sender(container, profile, target, port=DEFAULT_PORT, duration=30.0):
    """Run the traffic profile on the source host, blocking until done.

    Returns (traffic_log, status) where traffic_log is a string and
    status is "PASS" or "FAIL".
    """
    if get_traffic_generator() == "ditg" and profile != "icmp":
        argv = build_ditg_command(profile, target, port=port, duration=duration)
        result = subprocess.run(
            [*docker_prefix(), "docker", "exec", container] + argv,
            capture_output=True, text=True, timeout=int(duration) + 30,
        )
        log = (result.stdout or "") + (result.stderr or "")
        status = "PASS" if result.returncode == 0 else "FAIL"
        return log, status

    cmd = [
        "exec", container,
        "python3", "/tmp/trafficgen.py",
        "--role", "send",
        "--profile", profile,
        "--target", target,
        "--port", str(port),
        "--duration", str(int(duration)),
    ]
    result = _docker(cmd, capture_output=True, text=True,
                     timeout=int(duration) + 30)
    log = (result.stdout or "") + (result.stderr or "")
    status = "PASS" if result.returncode == 0 else "FAIL"
    return log, status


def _stop_ditg_receiver(container):
    # SIGINT makes ITGRecv run its terminate() handler (flush+close logs);
    # the [I] bracket avoids pkill matching its own sh -c command line.
    _docker(
        ["exec", container, "sh", "-c", "pkill -INT -f '[I]TGRecv' || true"],
        capture_output=True,
    )


def stop_receiver(container):
    """Stop any receiver process on the container (either backend).

    Both receive paths are reaped unconditionally so a stale process from
    the other backend can never linger across a backend switch.
    """
    _docker(
        ["exec", container, "sh", "-c", "pkill -f '[t]rafficgen.py' || true"],
        capture_output=True,
    )
    _stop_ditg_receiver(container)


def wait_receiver(source_container, dest_ip, port=DEFAULT_PORT, timeout=15.0):
    """Wait until the listener on the destination is ready.

    Builtin backend: probes from the source container (so the connection
    also traverses the same VPN path the traffic will use) and returns once
    a TCP connection to dest_ip:port succeeds.  Raises RuntimeError if the
    listener never becomes ready, so a trial fails cleanly instead of
    sending into a dead listener.

    D-ITG backend: ITGRecv binds a fixed signalling port and only opens the
    data port after flow negotiation, so probing TCP would either miss it or
    abort it.  Instead it polls the destination container until the ITGRecv
    process is alive (ITGRecv binds its signalling socket synchronously at
    startup, so process-alive == ready-to-accept).
    """
    if get_traffic_generator() == "ditg":
        dest_container = _endpoint_container_for_ip(dest_ip)
        deadline = time.time() + timeout
        while time.time() < deadline:
            res = _docker(
                ["exec", dest_container, "sh", "-c", "pgrep -f '[I]TGRecv'"],
                capture_output=True,
            )
            if res.returncode == 0:
                return True
            time.sleep(0.5)
        raise RuntimeError(
            f"D-ITG receiver in {dest_container} was not ready within "
            f"{timeout:.0f}s"
        )

    family = "AF_INET6" if ":" in dest_ip else "AF_INET"
    probe = (
        f"import socket; s=socket.socket(socket.{family}); "
        f"s.settimeout(1); s.connect((\"{dest_ip}\", {port})); print(\"OK\")"
    )
    deadline = time.time() + timeout
    while time.time() < deadline:
        res = subprocess.run(
            [*docker_prefix(), "docker", "exec", source_container, "python3", "-c", probe],
            capture_output=True,
            text=True,
            timeout=DOCKER_EXEC_TIMEOUT,
        )
        if res.returncode == 0:
            return True
        time.sleep(0.5)
    raise RuntimeError(
        f"listener at {dest_ip}:{port} was not ready within {timeout:.0f}s"
    )