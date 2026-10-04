import json
import os
import signal
import subprocess
import time
from pathlib import Path

from .config import CONFIG
from .topology import (
    TOPOLOGIES,
    container_name,
    deployment_key,
    resolve_topology,
)
from .validate import validate_config
from .generator import write_connection
from . import diagnose
from . import traffic as traffic_mod
from . import experiment_manifest as manifest_mod
from . import xdp_observation
from .privileges import docker_prefix


PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Every testbed subprocess is launched under ``sudo -n`` (non-interactive).
#
# The workers that drive the lab (FastAPI background tasks, dataset executor)
# must NEVER wait on an interactive sudo password prompt: a web worker has no
# controlling terminal session the operator can answer, so a plain ``sudo``
# would block for its (often multi-minute) conversation timeout and leave a
# dataset run looking stuck in RUNNING.  ``sudo -n`` fails immediately with
# "sudo: a password is required" / "sudo: interactive authentication is
# required" when non-interactive privilege is unavailable, which the dataset
# executor surfaces as a fast fatal FAILED run instead of an indefinite hang.
SUDO = ("sudo", "-n")

# Stage-appropriate bounded subprocess timeouts (seconds).  These are caps for
# host-side commands; the on-box traffic/capture stages keep their own
# duration-derived bounds.  Deliberately generous so a legitimately slow
# operation is never cut off, but bounded so a wedged child can never leave a
# dataset run perpetually RUNNING.
DEFAULT_COMMAND_TIMEOUT = 300.0      # generic per-command cap (docker exec/cp, swanctl, ping)
DOCKER_COMMAND_TIMEOUT = 120.0       # fast docker micro-operations (ping, swanctl, file copy)
LIFECYCLE_TIMEOUT = 900.0            # containerlab deploy --reconfigure (may pull images)
DESTROY_TIMEOUT = 600.0              # containerlab destroy --cleanup

# Host-bridge lifecycle.  The tunnel topology treats ``br-wan`` as an
# externally-managed root-namespace bridge that containerlab does NOT create
# (and refuses to recreate).  The authoritative deploy/destroy wrapper
# (scripts/deploy-ipsec.sh) ensures the bridge deterministically and
# idempotently before ``containerlab deploy`` and removes it only when it has
# no remaining members after ``containerlab destroy``.  Routing the tunnel
# lifecycle through this wrapper is the project's intended host-bridge
# lifecycle; the transport topology has no external bridge and keeps the raw
# containerlab calls.
LIFECYCLE_SCRIPT = PROJECT_ROOT / "scripts" / "deploy-ipsec.sh"


class FatalTopologyError(RuntimeError):
    """A topology deployment/infrastructure failure that cannot be retried.

    Raised when the lab cannot be deployed for an infrastructure-level reason
    (missing host bridge, bridge creation failure, containerlab deploy
    failure).  Such failures cannot be fixed by re-attempting the same sample,
    so the dataset runner treats them as fatal instead of burning the per
    sequence attempt budget on meaningless retries.
    """


def get_topology(mode, address_family, nat=False):
    return resolve_topology(mode, address_family, nat=nat)


def _privileged(*argv):
    """Return a command guaranteed to be non-interactive.

    The first token is the command (e.g. use ``_privileged("docker", ...)``).
    A web/background worker must never block on an interactive sudo prompt, so
    every privileged subprocess in the testbed path goes through this.
    ``docker`` operations resolve their prefix (``sudo -n`` when privileged
    sudo exists, bare ``docker`` when the socket is group/rootless-reachable);
    root-namespace steps (``containerlab``, the ``br-wan`` lifecycle wrapper)
    remain under ``sudo -n``.
    """
    if argv and argv[0] == "docker":
        return [*docker_prefix(), *argv]
    return [*SUDO, *argv]


def _kill_process_group(proc):
    """SIGKILL the whole process group started by ``proc`` (incl. children).

    ``subprocess.run`` only kills the direct child on timeout, which would
    orphan ``sudo`` -> ``bash`` -> ``containerlab`` (and its docker children).
    Every testbed subprocess starts a new session, so a single ``killpg``
    reaps the entire tree.
    """
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except Exception:
            pass
    try:
        proc.wait(timeout=5)
    except Exception:
        pass


def run(command, timeout=DEFAULT_COMMAND_TIMEOUT, cwd=None):
    print(f"$ {' '.join(command)}")

    # If a call site still greps for sudo arguments, always insert ``-n`` so
    # an interactive password prompt can never block the worker.
    if command and command[0] == "sudo" and not (
        len(command) > 1 and command[1] == "-n"
    ):
        command = ["sudo", "-n", *command[1:]]

    proc = subprocess.Popen(
        command,
        cwd=cwd or PROJECT_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        # Own session: the kill-on-timeout path can then reap the whole tree.
        start_new_session=True,
    )

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        _kill_process_group(proc)
        detail = (exc.stderr or exc.stdout or "").strip()
        message = (
            f"Command timed out after {timeout:.0f}s "
            f"(process group killed): {' '.join(command)}"
        )
        if detail:
            message += f": {detail[-2000:]}"
        raise RuntimeError(message)

    if stdout:
        print(stdout)

    if proc.returncode != 0:
        if stderr:
            print(stderr)

        detail = (stderr or stdout or "").strip()
        message = f"Command failed with exit code {proc.returncode}"
        if detail:
            message += f": {detail[-2000:]}"

        raise RuntimeError(message)

    return stdout


def topology_file(mode, nat=False):
    """Topology path for a sample.

    ``mode`` may already be a full deployment key (``transport-nat``); a bare
    mode is resolved through :func:`deployment_key` so ``nat=True`` selects the
    NAT deployment without changing the IPsec encapsulation mode.
    """
    key = mode if "-nat" in mode else deployment_key(mode, nat=nat)

    path = (
        PROJECT_ROOT
        / "topology"
        / key
        / "ipsec.clab.yml"
    )

    if not path.exists():
        raise FileNotFoundError(
            f"Topology not found: {path}"
        )

    return path

def destroy(mode, nat=False):
    topo = topology_file(mode, nat=nat)

    if mode == "tunnel":
        # Authoritative lifecycle wrapper: containerlab destroy --cleanup
        # AND removal of the externally-managed br-wan bridge (only when it
        # has no remaining members).
        run(_privileged("bash", str(LIFECYCLE_SCRIPT), "destroy"),
            timeout=DESTROY_TIMEOUT)
        return

    run(_privileged("containerlab", "destroy", "-t", str(topo), "--cleanup"),
        timeout=DESTROY_TIMEOUT)


def deploy(mode, nat=False):
    topo = topology_file(mode, nat=nat)

    try:
        if mode == "tunnel" and not nat:
            # Authoritative lifecycle wrapper: ensure br-wan (deterministic,
            # idempotent), then containerlab deploy --reconfigure, then the
            # GW-A observation health-check.  ``br-wan`` is externally managed
            # by containerlab, so it MUST exist in the root netns before
            # deploy enslaves the gateway endpoints.
            run(_privileged("bash", str(LIFECYCLE_SCRIPT), "deploy"),
                timeout=LIFECYCLE_TIMEOUT)
        else:
            run(_privileged("containerlab", "deploy", "-t", str(topo)),
                timeout=LIFECYCLE_TIMEOUT)
    except RuntimeError as exc:
        raise FatalTopologyError(str(exc)) from exc


#: Marker the endpoint entrypoint prints once charon is up AND
#: ``swanctl --load-all`` has finished, i.e. when the pre-shared key and the
#: baked-in connection are installed and an SA can actually be negotiated.
#: Must stay in sync with scripts/gw-entrypoint.sh and
#: scripts/transport-entrypoint.sh.
IPSEC_READY_MARKER = "StrongSwan ready"

#: Generous bound for the container boot sequence. charon start plus config
#: load is normally a second or two; the cap only exists so a genuinely broken
#: container fails the run instead of hanging it forever.
IPSEC_READY_TIMEOUT = 120.0


def wait_for_ipsec_ready(mode, nat=False, timeout=IPSEC_READY_TIMEOUT):
    """Block until every IPsec endpoint has finished loading its config.

    Both endpoints must be ready, not just the initiator: the responder parses
    the IKE_SA_INIT and needs its PSK already loaded to answer.  Readiness is
    read from the container's own startup log rather than a fixed sleep, so a
    slow-but-correct boot is not failed and a fast one is not delayed.
    """
    topology = get_topology(mode, "ipv4", nat=nat)
    key = deployment_key(mode, nat=nat)
    containers = [
        container_name(key, topology[side]["node"])
        for side in ("local", "remote")
    ]

    deadline = time.monotonic() + timeout
    pending = set(containers)
    while pending and time.monotonic() < deadline:
        for container in sorted(pending):
            proc = subprocess.run(
                _privileged("docker", "logs", container),
                capture_output=True,
                text=True,
                timeout=DOCKER_COMMAND_TIMEOUT,
            )
            output = f"{proc.stdout}\n{proc.stderr}"
            if IPSEC_READY_MARKER in output:
                print(f"{container}: {IPSEC_READY_MARKER}")
                pending.discard(container)
        if pending:
            time.sleep(1.0)

    if pending:
        raise RuntimeError(
            "IPsec endpoints did not finish loading strongSwan configuration "
            f"within {timeout:g}s: {', '.join(sorted(pending))}"
        )
    return True


def reset_and_deploy(mode, nat=False):
    print(f"\n=== Starting {mode} experiment ===\n")

    # Destroy EVERY containerlab topology before deploying.  The run may have
    # kept a different-mode topology alive for reuse, or resumed over one.
    # The NAT deployment is a separate lab and must be torn down too, or its
    # nodes would keep answering ARP for the addresses the direct deployment
    # is about to claim.
    for m in ("tunnel", "transport"):
        try:
            destroy(m)
        except RuntimeError:
            pass
    try:
        destroy("transport", nat=True)
    except RuntimeError:
        pass

    deploy(mode, nat=nat)

    # `containerlab deploy` returns as soon as the containers *start*, but each
    # endpoint entrypoint still has to bring up charon and run
    # `swanctl --load-all`, which is what installs the pre-shared key.  Loading
    # the generated connection and initiating immediately raced that boot: the
    # responder had no PSK yet and answered IKE_SA_INIT with
    # "no shared key found ... - ...".  Wait for the entrypoint's own readiness
    # marker so the SA configuration is always loaded against a ready daemon.
    wait_for_ipsec_ready(mode, nat=nat)

    print(f"\n=== {mode} topology deployed ===\n")


def generate_configs(config):
    validate_config(config)

    mode = config["mode"]
    nat = bool(config.get("nat", False))
    topology = get_topology(mode, config["address_family"], nat=nat)
    key = deployment_key(mode, nat=nat)

    local = topology["local"]
    remote = topology["remote"]

    output_dir = (
        PROJECT_ROOT
        / "controller"
        / "generated"
        / key
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

    # The remote host's config must point back at the *local* host, since
    # ``write_connection`` treats its first peer argument as "this host" and
    # the second as "the far end".  Passing ``remote`` here made every
    # non-NAT peer address itself (gw-b-to-gw-b with remote_addrs equal to its
    # own address), so the responder had no IKE config for the initiator's
    # address and answered IKE_SA_INIT with NO_PROPOSAL_CHOSEN.
    #
    # On a NAT path the far end additionally never sees the local host's real
    # address: the translator rewrites it to the MASQUERADE address.  Generating
    # the remote host's config with the untranslated peer address would
    # negotiate to an address that does not exist behind the NAT, so the
    # override is applied here rather than in the topology table (the LAN side
    # legitimately still uses the real address).
    remote_peer = local
    if nat:
        masquerade = topology["nat"]["masquerade"]
        remote_peer = dict(local)
        remote_peer["ip"] = masquerade
        remote_peer["ts"] = f"{masquerade}/32"

    write_connection(
        config,
        remote,
        remote_peer,
        remote_file,
    )

    print(f"Generated: {local_file}")
    print(f"Generated: {remote_file}")

    return local_file, remote_file

def load_generated_configs(config):
    mode = config["mode"]
    nat = bool(config.get("nat", False))
    key = deployment_key(mode, nat=nat)

    topology = get_topology(mode, config["address_family"], nat=nat)

    local = topology["local"]
    remote = topology["remote"]

    local_file, remote_file = generate_configs(config)

    local_container = container_name(key, local["node"])
    remote_container = container_name(key, remote["node"])

    local_tmp = f"/tmp/{local['id']}.conf"
    remote_tmp = f"/tmp/{remote['id']}.conf"

    print("\n=== Loading generated configurations ===\n")

    run(
        _privileged("docker", "cp", str(local_file), f"{local_container}:{local_tmp}"),
        timeout=DOCKER_COMMAND_TIMEOUT,
    )

    run(
        _privileged("docker", "cp", str(remote_file), f"{remote_container}:{remote_tmp}"),
        timeout=DOCKER_COMMAND_TIMEOUT,
    )

    run(
        _privileged("docker", "exec", local_container, "swanctl", "--load-conns", "--file", local_tmp),
        timeout=DOCKER_COMMAND_TIMEOUT,
    )

    run(
        _privileged("docker", "exec", remote_container, "swanctl", "--load-conns", "--file", remote_tmp),
        timeout=DOCKER_COMMAND_TIMEOUT,
    )

    print("\n=== Generated configurations loaded ===\n")

def initiate_ipsec(mode, address_family, nat=False):
    topology = get_topology(mode, address_family, nat=nat)
    local = topology["local"]

    container = container_name(deployment_key(mode, nat=nat), local["node"])

    connection_name = f"{local['id']}-to-{topology['remote']['id']}"

    print("\n=== Initiating IPsec ===\n")

    run(
        _privileged("docker", "exec", container, "swanctl", "--initiate", "--child", connection_name),
        timeout=DOCKER_COMMAND_TIMEOUT,
    )


def terminate_sas(mode, address_family, nat=False):
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
    key = deployment_key(mode, nat=nat)
    topology = get_topology(mode, address_family, nat=nat)
    local = topology["local"]
    remote = topology["remote"]

    local_container = container_name(key, local["node"])
    remote_container = container_name(key, remote["node"])

    connection_name = f"{local['id']}-to-{topology['remote']['id']}"

    containers = [local_container, remote_container]

    print("\n=== Terminating existing IPsec SAs ===\n")

    for container in containers:
        for command in (
            ["--terminate", "--child", connection_name],
            ["--terminate", "--ike", connection_name],
        ):
            try:
                run(
                    _privileged("docker", "exec", container, "swanctl", *command),
                    timeout=DOCKER_COMMAND_TIMEOUT,
                )
            except RuntimeError:
                pass

    print("\n=== Existing IPsec SAs terminated ===\n")


def test_connectivity(mode, address_family, nat=False):
    if mode == "tunnel" and not nat:
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
        # The destination is taken from the SAME endpoint table the swanctl
        # config was generated from, so the connectivity probe can never drift
        # away from the address actually negotiated (notably the NAT deployment,
        # where the peer's reachable address is on the far side of the
        # translator).
        topology = get_topology(mode, address_family, nat=nat)
        source = container_name(deployment_key(mode, nat=nat), topology["local"]["node"])
        destination = topology["remote"]["ip"]

        ping_command = ["ping"]
        if address_family == "ipv6":
            ping_command.append("-6")
        elif address_family != "ipv4":
            raise ValueError(
                f"Unsupported address family: {address_family}"
            )
        ping_command += ["-c", "3", "-i", "0.2", "-W", "1", destination]
    else:
        raise ValueError(f"Unsupported mode: {mode}")

    print("\n=== Testing connectivity ===\n")

    try:
        output = run(
            _privileged("docker", "exec", source, *ping_command),
            timeout=DOCKER_COMMAND_TIMEOUT,
        )
    except RuntimeError as exc:
        # The probe target belongs to this experiment, so re-raise through the
        # root-cause classifier with the SAME message text the pipeline has
        # always reported. A ping that never completes is a data-plane failure
        # with the SAs already verified, so classification happens against the
        # installed CHILD_SA selectors rather than SA state.
        raise _connectivity_failure(
            mode, address_family, nat, str(exc), probe_target=destination
        ) from exc

    packet_loss = None

    for line in output.splitlines():
        if "packet loss" in line:
            packet_loss = float(line.split("%")[0].split()[-1])
            break

    if packet_loss is None:
        raise _connectivity_failure(
            mode, address_family, nat, "Could not determine packet loss",
            probe_target=destination,
        )

    connectivity = {
        "packet_loss": packet_loss,
        "status": "PASS" if packet_loss == 0 else "FAIL",
    }

    if connectivity["status"] == "FAIL":
        connectivity["classification"] = _classify_connectivity(
            mode, address_family, nat, connectivity, probe_target=destination
        )

    return connectivity
def _classify_connectivity(
    mode, address_family, nat, connectivity, probe_target=None
):
    """Classify a data-plane failure against the INSTALLED CHILD_SA selectors.

    At this point ``verify_ipsec`` has already passed, so the IKE_SA is
    established and the CHILD_SA is installed by definition. That is passed
    explicitly rather than re-read from the daemon so the classifier cannot
    silently claim a state it did not observe.
    """
    topology = get_topology(mode, address_family, nat=nat)
    peers = [
        container_name(deployment_key(mode, nat=nat), topology[side]["node"])
        for side in ("local", "remote")
    ]
    sas = ""
    try:
        proc = subprocess.run(
            _privileged("docker", "exec", peers[0], "swanctl", "--list-sas"),
            capture_output=True, text=True, timeout=DOCKER_COMMAND_TIMEOUT,
        )
        sas = f"{proc.stdout}\n{proc.stderr}"
    except Exception as exc:
        print(f"[diagnose] could not read SA state for classification: {exc}")

    ike_evidence = diagnose.parse_ike_evidence(_collect_charon_evidence(peers))

    return diagnose.classify_failure(
        stage="CONNECTIVITY",
        sa_state={
            "ike_state": diagnose.IKE_ESTABLISHED,
            "child_state": diagnose.CHILD_INSTALLED,
            "mode": mode.upper(),
            "nat_t": nat,
            "encapsulation": "UDP_4500" if nat else "NONE",
        },
        ike_evidence=ike_evidence,
        nat=nat,
        connectivity=connectivity,
        probe_target=probe_target,
    )


def _connectivity_failure(
    mode, address_family, nat, message, probe_target=None
):
    """Wrap a connectivity failure, preserving its original message."""
    classification = _classify_connectivity(
        mode, address_family, nat,
        {"status": "FAIL", "packet_loss": None},
        probe_target=probe_target,
    )
    print(f"[diagnose] root_cause={classification['root_cause']} "
          f"confidence={classification['confidence']}")
    return ConnectivityVerificationError(message, classification)


class IpsecVerificationError(RuntimeError):
    """A failed IPsec SA check that also carries a specific root cause.

    Subclasses ``RuntimeError`` and keeps the original generic message, so every
    existing caller/assertion that matches ``RuntimeError`` or the message text
    keeps working unchanged. The structured classification is additive, exposed
    through ``.classification`` (see ``controller.diagnose``).
    """

    def __init__(self, message, classification=None):
        super().__init__(message)
        self.classification = classification or {
            "stage": "IPSEC",
            "root_cause": diagnose.UNKNOWN_IPSEC_FAILURE,
            "confidence": diagnose.INSUFFICIENT_EVIDENCE,
            "reason": (
                f"{message}: Sentinel captured no strongSwan notification that "
                "identifies a specific root cause."
            ),
            "evidence": {},
        }


class ConnectivityVerificationError(RuntimeError):
    """A failed data-plane check that also carries a specific root cause.

    Same additive contract as :class:`IpsecVerificationError`: still a
    ``RuntimeError`` with the original message, plus ``.classification``.
    """

    def __init__(self, message, classification=None):
        super().__init__(message)
        self.classification = classification or {
            "stage": "CONNECTIVITY",
            "root_cause": diagnose.UNKNOWN_IPSEC_FAILURE,
            "confidence": diagnose.INSUFFICIENT_EVIDENCE,
            "reason": (
                f"{message}: Sentinel captured no evidence that identifies a "
                "specific root cause."
            ),
            "evidence": {},
        }


def _collect_charon_evidence(containers):
    """Best-effort charon log capture for root-cause classification.

    Never raises: an evidence-collection problem must not mask the underlying
    SA failure that is already being reported.
    """
    text = ""
    for container in containers:
        try:
            proc = subprocess.run(
                _privileged("docker", "logs", "--tail", "400", container),
                capture_output=True,
                text=True,
                timeout=DOCKER_COMMAND_TIMEOUT,
            )
            text += f"{proc.stdout}\n{proc.stderr}\n"
        except Exception as exc:  # evidence is best-effort, never fatal
            print(f"[diagnose] could not collect charon log from "
                  f"{container}: {exc}")
    return text


def verify_ipsec(mode, address_family, nat=False):
    topology = get_topology(mode, address_family, nat=nat)

    local = topology["local"]

    source = container_name(deployment_key(mode, nat=nat), local["node"])

    print("\n=== Verifying IPsec SA ===\n")

    output = run(
        _privileged("docker", "exec", source, "swanctl", "--list-sas"),
        timeout=DOCKER_COMMAND_TIMEOUT,
    )

    sa_state = diagnose.parse_sa_state(output)

    def _fail(message):
        # Classify from the SAME evidence the verdict came from: the live
        # ``swanctl --list-sas`` state plus both peers' charon logs.
        peers = [
            container_name(
                deployment_key(mode, nat=nat), topology[side]["node"]
            )
            for side in ("local", "remote")
        ]
        ike_evidence = diagnose.parse_ike_evidence(
            _collect_charon_evidence(peers)
        )
        classification = diagnose.classify_failure(
            stage="IPSEC",
            sa_state=sa_state,
            ike_evidence=ike_evidence,
            nat=nat,
        )
        print(f"[diagnose] root_cause={classification['root_cause']} "
              f"confidence={classification['confidence']}")
        raise IpsecVerificationError(message, classification)

    if "ESTABLISHED" not in output:
        _fail("IKE SA is not established")

    if "INSTALLED" not in output:
        _fail("CHILD SA is not installed")

    expected_mode = mode.upper()

    if expected_mode not in output:
        _fail(f"Expected {expected_mode} IPsec SA not found")

    print("IPsec SA verification: PASS")

    return {
      "ike_sa": "ESTABLISHED",
      "child_sa": "INSTALLED",
      "mode": expected_mode,
}

def ensure_live_observation(mode, address_family="ipv4", log=None, nat=False):
    """Make the live XDP observation path ready for a deployed testbed.

    Every mode declares a passive sensor that feeds the SAME shared live
    journal, so the result is identical in shape for both topologies: the
    tunnel sensor (``clab-ipsec-sensor``) observes the gw-a WAN mirror and the
    transport sensor (``clab-ipsec-transport-sensor``) observes the host-c
    host-to-host mirror.  The concrete sensor is resolved by
    ``xdp_observation.ensure_for_mode``; readiness failures raise
    ``ObservationReadinessError`` instead of degrading to "no observation".
    """
    return xdp_observation.ensure_for_mode(mode, log=log, nat=nat)


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
    nat = bool(config.get("nat", False))
    profile, duration = validate_traffic(config["traffic"])

    # The NAT axis has to be resolved here as well. ``traffic.runtime`` keys
    # its endpoint table on ``mode``/``address_family``/``nat``, and a NAT
    # deployment is a different lab with different container names
    # (``clab-ipsec-transport-nat-*``). Omitting ``nat`` made every NAT sample
    # resolve the NON-NAT endpoints, so the traffic payload was copied into
    # containers that do not exist in the NAT lab.
    runtime_ctx = traffic_mod.runtime(mode, address_family, nat=nat)

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


def run_experiment(config, on_stage=None, job_id=None):
    mode = config["mode"]
    address_family = config["address_family"]
    started_at_ns = int(time.time_ns())

    validate_config(config)

    if "traffic" in config and config["traffic"] is not None:
        profile, duration = validate_traffic(config["traffic"])
    else:
        profile, duration = None, None

    def stage(stage):
        if on_stage is not None:
            on_stage(stage)

    # Lifecycle order (observation readiness is the gate BEFORE connectivity
    # and traffic; see docs/reports/CAPTURE_FEED_IMPLEMENTATION_REPORT.md):
    #   DEPLOY -> IPSEC config -> SA verification -> OBSERVATION readiness
    #   -> CONNECTIVITY verification -> TRAFFIC generation.
    stage("DEPLOY")
    # A new deploy can only belong to this run: clear the previous experiment's
    # manifest so a stale identity can never be attached to the new journal.
    manifest_mod.clear()
    nat = bool(config.get("nat", False))
    reset_and_deploy(mode, nat=nat)
    stage("IPSEC")
    load_generated_configs(config)
    initiate_ipsec(mode, address_family, nat=nat)
    ipsec = verify_ipsec(mode, address_family, nat=nat)
    stage("OBSERVATION")
    observation = ensure_live_observation(mode, address_family, nat=nat)
    if observation.get("status") != "live":
        raise xdp_observation.ObservationReadinessError(
            f"live XDP observation not ready: {observation}"
        )
    # The live observation is now flowing against a truncated journal. Record
    # its exact byte boundary at this moment: the analytics feed will serve
    # ONLY lines at/after this offset, so no pre-experiment history can ever
    # appear in the LIVE table for this run.
    observation_start_bytes = manifest_mod.current_journal_size()
    if manifest_mod.write_start(job_id, config, started_at_ns, observation_start_bytes):
        print(
            f"published live observation boundary @ byte {observation_start_bytes} "
            "for this experiment"
        )
    stage("CONNECTIVITY")
    connectivity = test_connectivity(mode, address_family, nat=nat)

    # Root-cause classification for a data-plane failure that did NOT raise
    # (ping completed but reported loss). ``verify_ipsec`` already passed, so
    # ``ipsec`` carries the observed SA state the classifier needs.
    if connectivity.get("status") == "FAIL" and "classification" not in connectivity:
        connectivity["classification"] = diagnose.classify_failure(
            stage="CONNECTIVITY",
            sa_state=diagnose.parse_sa_state("ESTABLISHED INSTALLED"),
            ike_evidence={},
            nat=nat,
            connectivity=connectivity,
        )

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
        "observation": observation,
    }

    if profile is not None:
        stage("TRAFFIC")
        traffic = run_traffic(config)
        result["traffic"] = traffic

        if traffic["status"] != "PASS":
            result["status"] = "FAIL"

        # Evidence readiness is checked HERE, after traffic has been generated,
        # and never at attach time: a correctly attached monitor legitimately
        # has an empty journal until packets exist.  This is the point where
        # "observations are actually arriving" is a meaningful claim.
        if observation.get("status") == "live":
            baseline = int(observation.get("journal_lines") or 0)
            try:
                evidence_summary = xdp_observation.await_observation_evidence(
                    baseline_lines=baseline, log=print,
                )
            except xdp_observation.ObservationReadinessError as exc:
                result["observation_evidence"] = {
                    "status": "FAIL",
                    "reason": str(exc),
                }
                result["status"] = "FAIL"
                print(f"[traffic] live journal received no observations: {exc}")
            else:
                result["observation_evidence"] = {
                    "status": "PASS",
                    "new_observations": evidence_summary["lines"] - baseline,
                    "journal_lines": evidence_summary["lines"],
                    "journal_bytes": evidence_summary["bytes"],
                }

    # Refresh the open manifest with the real observed verdicts (observed SPIs,
    # observation/connectivity/traffic results) BEFORE marking the run ended.
    # The start manifest is written the moment observation goes live, so its
    # observed block is still empty; without this refresh the current-run annex
    # has no observed SPIs to project risk onto, and every live packet reads
    # UNASSESSED for the whole run. No ``ended_at_ns`` here, so the boundary
    # gate stays open and the assessment covers the packets observed so far.
    if (
        observation.get("status") == "live"
        and manifest_mod.write_current(
            job_id, config, result, started_at_ns,
            observation_start_bytes=observation_start_bytes,
            ended_at_ns=None,
        )
    ):
        print("published open manifest with observed verdicts for live risk "
              "projection")

    # Persist the current-run identity + real observed verdicts for the
    # analytics backend, but only when a real live observation was produced
    # (a live XDP journal on this mode's passive sensor). Specifying
    # ``ended_at_ns`` marks the run as finished so the feed drops LIVE rows
    # immediately on stop. The manifest is cleared at the next DEPLOY, so it
    # can never describe a different run.
    if (
        observation.get("status") == "live"
        and manifest_mod.write_current(
            job_id, config, result, started_at_ns,
            observation_start_bytes=observation_start_bytes,
            ended_at_ns=int(time.time_ns()),
        )
    ):
        print("published current experiment manifest for live analytics binding")

    return result


if __name__ == "__main__":
    result = run_experiment(CONFIG)

    print("\n=== Experiment Result ===\n")
    print(json.dumps(result, indent=2))
