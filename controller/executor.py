import json
import os
import signal
import subprocess
import time
from pathlib import Path

from .config import CONFIG
from .topology import TOPOLOGIES
from .validate import validate_config
from .generator import write_connection
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

    if mode == "tunnel":
        # Authoritative lifecycle wrapper: containerlab destroy --cleanup
        # AND removal of the externally-managed br-wan bridge (only when it
        # has no remaining members).
        run(_privileged("bash", str(LIFECYCLE_SCRIPT), "destroy"),
            timeout=DESTROY_TIMEOUT)
        return

    run(_privileged("containerlab", "destroy", "-t", str(topo), "--cleanup"),
        timeout=DESTROY_TIMEOUT)


def deploy(mode):
    topo = topology_file(mode)

    try:
        if mode == "tunnel":
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

    run(
        _privileged("docker", "exec", container, "swanctl", "--initiate", "--child", connection_name),
        timeout=DOCKER_COMMAND_TIMEOUT,
    )


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
                run(
                    _privileged("docker", "exec", container, "swanctl", *command),
                    timeout=DOCKER_COMMAND_TIMEOUT,
                )
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
        _privileged("docker", "exec", source, *ping_command),
        timeout=DOCKER_COMMAND_TIMEOUT,
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

    output = run(
        _privileged("docker", "exec", source, "swanctl", "--list-sas"),
        timeout=DOCKER_COMMAND_TIMEOUT,
    )

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

def ensure_live_observation(mode, address_family="ipv4", log=None):
    """Make the live XDP observation path ready for a deployed testbed.

    Every mode declares a passive sensor that feeds the SAME shared live
    journal, so the result is identical in shape for both topologies: the
    tunnel sensor (``clab-ipsec-sensor``) observes the gw-a WAN mirror and the
    transport sensor (``clab-ipsec-transport-sensor``) observes the host-c
    host-to-host mirror.  The concrete sensor is resolved by
    ``xdp_observation.ensure_for_mode``; readiness failures raise
    ``ObservationReadinessError`` instead of degrading to "no observation".
    """
    return xdp_observation.ensure_for_mode(mode, log=log)


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
    reset_and_deploy(mode)
    stage("IPSEC")
    load_generated_configs(config)
    initiate_ipsec(mode, address_family)
    ipsec = verify_ipsec(mode, address_family)
    stage("OBSERVATION")
    observation = ensure_live_observation(mode, address_family)
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
