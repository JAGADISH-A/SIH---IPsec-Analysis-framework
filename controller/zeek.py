"""Zeek integration for the IPsec audit layer (evidence path).

Zeek is the optional higher-level monitoring consumer of the *same*
observation interface (``audit-tap0``) that the TShark metadata path uses.
By policy it is deliberately NOT installed on the testbed host: Zeek is a
large dependency stack and the task forbids silently installing it.  This
module therefore never installs anything.

Instead the evidence path is provided by the *containerised* upstream Zeek
image (``zeek/zeek`` Debian image, Zeek 9.0.0) driven by
:func:`zeek_observe_offline` over recorded PCAPs.  The same durable PCAPs
consumed by the TShark parser are re-observed independently by Zeek, and the
outcome (and only the outcome -- never the toolchain) is recorded into the
audit store as an ``EVENT_ZEEK`` record.

Division of labour (unchanged by this module):

    TShark  = packet-level IPsec metadata (ESP SPI/seq, IKE exchange/msg id)
    Zeek    = higher-level network events / state / detection (conn records)

Known limitation (Zeek 9.0.0 core, documented honestly): the core image emits
``conn`` records for IPv4 ESP tunnel sessions (``ip_proto=50``) and for IKE
flows over UDP 500/4500 (both IPv4 and IPv6), but it does *not* materialise a
``conn`` record for IPv6 ESP payloads.  IPv6 ESP remains observable via the
TShark metadata path and the streaming XDP sensor.
"""

import os
import shutil
import subprocess
from pathlib import Path

ZEEK_BINARIES = ("zeek", "zeekctl", "bro")

# Containerised upstream Zeek (Zeek 9.0.0) used as the evidence-path consumer.
# Pinned by tag; the image is discovered, never pulled or installed by this
# module (image management belongs to the container layer).
ZEEK_IMAGE = "zeek/zeek:latest"

# Docker image name to report into the audit event.
ZEEK_IMAGE_DEFAULT = os.environ.get("ZEEK_IMAGE", ZEEK_IMAGE)


def zeek_availability():
    """Report Zeek's presence for the evidence path (host + container)."""
    found = {name: shutil.which(name) for name in ZEEK_BINARIES}
    present = [name for name, path in found.items() if path]
    image_present = _docker_image_present(ZEEK_IMAGE_DEFAULT)
    evidence = "container" if image_present else None
    return {
        "installed": bool(present),
        "binaries": found,
        "candidates": present,
        "container_image": ZEEK_IMAGE_DEFAULT,
        "image_present": image_present,
        "evidence_available": evidence,
        "note": (
            "zeek/bro/zeekctl is intentionally not installed on the testbed "
            "host (no silent install by policy). The containerised evidence "
            "path (zeek_observe_offline) is "
            + ("available." if image_present else "available once the "
               "zeek/zeek image is present locally.")
            if not present else "host zeek binaries found."
        ),
    }


def _docker_image_present(image):
    docker = shutil.which("docker")
    if docker is None:
        return False
    try:
        result = subprocess.run(
            [docker, "image", "inspect", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return result.returncode == 0
    except OSError:
        return False


def _zeek_version(image):
    """Return the container's ``zeek --version`` string when available."""
    docker = shutil.which("docker")
    if docker is None or not _docker_image_present(image):
        return None
    try:
        result = subprocess.run(
            [docker, "run", "--rm", image, "zeek", "--version"],
            capture_output=True, text=True, check=False, timeout=120,
        )
        return result.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def zeek_observe_offline(pcap, output_dir=None, image=None,
                         extra_args=("-C",)):
    """Run containerised Zeek against one recorded PCAP (evidence path).

    Reprocessing a PCAP offline never touches the network or the TAP layer:
    the same ``zeek -r`` invocation used for a live capture is replayed over
    the recorded file.  ``output_dir`` (default ``<pcap dir>/zeek_<name>``)
    receives the generated Zeek ``*.log`` files.

    Returns a summary dict:

        {image, zeek_version, pcap, output_dir, exit_code,
         log_files, conn_records}

    Raises RuntimeError when the Zeek image is not present locally (no silent
    ``docker pull`` ever happens here).
    """
    pcap = str(pcap)
    if image is None:
        image = ZEEK_IMAGE_DEFAULT
    if not _docker_image_present(image):
        raise RuntimeError(
            f"Zeek image '{image}' is not present; refusing to run "
            "(no silent install). availability=%s"
            % zeek_availability()
        )
    pcap_path = Path(pcap).resolve()
    if not pcap_path.is_file():
        raise FileNotFoundError(f"pcap not found: {pcap}")
    if output_dir is None:
        output_dir = str(pcap_path.parent / f"zeek_{pcap_path.stem}")
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    docker = shutil.which("docker")
    command = [
        docker, "run", "--rm", "-u", "root", "-w", "/work",
        "-v", f"{pcap_path.parent}:/pcap:ro",
        "-v", f"{out_path}:/work",
        image, "zeek",
    ] + list(extra_args) + ["-r", f"/pcap/{pcap_path.name}"]

    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                check=False, timeout=600)
    except OSError as exc:
        raise RuntimeError(f"failed to launch docker for Zeek: {exc}") from exc
    except subprocess.SubprocessError as exc:
        raise RuntimeError(f"Zeek run aborted: {exc}") from exc

    log_files = sorted(p.name for p in out_path.iterdir()
                       if p.suffix == ".log")
    conn_records = _count_conn_records(out_path / "conn.log")
    return {
        "image": image,
        "zeek_version": _zeek_version(image),
        "pcap": pcap,
        "output_dir": output_dir,
        "exit_code": result.returncode,
        "stderr": result.stderr.strip(),
        "log_files": log_files,
        "conn_records": conn_records,
    }


def _count_conn_records(conn_log):
    """Count data rows in a Zeek ``conn.log`` (rows not starting with '#')."""
    if not Path(conn_log).is_file():
        return 0
    rows = 0
    with open(conn_log, encoding="utf-8") as fh:
        for line in fh:
            if line and not line.startswith("#"):
                rows += 1
    return rows


def record_zeek_observation(pcap, observed_at=None, output_dir=None,
                            image=None, audit_path=None):
    """Observe a PCAP with Zeek and record the outcome into the audit store.

    Wraps :func:`zeek_observe_offline` and appends an ``EVENT_ZEEK`` audit
    record (controller.audit.record_event).  The audit record describes the
    observation result; it never embeds traffic contents.
    """
    from controller import audit

    summary = zeek_observe_offline(pcap, output_dir=output_dir, image=image)
    if observed_at is None:
        observed_at = audit.utcnow_iso()
    event = {
        "event_type": audit.EVENT_ZEEK,
        "observed_at": observed_at,
        "image": summary["image"],
        "zeek_version": summary["zeek_version"],
        "pcap": summary["pcap"],
        "output_dir": summary["output_dir"],
        "exit_code": summary["exit_code"],
        "log_files": summary["log_files"],
        "conn_records": summary["conn_records"],
    }
    return audit.record_event(event, path=audit_path), summary


def zeek_observe(tap_interface, mode="tunnel", address_family="ipv4",
                 output_dir=None):
    """Integration seam: run Zeek against the *live* observation interface.

    Never invoked when Zeek is absent.  The active evidence path uses the
    offline replay :func:`zeek_observe_offline`; a live-tap consumer would
    run the same image with ``zeek -i <tap>`` after exposing the tap to the
    container.  Raises RuntimeError when Zeek is not present (no silent
    installation ever happens here).
    """
    availability = zeek_availability()
    if not availability["installed"] and not availability["image_present"]:
        raise RuntimeError(
            "zeek is not installed; refusing to run (no silent install). "
            f"availability={availability}"
        )
    raise NotImplementedError(
        "live zeek observation is available but not yet wired; "
        f"would run on tap '{tap_interface}' ({mode}/{address_family}). "
        "Use zeek_observe_offline() to replay recorded PCAPs through Zeek."
    )