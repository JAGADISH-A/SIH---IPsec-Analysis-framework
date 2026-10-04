"""Current testbed experiment manifest (the controller -> analytics seam).

The manual testbed path (``POST /experiments`` driven from the testbed
frontend) produces real IPsec traffic and a real live XDP journal, but kept no
per-run identity for the analytics backend: Sentinel had nothing but the static
startup store to bind a packet against, so a live packet was either left
unassessed or attached to a stale recorded dataset run whose SPI happened to
match.

This module writes ONE authoritative, read-only JSON record of the current
experiment next to the live journal: the job identity, the configuration that
was really deployed, the observed verification verdicts (IPsec SA, connectivity,
traffic, live observation summary), the SPI values actually observed in the
journal, and the authoritative security posture band for the deployed config
(from ``dataset_planner.posture_of_config`` -- the same rule the dataset plan
uses; it is never recomputed or invented here).

The manifest is cleared the moment a new experiment starts deploying (the live
journal is truncated then too), so a stale manifest can never be attached to a
different run. Path is ``results/observed-state/xdp/experiment.json`` unless
``TESTBED_MANIFEST_PATH`` overrides it.
"""

import json
import os
import tempfile
import time
import hashlib
from pathlib import Path

from . import xdp_observation

MANIFEST_FILE = "experiment.json"
ENV_PATH = "TESTBED_MANIFEST_PATH"

SCHEMA = "testbed-experiment-manifest/v1"

#: Process-local identity of the continuous dataset run whose live boundary
#: this process owns.  ``None`` when no dataset run is publishing.  The testbed
#: is serialized by ``TestbedLock`` (one run at a time), so a single slot is
#: sufficient and the live pipeline can re-anchor the boundary without being
#: threaded the run identity.
_ACTIVE_SESSION = None


def manifest_path():
    """The current-run manifest path, next to the live XDP journal."""
    override = os.environ.get(ENV_PATH)
    if override:
        return Path(override)
    return xdp_observation.JOURNAL_DIRECTORY / MANIFEST_FILE


def _journal_path():
    return xdp_observation.journal_path(
        journal_dir=xdp_observation.JOURNAL_DIRECTORY,
        journal_file=xdp_observation.JOURNAL_FILE,
    )


def _read_events(journal: Path):
    """Read the real live journal rows read-only (never modified)."""
    journal = Path(journal)
    events = []
    try:
        if journal.is_file() and journal.stat().st_size > 0:
            with open(journal, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                    except (ValueError, TypeError):
                        continue
    except OSError:
        return []
    return events


def collect_observed_spis(journal: Path = None):
    """Distinct SPI values the live journal actually observed for this run.

    Returned as ``(spis, spi_stats)`` where ``spis`` is an ordered list of
    integers and ``spi_stats`` maps each SPI to ``{first_seen_ns,
    last_seen_ns, packet_count, sequences}`` as observed.
    """
    journal = journal or _journal_path()
    stats = {}
    for event in _read_events(journal):
        spi = event.get("spi")
        if spi in (None, ""):
            continue
        try:
            spi = int(str(spi), 0)
        except (TypeError, ValueError):
            continue
        ts_ns = event.get("ts")
        try:
            ts_ns = int(ts_ns)
        except (TypeError, ValueError):
            ts_ns = None
        seq = event.get("seq")
        try:
            seq = int(seq)
        except (TypeError, ValueError):
            seq = None
        entry = stats.setdefault(
            spi,
            {
                "first_seen_ns": ts_ns,
                "last_seen_ns": ts_ns,
                "packet_count": 0,
                "sequences": [],
            },
        )
        entry["packet_count"] += 1
        if ts_ns is not None:
            if entry["first_seen_ns"] is None or ts_ns < entry["first_seen_ns"]:
                entry["first_seen_ns"] = ts_ns
            if entry["last_seen_ns"] is None or (ts_ns > entry["last_seen_ns"]):
                entry["last_seen_ns"] = ts_ns
        if seq is not None and seq not in entry["sequences"]:
            entry["sequences"].append(seq)
        if len(entry["sequences"]) > 64:
            entry["sequences"] = entry["sequences"][-64:]
    spis = list(stats.keys())
    return spis, stats


def _posture_band(config):
    """Authoritative posture for the deployed config, via the dataset planner.

    The planner's rule is the backend authority the dataset samples use; the
    manifest consumes that same value and never recomputes it.
    """
    try:
        from .dataset_planner import posture_of_config

        band, score = posture_of_config(config)
        return {"band": band, "score": score}
    except Exception as error:  # noqa: BLE001 - posture is best-effort metadata
        return {"band": None, "score": None, "reason": f"{type(error).__name__}: {error}"}


def experiment_identity(job_id, started_at_ns):
    """Stable run/identity fields for the manifest."""
    run_id = f"testbed-{job_id}" if job_id else "testbed-manual"
    sequence = 1
    slot = "current"
    assessment_id = f"{run_id}:{sequence}:{slot}"
    experiment_id = f"{run_id}-exp-{sequence:04d}"
    return {
        "dataset_run_id": run_id,
        "sequence": sequence,
        "slot": slot,
        "assessment_id": assessment_id,
        "experiment_id": experiment_id,
    }


def build_manifest(job_id, config, result, started_at_ns,
                   observation_start_bytes=0, ended_at_ns=None):
    """Assemble the manifest dict from real observed values.

    ``observation_start_bytes`` is the journal byte offset at the moment the
    live observation went live; it is the ``CaptureFeedService`` boundary that
    isolates LIVE rows to this experiment only. When ``ended_at_ns`` is given
    the feed treats the run as finished and stops serving rows immediately.
    """
    result = result or {}
    identity = experiment_identity(job_id, started_at_ns)
    journal = Path(_journal_path())
    spis, spi_stats = collect_observed_spis(journal)
    events = _read_events(journal)
    run = {
        **identity,
        "job_id": job_id,
        "source": "testbed-frontend",
        "started_at_ns": started_at_ns,
        "status": result.get("status"),
    }
    if observation_start_bytes:
        run["observation_start_bytes"] = int(observation_start_bytes)
    if ended_at_ns is not None:
        run["completed_at_ns"] = int(ended_at_ns)
        run["ended_at_ns"] = int(ended_at_ns)
    return {
        "schema": SCHEMA,
        "run": run,
        "config": {
            "mode": config.get("mode"),
            "address_family": config.get("address_family"),
            "ike": config.get("ike"),
            "esp": config.get("esp"),
            "traffic": config.get("traffic"),
        },
        "observed": {
            "ipsec": result.get("ipsec"),
            "connectivity": result.get("connectivity"),
            "observation": result.get("observation"),
            "traffic": result.get("traffic"),
            "spis": spis,
            "spi_stats": {
                str(spi): {
                    "first_seen_ns": stats["first_seen_ns"],
                    "last_seen_ns": stats["last_seen_ns"],
                    "packet_count": stats["packet_count"],
                    "distinct_sequences": len(stats["sequences"]),
                }
                for spi, stats in spi_stats.items()
            },
            "summary": journal_summary(events),
            "journal_events": len(events),
        },
        "posture": _posture_band(config),
        "journal": {
            "path": str(journal),
            "byte_size": journal.stat().st_size if journal.is_file() else 0,
            "observation_start_bytes": int(observation_start_bytes or 0),
        },
    }


def journal_summary(events):
    """Real aggregate of the live journal (packets/bytes/flags/time-span)."""
    summary = {
        "packets": 0,
        "bytes": 0,
        "esp": 0,
        "ike": 0,
        "ah": 0,
        "udp": 0,
        "tunnel_seen": False,
        "esp_seen": False,
        "ike_seen": False,
        "first_ts_ns": None,
        "last_ts_ns": None,
    }
    for event in events:
        summary["packets"] += 1
        length = event.get("len")
        try:
            summary["bytes"] += int(length)
        except (TypeError, ValueError):
            pass
        ts = event.get("ts")
        try:
            ts = int(ts)
        except (TypeError, ValueError):
            ts = None
        if ts is not None:
            if summary["first_ts_ns"] is None or ts < summary["first_ts_ns"]:
                summary["first_ts_ns"] = ts
            if summary["last_ts_ns"] is None or ts > summary["last_ts_ns"]:
                summary["last_ts_ns"] = ts
        proto = event.get("proto")
        classification = str(event.get("classification", "") or "").upper()
        if classification in ("ESP", "AH", "IKE"):
            if classification == "ESP":
                summary["esp"] += 1
                summary["esp_seen"] = True
                summary["tunnel_seen"] = True
            elif classification == "AH":
                summary["ah"] += 1
            else:
                summary["ike"] += 1
                summary["ike_seen"] = True
        elif classification in ("ESP-IN-UDP",):
            summary["esp"] += 1
            summary["esp_seen"] = True
            summary["tunnel_seen"] = True
        elif proto is not None:
            try:
                proto = int(proto)
            except (TypeError, ValueError):
                continue
            if proto == 50:
                summary["esp"] += 1
                summary["esp_seen"] = True
                summary["tunnel_seen"] = True
            elif proto == 51:
                summary["ah"] += 1
            elif proto == 17:
                summary["udp"] += 1
    return summary


def _sha256(path: Path):
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def write_start(job_id, config, started_at_ns, observation_start_bytes=0, result=None):
    """Persist the interim start manifest atomically (no ended marker).

    Written the moment the live observation goes live, so the feed can gate
    LIVE rows to this experiment only. The final ``write_current`` reuses the
    same ``observation_start_bytes`` and adds ``ended_at_ns``.

    ``result`` carries the already-observed facts that exist at boundary time
    (notably the real ``swanctl --list-sas`` verification).  Recording them here
    is what makes the manifest's ``observed.ipsec.mode`` the *authoritative*
    deployed encapsulation mode, so the analytics layer can compare mode
    without ever inferring it from the wire.
    """
    path = Path(manifest_path())
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    manifest = build_manifest(
        job_id, config, result, started_at_ns,
        observation_start_bytes=observation_start_bytes,
    )
    manifest["manifest_sha256"] = _sha256(path)
    fd, tmp = tempfile.mkstemp(prefix=".experiment-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2, sort_keys=False)
            handle.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return True


def current_journal_size():
    """Byte size of the live observation journal (the feed boundary seed)."""
    journal = Path(_journal_path())
    try:
        return journal.stat().st_size
    except OSError:
        return 0


def write_current(job_id, config, result, started_at_ns,
                  observation_start_bytes=0, ended_at_ns=None):
    """Persist the current-run manifest atomically (tmp + rename)."""
    path = Path(manifest_path())
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    manifest = build_manifest(
        job_id, config, result, started_at_ns,
        observation_start_bytes=observation_start_bytes,
        ended_at_ns=ended_at_ns,
    )
    manifest["manifest_sha256"] = _sha256(path)
    fd, tmp = tempfile.mkstemp(prefix=".experiment-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2, sort_keys=False)
            handle.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return True


def clear():
    """Remove the current-run manifest (called at experiment deploy start)."""
    path = Path(manifest_path())
    if path.is_file():
        try:
            path.unlink()
            return True
        except OSError:
            return False
    return True


# ---------------------------------------------------------------------------
# Continuous dataset-run session boundary
# ---------------------------------------------------------------------------
#
# A dataset run is a *continuous* live session: the topology is deployed once
# and the XDP monitor/journal are kept alive across samples, so Packet Analysis
# must stay LIVE for the whole run instead of for a single experiment.  The
# manual path opens and closes a boundary per experiment (``write_start`` /
# ``write_current`` in ``controller.executor``); the automated path had no
# boundary at all, so the experiment-gated capture feed served zero rows for
# the entire run.  These helpers own ONE run-spanning boundary:
#
#   begin_run_session()          arm this process as the run's boundary owner
#   publish_session_boundary()   open at the first live observation; re-anchor
#                                whenever the sensor journal is truncated by a
#                                monitor (re)start (mode switch / redeploy)
#   close_run_session()          mark the run ended (generation stopped)
#
# ``publish`` is a no-op unless the process is the armed owner, so the manual
# and unit-test paths (which never arm) are untouched.

def begin_run_session(dataset_run_id):
    """Arm this process as the live-boundary owner for a dataset run."""
    global _ACTIVE_SESSION
    _ACTIVE_SESSION = {
        "dataset_run_id": dataset_run_id,
        "config": None,
        "started_at_ns": None,
        "anchor": None,
        "result": None,
    }
    return True


def session_active():
    """True when this process is publishing a continuous run's boundary."""
    return _ACTIVE_SESSION is not None


def publish_session_boundary(config, observation=None, log=None, result=None):
    """Open (or re-anchor) the continuous run's live boundary.

    Writes once at the first live observation, and again whenever the sensor's
    journal was truncated by a monitor (re)start (``observation.action ==
    "started"``), re-seeding ``observation_start_bytes`` to the post-truncation
    size.  On clean reuse (``action == "reuse"``) an already-open boundary is
    left untouched so the whole run remains one LIVE window.  Returns True when
    a boundary write happened.

    ``result`` is the run's already-observed facts (the real ``swanctl
    --list-sas`` verification and the live observation record).  Recording the
    observed SA mode at every anchor keeps ``observed.ipsec.mode``
    authoritative for the whole session, including after a mode switch, where
    the previous sample's mode must not leak into the new one.
    """
    session = _ACTIVE_SESSION
    if session is None:
        return False
    if (observation or {}).get("status") != "live":
        return False
    log = log or (lambda msg: None)
    action = (observation or {}).get("action")
    started_at_ns = session.get("started_at_ns") or time.time_ns()
    session["started_at_ns"] = started_at_ns
    needs_write = (
        session.get("anchor") is None
        or action == "started"
        or not Path(manifest_path()).is_file()
    )
    if not needs_write:
        return False
    start_bytes = current_journal_size()
    if write_start(
        session["dataset_run_id"], config, started_at_ns,
        observation_start_bytes=start_bytes,
        result=result,
    ):
        session["config"] = config
        session["anchor"] = start_bytes
        session["result"] = result
        log(
            f"published continuous live boundary @ byte {start_bytes} "
            f"for dataset run {session['dataset_run_id']}"
        )
        return True
    return False


def close_run_session(result=None, log=None):
    """Close the continuous run's live boundary (generation stopped).

    Writes the final ``ended_at_ns`` marker so the experiment-gated feed drops
    LIVE rows immediately.  No-op when this process is not the armed owner, so
    it is safe to call unconditionally from a worker ``finally``.
    """
    global _ACTIVE_SESSION
    session = _ACTIVE_SESSION
    if session is None:
        return False
    _ACTIVE_SESSION = None
    config = session.get("config")
    if not config:
        return False
    log = log or (lambda msg: None)
    try:
        written = write_current(
            session["dataset_run_id"], config,
            result if result is not None else session.get("result"),
            session.get("started_at_ns") or time.time_ns(),
            observation_start_bytes=session.get("anchor") or 0,
            ended_at_ns=time.time_ns(),
        )
    except Exception as exc:  # noqa: BLE001 - close is best-effort
        log(f"could not close the continuous live boundary ({exc})")
        return False
    if written:
        log(
            f"closed continuous live boundary for dataset run "
            f"{session['dataset_run_id']}"
        )
    return bool(written)