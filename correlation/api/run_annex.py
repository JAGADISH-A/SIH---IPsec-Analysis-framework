"""Live testbed run annex -- the analytics half of the controller seam.

The recorded assessment store is DETERMINISTIC and built once at startup: every
assessment it serves is computed by the real Phase-3..7 engines over recorded
artifacts, and it is deliberately immutable. The manual testbed path
(``POST /experiments`` from the testbed frontend) produces *live* packets in the
XDP journal, and the running store has no way to know that a fresh experiment
just deployed.

This annex closes exactly that gap with minimal surface:

* it reads the *real* current-run manifest the controller wrote next to the
  live journal (``results/observed-state/xdp/experiment.json``), read-only;
* it is active ONLY while the live capture feed is ``current`` (a journal being
  appended to right now), which is exactly the window in which a packet the
  testbed generated *and* the Sentinel row for it both exist;
* when active, it materializes the deployed config through the SAME
  ``ExpectedStateAdapter``, then runs the SAME comparison / risk / XAI engines
  the recorded store uses, and registers the result as one ordinary assessment
  (``<run>:1:current``) through the store's own ``_register`` -- so the risk,
  findings, posture, severity, explanations and headers are produced by the real
  backend, exactly as for any recorded run;
* it re-keys the capture feed's SPI index so a live packet binds to this run
  (never to a stale recorded dataset whose SPI happens to coincide);
* when the feed stops being current (traffic stopped, journal went quiet), or
  the next experiment clears the manifest, it unregisters and restores the
  recorded store byte-for-byte.

Nothing is invented: no posture, finding, risk or fact is supplied here. Every
input in the manifest is something the controller actually deployed or the
journal actually observed. If an input is missing or unusable, the annex stays
inactive and the store serves exactly what it served before.
"""

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .. import artifacts
from ..adapters import ExpectedStateAdapter
from ..comparison import ComparisonEngine, ComparisonEngineOptions
from ..models import ObservedState, SpiObservation
from ..risk import RiskEngine, RiskPolicy
from ..xai import ExplainabilityEngine
from .adapters import header_view
from .capture_feed import GATE_ACTIVE, GATE_LEGACY
from .store import MATERIALIZED_AT

MANIFEST_FILE = "experiment.json"
ENV_PATH = "TESTBED_MANIFEST_PATH"
SLOT = "current"
SCHEMA = "testbed-experiment-manifest/v1"


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _as_int_ns(value, default=0):
    try:
        out = int(value)
    except (TypeError, ValueError):
        return int(default)
    if isinstance(value, bool):
        return int(default)
    return out


class CurrentRunAnnex:
    """Read-only, reversible live binding between the current journal and store."""

    def __init__(self, store, feed, manifest_path: Optional[str] = None) -> None:
        self.store = store
        self.feed = feed
        self.manifest_path = Path(
            manifest_path
            if manifest_path
            else os.environ.get(ENV_PATH, self._default_manifest_path())
        )
        self._registered = False
        self._assessment_id: Optional[str] = None
        self._manifest_mtime = 0
        self._spi_stamp: Optional[tuple] = None
        self._spi_cache: set = set()
        self._manifest: Optional[Dict[str, Any]] = None
        self._saved_risk: Dict[int, Any] = {}
        self.last_status: Dict[str, Any] = {"active": False, "reason": "not started"}

    # -- path helpers --------------------------------------------------------

    def _default_manifest_path(self) -> str:
        base = os.path.dirname(os.path.abspath(self.feed.path))
        return os.path.join(base, MANIFEST_FILE)

    @staticmethod
    def _mtime(path: Path) -> Optional[int]:
        try:
            return path.stat().st_mtime_ns
        except OSError:
            return None

    # -- lifecycle -----------------------------------------------------------

    def sync(self) -> Dict[str, Any]:
        """Reconcile the annex with the live journal + manifest (call per read)."""
        mtime = self._mtime(self.manifest_path)
        feed_current = bool((self.feed._currentness() or {}).get("current"))
        # A live experiment stays active for as long as its boundary gate is
        # open (manifest present, same journal, not ended). Journal freshness
        # only drives the live/stale indicator: coupling registration to it
        # unregistered the assessment whenever traffic paused, so packets
        # already on screen lost their severity. The ungated (recorded-demo)
        # path keeps the original freshness-based rule.
        gate = None
        boundary = getattr(self.feed, "_boundary_gate", None)
        if callable(boundary):
            try:
                gate, _ = boundary()
            except Exception:  # noqa: BLE001 - never break the read path
                gate = None
        active = mtime is not None and (
            gate == GATE_ACTIVE or (gate == GATE_LEGACY and feed_current)
        )
        if not active:
            changed = self.unregister()
            self.last_status = {
                "active": False,
                "reason": "no current live journal with a controller manifest",
                "manifest_present": mtime is not None,
                "feed_current": feed_current,
                "gate": gate,
            }
            if mtime is not None and mtime != self._manifest_mtime:
                self.last_status["new_manifest"] = True
            return self.last_status
        if self._registered and self._manifest_mtime == mtime:
            # The run is still going and its manifest has not changed, but the
            # journal keeps producing new SA traffic.  Re-project the same
            # assessment onto the SPIs observed so far instead of freezing the
            # projection at first read (no re-assessment, no new risk logic).
            projected = self._project_risk()
            self.last_status = {
                "active": True,
                "assessment_id": self._assessment_id,
                "reason": "current live run already registered",
                "projected_spis": len(projected),
            }
            return self.last_status
        if self._registered:
            self.unregister()
        try:
            self.register(mtime)
            self.last_status = {
                "active": True,
                "assessment_id": self._assessment_id,
                "current_journal": mtime is not None,
            }
        except Exception as error:  # noqa: BLE001 - never break the read path
            self.last_status = {
                "active": False,
                "reason": f"{type(error).__name__}: {error}",
            }
        return self.last_status

    def is_active(self) -> bool:
        return self._registered

    # -- registration --------------------------------------------------------

    def _load_manifest(self) -> Dict[str, Any]:
        try:
            raw = self.manifest_path.read_text(encoding="utf-8")
        except OSError:
            raise LookupError(f"manifest not readable: {self.manifest_path}")
        manifest = json.loads(raw)
        if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
            raise ValueError("manifest has an unknown schema")
        run = manifest.get("run") or {}
        required = ("dataset_run_id", "sequence", "assessment_id")
        if any(not run.get(key) for key in required):
            raise ValueError("manifest run identity is incomplete")
        config = manifest.get("config") or {}
        ipsec = config.get("ipsec_configuration")
        observed = manifest.get("observed") or {}
        if not isinstance(ipsec, dict) and not isinstance(config.get("ike"), dict):
            raise ValueError("manifest has no usable ipsec configuration")
        # The interim start manifest (write_start) legitimately carries zero
        # observed journal events: it goes live before any traffic exists. The
        # field must be present, but a zero count is valid and must not block
        # registering the run's assessment.
        if "journal_events" not in observed:
            raise ValueError("manifest has no observed journal events")
        self._manifest = manifest
        return manifest

    def _plan_from_manifest(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """One-sample plan document mirroring the dataset plan schema."""
        config = dict(manifest.get("config") or {})
        ipsec_configuration = dict(config.get("ipsec_configuration") or config)
        for key in ("mode", "address_family"):
            if key in config and key not in ipsec_configuration:
                ipsec_configuration[key] = config[key]
        ipsec_configuration.setdefault("ike", config.get("ike") or {})
        ipsec_configuration.setdefault("esp", config.get("esp") or {})
        run = manifest["run"]
        sample = {
            "sequence": run["sequence"],
            "configuration_id": run.get("experiment_id") or run["assessment_id"],
            "security_posture": (manifest.get("posture") or {}).get("band"),
            "mode": ipsec_configuration.get("mode"),
            "address_family": ipsec_configuration.get("address_family"),
            "ipsec_configuration": ipsec_configuration,
        }
        traffic = config.get("traffic")
        if isinstance(traffic, dict) and traffic.get("profile"):
            sample["traffic"] = traffic
            sample["traffic_profile"] = traffic.get("profile")
        return {"schema": "expected/plan", "samples": [sample]}

    def _observed(self, manifest: Dict[str, Any]) -> ObservedState:
        observed = manifest.get("observed") or {}
        summary = observed.get("summary") or {}
        spis = observed.get("spis") or []
        stats = observed.get("spi_stats") or {}
        timestamp_ns = _as_int_ns(
            summary.get("last_ts_ns"),
            _as_int_ns((manifest.get("run") or {}).get("completed_at_ns"), 0),
        )
        spi_obs = []
        for spi in spis:
            try:
                spi_int = int(str(spi), 0)
            except (TypeError, ValueError):
                continue
            entry = stats.get(str(spi)) or {}
            seqs = entry.get("distinct_sequences")
            spi_obs.append(
                SpiObservation(
                    spi=int(spi_int),
                    direction=None,
                    active=True,
                    first_seen_ns=_as_int_ns(entry.get("first_seen_ns"), timestamp_ns),
                    last_seen_ns=_as_int_ns(entry.get("last_seen_ns"), timestamp_ns),
                    packet_count=int(entry.get("packet_count") or 0),
                    sequence_delta=int(seqs) if seqs is not None else None,
                )
            )
        return ObservedState(
            timestamp_ns=int(timestamp_ns),
            endpoints={},
            tunnel_seen=bool(summary.get("tunnel_seen", False)),
            active=bool(summary.get("tunnel_seen", False)),
            packets_seen=int(summary.get("packets") or 0),
            bytes_seen=int(summary.get("bytes") or 0),
            packets_a_to_b=0,
            packets_b_to_a=0,
            bytes_a_to_b=0,
            bytes_b_to_a=0,
            ike_seen=bool(summary.get("ike_seen", False)),
            ike_nat_t_seen=False,
            esp_seen=bool(summary.get("esp_seen", False)),
            ah_seen=bool(summary.get("ah") or 0) > 0,
            observed_ike_activity=bool(summary.get("ike_seen", False)),
            last_esp_timestamp_ns=(
                int(timestamp_ns) if summary.get("esp_seen") else None
            ),
            spis=spi_obs,
        )

    def _live_journal_spis(self) -> set:
        """SPI values the live journal shows at/after this run's boundary.

        The manifest snapshots ``observed.spis`` when it is written, which for
        an in-flight experiment is before any ESP packet exists, so projecting
        risk from the manifest alone leaves every live packet UNASSESSED. The
        journal the feed is already bound to is the same evidence the manifest
        is derived from, read here from the experiment's own boundary offset
        (``observation_start_bytes``) so no earlier run's traffic is included.
        Cached by (size, mtime); never writes or truncates the journal.
        """
        journal = getattr(self.feed, "path", None)
        if not journal:
            return set()
        try:
            stat = os.stat(journal)
        except OSError:
            return set()
        start = 0
        try:
            manifest = self._load_manifest() or {}
            start = int((manifest.get("run") or {}).get("observation_start_bytes") or 0)
        except Exception:  # noqa: BLE001 - best effort projection only
            start = 0
        stamp = (stat.st_size, stat.st_mtime_ns, start)
        if self._spi_stamp == stamp:
            return self._spi_cache
        spis = set()
        try:
            with open(journal, "rb") as handle:
                handle.seek(max(0, start))
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    spi = record.get("spi")
                    if spi is None:
                        continue
                    try:
                        spis.add(int(str(spi), 0))
                    except (TypeError, ValueError):
                        continue
        except OSError:
            return self._spi_cache
        self._spi_stamp = stamp
        self._spi_cache = spis
        return spis

    def register(self, mtime: int) -> None:
        manifest = self._load_manifest()
        run = manifest["run"]
        assessment_id = run["assessment_id"]
        if assessment_id in self.store.bundles:
            raise ValueError(f"assessment already registered: {assessment_id}")

        plan = self._plan_from_manifest(manifest)
        materialized = ExpectedStateAdapter(materialized_at=MATERIALIZED_AT).from_plan_record(
            plan,
            run_id=str(run["dataset_run_id"]),
            sequence=int(run["sequence"]),
            experiment_id=str(run.get("experiment_id") or run["assessment_id"]),
            source_path=str(self.manifest_path),
            source_type="testbed-experiment-manifest",
        )
        observed = self._observed(manifest)

        engine = ComparisonEngine(ComparisonEngineOptions())
        correlation = engine.compare(
            materialized,
            observed,
            observed_identity=materialized.identity,
            observed_values=artifacts.observed_evidence_values(observed),
            live_features=None,
            ml_result=None,
            evidence_refs=(),
        )
        assessment = RiskEngine(RiskPolicy.default()).assess(
            expected=materialized,
            observed=observed,
            correlation=correlation,
            ml_result=None,
            evidence_refs=(),
        )
        xai = ExplainabilityEngine().explain(
            assessment,
            correlation=correlation,
            ml_result=None,
            evidence_refs=(),
        )

        label = _scenario_label(run)
        sources = [
            {
                "role": "testbed_current_run",
                "name": "experiment.json",
                "path": str(self.manifest_path),
                "sha256": manifest.get("manifest_sha256"),
            }
        ]
        try:
            self.store._register(
                assessment_id,
                slot=SLOT,
                scenario_label=label,
                expected=materialized.expected,
                observed=observed,
                correlation=correlation,
                assessment=assessment,
                xai=xai,
                ml_result=None,
                evidence_refs=(),
                sources=sources,
                custody_sources=[],
                observed_present=True,
            )
        except Exception:
            self.store.bundles.pop(assessment_id, None)
            self.store.headers = [
                h for h in self.store.headers if h.get("assessment_id") != assessment_id
            ]
            self.store.custody_inputs.pop(assessment_id, None)
            raise

        self._assessment_id = assessment_id
        self._project_risk(manifest)
        self._manifest_mtime = mtime
        self._registered = True
        self.store._build_overview()

    def _project_risk(self, manifest=None) -> set:
        """Project this run's assessment onto the SPIs observed so far.

        The severity/risk_score/finding_count are the assessment's own values,
        copied verbatim; only the set of SPIs they are attached to grows, as
        the live journal produces new SA traffic.  Anything overridden earlier
        is restored first, so a re-projection can never leave a stale SPI
        carrying this run's verdict.
        """
        assessment_id = self._assessment_id
        if not assessment_id or assessment_id not in self.store.bundles:
            return set()
        self._restore_saved_risk()
        if manifest is None:
            try:
                manifest = self._load_manifest() or {}
            except Exception:  # noqa: BLE001 - projection is best effort
                manifest = {}
        header = header_view(self.store.bundles[assessment_id])
        observed_spis = set((manifest.get("observed") or {}).get("spis") or [])
        observed_spis.update(self._live_journal_spis())
        projected = set()
        for spi in sorted(observed_spis, key=str):
            try:
                spi_int = int(str(spi), 0)
            except (TypeError, ValueError):
                continue
            self._saved_risk.setdefault(
                spi_int, list_maybe_snapshot(spi_int, self.feed.risk_index)
            )
            self.feed.risk_index[spi_int] = [
                {
                    "assessment_id": assessment_id,
                    "severity": header.get("severity"),
                    "risk_score": header.get("risk_score"),
                    "finding_count": header.get("finding_count"),
                }
            ]
            projected.add(spi_int)
        return projected

    def _restore_saved_risk(self) -> None:
        """Put back every risk-index entry this annex overrode."""
        for spi_int, previous in list(self._saved_risk.items()):
            if previous is None:
                self.feed.risk_index.pop(spi_int, None)
            else:
                self.feed.risk_index[spi_int] = list(previous)
        self._saved_risk.clear()

    def _manifest_cached(self, mtime: int) -> Optional[Dict[str, Any]]:
        """Best-effort manifest parse, cached until the file mtime changes."""
        if self._manifest_mtime == mtime and self._manifest is not None:
            return self._manifest
        try:
            raw = self.manifest_path.read_text(encoding="utf-8")
            manifest = json.loads(raw)
        except (OSError, ValueError):
            return None
        self._manifest = manifest
        self._manifest_mtime = mtime
        return manifest

    def boundary(self) -> Optional[Dict[str, Any]]:
        """Live row boundary the capture feed must enforce (or ``None``).

        ``None`` means no controller manifest at all: the feed treats the
        journal as having no active experiment and serves zero LIVE rows.
        Otherwise the feed serves ONLY journal lines at/after ``start_bytes``
        and, once ``ended`` is true (experiment stopped), serves zero rows
        immediately.
        """
        mtime = self._mtime(self.manifest_path)
        if mtime is None:
            return None
        manifest = self._manifest_cached(mtime)
        if manifest is None or not isinstance(manifest, dict):
            return None
        run = manifest.get("run") or {}
        journal = manifest.get("journal") or {}
        start = _as_int_ns(
            run.get("observation_start_bytes") or journal.get("observation_start_bytes")
        )
        return {
            "journal_path": os.path.abspath(
                str(journal.get("path") or str(self.manifest_path))
            ),
            "start_bytes": start,
            "ended": bool(run.get("ended_at_ns")),
        }

    def experiment_scope(self) -> Optional[Dict[str, Any]]:
        """The current experiment's run identity, or ``None`` when no experiment
        is live on THIS journal.

        ``None`` means the audit tail must serve zero LIVE rows: either there is
        no controller manifest at all, the experiment has ended, or the manifest
        belongs to a different journal than the one being served. ``run_id`` is
        an immutable boundary the same way ``start_bytes`` is for the capture
        feed: events recorded for a run never predate that run's start.
        """
        mtime = self._mtime(self.manifest_path)
        if mtime is None:
            return None
        manifest = self._manifest_cached(mtime)
        if manifest is None or not isinstance(manifest, dict):
            return None
        run = manifest.get("run") or {}
        journal = manifest.get("journal") or {}
        if run.get("ended_at_ns"):
            return None
        assessment_id = run.get("assessment_id")
        dataset_run_id = run.get("dataset_run_id")
        if not assessment_id or not dataset_run_id:
            return None
        journal_path = os.path.abspath(
            str(journal.get("path") or str(self.manifest_path))
        )
        if self.feed is None or journal_path != os.path.abspath(self.feed.path):
            return None
        return {
            "dataset_run_id": str(dataset_run_id),
            "sequence": _as_int_ns(run.get("sequence")),
            "assessment_id": str(assessment_id),
            "experiment_id": str(run.get("experiment_id") or assessment_id),
            "status": str(run.get("status") or "running"),
        }

    def unregister(self) -> bool:
        """Drop the current-run assessment and restore the recorded store."""
        if not self._registered:
            return False
        assessment_id = self._assessment_id
        self.store.bundles.pop(assessment_id, None)
        self.store.headers = [
            h for h in self.store.headers if h.get("assessment_id") != assessment_id
        ]
        self.store.custody_inputs.pop(assessment_id, None)
        for spi, previous in list(self._saved_risk.items()):
            if previous is None:
                self.feed.risk_index.pop(spi, None)
            else:
                self.feed.risk_index[spi] = previous
        self._saved_risk.clear()
        self._assessment_id = None
        self._registered = False
        self.store._build_overview()
        return True


def list_maybe_snapshot(spi, risk_index):
    """Snapshot the recorded SPI projection before override, if present."""
    current = risk_index.get(spi)
    if current is None:
        return None
    return list(current)


def _scenario_label(run: Dict[str, Any]) -> str:
    job = run.get("job_id")
    source = run.get("source", "testbed")
    exp = run.get("experiment_id") or run.get("assessment_id")
    status = run.get("status")
    return (
        f"live {source} experiment {job or exp}"
        + (f" ({status})" if status else "")
        + " scored against the real live XDP journal"
    )