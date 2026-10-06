"""PHASE 8 — Deterministic assessment store, fed by recorded artifacts.

Builds the dashboard's assessment index by running the REAL Phase-3 -> Phase-7
pipeline over artifacts this repository actually recorded:

* the **expected** state comes from the materialized Phase-3 plan
  (``results/datasets/dataset-20260924-003710/staging/plan.json``, 100 samples
  covering all five posture bands);
* the **observed** state comes from real ``ebpf.ipsec_state_builder`` snapshots
  under ``results/e2e-verification/parser/`` and ``results/observed-state/``;
* the **live feature window** comes from the real feature-schema-v2 windows the
  offline evidence path emitted for the same captures, so observation coverage
  -- and therefore whether an absence can be concluded -- is a recorded fact;
* the **ML result** is real RandomForest output from
  ``results/ml/live_bridge/window_path_100ms.jsonl``, mapped through the
  controller seam;
* the **evidence** is a self-verifying reference to the very file each assessment
  was built from, carrying that file's real SHA-256.

The store is DETERMINISTIC (fixed inputs -> fixed outputs; no time, random, or
network).

What the previous stand-ins claimed, and what replaced it
----------------------------------------------------------
The earlier store synthesized its inputs: SPI values from a formula
(``0x06000000 + sequence * 0x10000``), a two-key feature window, an
``MLResult`` with a typed-in ``anomaly=True``, and observed values copied *from
the expected state* so that every comparison agreed by construction. Every score
was computed by the real engines, but the inputs were invented, which made the
analyst view a demonstration rather than a report.

The replacements are honest about what a passive sensor can and cannot see:

* ``mode`` and the crypto variables are **not** in the state builder's
  vocabulary (``tunnel_seen`` means "traffic was observed", not "tunnel mode"),
  so no authoritative observed value is supplied for them and the comparison
  layer reports them UNKNOWN with its documented reasons. See
  :func:`correlation.artifacts.observed_evidence_values`.
* The trained model has no anomaly capability, so no assessment carries an
  anomaly. What the model really produced -- including its real
  misclassifications -- is reported as classification evidence, and the real
  ``ml.classification.disagreement`` rule does the rest.
* The one recorded state snapshot that contradicts itself is refused with its
  reason instead of being coerced into shape
  (:data:`correlation.artifacts.INCONSISTENT_STATE_ARTIFACTS`).

Every score / severity / finding / explanation is still produced by the real
Phase-6/7 engines consuming these inputs - never recomputed in the UI layer.
"""

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .. import artifacts
from ..adapters import ExpectedStateAdapter
from ..analysis import crypto_evidence, metadata, reports, sa, threat_matrix
from ..analysis.replay import ReplayAnalysis, analyze_replay
from ..artifacts import ArtifactUnavailable
from ..comparison import ComparisonEngine, ComparisonEngineOptions
from ..custody import ChainOfCustody, build_chain_of_custody
from ..drift import (
    BaselineRegistry,
    DRIFT_SOURCE_KIND_DECLARED,
    DRIFT_SOURCE_KIND_RECORDED,
    DriftAssessment,
    DriftCurrentSource,
    assess_drift,
    describe_canonicalization,
    DRIFT_CATEGORIES,
    UNSUPPORTED_DRIFT_CATEGORIES,
)
from ..mission import MissionProfileBook, mission_context
from ..models import EvidenceRef, MLResult, ObservedState
from ..response.planner import PlanningContext, plan as plan_response
from ..response.policy import ResponsePolicy
from ..risk import RiskEngine, RiskPolicy
from ..xai import ExplainabilityEngine
from .adapters import (
    STORE_VERSION,
    assessment_bundle,
    evidence_to_view,
    header_view,
    ml_to_view,
    with_analytical_contract,
)
from .redact import public_path

PLAN_PATH = os.path.join(artifacts.REPO_ROOT, artifacts.REAL_PLAN_PATH)

# Dataset run id derived from the plan's own location (Phase-3 identity
# convention), so the assessment ids name the run the plan really came from.
DATASET_RUN_ID = artifacts.REAL_PLAN_RUN_ID

# The plan is a recorded artifact with a recorded generation time; pinning the
# materialization stamp here is what keeps the store reproducible.
MATERIALIZED_AT = "2026-09-20T00:00:00+00:00"

#: One real recorded capture: the state snapshot, the feature window and the
#: capture they were both derived from. ``window_path`` is ``None`` when the
#: capture produced no v2 feature window, and ``address_family`` is the family the
#: snapshot itself shows, used to pair the capture with a real plan sample.
@dataclass(frozen=True)
class RecordedCase:
    name: str
    state_path: str
    window_path: Optional[str]
    capture: str
    description: str
    address_family: str
    #: The IPsec encapsulation mode this capture was taken in. Transport and
    #: tunnel put byte-identical protocol-50 ESP on the wire, so a capture is
    #: paired with a plan sample only when the mode matches too.
    mode: str = "tunnel"


RECORDED_CASES: Tuple[RecordedCase, ...] = (
    RecordedCase(
        name="tunnel-v4",
        state_path="results/e2e-verification/parser/tunnel_v4/state.jsonl",
        window_path="results/e2e-verification/parser/tunnel_v4/windows.jsonl",
        capture="tunnel/tunnel_v4_gwa_eth2.pcap",
        description="200 ESP frames, WAN 192.168.100.1<->.2, tunnel mode",
        address_family="ipv4",
    ),
    RecordedCase(
        name="tunnel-v6",
        state_path="results/e2e-verification/parser/tunnel_v6inner/state.jsonl",
        window_path="results/e2e-verification/parser/tunnel_v6inner/windows.jsonl",
        capture="tunnel/tunnel_v6inner_gwa_eth2.pcap",
        description=(
            "194 ESP frames whose inner payload is IPv6; the snapshot records "
            "the outer SA endpoints (WAN 192.168.100.1<->.2), so the "
            "observed address family is the outer one and an IPv6 plan sample "
            "genuinely disagrees with it"
        ),
        address_family="ipv6",
    ),
    RecordedCase(
        name="nat-t",
        state_path="results/observed-state/live_state_from_events_full.jsonl",
        window_path=None,
        capture="results/observed-state/live_events_full.jsonl",
        description=(
            "live-tap session with IKE NAT-T and four observed SPIs; the run "
            "recorded 100 ms packet counters but no v2 feature window, so this "
            "case carries the state snapshot alone"
        ),
        address_family="ipv4",
    ),
    RecordedCase(
        name="transport-v6",
        state_path="results/e2e-verification/parser/transport_v6_live/state.jsonl",
        window_path=None,
        capture="results/e2e-verification/parser/transport_v6_live/events.jsonl",
        description=(
            "live transport-mode capture of the same asset under an IPv6 "
            "configuration: outer SA endpoints 2001:db8:20::10<->.20, two real "
            "SPIs, ESP in force and AH absent. Recorded alongside the "
            "transport/IPv4 baseline of the same topology and encapsulation "
            "mode, so the two differ on the outer address family and on "
            "nothing else"
        ),
        address_family="ipv6",
        mode="transport",
    ),
)

#: Posture bands drawn from the real plan, one sample per documented band. The
#: risk trend the dashboard draws comes from the planner's own output.
POSTURE_BANDS: Tuple[str, ...] = (
    "STRONG", "GOOD", "MEDIUM", "WEAK", "WORST",
)

#: Scenario slots. These are no longer six synthetic postures: each one is a
#: recorded case or a recorded plan sample, named for what it actually shows.
SCENARIO_SLOTS = (
    "strong-clean",
    "pfs-weak",
    "tunnel-v4",
    "tunnel-v6",
    "transport-v6",
    "nat-t",
    "ml-mismatch",
    "unknown",
)


def _load(loader, path, *, required=True):
    """Load one recorded artifact, or record the honest reason it is missing."""
    try:
        return loader(path)
    except ArtifactUnavailable as error:
        if required:
            raise
        return None, _unavailable(path, str(error))


def _unavailable(path: str, reason: str) -> artifacts.ArtifactRecord:
    return artifacts.ArtifactRecord(
        path=path,
        artifact_sha256="",
        byte_size=0,
        record_count=0,
        detail={"available": False, "reason": reason},
    )


@dataclass(frozen=True)
class RecordedObservation:
    """A real observed state plus the real window that covers it."""

    case: RecordedCase
    observed: ObservedState
    window: Any
    state_record: artifacts.ArtifactRecord
    window_record: Optional[artifacts.ArtifactRecord]
    ml_result: Optional[MLResult] = None
    ml_record: Optional[artifacts.ArtifactRecord] = None
    ml_window: Optional[Dict[str, Any]] = None

    def provenance(self) -> List[Dict[str, Any]]:
        records = [self.state_record]
        if self.window_record is not None:
            records.append(self.window_record)
        if self.ml_record is not None:
            records.append(self.ml_record)
        return artifacts.provenance(*records)

    def custody_provenance(self) -> List[Dict[str, Any]]:
        """Role-tagged provenance for the chain of custody.

        :meth:`provenance` is left exactly as it is because the bundle's existing
        ``sources`` shape is part of the published contract. The custody layer
        additionally needs to say *what role* each artifact played, so that a
        reader can tell the state snapshot from the feature window from the model
        output rather than being handed three anonymous digests.
        """
        tagged: List[Dict[str, Any]] = []
        for role, record in (
            ("observed_state", self.state_record),
            ("live_feature_window", self.window_record),
            ("ml_output", self.ml_record),
        ):
            if record is None:
                continue
            for item in artifacts.provenance(record):
                tagged.append({**item, "role": role, "name": self.case.name})
        return tagged


@dataclass(frozen=True)
class RecordedMlEvidence:
    """Real model output for a real window, with no state observation attached.

    Used where the recorded capture has no ``ipsec_state_builder`` snapshot. The
    model result is then scored against the real plan sample that shares the
    window's ``configuration_id``, and no state from an unrelated capture is
    joined in to make the assessment look fuller than it is.
    """

    result: MLResult
    record: artifacts.ArtifactRecord
    window: Dict[str, Any]


def _real_ml_window(misclassified: Sequence[Dict[str, Any]], index: int = 0):
    """The recorded misclassified window at ``index``, or None."""
    if index < len(misclassified):
        return misclassified[index]
    return None


def load_recorded_observation(
    case: RecordedCase,
) -> RecordedObservation:
    """Load one recorded case: real state, real window, real model output.

    Every input is read from disk and carries its artifact's own digest. An
    artifact that is missing or self-inconsistent raises
    :class:`~correlation.artifacts.ArtifactUnavailable` -- the store never
    substitutes a stand-in to keep a scenario populated. A capture with no v2
    feature window is loaded without one rather than given another capture's.
    """
    observed, state_record = artifacts.load_observed_state(case.state_path)
    window = None
    window_record = None
    if case.window_path is not None:
        window, window_record = artifacts.load_feature_window(case.window_path)
    return RecordedObservation(
        case=case,
        observed=observed,
        window=window,
        state_record=state_record,
        window_record=window_record,
    )


def load_ml_evidence(window: Dict[str, Any]) -> RecordedMlEvidence:
    """Real model output for one recorded window, with its artifact's digest."""
    return RecordedMlEvidence(
        result=artifacts.ml_result_for_window(window),
        record=_ml_window_record(window),
        window=window,
    )


def _ml_window_record(window: Dict[str, Any]) -> artifacts.ArtifactRecord:
    digest, size = artifacts.fingerprint(artifacts.REAL_ML_WINDOW_PATH)
    return artifacts.ArtifactRecord(
        path=artifacts.REAL_ML_WINDOW_PATH,
        artifact_sha256=digest,
        byte_size=size,
        record_count=0,
        detail={
            "window_id": window.get("window_id"),
            "capture": window.get("capture"),
            "configuration_id": window.get("configuration_id"),
            "expected_profile": window.get("expected_profile"),
            "predicted_profile": window.get("traffic_profile"),
            "timestamp": window.get("timestamp"),
        },
    )


def real_evidence(sequence: int, *paths: str) -> List[EvidenceRef]:
    """Self-verifying references to the real files an assessment was built from.

    Each reference carries the artifact's real SHA-256 and size, so the
    dashboard's evidence column can be checked instead of trusted. A capture is
    never authoritative: it proves bytes were observed, not that an
    interpretation is correct.

    ``sequence`` is the assessment's own plan sequence. It is required because
    ``EvidenceRef`` refuses a capture sequence below 1; passing the real
    sequence is what makes the reference constructible at all.
    """
    refs: List[EvidenceRef] = []
    for path in paths:
        if path is None:
            continue
        ref = artifacts.evidence_ref_for(
            path, run_id=DATASET_RUN_ID, sequence=sequence)
        if ref is not None:
            refs.append(ref)
    return refs


def disclosed_sources(sources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Reduce recorded artifact records to their disclosed form.

    The chain of custody is served to a browser, so each recorded artifact keeps
    its role, digest, size and record count but loses its host path: the
    repository-relative form survives when the artifact is inside the repository
    (the most useful form for a client) and everything else collapses to a
    basename. The redaction is the API's existing disclosure policy applied once,
    at the boundary, so the custody layer itself needs no knowledge of the
    filesystem.
    """
    disclosed: List[Dict[str, Any]] = []
    for source in sources or ():
        if not isinstance(source, dict):
            continue
        item = dict(source)
        path = item.pop("path", None)
        item["public_path"] = public_path(path, repo_root=artifacts.REPO_ROOT)
        disclosed.append(item)
    return disclosed


@dataclass(frozen=True)
class CustodyInput:
    """The authoritative objects one assessment's chain of custody is built from.

    Retained alongside the serialized bundle because the bundle is a view, not
    the source: a custody chain must quote the real ``ExpectedState``,
    ``CorrelationResult``, ``RiskAssessment`` and response recommendation objects
    that the pipeline produced, not a re-parse of the view. Holding them lets
    :meth:`AssessmentStore.chain_of_custody` answer a request without re-running
    any stage, which is what keeps the read-only guarantee true.
    """

    assessment_id: str
    expected: Any
    observed: ObservedState
    correlation: Any
    assessment: Any
    xai: Any
    ml_result: Optional[MLResult]
    evidence_refs: Tuple[EvidenceRef, ...]
    sources: Tuple[Dict[str, Any], ...]
    #: ``False`` when no observed state was supplied, so the chain can say so.
    observed_present: bool
    #: The reused response plan, planned once with ``clock=None``.
    response_plan: Any


def _scenario_label(slot: str, sequence: int, posture: Optional[str],
                    case: Optional[RecordedCase] = None) -> str:
    """What each scenario actually is, named for the artifact behind it."""
    labels = {
        "strong-clean": (
            f"STRONG configuration against a real tunnel capture "
            f"(sequence {sequence}, posture {posture or 'STRONG'})"
        ),
        "pfs-weak": (
            f"WEAK configuration with PFS disabled, real tunnel capture "
            f"(sequence {sequence})"
        ),
        "tunnel-v4": "Real tunnel_v4 state snapshot + real v2 feature window",
        "tunnel-v6": "Real tunnel_v6inner state snapshot + real v2 feature window",
        "nat-t": "Real live-tap snapshot with IKE NAT-T and four observed SPIs",
        "ml-mismatch": (
            "Real RandomForest output that disagrees with the planned traffic "
            "profile (recorded misclassification, not an anomaly)"
        ),
        "unknown": (
            f"No authoritative observation supplied (sequence {sequence}); the "
            f"pipeline reports UNKNOWN rather than guessing"
        ),
    }
    label = labels.get(slot, f"posture band {sequence}")
    if case is not None:
        label = f"{label} - {case.description}"
    return label


def _observed_values(observation: Optional[RecordedObservation]) -> Optional[Dict[str, Any]]:
    """The authoritative observed values for one case, as the sensor recorded them.

    A real ``ipsec_state_builder`` snapshot establishes no protocol
    configuration, so this is the empty evidence channel and the comparison layer
    resolves those variables to UNKNOWN with its documented reasons. Passing
    ``None`` instead (the ``unknown`` scenario) removes the channel entirely.
    """
    if observation is None:
        return None
    return artifacts.observed_evidence_values(observation.observed)


@dataclass(frozen=True)
class DriftCurrentObservation:
    """One explicitly declared current observation for the longitudinal comparison.

    Deliberately *not* a :class:`RecordedObservation`. A recorded case is
    something a sensor captured; this input may be a controlled fixture derived
    from such a capture. Whether the current state was observed live or declared
    for a controlled demonstration is the single most important thing a reader
    needs to know about a drift claim, so it is carried in the type rather than
    in a flag that a caller could set inconsistently.

    The declared provenance is free-form because it comes from whoever produced
    the observation; the store records it verbatim and never upgrades a
    declaration into a capture.
    """

    slot: str
    observed: ObservedState
    #: The real artifact the state was loaded from, with its real digest.
    state_record: artifacts.ArtifactRecord
    #: The producer's own declaration: what it is, and what it was derived from.
    declared_provenance: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Refuse a declared observation whose artifact no longer matches itself.

        The digest carried by ``state_record`` is what a chain will publish. If
        the file has changed since it was loaded, that published digest is
        already false, and the only honest options are to fail or to say
        something weaker. This fails: a chain is never built on an artifact
        whose bytes disagree with the identity attached to them, and nothing is
        silently repaired or re-derived to make the mismatch disappear.
        """
        from ..models.evidence import sha256_file

        actual = sha256_file(artifacts._resolve(self.state_record.path))
        if actual != self.state_record.artifact_sha256:
            raise ArtifactUnavailable(
                f"declared current observation {self.state_record.path!r} has "
                f"changed since it was loaded: recorded sha256 "
                f"{self.state_record.artifact_sha256}, file hashes to {actual}"
            )

    def custody_provenance(self) -> List[Dict[str, Any]]:
        """Role-tagged provenance for the chain of custody.

        The role is fixed to ``controlled_drift_observation`` because that is
        what an explicitly declared current observation is, whatever the
        producer called it. The declared text is carried through as ``detail`` so
        the reader sees the producer's own words rather than a paraphrase.
        """
        tagged: List[Dict[str, Any]] = []
        for item in artifacts.provenance(self.state_record):
            declared = dict(self.declared_provenance or {})
            tagged.append({
                **item,
                "role": "controlled_drift_observation",
                "name": declared.get("name") or "declared-current-observation",
                "detail": {
                    key: declared[key]
                    for key in sorted(declared)
                    if key != "name" and not isinstance(
                        declared[key], (dict, list, tuple, set))
                },
            })
        return tagged


def _current_source_kind(drift: DriftAssessment) -> str:
    """What kind of artifact the current state was, for the drift surface."""
    source = getattr(drift, "current_source", None)
    return getattr(source, "kind", DRIFT_SOURCE_KIND_RECORDED)


def _current_source_is_capture(drift: DriftAssessment) -> bool:
    """Whether the current state came from a live capture."""
    source = getattr(drift, "current_source", None)
    return bool(getattr(source, "is_capture", True))


#: The bundle ``sources`` role for a packet journal, so a reader can tell the
#: per-packet sequence evidence apart from the state snapshot it summarises.
JOURNAL_SOURCE_ROLE = "packet journal (per-packet ESP sequence evidence)"

#: Where the sequence evidence came from when no journal exists at all.
SNAPSHOT_SOURCE_LABEL = "observed-state snapshot"


@dataclass(frozen=True)
class ObservationEvidence:
    """The recorded sequence evidence for one observation.

    ``state_path`` names the snapshot the counters and aggregates came from;
    ``journal_path`` names the per-packet journal when the capture is one, and
    is ``None`` when it is not (a pcap, for instance, is not parsed here).
    ``sequences`` is the journal's per-SPI ``(sequence, timestamp_ns)`` pairs
    or ``None`` when there is nothing per-packet to analyse.
    """

    sequences: Optional[Dict[str, Tuple[Tuple[int, int], ...]]] = None
    journal_path: Optional[str] = None
    state_path: str = SNAPSHOT_SOURCE_LABEL
    record: Optional[artifacts.ArtifactRecord] = None

    @property
    def replay_source(self) -> str:
        """Where the replay analysis's sequence evidence came from."""
        return self.journal_path or self.state_path

    def has_journal(self) -> bool:
        return self.journal_path is not None and self.sequences is not None


def sequence_journal_for(
    observation: Optional[RecordedObservation],
) -> ObservationEvidence:
    """Per-packet sequence evidence for one recorded observation, if any.

    The capture is read as a journal only when it *is* one (a ``.jsonl`` whose
    records carry ``spi``/``seq``/``ts``); a pcap is not parsed here, so a
    capture with no journal yields ``sequences=None`` and a replay source
    naming the state snapshot the aggregates came from. Nothing is
    substituted for a missing journal: the replay analysis reports the gap,
    and this function does not fill it.
    """
    if observation is None or observation.case is None:
        return ObservationEvidence()
    case = observation.case
    if not case.capture.endswith(".jsonl"):
        return ObservationEvidence(state_path=case.state_path)
    try:
        sequences, record = artifacts.load_sequence_journal(case.capture)
    except ArtifactUnavailable:
        # A journal that exists but carries no ESP sequence records is the
        # same evidence gap as no journal: aggregate evidence only.
        return ObservationEvidence(state_path=case.state_path)
    return ObservationEvidence(
        sequences=sequences,
        journal_path=case.capture,
        state_path=case.state_path,
        record=record,
    )


def build_analysis_products(
    *,
    assessment_id: str,
    slot: str,
    scenario: str,
    expected,
    observed,
    correlation,
    assessment,
    ml,
    response_plan,
    sources: Sequence[Mapping[str, Any]],
    observation_source: str,
    replay: Optional[ReplayAnalysis] = None,
) -> Dict[str, Any]:
    """The Phase-11 analytical products for one registered assessment.

    Every product is derived from objects the bundle already reports, so the
    bundle cannot describe one thing and the product another. Nothing here
    re-runs a comparison, re-scores a finding or re-classifies a window. Each
    product is stamped with the Phase-1 analytical contract: its ``producer``,
    plus ``state`` / ``reason`` / ``source`` only where the producer recorded
    none of its own.
    """
    if replay is None:
        replay = analyze_replay(observed, sequences=None,
                                source=observation_source)
    sa_product = sa.analyze_sa(observed, source=observation_source)
    crypto_product = crypto_evidence.analyze_crypto_evidence(
        expected, observed,
        source=f"{observation_source} + expected configuration")
    metadata_product = metadata.analyze_metadata_exposure(
        observed, source=observation_source)
    threat = threat_matrix.build_threat_matrix(
        assessment.findings, metadata=metadata_product)
    inputs = reports.ReportInputs(
        assessment_id=assessment_id,
        slot=slot,
        scenario=scenario,
        expected=expected,
        observed=observed,
        correlation=correlation,
        assessment=assessment,
        ml=ml_to_view(ml, expected=expected, correlation=correlation),
        sa=sa_product,
        crypto=crypto_product,
        replay=replay,
        metadata=metadata_product,
        threat=threat,
        response_plan=(
            response_plan.to_dict() if response_plan is not None else None
        ),
        sources=tuple(dict(source) for source in sources),
    )
    return {
        "sa": with_analytical_contract(sa_product.to_dict(), product="sa"),
        "crypto_evidence": with_analytical_contract(
            crypto_product.to_dict(), product="crypto_evidence"),
        "replay_assessment": with_analytical_contract(
            replay.to_dict(), product="replay_assessment"),
        "metadata_exposure": with_analytical_contract(
            metadata_product.to_dict(), product="metadata_exposure"),
        "threat_matrix": with_analytical_contract(
            threat.to_dict(), product="threat_matrix"),
        "report": with_analytical_contract(
            reports.build_technical_report(inputs).to_dict(),
            product="report"),
        "executive_report": with_analytical_contract(
            reports.build_executive_report(inputs).to_dict(),
            product="executive_report"),
    }


class AssessmentStore:
    """Deterministic in-memory index + bundles (built once, read-only)."""

    def __init__(self, plan_path: str = PLAN_PATH, *,
                 asset_id: Optional[str] = None,
                 mission_profiles: Optional[MissionProfileBook] = None,
                 baselines: Optional[BaselineRegistry] = None,
                 baseline_id: Optional[str] = None,
                 drift_observations: Sequence[DriftCurrentObservation] = (),
                 drift_scenario_label: Optional[str] = None) -> None:
        self.plan_path = os.path.abspath(plan_path)
        self.bundles: Dict[str, Dict[str, Any]] = {}
        self.headers: List[Dict[str, Any]] = []
        self.overview: Dict[str, Any] = {}
        self.store: Dict[str, Any] = {}
        self.sources: List[Dict[str, Any]] = []
        #: Authoritative pipeline objects per assessment, for the custody layer.
        self.custody_inputs: Dict[str, CustodyInput] = {}
        #: The asset this dataset run was declared to belong to, or ``None``.
        #: Operator-declared assessment input. It is never derived from the
        #: assessment, the capture or any observed value; with ``None`` every
        #: chain reports ``not_configured`` and keeps its technical risk alone.
        self.asset_id: Optional[str] = asset_id
        #: Declared asset mission profiles, or ``None`` when none were loaded.
        self.mission_profiles: Optional[MissionProfileBook] = mission_profiles
        #: Validated IPsec security-state baselines, or ``None``. Never inferred
        #: and never auto-populated: a store built without an explicit registry
        #: performs no drift comparison at all and says so.
        self.baselines: Optional[BaselineRegistry] = baselines
        #: Which registered baseline to compare against, named explicitly. No
        #: fallback to "the only one" or "the latest one" is performed.
        self.baseline_id: Optional[str] = baseline_id
        #: Current observations declared for the longitudinal comparison, keyed
        #: by scenario slot. Absent for a slot, the recorded observation for that
        #: slot is the current state, exactly as before.
        self.drift_observations: Dict[str, DriftCurrentObservation] = {
            item.slot: item for item in drift_observations
        }
        #: The scenario text used for a drift-origin assessment, or ``None`` to
        #: build one that names only what is true. The demonstration supplies its
        #: own text so the controlled nature of the data is visible in the
        #: dashboard row, not only in a report.
        self.drift_scenario_label = drift_scenario_label
        #: Drift comparison per assessment, computed at build time from the
        #: recorded observation. Empty when no baseline is configured.
        self.drift_inputs: Dict[str, DriftAssessment] = {}
        #: For a drift-origin assessment, the plan-based assessment whose slot
        #: supplied the current observation. ``None`` for a plan-based
        #: assessment's own comparison.
        self.drift_parent: Dict[str, Optional[str]] = {}
        self._build()

    # -- lifecycle ----------------------------------------------------------

    def _run_pipeline(self, sequence: int, slot: str, *,
                      observation: Optional[RecordedObservation] = None,
                      ml_evidence: Optional[RecordedMlEvidence] = None,
                      evidence_refs=(),
                      evidence: Optional[ObservationEvidence] = None):
        """Run the real Phase 3 -> 4 -> 5/6 -> 7 pipeline for one scenario.

        Every input is a recorded artifact: the expected state from the real
        plan, the observed state and feature window from a real capture, and
        the ML result from real model output. Nothing is overridden. An
        assessment may carry a state observation, an ML result, or both; a
        result is never attached to a state snapshot from another capture.

        ``evidence`` supplies the packet journal (when the capture is one) so
        the replay analysis and the risk engine see the same sequence
        evidence, and so no per-packet evidence is read twice.
        """
        evidence = evidence or ObservationEvidence()
        adapter = ExpectedStateAdapter(materialized_at=MATERIALIZED_AT)
        materialized = adapter.from_plan(self.plan_path, sequence=sequence)
        expected = materialized.expected
        identity = materialized.identity

        if observation is None:
            # No state observation: the comparison layer must resolve every
            # variable to UNKNOWN rather than assume agreement.
            observed = ObservedState(timestamp_ns=0)
            values = None
            window = None
        else:
            observed = observation.observed
            values = _observed_values(observation)
            window = observation.window
        ml_result = (
            observation.ml_result if observation is not None and observation.ml_result
            else (ml_evidence.result if ml_evidence is not None else None)
        )

        engine = ComparisonEngine(ComparisonEngineOptions())
        correlation = engine.compare(
            materialized,
            observed,
            observed_identity=identity,
            observed_values=values,
            live_features=window,
            ml_result=ml_result,
            evidence_refs=evidence_refs,
        )

        # One replay analysis, used twice: as the bundle's replay product and
        # as the evidence the risk engine is handed. It is never recomputed.
        replay = analyze_replay(
            observed,
            sequences=evidence.sequences,
            source=evidence.replay_source,
        )

        assessment = RiskEngine(RiskPolicy.default()).assess(
            expected=materialized,
            observed=observed,
            correlation=correlation,
            ml_result=ml_result,
            evidence_refs=evidence_refs,
            replay_evidence=replay.to_dict(),
        )

        xai = ExplainabilityEngine().explain(
            assessment,
            correlation=correlation,
            ml_result=ml_result,
            evidence_refs=evidence_refs,
        )
        return expected, observed, correlation, assessment, xai, ml_result, replay

    def _register(self, assessment_id: str, *, slot: str, scenario_label: str,
                  expected, observed, correlation, assessment, xai, ml_result,
                  evidence_refs, sources, custody_sources,
                  observed_present: bool,
                  observation_source: str = SNAPSHOT_SOURCE_LABEL,
                  replay: Optional[ReplayAnalysis] = None) -> Dict[str, Any]:
        """Index one completed assessment and keep its authoritative objects.

        Shared by the plan-based assessment and by a drift-origin assessment so
        that both are exposed through exactly the same bundle, header, custody
        and API surfaces. Re-using the same function is what keeps a drift
        finding from needing a parallel explanation implementation: it is
        registered the way any other assessment is, and every downstream layer
        treats it identically because it *is* an ordinary assessment.
        """
        bundle = assessment_bundle(
            assessment_id,
            identity=assessment.identity,
            expected=expected,
            observed=observed,
            correlation=correlation,
            ml=ml_result,
            assessment=assessment,
            xai=xai,
            slot=slot,
            scenario=scenario_label,
            evidence=[evidence_to_view(ev) for ev in evidence_refs],
        )
        bundle["sources"] = list(sources)
        # The custody layer reuses the reused response planner rather than
        # inventing a recommendation. ``clock=None`` keeps the plan free of any
        # wall-clock reading, so it is byte-identical across runs. The plan is
        # produced once here, at build time, alongside everything else, and the
        # reports below quote the very same plan object.
        response_plan = plan_response(
            PlanningContext(
                assessment=assessment,
                xai=xai,
                correlation=correlation,
                ml_result=ml_result,
                evidence_refs=tuple(evidence_refs),
                policy=ResponsePolicy.default(),
            ),
            clock=None,
        )
        bundle.update(
            build_analysis_products(
                assessment_id=assessment_id,
                slot=slot,
                scenario=scenario_label,
                expected=expected,
                observed=observed,
                correlation=correlation,
                assessment=assessment,
                ml=ml_result,
                response_plan=response_plan,
                sources=sources,
                observation_source=observation_source,
                replay=replay,
            )
        )
        self.bundles[assessment_id] = bundle
        self.headers.append(header_view(bundle))
        self.custody_inputs[assessment_id] = CustodyInput(
            assessment_id=assessment_id,
            expected=expected,
            observed=observed,
            correlation=correlation,
            assessment=assessment,
            xai=xai,
            ml_result=ml_result,
            evidence_refs=tuple(evidence_refs),
            sources=tuple(disclosed_sources(custody_sources)),
            observed_present=observed_present,
            response_plan=response_plan,
        )
        return bundle

    def _add(self, sequence: int, slot: str, *,
             observation: Optional[RecordedObservation] = None,
             ml_evidence: Optional[RecordedMlEvidence] = None,
             evidence_refs=(), scenario_label=None):
        sequence_evidence = sequence_journal_for(observation)
        expected, observed, correlation, assessment, xai, ml_result, replay = (
            self._run_pipeline(
                sequence, slot, observation=observation, ml_evidence=ml_evidence,
                evidence_refs=evidence_refs, evidence=sequence_evidence,
            )
        )
        assessment_id = f"{DATASET_RUN_ID}:{sequence}:{slot}"
        # The artifacts this bundle was actually built from, with their digests.
        sources: List[Dict[str, Any]] = []
        custody_sources: List[Dict[str, Any]] = []
        if observation is not None:
            sources.extend(observation.provenance())
            custody_sources.extend(observation.custody_provenance())
        if sequence_evidence.record is not None:
            # The journal is a separate artifact from the snapshot it was read
            # alongside, so it is disclosed as its own source (with its own
            # digest) rather than folded into the observation's provenance --
            # the observation's provenance describes what was observed, and
            # this file is the per-packet evidence the replay analysis read.
            sources.append({
                **artifacts.provenance(sequence_evidence.record)[0],
                "role": JOURNAL_SOURCE_ROLE,
            })
        if ml_evidence is not None:
            sources.extend(artifacts.provenance(ml_evidence.record))
            custody_sources.extend(
                {**item, "role": "ml_output", "name": "recorded-ml-window"}
                for item in artifacts.provenance(ml_evidence.record)
            )
        bundle = self._register(
            assessment_id,
            slot=slot,
            scenario_label=scenario_label or _scenario_label(
                slot, sequence, expected.security_posture,
                observation.case if observation is not None else None),
            expected=expected,
            observed=observed,
            correlation=correlation,
            assessment=assessment,
            xai=xai,
            ml_result=ml_result,
            evidence_refs=evidence_refs,
            sources=sources,
            custody_sources=custody_sources,
            observed_present=observation is not None,
            observation_source=sequence_evidence.state_path,
            replay=replay,
        )
        # Longitudinal comparison, performed once here against the current
        # observation when -- and only when -- a baseline was explicitly
        # configured. ``not_configured`` is a real, reported outcome; with no
        # baseline at all nothing is attached and every chain stays exactly as
        # it was before drift existed.
        if self.baselines is not None:
            self._attach_drift(
                assessment_id, sequence, slot, expected=expected,
                observed=observed, correlation=correlation, ml_result=ml_result,
                observation=observation, evidence_refs=evidence_refs,
                sources=sources, custody_sources=custody_sources,
                sequence_evidence=sequence_evidence, replay=replay,
            )
        return bundle

    def _attach_drift(self, assessment_id: str, sequence: int, slot: str, *,
                      expected, observed, correlation, ml_result,
                      observation: Optional[RecordedObservation],
                      evidence_refs, sources, custody_sources,
                      sequence_evidence: Optional[ObservationEvidence] = None,
                      replay: Optional[ReplayAnalysis] = None,
                      run_id: str = DATASET_RUN_ID) -> None:
        """Compare the current observation with the validated baseline, once.

        The comparison itself is always attached to the plan-based assessment,
        so ``no_drift`` and ``indeterminate`` stay visible exactly as the drift
        milestone defined them. When the comparison does produce findings, the
        drift result is additionally registered as an assessment in its own
        right: a drift finding is a real :class:`RiskAssessment` produced by the
        real risk engine, and nothing downstream -- custody, integrity, the
        explanation endpoint -- can reach a finding that is not registered.

        ``run_id`` names the dataset run the comparison belongs to. It defaults
        to the recorded plan run, so every existing caller is unaffected. A
        live testbed run passes its own real ``testbed-<job_id>`` so that both
        the recorded comparison identity and the drift-origin assessment id are
        derived from the run that actually produced the observation.
        """
        declared = self.drift_observations.get(slot)
        # The current state is the declared observation when the caller supplied
        # one for this slot, and the recorded observation otherwise.
        current = declared.observed if declared is not None else observed
        # A recorded capture is a recorded capture; a declared current state is
        # published as a declaration. This is the only place the distinction is
        # made, and it is made explicitly rather than inferred from the file.
        current_source = (
            DriftCurrentSource(
                kind=DRIFT_SOURCE_KIND_DECLARED,
                artifact_sha256=declared.state_record.artifact_sha256,
                public_path=public_path(
                    declared.state_record.path, repo_root=artifacts.REPO_ROOT),
                declared_kind=(declared.declared_provenance or {}).get("kind"),
                declaration=(declared.declared_provenance or {}).get("not_a_capture"),
                derived_from=(declared.declared_provenance or {}).get("derived_from"),
            )
            if declared is not None
            else DriftCurrentSource(kind=DRIFT_SOURCE_KIND_RECORDED)
        )

        # A declared current state is deliberately NOT given an ``EvidenceRef``.
        # ``evidence_ref_for`` types an artifact from its extension, and a
        # ``.jsonl`` state artifact is typed as a live XDP state artifact -- which
        # is exactly the claim a controlled fixture must not be given. It is
        # published through the provenance channel instead, where its role reads
        # ``controlled_drift_observation`` and its digest is the one
        # ``__post_init__`` just verified against the file. The evidence list
        # therefore keeps referring to recorded captures only.
        custody_for_drift: List[Dict[str, Any]] = list(custody_sources)
        sources_for_drift: List[Dict[str, Any]] = list(sources)
        drift_refs: List[EvidenceRef] = list(evidence_refs)
        if declared is not None:
            custody_for_drift.extend(declared.custody_provenance())
            sources_for_drift.extend(
                artifacts.provenance(declared.state_record))
            # The journal belongs to the recorded observation, not to a
            # declared fixture. The child's replay product below is built from
            # the fixture without per-packet sequences, so listing the journal
            # would claim an input that was not read.
            if sequence_evidence is not None and sequence_evidence.journal_path:
                sources_for_drift = [
                    item for item in sources_for_drift
                    if item.get("path") != sequence_evidence.journal_path
                ]

        drift = assess_drift(
            self.baselines.get(self.baseline_id),
            current,
            run_id=run_id,
            sequence=sequence,
            current_source_ref=current_source.public_path,
            current_source=current_source,
            evidence_refs=tuple(drift_refs),
        )
        self.drift_inputs[assessment_id] = drift
        self.drift_parent[assessment_id] = None
        self.bundles[assessment_id]["drift"] = drift.to_dict()
        # Re-point the plan-based chain at this comparison so its explanation
        # carries the longitudinal result as context.
        held = self.custody_inputs[assessment_id]
        self.custody_inputs[assessment_id] = CustodyInput(
            **{**held.__dict__, "evidence_refs": tuple(drift_refs),
               "sources": tuple(disclosed_sources(custody_for_drift))}
        )
        if drift.risk is None:
            # ``no_drift``, ``not_configured`` and ``indeterminate`` carry no
            # finding, so there is nothing to register and no assessment to add.
            return

        drift_slot = f"{slot}-drift"
        drift_id = f"{run_id}:{sequence}:{drift_slot}"
        drift_xai = ExplainabilityEngine().explain(
            drift.risk,
            correlation=correlation,
            ml_result=ml_result,
            evidence_refs=tuple(drift_refs),
        )
        self.drift_inputs[drift_id] = drift
        self.drift_parent[drift_id] = assessment_id
        # The longitudinal products describe THIS comparison. When the current
        # state is the recorded observation, the snapshot and journal that
        # described it describe it again; when it is a declared fixture, the
        # products are built from the fixture's own artifact and no packet
        # journal is claimed for a file that is not a capture.
        child_source = (
            declared.state_record.path if declared is not None
            else (sequence_evidence.state_path if sequence_evidence is not None
                  else SNAPSHOT_SOURCE_LABEL)
        )
        child_replay = (
            replay
            if declared is None and replay is not None
            else analyze_replay(current, sequences=None, source=child_source)
        )
        bundle = self._register(
            drift_id,
            slot=drift_slot,
            scenario_label=self.drift_scenario_label or (
                f"longitudinal comparison of the recorded "
                f"{observation.case.name if observation is not None else slot} "
                f"current state against validated baseline "
                f"{self.baseline_id!r}"),
            expected=expected,
            observed=current,
            correlation=correlation,
            assessment=drift.risk,
            xai=drift_xai,
            ml_result=ml_result,
            evidence_refs=drift_refs,
            sources=sources_for_drift,
            custody_sources=custody_for_drift,
            observed_present=True,
            observation_source=child_source,
            replay=child_replay,
        )
        bundle["drift"] = drift.to_dict()

    def _build(self) -> None:
        plan = self._load_plan_samples()
        by_cfg = {sample["configuration_id"]: sample for sample in plan}
        self.sources = self._record_sources(plan)

        # Posture bands: one real plan sample per documented band, each scored
        # against a real recorded capture. The risk trend the dashboard draws is
        # therefore the planner's own output, not a hand-picked sequence list.
        band_case = RECORDED_CASES[0]
        for band in POSTURE_BANDS:
            sequence = self._band_sequence(plan, band)
            if sequence is None:
                continue
            self._add(
                sequence,
                f"band-{band.lower()}",
                observation=load_recorded_observation(band_case),
                evidence_refs=real_evidence(
                    sequence, band_case.state_path, band_case.window_path),
                scenario_label=(
                    f"{band} configuration scored against the recorded "
                    f"{band_case.name} capture ({band_case.description})"
                ),
            )

        # Recorded cases, each against a plan sample for the same posture family
        # where one exists, plus the real classification-disagreement case.
        ml_pair = self._ml_mismatch_pair(by_cfg)
        for slot in SCENARIO_SLOTS:
            sequence, observation, label, ml_evidence = self._scenario(
                plan, by_cfg, slot, ml_pair)
            case = observation.case if observation is not None else None
            paths = [case.state_path, case.window_path] if case else []
            if ml_evidence is not None:
                paths.append(ml_evidence.record.path)
            self._add(
                sequence, slot,
                observation=observation,
                ml_evidence=ml_evidence,
                evidence_refs=real_evidence(sequence, *paths),
                scenario_label=label,
            )

        self._build_overview()

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _band_sequence(plan: List[Dict[str, Any]], band: str) -> Optional[int]:
        for sample in plan:
            if sample.get("security_posture") == band:
                return int(sample["sequence"])
        return None

    def _record_sources(self, plan: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Every artifact this store reads, with its digest, for the record."""
        sources: List[Dict[str, Any]] = [{
            "path": os.path.relpath(self.plan_path, artifacts.REPO_ROOT),
            "role": "expected state (materialized Phase-3 plan)",
            "samples": len(plan),
        }]
        for case in RECORDED_CASES:
            sources.append(self._source(
                case.state_path, f"observation ({case.name})"))
            if case.window_path is None:
                sources.append({
                    "path": case.capture,
                    "role": f"no v2 feature window for {case.name}",
                    "reason": (
                        "this capture recorded packet counters but no "
                        "feature-schema-v2 window; the assessment uses the "
                        "state snapshot alone rather than another "
                        "capture's window"
                    ),
                })
            else:
                sources.append(self._source(
                    case.window_path, f"feature window ({case.name})"))
        sources.append(self._source(
            artifacts.REAL_ML_WINDOW_PATH,
            "ML classification evidence (real model output)"))
        sources.append(self._source(
            artifacts.REAL_ML_REPLAY,
            "held-out parity evidence (not mapped onto MLResult)"))
        refused_path, refused_reason = next(
            iter(artifacts.INCONSISTENT_STATE_ARTIFACTS.items()))
        sources.append({
            "path": refused_path,
            "role": "REFUSED: not a usable observation (see reason)",
            "reason": refused_reason,
        })
        return sources

    @staticmethod
    def _source(path: str, role: str) -> Dict[str, Any]:
        digest, size = artifacts.fingerprint(path)
        return {
            "path": path,
            "role": role,
            "artifact_sha256": digest,
            "byte_size": size,
        }

    def _ml_mismatch_pair(self, by_cfg: Dict[str, Dict[str, Any]]):
        """A real plan sample + a real misclassified window for that same configuration.

        The join is on ``configuration_id``: the model output and the plan sample
        describe the same tunnel configuration, so the disagreement the risk
        engine reports is the model's real behaviour and not an artefact of
        comparing two unrelated things. The capture with the most recorded
        disagreements is chosen deterministically (most disagreements, then
        capture id) so the store stays reproducible.
        """
        groups, _ = artifacts.load_ml_results()
        best: Optional[Tuple[Any, Dict[str, Any]]] = None
        for group in sorted(groups, key=lambda item: str(item.get("capture"))):
            cfg = group.get("configuration_id")
            sample = by_cfg.get(cfg)
            if sample is None:
                continue
            misclassified = [
                window for window in group.get("windows") or ()
                if window.get("expected_profile") != window.get("traffic_profile")
            ]
            if not misclassified:
                continue
            rank = (-len(misclassified), str(group.get("capture")))
            if best is None or rank < best[0]:
                best = (rank, (group, sample, misclassified[0]))
        if best is None:
            return None
        return best[1]

    def _load_plan_samples(self) -> List[Dict[str, Any]]:
        with open(self.plan_path, "r", encoding="utf-8") as handle:
            return json.load(handle)["samples"]

    def _materialize(self, sample: Dict[str, Any]):
        adapter = ExpectedStateAdapter(materialized_at=MATERIALIZED_AT)
        sequence = sample["sequence"]
        return adapter.from_plan(self.plan_path, sequence=sequence).expected

    def _scenario(self, plan, by_cfg, slot, ml_pair):
        """Scenario -> (plan sequence, recorded observation, label, ML evidence).

        Every branch names an artifact. A branch whose artifact is unavailable
        is dropped from the index rather than filled with a stand-in, and the
        reason is recorded in :meth:`_record_sources`.
        """
        if slot in ("strong-clean", "pfs-weak"):
            band = "STRONG" if slot == "strong-clean" else "WEAK"
            sequence = self._band_sequence(plan, band)
            case = RECORDED_CASES[0]
            return (
                sequence,
                load_recorded_observation(case),
                _scenario_label(slot, sequence or 0, band, case),
                None,
            )
        if slot in ("tunnel-v4", "tunnel-v6", "transport-v6", "nat-t"):
            case = next(item for item in RECORDED_CASES if item.name == slot)
            sequence = self._case_sequence(plan, case)
            return (
                sequence,
                load_recorded_observation(case),
                _scenario_label(slot, sequence or 0, None, case),
                None,
            )
        if slot == "ml-mismatch":
            if ml_pair is None:
                raise ValueError(
                    "no recorded misclassification matches a plan sample; the "
                    "scenario is dropped rather than fabricated"
                )
            group, sample, window = ml_pair
            sequence = int(sample["sequence"])
            # Real model output only. The recorded capture this window came from
            # has no state snapshot, so no state from an unrelated capture is
            # attached: the disagreement is the model's, against the real plan.
            return (
                sequence,
                None,
                _scenario_label(slot, sequence, None)
                + f" (model output recorded on capture {group.get('capture')}, "
                  f"configuration {group.get('configuration_id')})",
                load_ml_evidence(window),
            )
        if slot == "unknown":
            # Deliberately no observation: the pipeline must report UNKNOWN for
            # everything it cannot establish, not assume agreement.
            return (
                self._band_sequence(plan, "GOOD"),
                None,
                _scenario_label("unknown", 0, "GOOD"),
                None,
            )
        raise ValueError(f"unknown scenario slot {slot!r}")

    @staticmethod
    def _case_sequence(plan: List[Dict[str, Any]], case: RecordedCase) -> int:
        """The plan sequence that best matches a recorded capture.

        The real captures are tunnel-mode IPv4/IPv6 with an ESP payload, so the
        first plan sample whose own ``address_family`` equals the capture's is
        used. A plan sample that does not declare a family is not a candidate:
        the family is checked exactly, so a capture can never be paired with a
        sample from the other family, and a plan without a matching sample is an
        error rather than a silent fallback to the first row.
        """
        family = case.address_family
        mode = case.mode
        for sample in plan:
            config = sample.get("ipsec_configuration") or {}
            if config.get("mode") != mode:
                continue
            if config.get("address_family") == family:
                return int(sample["sequence"])
        raise ValueError(
            f"no plan sample declares address_family {family!r} in {mode!r} "
            f"mode, "
            f"so capture {case.name!r} cannot be scored against a real expected "
            f"state; refusing to pair it with an unrelated sample"
        )

    def _build_overview(self) -> None:
        severities: Dict[str, int] = {}
        categories: Dict[str, int] = {}
        total_findings = 0
        unknown_observations = 0
        ml_anomalies = 0
        ml_disagreements = 0
        highest = None
        for header in self.headers:
            severities[header["severity"]] = severities.get(header["severity"], 0) + 1
            total_findings += header["finding_count"]
            bundle = self.bundles[header["assessment_id"]]
            for outcome in bundle["correlation"]["rows"]:
                if outcome["status"] == "UNKNOWN":
                    unknown_observations += 1
            if header["ml_present"] and header["ml_anomaly"] is True:
                ml_anomalies += 1
            if header["ml_present"] and any(
                    finding["rule_id"] == "ml.classification.disagreement"
                    for finding in bundle["risk"]["findings"]):
                ml_disagreements += 1
            if highest is None or header["risk_score"] > highest["risk_score"]:
                highest = header
        for header in self.headers:
            bundle = self.bundles[header["assessment_id"]]
            for finding in bundle["risk"]["findings"]:
                categories[finding["category"]] = (
                    categories.get(finding["category"], 0) + 1
                )
        severity_order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        self.overview = {
            "store_version": STORE_VERSION,
            "total_assessments": len(self.headers),
            "severity_counts": {s: severities.get(s, 0) for s in severity_order},
            "category_counts": dict(sorted(categories.items())),
            "findings_total": total_findings,
            "unknown_observations": unknown_observations,
            # The trained model has no anomaly capability, so this is reported
            # as what it is: zero recorded anomalies, and the real count of
            # classification disagreements the model actually produced.
            "ml_anomalies": ml_anomalies,
            "ml_classification_disagreements": ml_disagreements,
            "risk_policy_version": self.bundles[self.headers[0]["assessment_id"]][
                "risk"]["risk_policy_version"
            ],
            "xai_available": True,
            "source": (
                "recorded artifacts (real Phase-3 plan, real ipsec_state_builder "
                "snapshots, real v2 feature windows, real RandomForest output) "
                "+ Phase-4/5/6/7 pipeline (deterministic)"
            ),
            "dataset_run_id": DATASET_RUN_ID,
            "sources": self.sources,
            "highest_risk": highest["risk_score"] if highest else None,
            "highest_severity": highest["severity"] if highest else None,
        }
        self.store = {
            "api_schema_version": "v1",
            "overview": dict(self.overview),
            "headers": [dict(h) for h in self.headers],
        }
        if self.baselines is not None:
            self.store["drift"] = self.drift_summary()
            self.overview["drift"] = self.drift_summary()

    # -- drift ---------------------------------------------------------------

    def drift_summary(self) -> Dict[str, Any]:
        """The drift surface of this store: what was compared, and what changed.

        Reported whether or not a baseline is configured, because "nothing was
        configured" is itself the honest answer for a store that has no
        baseline, and a client must not read an absent section as "no drift".
        """
        if self.baselines is None:
            return {
                "configured": False,
                "reason": (
                    "no validated baseline registry was supplied to this store, "
                    "so no longitudinal comparison was made and no drift is "
                    "claimed; the absence of drift findings is not evidence that "
                    "the security state is unchanged over time"
                ),
                "baseline_id": None,
                "supported_categories": list(DRIFT_CATEGORIES),
                "unsupported_categories": list(UNSUPPORTED_DRIFT_CATEGORIES),
                "canonicalization": describe_canonicalization(),
                "status_counts": {},
                "assessments": {},
            }
        counts: Dict[str, int] = {}
        source_kinds: Dict[str, int] = {}
        compared: Dict[Tuple[Any, ...], str] = {}
        for drift in self.drift_inputs.values():
            counts[drift.status] = counts.get(drift.status, 0) + 1
            # One comparison is reported against two assessments when it
            # produced findings, and several assessments can share one
            # comparison result when they share one security state. Both facts
            # are published, so `status_counts` is never the only way to read
            # this surface.
            identity = (
                getattr(drift, "baseline_id", None),
                getattr(drift, "baseline_state_digest", None),
                getattr(drift, "current_state_digest", None),
                getattr(drift, "status", None),
            )
            compared.setdefault(identity, drift.status)
            kind = _current_source_kind(drift)
            source_kinds[kind] = source_kinds.get(kind, 0) + 1
        return {
            "configured": True,
            "reason": None,
            "baseline_id": self.baseline_id,
            "baseline": self.baseline_view(),
            "persistent": self.baselines.persistent,
            "supported_categories": list(DRIFT_CATEGORIES),
            "unsupported_categories": list(UNSUPPORTED_DRIFT_CATEGORIES),
            "canonicalization": describe_canonicalization(),
            # Assessment counts per status: the published contract, unchanged.
            "status_counts": dict(sorted(counts.items())),
            # Distinct comparison results. Lower than `assessment_count` when a
            # comparison is reported twice (once as context, once as the
            # drift-origin assessment) or when several assessments share one
            # security state.
            "comparison_count": len(compared),
            "assessment_count": len(self.drift_inputs),
            # How many of the reporting assessments are the drift-origin alias of
            # a comparison rather than an independent comparison.
            "drift_origin_count": sum(
                1 for parent in self.drift_parent.values() if parent
            ),
            # Which kind of artifact each current state was. Reported here so a
            # client scanning the table cannot read a declared demonstration as
            # an observation of a live device, and so the distinction is visible
            # without walking every per-assessment entry.
            "current_source_kinds": dict(sorted(source_kinds.items())),
            "assessments": {
                assessment_id: {
                    "status": drift.status,
                    "drift_detected": drift.drift_detected,
                    "drift_categories": list(drift.drift_categories),
                    "current_source_kind": _current_source_kind(drift),
                    "current_source_is_capture": _current_source_is_capture(drift),
                    "entry_kind": (
                        "drift_origin" if self.drift_parent.get(assessment_id)
                        else "plan_comparison"
                    ),
                    "parent_assessment_id": self.drift_parent.get(assessment_id),
                    "changed_fields": [
                        change.to_dict() for change in drift.changed_fields
                    ],
                    "reason": drift.reason,
                }
                for assessment_id, drift in sorted(self.drift_inputs.items())
            },
        }

    def baseline_view(self) -> Optional[Dict[str, Any]]:
        """The configured baseline as the API discloses it, or ``None``."""
        if self.baselines is None or not self.baseline_id:
            return None
        record = self.baselines.get(self.baseline_id)
        if record is None:
            return None
        payload = record.to_dict()
        return {
            "baseline_id": payload["baseline_id"],
            "validation_status": payload["validation_status"],
            "state_digest": payload["state_digest"],
            "baseline_digest": payload["baseline_digest"],
            "validated_at": payload["validated_at"],
            "validated_by": payload["validated_by"],
            "asset_id": payload["asset_id"],
            "captured_at": payload["captured_at"],
            "source_run_id": payload["source_run_id"],
            "source_observation_ref": payload["source_observation_ref"],
            "canonical_state": payload["canonical_state"],
            "model_version": payload["model_version"],
            "schema_version": payload["schema_version"],
        }

    def drift_for(self, assessment_id: str) -> Optional[DriftAssessment]:
        """The build-time drift comparison for one assessment, or ``None``."""
        return self.drift_inputs.get(assessment_id)

    # -- chain of custody ----------------------------------------------------

    def chain_of_custody(
        self,
        assessment_id: str,
        finding_id: str,
        *,
        audit_event_ids: Tuple[str, ...] = (),
        evidence_root: Optional[str] = None,
        verify_evidence: bool = True,
    ) -> ChainOfCustody:
        """The custody chain for one finding of one assessment.

        Raises :class:`KeyError` for an unknown assessment or a finding that
        assessment never produced -- a finding id repeats across assessments, so
        resolving the pair strictly is what keeps one assessment's decision from
        being explained with another's evidence.

        No stage is re-run here. Every value is read from the objects the real
        pipeline produced during :meth:`_build`, so serving a chain performs no
        detection, writes nothing and dispatches nothing.

        ``verify_evidence=False`` skips the artifact re-hash and reports each
        evidence link as ``not_performed`` rather than as verified.

        Declared asset context is attached when the store was built with an
        ``asset_id``. It is looked up in the mission profile book, never derived
        from the assessment: with no ``asset_id`` or no matching profile the
        chain reports ``not_configured`` and the technical risk stands alone.

        The drift comparison is attached only when the store was built with an
        explicit baseline, using the value computed at build time from the
        recorded observation. It is never recomputed here: serving a chain
        performs no comparison.
        """
        held = self.custody_inputs.get(assessment_id)
        if held is None:
            raise KeyError(assessment_id)
        finding = next(
            (
                item
                for item in held.assessment.findings
                if item.finding_id == finding_id
            ),
            None,
        )
        if finding is None:
            raise KeyError(f"{assessment_id}:{finding_id}")
        recommendation = next(
            (
                item
                for item in held.response_plan.recommendations
                if item.finding_id == finding_id
            ),
            None,
        )
        return build_chain_of_custody(
            assessment_id=assessment_id,
            finding=finding,
            assessment=held.assessment,
            correlation=held.correlation,
            expected=held.expected,
            observed=held.observed,
            recommendation=recommendation,
            sources=held.sources,
            audit_event_ids=audit_event_ids,
            evidence_root=evidence_root,
            observed_present=held.observed_present,
            verify_evidence=verify_evidence,
            mission_context=mission_context(
                technical_risk=held.assessment.overall_score,
                technical_severity=held.assessment.severity,
                asset_id=self.asset_id,
                profiles=self.mission_profiles,
            ),
            drift=self.drift_inputs.get(assessment_id),
        )


def build_store(plan_path: str = PLAN_PATH, *,
                asset_id: Optional[str] = None,
                mission_profiles: Optional[MissionProfileBook] = None,
                baselines: Optional[BaselineRegistry] = None,
                baseline_id: Optional[str] = None,
                drift_observations: Sequence[DriftCurrentObservation] = (),
                drift_scenario_label: Optional[str] = None) -> AssessmentStore:
    """Build the store, optionally bound to a declared asset and its profiles.

    ``asset_id`` is the operator's statement about which testbed asset this
    dataset run describes. It is the only link between an assessment and a
    mission profile, and it is supplied rather than inferred.

    ``baselines`` and ``baseline_id`` are the same kind of explicit declaration
    for drift: without both, no longitudinal comparison is made.
    """
    return AssessmentStore(
        plan_path=plan_path,
        asset_id=asset_id,
        mission_profiles=mission_profiles,
        baselines=baselines,
        baseline_id=baseline_id,
        drift_observations=drift_observations,
        drift_scenario_label=drift_scenario_label,
    )
