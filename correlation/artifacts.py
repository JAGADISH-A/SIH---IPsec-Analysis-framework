"""Read-only loaders for the artifacts this repository actually recorded.

The dashboard used to be fed stand-ins: a hand-written ``ObservedState`` whose
SPIs came from a formula, a two-key feature "window", and an ``MLResult`` with a
typed-in anomaly flag. Every score those produced was computed by the real
engines, but the *inputs* were invented, so the analyst view was a demonstration
of the pipeline rather than a report about the testbed.

This module is the replacement for those inputs. Every loader reads a committed
artifact, reports the artifact's own identity (path, SHA-256, byte size), and
refuses rather than substitutes:

* :func:`load_observed_state` reads a real ``ebpf.ipsec_state_builder``
  snapshot. The snapshot is the *only* authority for what was observed, and it
  establishes no protocol configuration -- ``mode``, ciphers, DH groups and PFS
  are not in the passive sensor's vocabulary, so
  :func:`observed_evidence_values` returns nothing for them rather than
  inferring them.
* :func:`load_feature_window` reads a real feature-schema-v2 window, which is
  what establishes observation *coverage* (and therefore whether an absence can
  be concluded at all).
* :func:`load_ml_results` reads real RandomForest replay records and maps them
  through the single controller seam
  (:func:`correlation.ml.controller_bridge.controller_result_to_ml_result`).
  The trained model has no anomaly capability, so the mapped results carry
  ``anomaly=None``. A misclassification is a real thing the committed replay
  contains, and it is reported as one -- never as an anomaly.

Nothing here writes, repairs or synthesizes. A missing, truncated or internally
inconsistent artifact raises :class:`ArtifactUnavailable` with the reason, so a
caller can report the absence instead of quietly falling back to a stand-in.
"""

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .models.features import LiveFeatureWindow
from .models.observed import OBSERVED_MODES, ObservedState

#: The repository root as seen from this package (``correlation/artifacts.py``).
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: The most recent materialized Phase-3 plan, with all five posture bands
#: represented across 100 samples (``results/datasets/dataset-20260924-003710``).
#: A real plan, not the five-sample test fixture: the posture trend the dashboard
#: draws has to come from the planner's own output.
REAL_PLAN_PATH = "results/datasets/dataset-20260924-003710/staging/plan.json"
REAL_PLAN_RUN_ID = "dataset-20260924-003710"

#: Real feature-schema-v2 windows from the offline evidence-path runs, one per
#: recorded capture (``results/e2e-verification/parser/``). Each covers the whole
#: observation epoch of its capture, which is what lets the comparison layer
#: conclude about an absence instead of reporting UNKNOWN.
REAL_FEATURE_WINDOWS: Tuple[str, ...] = (
    "results/e2e-verification/parser/tunnel_v4/windows.jsonl",
    "results/e2e-verification/parser/tunnel_v6inner/windows.jsonl",
    "results/e2e-verification/parser/transport_live_reverify/windows.jsonl",
)

#: Real ``ipsec_state_builder`` snapshots. The first two are the tunnel captures
#: whose state is self-consistent; see :data:`INCONSISTENT_STATE_ARTIFACTS`.
REAL_OBSERVED_STATES: Tuple[str, ...] = (
    "results/e2e-verification/parser/tunnel_v4/state.jsonl",
    "results/e2e-verification/parser/tunnel_v6inner/state.jsonl",
    "results/observed-state/live_state_from_events_full.jsonl",
    "results/observed-state/lab-verify-20260919-143813/state_events.jsonl",
)

#: Recorded state snapshots that the observation model refuses, with the reason.
#: They are listed rather than hidden so the gap is visible: a snapshot whose
#: ``last_esp_timestamp_ns`` is later than the ``timestamp_ns`` that claims to
#: summarize it is not a usable observation, and no loader may "fix" it.
INCONSISTENT_STATE_ARTIFACTS: Dict[str, str] = {
    "results/e2e-verification/parser/transport_live_reverify/state.jsonl": (
        "last_esp_timestamp_ns is later than the snapshot timestamp_ns, so the "
        "snapshot does not describe the instant it claims to summarize"
    ),
}

#: Real held-out replay records: live events -> v2 feature record -> the trained
#: RandomForest, over the test split. 46/46 correct, so this file contains no
#: misclassification; it is the parity evidence, not a source of findings.
REAL_ML_REPLAY = "results/ml/live_bridge/heldout_live_replay.jsonl"
#: The 100 ms live-path windows the same model was scored on, grouped per
#: capture. These are the real predictions that can be mapped onto ``MLResult``
#: (they carry the full controller contract, including a timestamp) and they
#: contain genuine misclassifications.
REAL_ML_WINDOW_PATH = "results/ml/live_bridge/window_path_100ms.jsonl"
#: The scored summary for the held-out replay.
REAL_ML_SUMMARY = "results/ml/live_bridge/heldout_summary.json"
#: The model artifact the predictions were produced by.
REAL_MODEL_ARTIFACT = "results/ml/model_traffic_rf_v1.joblib"


class ArtifactUnavailable(Exception):
    """A recorded artifact is missing, malformed or self-inconsistent."""


@dataclass(frozen=True)
class ArtifactRecord:
    """One loaded artifact plus the identity of the file it came from."""

    path: str
    artifact_sha256: str
    byte_size: int
    record_count: int
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "artifact_sha256": self.artifact_sha256,
            "byte_size": self.byte_size,
            "record_count": self.record_count,
            **self.detail,
        }


def _resolve(relative_path: str) -> str:
    """Resolve a repository-relative artifact path, refusing to escape the repo."""
    root = os.path.abspath(REPO_ROOT)
    resolved = os.path.abspath(os.path.join(root, relative_path))
    if resolved != root and not resolved.startswith(root + os.sep):
        raise ArtifactUnavailable(
            f"artifact {relative_path!r} resolves outside the repository root"
        )
    return resolved


def _fingerprint(relative_path: str) -> Tuple[str, int]:
    resolved = _resolve(relative_path)
    if not os.path.isfile(resolved):
        raise ArtifactUnavailable(
            f"artifact {relative_path!r} does not exist; nothing is substituted "
            f"for it"
        )
    from .models.evidence import sha256_file

    return sha256_file(resolved), os.path.getsize(resolved)


def fingerprint(relative_path: str) -> Tuple[str, int]:
    """The recorded artifact's own ``(sha256, byte_size)``."""
    return _fingerprint(relative_path)


def _read_jsonl(relative_path: str) -> List[Dict[str, Any]]:
    """Read a JSONL artifact, reporting a corrupt line instead of skipping it."""
    resolved = _resolve(relative_path)
    if not os.path.isfile(resolved):
        raise ArtifactUnavailable(
            f"artifact {relative_path!r} does not exist; nothing is substituted "
            f"for it"
        )
    records: List[Dict[str, Any]] = []
    with open(resolved, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ArtifactUnavailable(
                    f"artifact {relative_path!r} line {number} is not valid JSON: "
                    f"{exc}"
                ) from None
    if not records:
        raise ArtifactUnavailable(f"artifact {relative_path!r} holds no records")
    return records


def _last(records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    return records[-1]


def load_observed_state(relative_path: str) -> Tuple[ObservedState, ArtifactRecord]:
    """Load a real ``ipsec_state_builder`` snapshot.

    The snapshot's final line is the last state the builder emitted. A snapshot
    the observation model rejects is reported as unavailable, with the model's
    own reason, rather than coerced into shape.
    """
    if relative_path in INCONSISTENT_STATE_ARTIFACTS:
        raise ArtifactUnavailable(
            f"artifact {relative_path!r} is not a usable observation: "
            f"{INCONSISTENT_STATE_ARTIFACTS[relative_path]}"
        )
    digest, size = _fingerprint(relative_path)
    records = _read_jsonl(relative_path)
    payload = _last(records)
    try:
        observed = ObservedState.from_dict(payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise ArtifactUnavailable(
            f"artifact {relative_path!r} is not a valid observed state: {exc}"
        ) from None
    return observed, ArtifactRecord(
        path=relative_path,
        artifact_sha256=digest,
        byte_size=size,
        record_count=len(records),
        detail={
            "endpoints": dict(observed.endpoints),
            "packets_seen": observed.packets_seen,
            "esp_seen": observed.esp_seen,
            "ike_seen": observed.ike_seen,
            "ike_nat_t_seen": observed.ike_nat_t_seen,
            "spi_count": len(observed.spis),
            # Read from the snapshot itself: these two are recorded by the state
            # builder but are not fields of the correlation ObservedState model.
            "observation_start_ns": payload.get("observation_start_ns"),
            "last_packet_timestamp_ns": payload.get("last_packet_timestamp_ns"),
        },
    )


def load_feature_window(relative_path: str) -> Tuple[LiveFeatureWindow, ArtifactRecord]:
    """Load a real feature-schema-v2 window.

    The window's own bounds are the coverage evidence: the comparison layer uses
    them to decide whether an absence can be concluded at all.
    """
    digest, size = _fingerprint(relative_path)
    records = _read_jsonl(relative_path)
    payload = _last(records)
    if payload.get("feature_schema_version") != "v2":
        raise ArtifactUnavailable(
            f"artifact {relative_path!r} is not a v2 feature record "
            f"(feature_schema_version="
            f"{payload.get('feature_schema_version')!r})"
        )
    try:
        window = LiveFeatureWindow.from_dict(payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise ArtifactUnavailable(
            f"artifact {relative_path!r} is not a valid feature window: {exc}"
        ) from None
    span_ns = window.window_end_ns - window.window_start_ns
    return window, ArtifactRecord(
        path=relative_path,
        artifact_sha256=digest,
        byte_size=size,
        record_count=len(records),
        detail={
            "feature_schema_version": window.feature_schema_version,
            "window_start_ns": window.window_start_ns,
            "window_end_ns": window.window_end_ns,
            "span_seconds": span_ns / 1_000_000_000.0,
            "feature_count": len(window.features),
            "packet_count": window.features.get("packet_count"),
            "total_bytes": window.features.get("total_bytes"),
        },
    )


def load_ml_results(
    relative_path: str = REAL_ML_WINDOW_PATH,
) -> Tuple[List[Dict[str, Any]], ArtifactRecord]:
    """Load real model output for the recorded live windows, per capture.

    Each group is returned with its predictions already mapped onto
    correlation ``MLResult`` objects through the single documented seam
    (:func:`controller_result_to_ml_result`). The trained RandomForest has no
    anomaly capability, so every mapped result carries ``anomaly=None``; a
    disagreement between the expected profile and the prediction is reported as
    a disagreement, never relabelled as an anomaly.

    The held-out replay file is deliberately *not* the source here: its lines
    carry no ``timestamp``, which the controller contract requires, so mapping
    one would mean inventing a value. Use :func:`load_ml_parity` for that file.
    """
    from .ml.controller_bridge import controller_result_to_ml_result

    digest, size = _fingerprint(relative_path)
    groups = _read_jsonl(relative_path)
    for group in groups:
        for window in group.get("windows") or ():
            # Fail loudly rather than dropping a window the seam cannot map.
            ml_result = controller_result_to_ml_result(
                _as_controller_result(window, group))
            window.setdefault("ml_result", ml_result)
    return groups, ArtifactRecord(
        path=relative_path,
        artifact_sha256=digest,
        byte_size=size,
        record_count=len(groups),
        detail={
            "model_version": _first_window_value(groups, "model_version"),
            "feature_schema_version": _first_window_value(
                groups, "feature_schema_version"),
            "captures": len(groups),
        },
    )


def load_ml_parity(
    relative_path: str = REAL_ML_REPLAY,
) -> Tuple[List[Dict[str, Any]], ArtifactRecord]:
    """Load the held-out replay records as-is, for parity reporting only.

    These are real predictions with a real ``correct`` verdict, and they are the
    evidence that the live path and the offline path agree. They are not mapped
    onto ``MLResult``: the recorded lines carry no ``timestamp``, and inventing
    one to satisfy the controller contract would put a fabricated field into an
    audit-visible record.
    """
    digest, size = _fingerprint(relative_path)
    records = _read_jsonl(relative_path)
    return records, ArtifactRecord(
        path=relative_path,
        artifact_sha256=digest,
        byte_size=size,
        record_count=len(records),
        detail={
            "model_version": records[0].get("model_version"),
            "feature_schema_version": records[0].get("feature_schema_version"),
            "correct": sum(1 for record in records if record.get("correct")),
            "incorrect": sum(1 for record in records
                             if record.get("correct") is False),
            "mappable_to_ml_result": False,
        },
    )


def load_ml_summary(relative_path: str = REAL_ML_SUMMARY) -> Dict[str, Any]:
    """The recorded held-out summary (accuracy, per-profile counts, parity)."""
    resolved = _resolve(relative_path)
    if not os.path.isfile(resolved):
        raise ArtifactUnavailable(f"artifact {relative_path!r} does not exist")
    with open(resolved, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _first_window_value(groups: Sequence[Dict[str, Any]], key: str) -> Optional[Any]:
    for group in groups:
        for window in group.get("windows") or ():
            if key in window:
                return window[key]
    return None


def load_ml_window_path(
    relative_path: str = REAL_ML_WINDOW_PATH,
) -> Tuple[List[Dict[str, Any]], ArtifactRecord]:
    """Load the raw per-capture 100 ms window groups (no ML mapping applied)."""
    digest, size = _fingerprint(relative_path)
    groups = _read_jsonl(relative_path)
    return groups, ArtifactRecord(
        path=relative_path,
        artifact_sha256=digest,
        byte_size=size,
        record_count=len(groups),
        detail={"captures": len(groups)},
    )


def misclassified_windows(
    groups: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """The real windows whose prediction disagrees with the expected profile.

    Each returned entry is a real record: the capture it came from, the window
    id, the expected profile, the predicted profile and the full probability
    vector. Nothing is ranked or synthesised; the list is the recorded
    disagreements, in file order.
    """
    found: List[Dict[str, Any]] = []
    for group in groups:
        for window in group.get("windows") or ():
            expected = window.get("expected_profile")
            predicted = window.get("traffic_profile")
            if expected is None or predicted is None or expected == predicted:
                continue
            found.append({
                "capture": group.get("capture"),
                "configuration_id": group.get("configuration_id"),
                "window_id": window.get("window_id"),
                "expected_profile": expected,
                "predicted_profile": predicted,
                "packet_count": window.get("packet_count"),
                "probabilities": dict(window.get("probabilities") or {}),
                "model_version": window.get("model_version"),
                "feature_schema_version": window.get("feature_schema_version"),
                "timestamp": window.get("timestamp"),
            })
    return found


def _as_controller_result(
    window: Dict[str, Any],
    group: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Restate a recorded window-path prediction in the controller contract.

    Only field *names* are restated (``predicted_profile`` -> ``traffic_profile``
    for the replay shape); no value is invented. A record without a probability
    vector or a timestamp is rejected by the seam rather than defaulted, and
    that rejection propagates -- a window that cannot be mapped honestly is not
    quietly dropped.
    """
    profile = window.get("traffic_profile") or window.get("predicted_profile")
    if not profile:
        raise ArtifactUnavailable(
            "recorded window carries no predicted profile; the model output "
            "cannot be mapped onto MLResult"
        )
    return {
        "model_version": window.get("model_version"),
        "feature_schema_version": window.get("feature_schema_version"),
        "window_id": window.get("window_id"),
        "timestamp": window.get("timestamp"),
        "traffic_profile": profile,
        "probabilities": window.get("probabilities"),
    }


def ml_result_for_window(
    window: Dict[str, Any],
) -> Any:
    """Map one real window-path prediction onto ``MLResult`` via the seam."""
    from .ml.controller_bridge import controller_result_to_ml_result

    return controller_result_to_ml_result({
        "model_version": window.get("model_version"),
        "feature_schema_version": window.get("feature_schema_version"),
        "window_id": window.get("window_id"),
        "timestamp": window.get("timestamp"),
        "traffic_profile": window.get("traffic_profile"),
        "probabilities": window.get("probabilities"),
    })


def observed_evidence_values(observed: ObservedState) -> Dict[str, Any]:
    """The authoritative observed values a passive snapshot actually carries.

    This is deliberately tiny, and the emptiness is the finding rather than a
    gap to be papered over:

    ``ebpf.ipsec_state_builder`` records ``tunnel_seen`` as "any traffic was
    observed at all" (``observation_start_ns is not None``), *not* as the IPsec
    mode, and it exposes no cipher, DH group, PFS or IKE-version field at all.
    Inferring ``mode`` from ``tunnel_seen`` would be exactly the false inference
    the state builder's ``_FORBIDDEN_INFERENCE_KEYS`` exists to prevent, and
    deriving ``esp.encryption`` from an expected value would make every
    comparison agree by construction.  Deriving ``mode`` from ``esp_seen`` is
    the same class of error for the opposite reason: tunnel and transport mode
    put byte-identical protocol-50 ESP on the wire, so ESP presence proves
    *neither* mode and would report ``"tunnel"`` for every transport sample.

    ``mode`` is therefore returned only when it is genuinely authoritative --
    ``ObservedState.mode``, populated from the real deployed SA report
    (``swanctl --list-sas`` -> ``TUNNEL`` / ``TRANSPORT``).  With no
    authoritative source it stays absent and the comparison layer reports the
    variable as UNKNOWN, never as a match and never as a mismatch.

    Crypto parameters stay absent unconditionally: the state engine refuses to
    infer them. The authoritative statements about the SA remain the signals the
    snapshot really has: ESP/IKE presence, SPI observations, and window
    coverage.
    """
    mode = getattr(observed, "mode", None)
    return {"mode": mode} if mode in OBSERVED_MODES else {}


def evidence_ref_for(relative_path: str, *, run_id: str, sequence: int) -> Any:
    """A self-verifying reference to a real artifact backing one assessment.

    Carries the artifact's real digest and size, so the dashboard's evidence
    column is checkable rather than a path somebody typed. Returns ``None`` only
    when the artifact is absent, unreadable or of an unknown type — i.e. a fact
    about the recording. A malformed *call* (an invalid capture sequence, for
    example) is a defect and is raised, not silently turned into "no evidence".
    """
    from .evidence_linkage import EvidenceArtifactError, evidence_from_artifact

    try:
        return evidence_from_artifact(
            relative_path, evidence_root=REPO_ROOT, run_id=run_id,
            sequence=sequence,
        )
    except (EvidenceArtifactError, OSError):
        return None


def provenance(*records: ArtifactRecord) -> List[Dict[str, Any]]:
    """The identity of every artifact a bundle was built from."""
    return [record.to_dict() for record in records]
