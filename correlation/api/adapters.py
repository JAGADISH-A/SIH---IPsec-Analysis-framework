"""PHASE 8 — Dashboard API adapters.

Backend model -> Dashboard view-model mapping. PURE mapping: every function
returns NEW dictionaries and NEVER mutates the backend domain objects it
consumes. No comparison rules, risk rules, scoring, ML decisions or XAI text
are re-implemented here - the API is an adapter, not another decision engine.
"""

from typing import Any, Dict, List, Optional

from ..analysis.states import (
    STATE_ASSESSED,
    STATE_INFERRED,
    STATE_NOT_APPLICABLE,
    STATE_NOT_AVAILABLE,
    STATE_OBSERVED,
    STATE_UNKNOWN,
)
from ..models import (
    ALLOWED_TRAFFIC_PROFILES,
    CORRELATION_STATUS_MATCH,
    CORRELATION_STATUS_MISMATCH,
    CORRELATION_STATUS_NOT_APPLICABLE,
    CORRELATION_STATUS_UNKNOWN,
    CorrelationResult,
    ExpectedState,
    MLResult,
    ObservedState,
)
from ..risk.models import RiskAssessment, RiskFinding
from ..xai.models import ExplainabilityResult

STORE_VERSION = "v1"
API_SCHEMA_VERSION = "v1"

# comparison statuses that the UI (and this adapter) understands; the values
# ARE the authoritative Phase-4 vocabulary - never re-derived here.
COMPARISON_STATUSES = (
    CORRELATION_STATUS_MATCH,
    CORRELATION_STATUS_MISMATCH,
    CORRELATION_STATUS_UNKNOWN,
    CORRELATION_STATUS_NOT_APPLICABLE,
)


def assessment_id_for(dataset_run_id: str, sequence: int, slot: str) -> str:
    return f"{dataset_run_id}:{sequence}:{slot}"


def parse_assessment_id(value: Any):
    """Validate + split an assessment id; return (run_id, sequence, slot) or None."""
    if not isinstance(value, str):
        return None
    parts = value.split(":")
    if len(parts) != 3 or not parts[0] or not parts[2]:
        return None
    try:
        sequence = int(parts[1])
    except ValueError:
        return None
    if sequence < 1:
        return None
    return parts[0], sequence, parts[2]


# ---------------------------------------------------------------------------
# Phase-1 analytical contract (brief area 1): producer / state / reason / source
# ---------------------------------------------------------------------------

#: One producer name per analytical product: the module-level call that built
#: it. Written out rather than derived so a reader can name the producer of any
#: value without guessing, and so a rename shows up as an edit here.
PRODUCT_PRODUCERS: Dict[str, str] = {
    "sa": "correlation.analysis.sa.analyze_sa",
    "crypto_evidence":
        "correlation.analysis.crypto_evidence.analyze_crypto_evidence",
    "replay_assessment": "correlation.analysis.replay.analyze_replay",
    "metadata_exposure":
        "correlation.analysis.metadata.analyze_metadata_exposure",
    "threat_matrix": "correlation.analysis.threat_matrix.build_threat_matrix",
    "report": "correlation.analysis.reports.build_technical_report",
    "executive_report":
        "correlation.analysis.reports.build_executive_report",
    "correlation": "correlation.comparison.engine.ComparisonEngine.compare",
    "ml": "correlation.ml.controller_bridge.controller_result_to_ml_result",
    "risk": "correlation.risk.engine.RiskEngine.assess",
    "xai": "correlation.xai.engine.ExplainabilityEngine.explain",
    "evidence": "correlation.api.adapters.assessment_bundle",
}


def with_analytical_contract(
    view: Dict[str, Any],
    *,
    product: str,
    state: Optional[str] = None,
    reason: Optional[str] = None,
    source: Optional[str] = None,
) -> Dict[str, Any]:
    """Complete the Phase-1 contract for one analytical product view.

    ``producer`` is always written: it names the call that produced the
    product. ``state``, ``reason`` and ``source`` are filled only where the
    producer recorded none -- a value the producer already carries is never
    overwritten, and nothing here is re-derived from the product's contents.
    ``expected``, ``observed`` and ``ipsec_state`` are inputs to this contract,
    not analytical products, so they are deliberately not stamped.
    """
    contract = dict(view)
    contract["producer"] = PRODUCT_PRODUCERS[product]
    if contract.get("state") is None and state is not None:
        contract["state"] = state
    if contract.get("reason") is None and reason is not None:
        contract["reason"] = reason
    if contract.get("source") is None and source is not None:
        contract["source"] = source
    return contract


# ---------------------------------------------------------------------------
# identity
# ---------------------------------------------------------------------------

def identity_to_view(identity) -> Dict[str, Any]:
    """All identity fields, preserving None (the UI shows NOT AVAILABLE)."""
    return {
        "dataset_run_id": identity.dataset_run_id,
        "sequence": identity.sequence,
        "experiment_id": identity.experiment_id,
        "attempt_number": identity.attempt_number,
        "window_index": identity.window_index,
        "window_start_ns": identity.window_start_ns,
        "window_end_ns": identity.window_end_ns,
    }


# ---------------------------------------------------------------------------
# expected / configuration
# ---------------------------------------------------------------------------

def expected_to_view(expected: ExpectedState) -> Dict[str, Any]:
    """The authoritative ExpectedState, exposed for the Configuration view."""
    return {
        "mode": expected.mode,
        "address_family": expected.address_family,
        "ike": {
            "version": expected.ike.version,
            "encryption": expected.ike.encryption,
            "integrity": expected.ike.integrity,
            "dh_group": expected.ike.dh_group,
        },
        "esp": {
            "encryption": expected.esp.encryption,
            "integrity": expected.esp.integrity,
            "dh_group": expected.esp.dh_group,
            "pfs": expected.esp.pfs,
        },
        "traffic": {
            "profile": expected.traffic.profile,
            "duration": expected.traffic.duration,
            "port": expected.traffic.port,
        },
        "capture_filter": expected.capture_filter,
        "configuration_id": expected.configuration_id,
        "security_posture": expected.security_posture,
    }


# ---------------------------------------------------------------------------
# observed / ipsec state
# ---------------------------------------------------------------------------

def observed_to_view(observed: Optional[ObservedState]) -> Dict[str, Any]:
    """Observed live-path state. None fields stay null (honest 'NOT AVAILABLE').

    Cryptographic configuration is NEVER inferred here: ObservedState has no
    crypto fields and the view exposes exactly what the state builder produced.
    """
    if observed is None:
        return {"present": False, "reason": "no observed-state snapshot supplied"}
    return {
        "present": True,
        "timestamp_ns": observed.timestamp_ns,
        "endpoints": dict(observed.endpoints),
        "active": observed.active,
        "tunnel_seen": observed.tunnel_seen,
        "packets_seen": observed.packets_seen,
        "bytes_seen": observed.bytes_seen,
        "packets_a_to_b": observed.packets_a_to_b,
        "packets_b_to_a": observed.packets_b_to_a,
        "bytes_a_to_b": observed.bytes_a_to_b,
        "bytes_b_to_a": observed.bytes_b_to_a,
        "ike_seen": observed.ike_seen,
        "ike_nat_t_seen": observed.ike_nat_t_seen,
        "esp_seen": observed.esp_seen,
        "ah_seen": observed.ah_seen,
        "observed_ike_activity": observed.observed_ike_activity,
        "last_ike_timestamp_ns": observed.last_ike_timestamp_ns,
        "last_ike_nat_t_timestamp_ns": observed.last_ike_nat_t_timestamp_ns,
        "last_esp_timestamp_ns": observed.last_esp_timestamp_ns,
        "last_ah_timestamp_ns": observed.last_ah_timestamp_ns,
        "spis": [spi_to_view(spi) for spi in observed.spis],
        "transitions": [dict(t.to_dict()) for t in observed.transitions],
        # Observation window and multi-SA views. ``None`` means "this build did
        # not record the field"; it is never rendered as zero.
        "observation_start_ns": observed.observation_start_ns,
        "last_packet_timestamp_ns": observed.last_packet_timestamp_ns,
        "active_timeout_ms": observed.active_timeout_ms,
        "outer_endpoint_pairs": (
            [list(pair) for pair in observed.outer_endpoint_pairs]
            if observed.outer_endpoint_pairs is not None else None
        ),
        "spi_less_esp_packets": observed.spi_less_esp_packets,
        "sa_snapshots": (
            [dict(entry) for entry in observed.sa_snapshots]
            if observed.sa_snapshots is not None else None
        ),
        "sa_groups": (
            [dict(entry) for entry in observed.sa_groups]
            if observed.sa_groups is not None else None
        ),
    }


def spi_to_view(spi) -> Dict[str, Any]:
    """Per-SPI state (preserved exactly; SPI formatting stays client-side)."""
    return {
        "spi": spi.spi,
        "direction": spi.direction,
        "active": spi.active,
        "first_seen_ns": spi.first_seen_ns,
        "last_seen_ns": spi.last_seen_ns,
        "packet_count": spi.packet_count,
        "first_sequence": spi.first_sequence,
        "last_sequence": spi.last_sequence,
        "highest_sequence": spi.highest_sequence,
        "sequence_delta": spi.sequence_delta,
    }


# ---------------------------------------------------------------------------
# correlation / comparison rows
# ---------------------------------------------------------------------------

def _outcome_row(outcome: Dict[str, Any]) -> Dict[str, Any]:
    """One comparison row, plus the Phase-11 enrichment (brief area 5).

    The enrichment keys are derived from what Phase 4 already recorded, so a
    row can be rendered next to a finding with the same vocabulary and still
    make no claim the comparison did not make:

    ``configured_value``  the expected side, under the brief's name
    ``state``             why the row holds: UNKNOWN stays UNKNOWN,
                          NOT_APPLICABLE stays NOT_APPLICABLE, an established
                      comparison is ASSESSED, and it is OBSERVED only
                      when a runtime value actually backs it
    ``runtime_observable`` True when this observation produced a value for the
                      variable -- the same presence test the crypto-evidence
                      product applies per property
    ``evidence_source``  where the observed side came from (the sources named
                      by the row's evidence references, else the observed
                      state the comparison consumed)
    ``verdict``         the row's status under the brief's name for it: one
                      canonical value carried twice, never a second decision
    """
    refs = [dict(ev) for ev in outcome.get("evidence_refs") or []]
    status = outcome.get("status")
    observed_value = outcome.get("observed_value")
    if status == CORRELATION_STATUS_UNKNOWN:
        state = STATE_UNKNOWN
    elif status == CORRELATION_STATUS_NOT_APPLICABLE:
        state = STATE_NOT_APPLICABLE
    elif observed_value is not None:
        state = STATE_OBSERVED
    else:
        state = STATE_ASSESSED
    sources = sorted({
        ev.get("source") for ev in refs
        if isinstance(ev, dict) and ev.get("source")
    })
    return {
        "variable": outcome.get("variable"),
        "status": status,
        "verdict": status,
        "expected_value": outcome.get("expected_value"),
        "observed_value": observed_value,
        "configured_value": outcome.get("expected_value"),
        "comparison_rule": outcome.get("comparison_rule"),
        "reason": outcome.get("reason"),
        "state": state,
        "runtime_observable": observed_value is not None,
        "evidence_source": (
            ", ".join(sources) if sources
            else ("observed_state" if observed_value is not None else None)
        ),
        "evidence_refs": refs,
    }


def correlation_to_view(correlation: CorrelationResult) -> Dict[str, Any]:
    """Comparison table rows + status counts + non-decision metadata."""
    rows: List[Dict[str, Any]] = []
    status_counts = {status: 0 for status in COMPARISON_STATUSES}
    for bucket in ("matches", "mismatches", "unknowns", "not_applicable"):
        for outcome in getattr(correlation, bucket):
            row = _outcome_row(outcome)
            status = row["status"]
            if status in status_counts:
                status_counts[status] += 1
            rows.append(row)
    # deterministic ordering: variable then bucket order is natural -> keep
    # the pipeline order, then sort by (variable) for the table display.
    rows.sort(key=lambda row: (row.get("variable") or ""))
    metadata = dict(correlation.metadata or {})
    return {
        "status": correlation.status,
        "rows": rows,
        "status_counts": status_counts,
        "metadata": metadata,
    }


# ---------------------------------------------------------------------------
# ml
# ---------------------------------------------------------------------------

#: Inference-status vocabulary (brief area 10, ML transparency). It reports
#: what happened to inference, never how good the model is.
ML_INFERENCE_NOT_EXECUTED = "NOT_EXECUTED"
ML_INFERENCE_COMPLETED = "COMPLETED"
ML_INFERENCE_INCOMPLETE = "INCOMPLETE"

#: ``MLResult.extras`` keys copied verbatim into ``provenance``. Only keys the
#: producer actually recorded appear; a missing key stays missing rather than
#: being filled with a plausible value.
_ML_PROVENANCE_KEYS = (
    "source",
    "bridge",
    "model_type",
    "model_label",
    "label_mapping",
    "mapped_to_canonical_profile",
    "unmapped_label",
    "feature_schema_version",
    "window_id",
    "timestamp",
    "probability_supported",
    "anomaly_supported",
    "anomaly_threshold",
    "model_artifact_sha256",
    "model_trained_git_commit",
    "model_training_datasets",
    "model_trained_at",
    "sa_identity",
)


def ml_to_view(
    ml: Optional[MLResult],
    *,
    expected: Optional[ExpectedState] = None,
    correlation: Optional[CorrelationResult] = None,
) -> Dict[str, Any]:
    """ML-derived evidence with the transparency block (brief area 10).

    Every added key answers one of the brief's questions with the value the
    producer recorded:

    ``model``            the model identity, preferring a name the producer
                         recorded and falling back to the version string (the
                         provenance block says which was used)
    ``predicted_class``  the canonical class the model predicted (``None`` when
                         it predicted no canonical class)
    ``probabilities``    the full probability vector when the producer supplied
                          one, otherwise ``None`` -- never a guessed distribution
    ``classes``          the class names the probability vector is indexed by,
                          only when a full vector exists whose keys are exactly
                          the six canonical traffic profiles; ``None`` otherwise
                          (never a partial list and never an invented order)
    ``inference_status`` NOT_EXECUTED / COMPLETED / INCOMPLETE
    ``provenance``       where the result came from, verbatim from ``extras``
    ``predicted_vs_policy`` the verdict of predicted class vs the configured
                         traffic profile: MATCH / MISMATCH / UNKNOWN /
                         NOT_APPLICABLE, with the reason for that verdict

    ``expected`` and ``correlation`` are optional so existing one-argument
    callers keep working; without ``expected`` the verdict is NOT_APPLICABLE
    because there is no configured class to compare against.
    """
    if ml is None:
        return {
            "present": False,
            "reason": "ML was not executed for this assessment",
            "model": None,
            "model_version": None,
            "traffic_class": None,
            "predicted_class": None,
            "classification_confidence": None,
            "probabilities": None,
            "classes": None,
            "inference_status": ML_INFERENCE_NOT_EXECUTED,
            "provenance": None,
            "predicted_vs_policy": _predicted_vs_policy(
                None, expected, ML_INFERENCE_NOT_EXECUTED
            ),
            "anomaly": None,
            "anomaly_score": None,
        }

    extras = dict(ml.extras or {})
    probabilities = extras.get("probabilities")
    if not isinstance(probabilities, dict):
        probabilities = None
    # The class list is exposed only beside a probability vector that is
    # indexed by exactly the six canonical profiles: a vector is what gives a
    # class list meaning here. The order is the producer's own when it recorded
    # a set-equal one, otherwise the canonical contract order -- never a partial
    # list, never a second classifier's vocabulary.
    classes: Optional[List[str]] = None
    if (
        probabilities is not None
        and len(probabilities) == len(ALLOWED_TRAFFIC_PROFILES)
        and set(probabilities) == set(ALLOWED_TRAFFIC_PROFILES)
    ):
        recorded = extras.get("classes")
        if (
            isinstance(recorded, (list, tuple))
            and len(recorded) == len(ALLOWED_TRAFFIC_PROFILES)
            and all(isinstance(item, str) for item in recorded)
            and set(recorded) == set(ALLOWED_TRAFFIC_PROFILES)
        ):
            classes = [str(item) for item in recorded]
        else:
            classes = list(ALLOWED_TRAFFIC_PROFILES)
    if extras.get("model") is not None:
        model, model_identity_source = extras.get("model"), "extras.model"
    elif extras.get("model_type") is not None:
        model = extras["model_type"]
        model_identity_source = "extras.model_type"
    else:
        # The contract records no separate model name, so the version string
        # IS the identity we have; provenance says that is what happened.
        model, model_identity_source = ml.model_version, "model_version"
    inference_status = (
        ML_INFERENCE_COMPLETED if ml.traffic_class is not None
        else ML_INFERENCE_INCOMPLETE
    )
    provenance = {key: extras[key] for key in _ML_PROVENANCE_KEYS if key in extras}
    provenance.update(
        {
            # The first-class field, not an extras key: the provenance block
            # must be able to show which model produced the prediction even
            # when the producer recorded no separate model name.
            "model_version": ml.model_version,
            "model_identity_source": model_identity_source,
            "sa_group_id": ml.sa_group_id,
            "sa_id": ml.sa_id,
            "executed_by_this_backend": False,
            "evidence_class": "model-derived evidence, never a protocol observation",
        }
    )
    if correlation is not None:
        # Whether Phase 4 actually consumed ML, as recorded by Phase 4.
        # ``None`` means the comparison never recorded it -- not "it did not".
        provenance["ml_evaluated"] = (
            (correlation.metadata or {}).get("ml_evaluated")
        )
    return {
        "present": True,
        "reason": (
            "An ML result was consumed for this assessment. It is "
            "model-derived evidence: it never overrides an authoritative "
            "observation and is never a protocol observation itself."
        ),
        "model": model,
        "model_version": ml.model_version,
        "traffic_class": ml.traffic_class,
        "predicted_class": ml.traffic_class,
        "classification_confidence": ml.classification_confidence,
        "probabilities": probabilities,
        "classes": classes,
        "inference_status": inference_status,
        "provenance": provenance,
        "predicted_vs_policy": _predicted_vs_policy(
            ml.traffic_class, expected, inference_status
        ),
        "anomaly": ml.anomaly,
        "anomaly_score": ml.anomaly_score,
    }


def _predicted_vs_policy(
    predicted_class: Optional[str],
    expected: Optional[ExpectedState],
    inference_status: str,
) -> Dict[str, Any]:
    """Predicted class vs the configured traffic profile (area 10).

    The verdict vocabulary is the Phase-4 one on purpose: this is a
    comparison of two recorded values, and it must not invent a fifth answer.
    """
    policy_expected_class = (
        expected.traffic.profile if expected is not None else None
    )
    if predicted_class is None and inference_status == ML_INFERENCE_NOT_EXECUTED:
        status, reason = (
            "NOT_APPLICABLE",
            "No ML result was consumed, so there is no prediction to compare "
            "against the configured traffic profile.",
        )
    elif expected is None:
        status, reason = (
            "NOT_APPLICABLE",
            "No expected configuration was supplied to this view, so the "
            "configured traffic profile is unknown to it.",
        )
    elif predicted_class is None:
        status, reason = (
            "UNKNOWN",
            "Inference produced no canonical predicted class "
            f"(inference status {inference_status}), so the comparison cannot "
            "be made. This is an evidence gap, never an agreement.",
        )
    elif predicted_class == policy_expected_class:
        status, reason = (
            "MATCH",
            f"The model predicted {predicted_class!r}, which is the "
            "configured traffic profile for this run.",
        )
    else:
        status, reason = (
            "MISMATCH",
            f"The model predicted {predicted_class!r} while the configured "
            f"traffic profile is {policy_expected_class!r}. This is a "
            "model-vs-configuration discrepancy, not a protocol observation.",
        )
    return {
        "status": status,
        "predicted_class": predicted_class,
        "policy_expected_class": policy_expected_class,
        "compared_against": "expected.traffic.profile",
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# risk
# ---------------------------------------------------------------------------

def finding_to_view(finding: RiskFinding) -> Dict[str, Any]:
    """The Phase-6/11 finding, exposed through its own ``to_dict``.

    Sharing one definition is deliberate: ``test_score_severity_verbatim``
    asserts this view equals ``finding.to_dict()`` element for element, so the
    report, the threat matrix and the dashboard can never disagree on a key.
    """
    return dict(finding.to_dict())


def evidence_to_view(ref) -> Dict[str, Any]:
    data = ref.to_dict() if hasattr(ref, "to_dict") else ref
    return {
        "pcap_path": data.get("pcap_path"),
        "capture_sequence": data.get("capture_sequence"),
        "audit_event_reference": data.get("audit_event_reference"),
        "source": data.get("source"),
        "timestamp": data.get("timestamp"),
    }


def risk_to_view(assessment: RiskAssessment) -> Dict[str, Any]:
    """Every value copied verbatim from the authoritative RiskAssessment."""
    score_detail = assessment.metadata.get("score_detail") or {}
    return {
        "schema_version": assessment.schema_version,
        "risk_engine_version": assessment.risk_engine_version,
        "risk_policy_version": assessment.risk_policy_version,
        "overall_score": assessment.overall_score,
        "severity": assessment.severity,
        "identity": identity_to_view(assessment.identity),
        "findings": [finding_to_view(f) for f in assessment.findings],
        "evidence_refs": [ev.to_dict() for ev in assessment.evidence_refs],
        "score_detail": dict(score_detail),
        "metadata": dict(assessment.metadata or {}),
    }


# ---------------------------------------------------------------------------
# xai
# ---------------------------------------------------------------------------

def xai_to_view(xai: ExplainabilityResult) -> Dict[str, Any]:
    """The Phase-7 ExplainabilityResult exposed verbatim (explanation panel)."""
    return dict(xai.to_dict())


# ---------------------------------------------------------------------------
# assessment bundle (the joined full-detail view for one assessment)
# ---------------------------------------------------------------------------

def assessment_bundle(
    assessment_id: str,
    *,
    identity,
    expected: ExpectedState,
    observed: Optional[ObservedState],
    correlation: CorrelationResult,
    ml: Optional[MLResult],
    assessment: RiskAssessment,
    xai: ExplainabilityResult,
    slot: str,
    scenario: str,
    evidence: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Assemble the full dashboard detail document for one assessment.

    Every sub-view is produced by the read-only mappers above from the
    already-computed backend outputs; nothing is re-decisioned here.
    """
    expected_view = expected_to_view(expected)
    observed_view = observed_to_view(observed)
    correlation_view = correlation_to_view(correlation)
    counts = correlation_view["status_counts"]
    ml_view = ml_to_view(ml, expected=expected, correlation=correlation)
    xai_view = xai_to_view(xai)
    return {
        "assessment_id": assessment_id,
        "slot": slot,
        "scenario": scenario,
        "dataset_run_id": identity.dataset_run_id,
        "identity": identity_to_view(identity),
        "expected": expected_view,
        "observed": observed_view,
        "correlation": with_analytical_contract(
            correlation_view,
            product="correlation",
            state=STATE_ASSESSED,
            reason=(
                f"Phase 4 compared {len(correlation_view['rows'])} variable(s) "
                f"and recorded {counts['MATCH']} MATCH, "
                f"{counts['MISMATCH']} MISMATCH, {counts['UNKNOWN']} UNKNOWN "
                f"and {counts['NOT_APPLICABLE']} NOT_APPLICABLE row(s). Each "
                "row carries its own state; this product reports the "
                "comparison and never a verdict of its own."
            ),
            source="materialized plan compared with the observed-state "
                   "snapshot (Phase 4)",
        ),
        "ml": with_analytical_contract(
            ml_view,
            product="ml",
            state=(
                STATE_INFERRED if ml_view["present"] else STATE_NOT_AVAILABLE
            ),
            source=(
                "model output recorded by the ML producer (see provenance)"
                if ml_view["present"]
                else "none: no ML result was consumed for this assessment"
            ),
        ),
        "risk": with_analytical_contract(
            risk_to_view(assessment),
            product="risk",
            state=STATE_ASSESSED,
            reason=(
                f"Risk score {assessment.overall_score}/100 at severity "
                f"{assessment.severity} from {len(assessment.findings)} "
                f"finding(s) under policy {assessment.risk_policy_version}; "
                "every value is the risk engine's own."
            ),
            source="Phase 6 risk engine over this assessment's "
                   "comparison, replay and evidence inputs",
        ),
        "xai": with_analytical_contract(
            xai_view,
            product="xai",
            state=STATE_ASSESSED,
            reason=(
                (xai_view.get("summary") or {}).get("overall_explanation")
                or "The explainability engine recorded no overall "
                   "explanation for this assessment."
            ),
            source="Phase 7 explainability engine over the risk "
                   "assessment, comparison and ML result",
        ),
        "evidence": with_analytical_contract(
            {
                "total_refs": len(evidence),
                "refs": [dict(ev) for ev in evidence],
                "sources": sorted({ev.get("source") for ev in evidence if ev.get("source")}),
                "limitation": None if evidence else (
                    "No evidence references were supplied."
                ),
            },
            product="evidence",
            state=STATE_OBSERVED if evidence else STATE_NOT_AVAILABLE,
            reason=(
                f"{len(evidence)} evidence reference(s) recorded for this "
                "assessment, cited by the products that used them."
                if evidence
                else "No evidence reference was recorded for this assessment; "
                     "the gap is reported rather than filled."
            ),
            source=(
                ", ".join(sorted({
                    ev.get("source") for ev in evidence if ev.get("source")
                }))
                if evidence else "no evidence reference recorded"
            ),
        ),
        "ipsec_state": observed_view,
    }


def header_view(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """One table row for the Assessments/Runs page."""
    risk = bundle["risk"]
    correlation = bundle["correlation"]
    identity = bundle["identity"]
    expected = bundle["expected"]
    ml = bundle["ml"]
    return {
        "assessment_id": bundle["assessment_id"],
        "slot": bundle["slot"],
        "scenario": bundle["scenario"],
        "dataset_run_id": identity["dataset_run_id"],
        "sequence": identity["sequence"],
        "experiment_id": identity["experiment_id"],
        "attempt_number": identity["attempt_number"],
        "window_index": identity["window_index"],
        "window_start_ns": identity["window_start_ns"],
        "window_end_ns": identity["window_end_ns"],
        "configuration_id": expected.get("configuration_id"),
        "traffic_profile": expected["traffic"]["profile"],
        "security_posture": expected.get("security_posture"),
        "mode": expected["mode"],
        "address_family": expected["address_family"],
        "ike_version": expected["ike"]["version"],
        "esp_encryption": expected["esp"]["encryption"],
        "risk_score": risk["overall_score"],
        "severity": risk["severity"],
        "finding_count": len(risk["findings"]),
        "correlation_status": correlation["status"],
        "ml_present": ml["present"],
        "ml_anomaly": ml.get("anomaly"),
    }