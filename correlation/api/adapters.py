"""PHASE 8 — Dashboard API adapters.

Backend model -> Dashboard view-model mapping. PURE mapping: every function
returns NEW dictionaries and NEVER mutates the backend domain objects it
consumes. No comparison rules, risk rules, scoring, ML decisions or XAI text
are re-implemented here - the API is an adapter, not another decision engine.
"""

from typing import Any, Dict, List, Optional

from ..models import (
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
    return {
        "variable": outcome.get("variable"),
        "status": outcome.get("status"),
        "expected_value": outcome.get("expected_value"),
        "observed_value": outcome.get("observed_value"),
        "comparison_rule": outcome.get("comparison_rule"),
        "reason": outcome.get("reason"),
        "evidence_refs": [dict(ev) for ev in outcome.get("evidence_refs") or []],
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

def ml_to_view(ml: Optional[MLResult]) -> Dict[str, Any]:
    """ML-derived evidence. present=False when no ML result was consumed."""
    if ml is None:
        return {
            "present": False,
            "reason": "ML was not executed for this assessment",
            "model_version": None,
            "traffic_class": None,
            "classification_confidence": None,
            "anomaly": None,
            "anomaly_score": None,
        }
    return {
        "present": True,
        "model_version": ml.model_version,
        "traffic_class": ml.traffic_class,
        "classification_confidence": ml.classification_confidence,
        "anomaly": ml.anomaly,
        "anomaly_score": ml.anomaly_score,
    }


# ---------------------------------------------------------------------------
# risk
# ---------------------------------------------------------------------------

def finding_to_view(finding: RiskFinding) -> Dict[str, Any]:
    return {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "category": finding.category,
        "severity": finding.severity,
        "title": finding.title,
        "description": finding.description,
        "reason": finding.reason,
        "condition": finding.condition,
        "source": finding.source,
        "evidence_type": finding.evidence_type,
        "related_variable": finding.related_variable,
        "expected_value": finding.expected_value,
        "observed_value": finding.observed_value,
        "confidence": finding.confidence,
        "model_version": finding.model_version,
        "evidence_refs": [ev.to_dict() for ev in finding.evidence_refs],
    }


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
    return {
        "assessment_id": assessment_id,
        "slot": slot,
        "scenario": scenario,
        "dataset_run_id": identity.dataset_run_id,
        "identity": identity_to_view(identity),
        "expected": expected_view,
        "observed": observed_view,
        "correlation": correlation_to_view(correlation),
        "ml": ml_to_view(ml),
        "risk": risk_to_view(assessment),
        "xai": xai_to_view(xai),
        "evidence": {
            "total_refs": len(evidence),
            "refs": [dict(ev) for ev in evidence],
            "sources": sorted({ev.get("source") for ev in evidence if ev.get("source")}),
            "limitation": None if evidence else (
                "No evidence references were supplied."
            ),
        },
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