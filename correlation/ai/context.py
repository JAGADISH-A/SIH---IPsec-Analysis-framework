"""The context builder: the only place the assistant reads authoritative state.

This module is read-only by construction. It holds no assessment, creates no
finding, re-runs no pipeline stage, and recomputes no score. Every value it
returns is copied from an object the analysis pipeline already produced, and
every copy is labelled with the origin that produced it.

What it reads
-------------
* :meth:`StoreContextSource.assessment` -- the assessment bundle the risk
  engine already emitted, through the store's own public read API.
* :meth:`StoreContextSource.finding` -- the finding, the comparison rows behind
  it, and the ``score_detail`` contribution the scorer already booked.
* :meth:`StoreContextSource.custody` -- the provenance chain, stages as recorded.
* :meth:`StoreContextSource.drift` -- the drift comparison computed at build time.

:class:`HttpContextSource` is the same contract against a running analytics API,
using only ``GET``. It exists so the assistant can read an assessment that was
registered by a live run, which an independently built store does not have.

What it deliberately does not do
--------------------------------
* It does not backfill a missing field from the expected state. A missing
  observed ESP encryption value stays ``None``; the assistant is required to say
  the backend did not record it.
* It does not join a finding id to the wrong assessment. A finding id repeats
  across assessments, so the pair is resolved strictly and an unresolved pair is
  reported as unresolved.
* It does not read the packet journal, the audit journal, or any artifact. Those
  reach the assistant only as identifiers the backend already minted.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .models import (
    GroundedComparison,
    GroundedCustody,
    GroundedDrift,
    GroundedFinding,
    GroundedMl,
    GroundingContext,
)

SOURCE_RISK = "correlation.risk.engine"
SOURCE_COMPARISON = "correlation.comparison.engine"
SOURCE_OBSERVED = "correlation.models.observed"
SOURCE_EXPECTED = "correlation.adapters.expected_state"
SOURCE_ML = "correlation.ml.controller_bridge"
SOURCE_CUSTODY = "correlation.custody.builder"
SOURCE_DRIFT = "correlation.drift.comparison"
SOURCE_STORE = "correlation.api.store.AssessmentStore"
SOURCE_ANALYTICS = "analytics-api:/api/v1"


class ContextUnavailable(RuntimeError):
    """The authoritative context could not be read. Never a substitute answer."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------------------
# sources
# ---------------------------------------------------------------------------

class ContextSource:
    """Read-only access to authoritative assessment state.

    Deliberately tiny. A source resolves an assessment, a finding inside it, a
    custody chain and a drift comparison, and returns plain data. Anything
    richer would tempt the context builder into decisions.
    """

    available: bool = False
    reason: Optional[str] = None

    def assessment(self, assessment_id: str) -> Dict[str, Any]:
        raise NotImplementedError

    def finding(self, assessment_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    def custody(self, assessment_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
        return None

    def drift(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        return None

    def describe(self) -> str:
        return "unknown source"


class StoreContextSource(ContextSource):
    """In-process read-only access to an ``AssessmentStore``.

    The store is deterministic and read-only once built, so holding a reference
    to one grants no write path. Nothing here calls a public mutator; the only
    store methods touched are ``bundles``, ``custody_inputs``, ``drift_for`` and
    ``chain_of_custody``, all of which read state the build already produced.
    """

    def __init__(self, store) -> None:
        self._store = store
        self.available = store is not None
        self.reason = None if store is not None else "no assessment store is attached"

    def describe(self) -> str:
        return f"{SOURCE_STORE} (in-process)"

    def assessment(self, assessment_id: str) -> Dict[str, Any]:
        bundle = (self._store.bundles or {}).get(assessment_id)
        if bundle is None:
            raise ContextUnavailable(
                f"assessment {assessment_id!r} is not in the recorded store"
            )
        return dict(bundle)

    def finding(self, assessment_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
        held = (self._store.custody_inputs or {}).get(assessment_id)
        if held is None:
            return None
        for item in getattr(held.assessment, "findings", ()) or ():
            if item.finding_id == finding_id:
                return self._finding_record(held, item)
        return None

    def _finding_record(self, held, finding) -> Dict[str, Any]:
        detail = dict(getattr(held.assessment, "metadata", {}) or {})
        detail = dict(detail.get("score_detail") or {})
        contribution = None
        weight = None
        for row in detail.get("contributions") or ():
            if row.get("finding_id") == finding.finding_id:
                contribution = row.get("added")
                weight = row.get("weight")
                break
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
            "related_variable": finding.related_variable,
            "expected_value": finding.expected_value,
            "observed_value": finding.observed_value,
            "score_contribution": contribution,
            "rule_weight": weight,
            "confidence": finding.confidence,
            "model_version": finding.model_version,
            "evidence_ids": [
                ref.evidence_id
                for ref in (finding.evidence_refs or ())
                if getattr(ref, "evidence_id", None)
            ],
        }

    def custody(self, assessment_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
        try:
            chain = self._store.chain_of_custody(assessment_id, finding_id)
        except KeyError:
            return None
        return chain.to_dict()

    def drift(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        try:
            found = self._store.drift_for(assessment_id)
        except Exception:
            return None
        return None if found is None else found.to_dict()


class HttpContextSource(ContextSource):
    """Read-only access through the analytics API, using only ``GET``.

    Used when the assessment of interest was registered by a live run, which an
    independently constructed store does not contain. Only the read-only
    ``/api/v1`` routes are touched; no mutating verb exists on that surface and
    none is attempted here.
    """

    def __init__(self, base_url: str, *, timeout: float = 5.0, opener=None) -> None:
        self._base = str(base_url or "").rstrip("/")
        self._timeout = timeout
        self._opener = opener or _urllib_get_json
        self.available = bool(self._base)
        self.reason = None if self._base else "no analytics API base URL is configured"

    def describe(self) -> str:
        return f"{SOURCE_ANALYTICS} (read-only)"

    def _get(self, path: str) -> Optional[Dict[str, Any]]:
        return self._opener(f"{self._base}{path}", self._timeout)

    def assessment(self, assessment_id: str) -> Dict[str, Any]:
        payload = self._get(f"/api/v1/assessments/{_seg(assessment_id)}")
        if payload is None:
            raise ContextUnavailable(
                f"assessment {assessment_id!r} was not returned by the analytics API"
            )
        bundle = payload.get("assessment")
        return dict(bundle) if isinstance(bundle, dict) else dict(payload)

    def finding(self, assessment_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
        payload = self._get(
            f"/api/v1/assessments/{_seg(assessment_id)}/findings/{_seg(finding_id)}"
        )
        if not payload:
            return None
        rows = payload.get("findings") or []
        for row in rows:
            if isinstance(row, dict) and row.get("finding_id") == finding_id:
                detail = dict(
                    (payload.get("risk") or {}).get("score_detail") or {}
                ) or dict((payload.get("assessment") or {}).get("risk", {}).get("score_detail") or {})
                contribution = None
                weight = None
                for item in detail.get("contributions") or ():
                    if item.get("finding_id") == finding_id:
                        contribution = item.get("added")
                        weight = item.get("weight")
                        break
                out = dict(row)
                out["score_contribution"] = contribution
                out["rule_weight"] = weight
                out["evidence_ids"] = [
                    ref.get("evidence_id")
                    for ref in (row.get("evidence_refs") or ())
                    if isinstance(ref, dict) and ref.get("evidence_id")
                ]
                return out
        return None

    def custody(self, assessment_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
        return self._get(
            f"/api/v1/assessments/{_seg(assessment_id)}/findings/{_seg(finding_id)}"
            f"/explanation?verify=false"
        )

    def drift(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        return self._get(f"/api/v1/assessments/{_seg(assessment_id)}/drift")


def _seg(value: str) -> str:
    from urllib.parse import quote

    return quote(str(value), safe="")


def _urllib_get_json(url: str, timeout: float) -> Optional[Dict[str, Any]]:
    from urllib.error import HTTPError, URLError
    from urllib.request import urlopen

    try:
        with urlopen(url, timeout=timeout) as response:  # noqa: S310 - fixed http(s) host from config
            raw = response.read()
    except (HTTPError, URLError, OSError, ValueError):
        return None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


# ---------------------------------------------------------------------------
# the builder
# ---------------------------------------------------------------------------

def build_grounding_context(
    source: ContextSource,
    *,
    assessment_id: Optional[str] = None,
    finding_id: Optional[str] = None,
) -> GroundingContext:
    """Assemble the authoritative slice one question may be answered from.

    Never raises for a missing assessment: an absent assessment is a legitimate
    state that the assistant must be able to talk about honestly, and it is
    returned as ``available=False`` with a reason.
    """
    if source is None or not getattr(source, "available", False):
        return GroundingContext(
            available=False,
            reason=getattr(source, "reason", None) or "no authoritative context source is attached",
        )
    if not assessment_id:
        return GroundingContext(
            available=False,
            reason="no assessment is selected, so there is no recorded context to explain",
        )
    try:
        bundle = source.assessment(assessment_id)
    except ContextUnavailable as exc:
        return GroundingContext(assessment_id=assessment_id, available=False, reason=exc.reason)
    except Exception:
        return GroundingContext(
            assessment_id=assessment_id,
            available=False,
            reason=(
                "the assessment could not be read from the authoritative store; "
                "no values are reported rather than reporting partial ones"
            ),
        )

    risk = dict(bundle.get("risk") or {})
    identity = dict(bundle.get("identity") or {})
    expected = dict(bundle.get("expected") or {})
    observed = dict(bundle.get("observed") or {})
    correlation = dict(bundle.get("correlation") or {})

    findings = [row for row in (risk.get("findings") or []) if isinstance(row, dict)]
    findings.sort(key=lambda row: str(row.get("finding_id") or ""))

    selected = None
    if finding_id:
        for row in findings:
            if row.get("finding_id") == finding_id:
                selected = row
                break

    context = GroundingContext(
        assessment_id=assessment_id,
        available=True,
        reason=None,
        scenario=bundle.get("scenario"),
        slot=bundle.get("slot"),
        dataset_run_id=identity.get("dataset_run_id") or bundle.get("dataset_run_id"),
        sequence=identity.get("sequence"),
        severity=risk.get("severity"),
        risk_score=risk.get("overall_score"),
        risk_policy_version=risk.get("risk_policy_version"),
        risk_engine_version=risk.get("risk_engine_version"),
        finding_ids=tuple(str(row.get("finding_id")) for row in findings if row.get("finding_id")),
        finding_summaries=tuple(
            f"{row.get('severity')} {row.get('title')}"
            for row in findings
            if row.get("severity") and row.get("title")
        ),
        expected=_project_expected(expected),
        observed=_project_observed(observed),
        comparisons=tuple(_comparisons(correlation)),
        variables=tuple(
            str(row.get("variable"))
            for row in (correlation.get("rows") or [])
            if isinstance(row, dict) and row.get("variable")
        ),
        ml=_project_ml(bundle.get("ml")),
        evidence_count=_evidence_count(bundle.get("evidence")),
        evidence_sources=_evidence_sources(bundle.get("evidence")),
    )

    if selected is not None:
        context = _with_finding(context, selected, findings, source, assessment_id)
    return context


def _with_finding(
    context: GroundingContext,
    selected: Dict[str, Any],
    findings: Sequence[Dict[str, Any]],
    source: ContextSource,
    assessment_id: str,
) -> GroundingContext:
    """Attach one selected finding, its contribution and its provenance chain.

    The contribution is taken from the recorded ``score_detail`` when the source
    can supply it. It is never derived from severity and the policy weights,
    because the per-category cap means the booked amount can be lower than the
    weight and stating the weight as the contribution would overstate it.
    """
    record = dict(selected)
    if not record.get("score_contribution"):
        try:
            resolved = source.finding(assessment_id, str(record.get("finding_id")))
        except Exception:
            resolved = None
        if resolved:
            record.update(
                {
                    key: resolved.get(key)
                    for key in ("score_contribution", "rule_weight", "evidence_ids")
                    if resolved.get(key) is not None
                }
            )

    finding = GroundedFinding(
        finding_id=str(record.get("finding_id") or ""),
        rule_id=str(record.get("rule_id") or ""),
        category=str(record.get("category") or ""),
        severity=str(record.get("severity") or ""),
        title=str(record.get("title") or ""),
        description=str(record.get("description") or ""),
        reason=str(record.get("reason") or ""),
        condition=str(record.get("condition") or ""),
        source=str(record.get("source") or ""),
        related_variable=record.get("related_variable"),
        expected_value=record.get("expected_value"),
        observed_value=record.get("observed_value"),
        score_contribution=record.get("score_contribution"),
        rule_weight=record.get("rule_weight"),
        confidence=record.get("confidence"),
        model_version=record.get("model_version"),
    )

    evidence_ids = tuple(
        dict.fromkeys(
            [
                str(value)
                for value in list(record.get("evidence_ids") or ()) + list(context.evidence_ids)
                if value
            ]
        )
    )
    chain = _custody(source, assessment_id, finding.finding_id)
    return GroundingContext(
        assessment_id=context.assessment_id,
        available=True,
        reason=None,
        scenario=context.scenario,
        slot=context.slot,
        dataset_run_id=context.dataset_run_id,
        sequence=context.sequence,
        severity=context.severity,
        risk_score=context.risk_score,
        risk_policy_version=context.risk_policy_version,
        risk_engine_version=context.risk_engine_version,
        finding=finding,
        finding_ids=context.finding_ids,
        finding_summaries=context.finding_summaries,
        expected=context.expected,
        observed=context.observed,
        comparisons=context.comparisons,
        variables=context.variables,
        evidence_ids=evidence_ids,
        evidence_sources=context.evidence_sources,
        evidence_count=context.evidence_count,
        integrity_status=_summarise_integrity(chain),
        custody=chain,
        drift=_drift(source, assessment_id),
        ml=context.ml,
        asset=None,
    )


def _project_expected(expected: Dict[str, Any]) -> Dict[str, Any]:
    """The configured policy, flattened to the fields an analyst asks about.

    A field the backend did not record stays absent from the projection rather
    than being filled with a placeholder, so "not recorded" and "recorded as
    empty" remain distinguishable downstream.
    """
    out: Dict[str, Any] = {}
    ike = dict(expected.get("ike") or {})
    esp = dict(expected.get("esp") or {})
    traffic = dict(expected.get("traffic") or {})
    mapping = (
        ("mode", expected.get("mode")),
        ("address_family", expected.get("address_family")),
        ("ike_version", ike.get("version")),
        ("ike_encryption", ike.get("encryption")),
        ("ike_integrity", ike.get("integrity")),
        ("ike_dh_group", ike.get("dh_group")),
        ("esp_encryption", esp.get("encryption")),
        ("esp_integrity", esp.get("integrity")),
        ("esp_dh_group", esp.get("dh_group")),
        ("esp_pfs", esp.get("pfs")),
        ("traffic_profile", traffic.get("profile")),
        ("traffic_port", traffic.get("port")),
        ("traffic_duration", traffic.get("duration")),
        ("configuration_id", expected.get("configuration_id")),
        ("security_posture", expected.get("security_posture")),
        ("capture_filter", expected.get("capture_filter")),
    )
    for key, value in mapping:
        if value is not None and value != "":
            out[key] = value
    return out


def _project_observed(observed: Dict[str, Any]) -> Dict[str, Any]:
    """What the capture produced, reduced to the fields that carry meaning.

    No crypto field is ever derived here. The observed state has no encryption,
    integrity, DH or PFS fields, and this projection does not manufacture them:
    an ESP encryption question answered from a capture would be a guess.
    """
    if not observed or not observed.get("present", False):
        return {}
    endpoints = dict(observed.get("endpoints") or {})
    out: Dict[str, Any] = {}
    mapping = (
        ("timestamp_ns", observed.get("timestamp_ns")),
        ("active", observed.get("active")),
        ("tunnel_seen", observed.get("tunnel_seen")),
        ("packets_seen", observed.get("packets_seen")),
        ("bytes_seen", observed.get("bytes_seen")),
        ("packets_a_to_b", observed.get("packets_a_to_b")),
        ("packets_b_to_a", observed.get("packets_b_to_a")),
        ("ike_seen", observed.get("ike_seen")),
        ("ike_nat_t_seen", observed.get("ike_nat_t_seen")),
        ("esp_seen", observed.get("esp_seen")),
        ("ah_seen", observed.get("ah_seen")),
        ("observed_ike_activity", observed.get("observed_ike_activity")),
        ("last_ike_timestamp_ns", observed.get("last_ike_timestamp_ns")),
        ("last_esp_timestamp_ns", observed.get("last_esp_timestamp_ns")),
    )
    for key, value in mapping:
        if value is not None:
            out[key] = value
    for key, value in endpoints.items():
        if value:
            out[f"endpoint_{key}"] = value
    spis = [row for row in (observed.get("spis") or []) if isinstance(row, dict)]
    if spis:
        out["spi_count"] = len(spis)
        out["spis"] = [
            {
                "spi": row.get("spi"),
                "direction": row.get("direction"),
                "active": row.get("active"),
                "packet_count": row.get("packet_count"),
                "first_sequence": row.get("first_sequence"),
                "last_sequence": row.get("last_sequence"),
                "highest_sequence": row.get("highest_sequence"),
                "sequence_delta": row.get("sequence_delta"),
            }
            for row in spis
        ]
    return out


def _comparisons(correlation: Dict[str, Any]) -> Iterable[GroundedComparison]:
    for row in correlation.get("rows") or ():
        if not isinstance(row, dict) or not row.get("variable"):
            continue
        yield GroundedComparison(
            variable=str(row.get("variable")),
            status=str(row.get("status") or "UNKNOWN"),
            expected_value=row.get("expected_value"),
            observed_value=row.get("observed_value"),
            reason=row.get("reason"),
        )


def _project_ml(ml: Any) -> Optional[GroundedMl]:
    """ML output, kept as its own object with its own origin.

    ``present=False`` is preserved as an explicit statement rather than being
    collapsed to ``None``, because "ML did not run" and "ML ran without a
    probability" need different explanations.
    """
    if not isinstance(ml, dict):
        return GroundedMl(
            present=False,
            reason="the backend supplied no ML result for this assessment",
        )
    if not ml.get("present", False):
        return GroundedMl(
            present=False,
            reason=ml.get("reason") or "ML was not executed for this assessment",
        )
    return GroundedMl(
        present=True,
        traffic_class=ml.get("traffic_class"),
        classification_confidence=ml.get("classification_confidence"),
        model_version=ml.get("model_version"),
        anomaly=ml.get("anomaly"),
        anomaly_score=ml.get("anomaly_score"),
        reason=None,
    )


def _evidence_count(evidence: Any) -> Optional[int]:
    if not isinstance(evidence, dict):
        return None
    total = evidence.get("total_refs")
    if isinstance(total, int):
        return total
    refs = evidence.get("refs")
    return len(refs) if isinstance(refs, list) else None


def _evidence_sources(evidence: Any) -> Tuple[str, ...]:
    if not isinstance(evidence, dict):
        return ()
    sources: List[str] = []
    for row in evidence.get("refs") or ():
        if isinstance(row, dict):
            value = row.get("source")
            if value:
                sources.append(str(value))
            ident = row.get("evidence_id")
            if ident:
                sources.append(str(ident))
    return tuple(dict.fromkeys(sources))


def _summarise_integrity(chain: Optional[GroundedCustody]) -> Optional[str]:
    """One word for the recorded integrity checks, without collapsing a failure.

    A ``fail`` is reported as ``fail`` and never averaged away into an
    "overall" value: an assistant that turns one failed check into a pass
    because the rest passed would be making the security decision this package
    exists to avoid making.
    """
    if chain is None or not chain.integrity_statuses:
        return None
    statuses = set(chain.integrity_statuses)
    for worst in ("fail", "unavailable"):
        if worst in statuses:
            return worst
    if "not_applicable" in statuses:
        return "not_applicable"
    return "pass" if "pass" in statuses else None


def _custody(source: ContextSource, assessment_id: str, finding_id: str) -> Optional[GroundedCustody]:
    try:
        chain = source.custody(assessment_id, finding_id)
    except Exception:
        return None
    if not isinstance(chain, dict) or not chain:
        return None
    steps: List[str] = []
    for step in chain.get("steps") or ():
        if isinstance(step, dict) and step.get("stage"):
            stages = str(step.get("stage"))
            if stages not in steps:
                steps.append(stages)
    facts: List[str] = []
    for fact in chain.get("facts") or ():
        if not isinstance(fact, dict):
            continue
        label = fact.get("label")
        value = fact.get("value")
        if label and value is not None:
            facts.append(f"{label}: {value}")
    evidence_ids: List[str] = []
    for link in chain.get("evidence") or ():
        if isinstance(link, dict) and link.get("evidence_id"):
            evidence_ids.append(str(link["evidence_id"]))
    statuses = [
        str(check.get("status"))
        for check in chain.get("integrity") or ()
        if isinstance(check, dict) and check.get("status")
    ]
    return GroundedCustody(
        available=bool(steps),
        stages=tuple(steps),
        facts=tuple(facts),
        evidence_ids=tuple(dict.fromkeys(evidence_ids)),
        audit_linkage=chain.get("audit_linkage_status"),
        integrity_statuses=tuple(dict.fromkeys(statuses)),
        reason=None if steps else "the backend returned no recorded custody stages",
    )


def _drift(source: ContextSource, assessment_id: str) -> Optional[GroundedDrift]:
    try:
        drift = source.drift(assessment_id)
    except Exception:
        return None
    if not isinstance(drift, dict) or not drift:
        return GroundedDrift(
            configured=False,
            reason="the backend recorded no drift comparison for this assessment",
        )
    status = drift.get("status")
    if status == "not_configured":
        return GroundedDrift(
            configured=False,
            status=status,
            reason=(
                drift.get("reason")
                or "no validated baseline is configured, so no drift comparison was performed"
            ),
        )
    changed = tuple(
        str(row.get("variable"))
        for row in (drift.get("changed_fields") or ())
        if isinstance(row, dict) and row.get("variable")
    )
    return GroundedDrift(
        configured=True,
        status=str(status) if status else None,
        reason=drift.get("reason"),
        changed_variables=changed,
        baseline_id=drift.get("baseline_id"),
    )
