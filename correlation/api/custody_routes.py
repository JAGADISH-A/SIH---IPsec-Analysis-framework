"""HTTP handler for the finding chain-of-custody routes.

Two routes, because a finding id is **not** a unique key:

    GET /api/v1/assessments/{assessment_id}/findings/{finding_id}/explanation
    GET /api/v1/findings/{finding_id}/explanation

The nested route addresses one decision unambiguously and is the primary
contract. The flat route is the convenience form a client reaches for first, and
because the same ``finding_id`` genuinely occurs in several assessments
(``RISK-PFS-DISABLED`` is raised by four of the recorded cases), the flat route
refuses to guess: with more than one candidate it answers ``409`` and lists the
assessment ids, and the client re-requests with ``?assessment_id=`` or switches
to the nested route.

Returning the first match, or merging the candidates into one synthetic chain,
would both be worse than a 409. The first would attach one capture's evidence to
another capture's finding; the second would invent a decision that no assessment
made.

Authority boundary
------------------
The handler resolves a chain and serializes it. It runs no pipeline stage,
re-derives no finding, verifies no digest itself and applies no control. The
read-only guarantee is structural: this module defines no mutating verb, the
returned model rejects ``applied=True`` on a recommendation, and every integrity
status that could not be evaluated is reported as ``unavailable`` rather than
``pass``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..custody import ChainOfCustody
from .adapters import parse_assessment_id
from .routes import ApiError

API_CUSTODY = "custody"

#: Bounded so a pathological query cannot reflect an unbounded id list.
MAX_CANDIDATES = 50


def _audit_event_ids(audit_store, chain_identity: Dict[str, Any]) -> Tuple[str, ...]:
    """Content-addressed audit event ids for one assessment, if a journal exists.

    Returns an empty tuple when no journal is attached or the assessment has no
    recorded event. The chain then reports ``audit_linkage_status:
    "unavailable"`` and a matching integrity check, which is the honest answer:
    the chain is built from live pipeline objects and is not anchored in the
    tamper-evident journal. Nothing is fabricated to fill the gap.
    """
    if audit_store is None:
        return ()
    run_id = chain_identity.get("dataset_run_id")
    sequence = chain_identity.get("sequence")
    if not run_id or sequence is None:
        return ()
    try:
        events = audit_store.select()
    except Exception:  # pragma: no cover - a journal read must never 500 here
        return ()
    matched: List[str] = []
    for event in events or ():
        identity = getattr(event, "identity", None)
        if identity is None:
            continue
        if (
            identity.dataset_run_id == run_id
            and identity.sequence == sequence
        ):
            matched.append(event.event_id)
    return tuple(sorted(set(matched)))


#: Query values that mean "do not re-hash the artifacts".
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def _wants_verification(params: Optional[Dict[str, Any]]) -> bool:
    """Whether the caller asked for the artifact re-hash (the default)."""
    return str((params or {}).get("verify") or "").strip().lower() not in _FALSE_VALUES


def _candidates(store, finding_id: str) -> Tuple[str, ...]:
    """Every assessment id that produced this finding id, in a stable order."""
    found = []
    for assessment_id in sorted(store.bundles):
        held = store.custody_inputs.get(assessment_id)
        if held is None:
            continue
        if any(item.finding_id == finding_id for item in held.assessment.findings):
            found.append(assessment_id)
    return tuple(found)


def _envelope(
    chain: ChainOfCustody,
    *,
    route: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """The standard single-resource envelope for a chain."""
    body = chain.to_dict()
    body.update(
        {
            "api": API_CUSTODY,
            "route": route,
            "read_only": True,
            "finding_id": chain.finding_id,
            "assessment_id": chain.assessment_id,
        }
    )
    if not _wants_verification(params):
        # The re-hash was genuinely skipped by the builder, so this is a
        # description of what happened rather than an annotation added after
        # the fact. See verify_evidence in build_chain_of_custody.
        body["verification"] = {
            "performed": False,
            "reason": "verify=false was requested; recorded digests are served unverified",
        }
    else:
        body["verification"] = {
            "performed": True,
            "reason": "each referenced artifact was re-hashed and compared with its "
                      "recorded digest",
        }
    return body


def handle_assessment_finding_explanation(
    store,
    assessment_id: str,
    finding_id: str,
    params: Optional[Dict[str, Any]] = None,
    *,
    audit_store=None,
) -> Dict[str, Any]:
    """The chain for one finding of one assessment. 404 when either is unknown.

    The pair is the identity of a decision, so the pair is resolved strictly: a
    finding id that exists in a *different* assessment is a 404 here, never that
    other assessment's evidence.
    """
    if parse_assessment_id(assessment_id) is None:
        raise ApiError(404, "invalid_assessment_id", "assessment id has an invalid format")
    if not finding_id or "/" in finding_id:
        raise ApiError(404, "invalid_finding_id", "finding id has an invalid format")
    if assessment_id not in store.bundles:
        raise ApiError(404, "assessment_not_found", f"no assessment {assessment_id!r}")

    held = store.custody_inputs.get(assessment_id)
    if held is None:
        raise ApiError(
            503, "custody_unavailable",
            f"assessment {assessment_id!r} carries no retained pipeline objects, "
            f"so its chain of custody cannot be reconstructed without re-running "
            f"analysis, which this read-only API will not do",
        )
    try:
        chain = store.chain_of_custody(
            assessment_id,
            finding_id,
            audit_event_ids=_audit_event_ids(audit_store, held.assessment.identity.to_dict()),
            verify_evidence=_wants_verification(params),
        )
    except KeyError:
        raise ApiError(
            404, "finding_not_found",
            f"assessment {assessment_id!r} produced no finding "
            f"{finding_id!r}; the same finding id may exist in another assessment",
        ) from None
    return _envelope(
        chain,
        route="assessment-finding-explanation",
        params=params,
    )


def handle_finding_explanation(
    store,
    finding_id: str,
    params: Optional[Dict[str, Any]] = None,
    *,
    audit_store=None,
) -> Dict[str, Any]:
    """The chain for a finding id, disambiguated by ``?assessment_id=``.

    404 when no assessment produced the finding, 409 when more than one did and
    no disambiguator was supplied.
    """
    if not finding_id or "/" in finding_id:
        raise ApiError(404, "invalid_finding_id", "finding id has an invalid format")

    matches = _candidates(store, finding_id)
    requested = str((params or {}).get("assessment_id") or "").strip()
    if not matches:
        raise ApiError(
            404, "finding_not_found",
            f"no assessment produced finding {finding_id!r}",
        )
    if requested:
        if requested not in matches:
            raise ApiError(
                404, "finding_not_found",
                f"assessment {requested!r} did not produce finding {finding_id!r}",
            )
        matches = (requested,)
    elif len(matches) > 1:
        raise ApiError(
            409,
            "finding_ambiguous",
            f"finding {finding_id!r} was produced by {len(matches)} assessments, so "
            f"a single chain cannot be chosen; re-request with ?assessment_id=<id> "
            f"or use /api/v1/assessments/{{assessment_id}}/findings/"
            f"{finding_id}/explanation",
            extra={
                "candidates": list(matches[:MAX_CANDIDATES]),
                "candidate_count": len(matches),
                "truncated": len(matches) > MAX_CANDIDATES,
            },
        )
    return handle_assessment_finding_explanation(
        store, matches[0], finding_id, params, audit_store=audit_store
    )
