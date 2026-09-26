"""Read-only evidence-reference routes (Phase 15).

These handlers expose *references* — immutable metadata about a real artifact —
never artifact bytes. The bytes remain behind the existing, already-hardened
``/api/v1/evidence/{id}/pcap`` path in :mod:`correlation.api.v1`.

Routes
------
``GET /api/v1/evidence``
    Every registered reference with its integrity status.
``GET /api/v1/evidence/{evidence_id}``
    One reference, its window binding, its capture interval and its integrity
    status. Extends the pre-existing descriptor rather than replacing it.
``GET /api/v1/runs/{run_id}/evidence``
    Evidence grouped per analysis window for a run. Supports
    ``?window_index=N`` to narrow to a single window.
``GET /api/v1/audit/events/{event_id}/evidence``
    The evidence that supported a recorded stage (e.g. a risk finding).
``GET /api/v1/responses/{recommendation_id}/evidence``
    The evidence carried by a response proposal's lifecycle records, when a
    response ledger is attached.

Security
--------
Callers present an ``evidence_id`` and nothing else. No handler accepts a
filesystem path, so this surface cannot be turned into a file oracle; the
existing ``PcapRegistry`` hardening remains the only thing that maps an id onto
a real file. A reference whose artifact is missing or altered is reported as
``unavailable`` / ``invalid`` and is never repaired or substituted.

Authority
---------
A capture is not a protocol conclusion. Every payload here reports
``authoritative: false`` for the artifact itself and points at the observation
event that *is* authoritative, so PCAP evidence is never confused with an
interpreted state.
"""

import os
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..models.evidence import EvidenceRef, resolve_within_root
from ..evidence_linkage import window_packet_coverage
from .pcap import PcapService
from .routes import ApiError

EVIDENCE_LIST_PATH = "/api/v1/evidence"
RUN_EVIDENCE_PREFIX = "/api/v1/runs/"
RESPONSE_EVIDENCE_PREFIX = "/api/v1/responses/"


def _registry(context) -> PcapService:
    pcap = getattr(context, "pcap", None)
    if pcap is None:
        raise ApiError(503, "evidence_unavailable", "no evidence service attached")
    return pcap


def _catalog_refs(context) -> Dict[str, EvidenceRef]:
    """Registered references, keyed by id.

    A reference registered through the hardened ``PcapRegistry`` is the single
    source of truth, so a ref can never be visible here without having passed
    the id validation in :meth:`PcapRegistry.register_reference`.
    """
    return _registry(context).registry.references()


def evidence_payload(
    context, ref: EvidenceRef, *, window_start_ns: Optional[int] = None,
    window_end_ns: Optional[int] = None,
) -> Dict[str, Any]:
    """Reference + integrity + window coverage, for one reference.

    Contains no artifact payload: the digest, size, interval and window binding
    are enough to locate and verify the capture without shipping its bytes.
    """
    pcap = _registry(context)
    verification = pcap.verify(ref.evidence_id)
    if verification is None:
        verification = ref.verify(pcap.registry.root or None)
    payload: Dict[str, Any] = {
        "evidence_id": ref.evidence_id,
        "reference": ref.to_dict(),
        "integrity": {
            "status": verification.status,
            "detail": verification.detail,
            "artifact_present": verification.artifact_present,
            "artifact_sha256": verification.actual_sha256,
            "expected_sha256": verification.expected_sha256,
            "byte_size": verification.byte_size,
            "matches_recorded": verification.status == "valid",
        },
        # A capture is evidence that bytes existed, never that an
        # interpretation is correct.
        "authoritative": False,
        "authoritative_source": "observation/state-builder",
        "read_only": True,
        "download_path": f"/api/v1/evidence/{ref.evidence_id}/pcap",
    }
    payload["window_coverage"] = window_packet_coverage(
        ref, window_start_ns, window_end_ns
    )
    if pcap.registry.resolve(ref.evidence_id) is not None:
        payload["downloadable"] = True
    else:
        payload["downloadable"] = False
    return payload


def register_journal_evidence(store, registry, *, root: str) -> Dict[str, Any]:
    """Make the journal's recorded evidence references resolvable, read-only.

    The journal is the single source of truth for *which* evidence exists; this
    only makes those already-recorded references resolvable through the
    metadata API. Nothing is invented -- a reference is registered only if it
    is present in the journal, and its artifact must already resolve inside
    ``root``.

    Returns how many references were registered and why any were skipped, so a
    missing or relocated capture is visible to the operator rather than
    silently absent from the API.
    """
    registered: List[str] = []
    seen: set = set()
    skipped: Dict[str, Dict[str, Any]] = {}
    for event in store.select():
        for ref in getattr(event, "evidence_refs", ()):
            evidence_id = getattr(ref, "evidence_id", None)
            if not evidence_id or evidence_id in seen:
                continue
            seen.add(evidence_id)
            try:
                if resolve_within_root(ref.pcap_path, root) is None:
                    raise ValueError(
                        f"artifact {ref.pcap_path!r} does not resolve inside "
                        f"{root}"
                    )
                registry.register_reference(ref)
                # The reference is the recorded source of truth, so its own
                # already-validated in-root path is what the download mapping
                # may serve. This is id-keyed only: the API still accepts an
                # evidence id and nothing else, and no path from a request ever
                # reaches the registry.
                registry.register(evidence_id, ref.pcap_path)
            except (TypeError, ValueError) as error:
                # Keyed by id so one relocated capture is reported once, not
                # once per event that references it.
                skipped[evidence_id] = {
                    "evidence_id": evidence_id,
                    "pcap_path": ref.pcap_path,
                    "reason": str(error),
                }
                continue
            registered.append(evidence_id)
    return {
        "registered": len(registered),
        "skipped": [skipped[key] for key in sorted(skipped)],
    }


def handle_evidence_list(context, params: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Every registered reference, optionally filtered by run / artifact type."""
    params = dict(params or {})
    refs = list(_catalog_refs(context).values())
    run_id = params.get("run_id")
    if isinstance(run_id, str) and run_id:
        refs = [ref for ref in refs if ref.run_id == run_id]
    artifact_type = params.get("artifact_type")
    if isinstance(artifact_type, str) and artifact_type:
        refs = [ref for ref in refs if ref.artifact_type == artifact_type]
    window_index = params.get("window_index")
    if window_index not in (None, ""):
        try:
            wanted = int(window_index)
        except (TypeError, ValueError):
            raise ApiError(400, "invalid_query_parameter",
                           f"window_index must be an integer, got {window_index!r}")
        refs = [ref for ref in refs if ref.window_index == wanted]
    refs.sort(key=lambda ref: (ref.run_id or "", ref.window_index
                               if ref.window_index is not None else -1,
                               ref.evidence_id))
    return {
        "api": "evidence-list",
        "evidence_count": len(refs),
        "evidence": [evidence_payload(context, ref) for ref in refs],
        "read_only": True,
    }


def handle_run_evidence(
    context, run_id: str, params: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:
    """Evidence grouped per window for one run: the run/window -> evidence edge."""
    params = dict(params or {})
    refs = [ref for ref in _catalog_refs(context).values() if ref.run_id == run_id]
    if not refs:
        raise ApiError(404, "evidence_run_not_found",
                       f"no evidence registered for run {run_id!r}")
    window_index = params.get("window_index")
    if window_index not in (None, ""):
        try:
            wanted = int(window_index)
        except (TypeError, ValueError):
            raise ApiError(400, "invalid_query_parameter",
                           f"window_index must be an integer, got {window_index!r}")
        refs = [ref for ref in refs if ref.window_index == wanted]
        if not refs:
            # A window that was analysed but carries no evidence is a real,
            # answerable question ("this window has no capture") and is
            # reported as an empty result. Only a window that does not exist at
            # all in the journal is a 404. Neither case invents evidence.
            store = getattr(context, "audit_store", None)
            recorded = None
            if store is not None:
                try:
                    recorded = store.window(run_id, wanted)
                except Exception:
                    recorded = None
            if recorded is None:
                raise ApiError(
                    404, "evidence_window_not_found",
                    f"run {run_id!r} has no window {wanted} and no evidence "
                    f"bound to it",
                )
            return {
                "api": "run-evidence",
                "run_id": run_id,
                "window_count": 1,
                "evidence_count": 0,
                "windows": [{"window_index": wanted, "evidence": []}],
                "no_evidence_reason": (
                    f"window {wanted} of run {run_id!r} is recorded in the "
                    f"analysis journal but has no evidence reference bound to "
                    f"it; none is substituted"
                ),
                "read_only": True,
            }

    # Window bounds come from the audit store when one is attached, so the
    # packet-coverage answer is grounded in the recorded window rather than a
    # guess. Absent a store the coverage reason simply says so.
    bounds: Dict[int, Sequence[Optional[int]]] = {}
    store = getattr(context, "audit_store", None)
    if store is not None:
        for ref in refs:
            if ref.window_index is None or ref.window_index in bounds:
                continue
            try:
                window = store.window(ref.run_id, ref.window_index)
            except Exception:
                window = None
            if window is not None:
                bounds[ref.window_index] = (
                    window.get("window_start_ns"), window.get("window_end_ns"),
                )

    grouped: Dict[Any, List[Dict[str, Any]]] = {}
    for ref in refs:
        key = ref.window_index
        start, end = bounds.get(ref.window_index, (None, None)) if key is not None \
            else (None, None)
        grouped.setdefault(key, []).append(
            evidence_payload(context, ref, window_start_ns=start, window_end_ns=end)
        )
    return {
        "api": "run-evidence",
        "run_id": run_id,
        "window_count": len(grouped),
        "evidence_count": sum(len(entries) for entries in grouped.values()),
        "windows": [
            {"window_index": key, "evidence": entries}
            for key, entries in sorted(
                grouped.items(), key=lambda item: (item[0] is None, item[0])
            )
        ],
        "read_only": True,
    }


def handle_event_evidence(context, event_id: str) -> Dict[str, Any]:
    """The evidence that supported one recorded audit stage.

    Answers the finding -> evidence question directly: a risk event's recorded
    references are the evidence its finding was derived from.
    """
    store = getattr(context, "audit_store", None)
    if store is None:
        raise ApiError(
            503, "audit_unavailable",
            "no analysis audit journal is attached; evidence lookup by event "
            "requires --audit-journal <path>",
        )
    event = store.get_event(event_id)
    if event is None:
        raise ApiError(404, "audit_event_not_found",
                       f"no audit event {event_id!r}")
    # get_event() returns a materialized AuditEvent, not a raw dict; go through
    # to_dict() so this path reads the same verified shape the journal stores.
    event = event.to_dict() if hasattr(event, "to_dict") else dict(event)
    identity = event.get("identity") or {}
    refs = event.get("evidence_refs") or []
    payloads: List[Dict[str, Any]] = []
    for raw in refs:
        ref = EvidenceRef.from_dict(raw)
        payloads.append(
            evidence_payload(
                context, ref,
                window_start_ns=identity.get("window_start_ns"),
                window_end_ns=identity.get("window_end_ns"),
            )
        )
    return {
        "api": "audit-event-evidence",
        "event_id": event_id,
        "event_type": event.get("event_type"),
        "source": event.get("source"),
        "authoritative": event.get("authoritative"),
        "run_id": identity.get("dataset_run_id"),
        "experiment_id": identity.get("experiment_id"),
        "window_index": identity.get("window_index"),
        "evidence_count": len(payloads),
        "evidence": payloads,
        "read_only": True,
    }


def handle_response_evidence(context, recommendation_id: str) -> Dict[str, Any]:
    """Evidence carried by a response proposal's lifecycle records.

    Reads the response ledger only when one is attached; it never implies the
    proposal was authorized or executed, and the lifecycle distinction is passed
    through verbatim.
    """
    store = getattr(context, "audit_store", None)
    if store is None:
        raise ApiError(
            503, "audit_unavailable",
            "no analysis audit journal is attached; response evidence lookup "
            "requires --audit-journal <path>",
        )
    lifecycle = store.response_lifecycle(recommendation_id)
    if not lifecycle.get("available"):
        raise ApiError(
            404, "response_not_found",
            f"no response lifecycle recorded for {recommendation_id!r}"
            + ("" if lifecycle.get("unavailable_reason") is None
               else f" ({lifecycle['unavailable_reason']})"),
        )
    merged: Dict[str, EvidenceRef] = {}
    for record in lifecycle.get("events") or []:
        for raw in record.get("evidence_refs") or ():
            ref = EvidenceRef.from_dict(raw)
            merged.setdefault(ref.evidence_id, ref)
    identity = (lifecycle.get("events") or [{}])[0].get("assessment_identity") or {}
    payloads = [
        evidence_payload(
            context, ref,
            window_start_ns=identity.get("window_start_ns"),
            window_end_ns=identity.get("window_end_ns"),
        )
        for ref in merged.values()
    ]
    return {
        "api": "response-evidence",
        "recommendation_id": recommendation_id,
        "run_id": identity.get("dataset_run_id"),
        "experiment_id": identity.get("experiment_id"),
        "window_index": identity.get("window_index"),
        # proposed != authorized != executed, kept exactly as recorded.
        "lifecycle": [
            {
                "event_type": record.get("event_type"),
                "action": record.get("action"),
                "previous_status": record.get("previous_status"),
                "new_status": record.get("new_status"),
                "approval_id": record.get("approval_id"),
                "evidence_count": len(record.get("evidence_refs") or ()),
            }
            for record in lifecycle.get("events") or []
        ],
        "chain_verified": lifecycle.get("chain_verified"),
        "evidence_count": len(payloads),
        "evidence": payloads,
        "read_only": True,
    }


def handle_evidence_id(context, evidence_id: str) -> Dict[str, Any]:
    """One reference, preferring the registered ``EvidenceRef`` when present."""
    pcap = _registry(context)
    ref = pcap.registry.reference(evidence_id)
    if ref is not None:
        # Resolve the recorded window bounds from the audit store so the
        # packet-coverage answer is grounded in the real analysis window rather
        # than reported as "no time bounds".
        start = end = None
        store = getattr(context, "audit_store", None)
        if store is not None and ref.run_id and ref.window_index is not None:
            try:
                window = store.window(ref.run_id, ref.window_index)
            except Exception:
                window = None
            if window is not None:
                start = window.get("window_start_ns")
                end = window.get("window_end_ns")
        return evidence_payload(context, ref, window_start_ns=start,
                                window_end_ns=end)
    # Fall back to the pre-existing download-descriptor contract for an id that
    # is registered for download but carries no reference.
    if not pcap.registry.has(evidence_id):
        raise ApiError(404, "evidence_not_found", f"no evidence {evidence_id!r}")
    resolved = pcap.registry.resolve(evidence_id)
    if resolved is None:
        raise ApiError(
            403, "evidence_unavailable",
            f"evidence {evidence_id!r} cannot be served (no capture resolved)",
        )
    return {
        "api": "evidence-detail",
        "evidence_id": evidence_id,
        "served_from": resolved,
        "extension_locked": True,
        "read_only": True,
        "download_path": f"/api/v1/evidence/{evidence_id}/pcap",
        "reference": None,
        "integrity": {
            "status": "unverified",
            "detail": "no EvidenceRef is registered for this id",
            "matches_recorded": False,
        },
        "authoritative": False,
    }


# -- governance journal (read-only) -----------------------------------------
#
# The governance journal is the *write* side that
# ``correlation/response/audit.py:AuditLedger`` appends to; these handlers only
# read it. They exist so the persisted assessment/recommendation/authorization/
# approval record is inspectable, and so an approval can be walked back to the
# evidence it cited. Nothing here approves, authorizes or executes anything.


def _governance(context):
    ledger = getattr(context, "governance", None)
    if ledger is None:
        raise ApiError(
            503, "governance_unavailable",
            "no governance journal is attached; attach one with "
            "--governance-journal <path>",
        )
    return ledger


def _governance_summary(event) -> Dict[str, Any]:
    return {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "timestamp": event.timestamp,
        "principal": event.principal,
        "action": event.action,
        "previous_status": event.previous_status,
        "new_status": event.new_status,
        "reason": event.reason,
        "policy_version": event.policy_version,
        "recommendation_id": event.recommendation_id,
        "approval_id": event.approval_id,
        "run_id": event.assessment_identity.dataset_run_id,
        "sequence": event.assessment_identity.sequence,
        "experiment_id": event.assessment_identity.experiment_id,
        "window_index": event.assessment_identity.window_index,
        "evidence_count": len(event.evidence_refs),
        "previous_hash": event.previous_hash,
        "event_hash": event.event_hash,
    }


def handle_governance_list(context, params: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """The persisted governance chain, in order, with its integrity state."""
    ledger = _governance(context)
    events = ledger.events()
    # Report the chain as it stands. A chain that does not verify is reported
    # as such; it is never repaired, reordered or hidden.
    try:
        chain_verified = ledger.verify()
        chain_detail = None
    except Exception as exc:
        chain_verified = False
        chain_detail = str(exc)
    return {
        "api": "governance",
        "journal": str(ledger.path) if ledger.path is not None else None,
        "engine_version": ledger.engine_version,
        "event_count": len(events),
        "chain_verified": chain_verified,
        "chain_detail": chain_detail,
        "events": [_governance_summary(event) for event in events],
        "read_only": True,
    }


def handle_governance_event(context, event_id: str) -> Dict[str, Any]:
    """One governance event, its evidence, and where that evidence resolves."""
    ledger = _governance(context)
    for event in ledger.events():
        if event.event_id == event_id:
            observation = getattr(context, "observation_journal", None)
            payloads = [
                evidence_payload(
                    context, ref,
                    window_start_ns=event.assessment_identity.window_start_ns,
                    window_end_ns=event.assessment_identity.window_end_ns,
                )
                for ref in event.evidence_refs
            ]
            summary = _governance_summary(event)
            summary.update({
                "api": "governance-event",
                "journal": str(ledger.path) if ledger.path is not None else None,
                "evidence": payloads,
                "observation_journal": observation,
                "read_only": True,
            })
            return summary
    raise ApiError(404, "governance_event_not_found",
                   f"no governance event {event_id!r}")
