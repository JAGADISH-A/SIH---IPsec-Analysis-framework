"""Observability classification metadata.

Phase 1 established the current sensors' capabilities. This module documents,
for every canonical testbed variable, whether its value is currently
obtainable and from which future source it could be observed. This is
DOCUMENTATION / DATA-CONTRACT INFORMATION ONLY. It does NOT produce any risk
score and MUST NOT be used to generate scores in this phase.

Semantics:

DIRECTLY_OBSERVABLE
    the value is available from the outer (live) IPsec stream without deep
    parse.

INDIRECTLY_OBSERVABLE
    the value is derivable from the v2 feature vector / ML classification or
    from light feature engineering.

AUDIT_ONLY
    the value requires audit / PCAP provenance (IKE exchange parse, e.g. via
    the audit Tap TShark ``events.jsonl``); the outer feature stream cannot
    provide it.

NOT_CURRENTLY_OBSERVABLE
    the value is not obtainable from the current sensor stack (hidden inside
    the ESP payload, or a planning-only property).
"""

from typing import Dict, Tuple

DIRECTLY_OBSERVABLE = "DIRECTLY_OBSERVABLE"
INDIRECTLY_OBSERVABLE = "INDIRECTLY_OBSERVABLE"
AUDIT_ONLY = "AUDIT_ONLY"
NOT_CURRENTLY_OBSERVABLE = "NOT_CURRENTLY_OBSERVABLE"


class Observability:
    DIRECTLY_OBSERVABLE = DIRECTLY_OBSERVABLE
    INDIRECTLY_OBSERVABLE = INDIRECTLY_OBSERVABLE
    AUDIT_ONLY = AUDIT_ONLY
    NOT_CURRENTLY_OBSERVABLE = NOT_CURRENTLY_OBSERVABLE


# canonical variable -> Observability class
OBSERVABILITY: Dict[str, str] = {
    "mode": DIRECTLY_OBSERVABLE,  # outer IP/ESP structure + swanctl config
    "address_family": DIRECTLY_OBSERVABLE,  # IP version of outer header
    "ike.version": AUDIT_ONLY,  # requires IKE exchange type parse (audit/PCAP)
    "ike.encryption": AUDIT_ONLY,  # requires IKE SA payload parse
    "ike.integrity": AUDIT_ONLY,  # requires IKE SA payload parse
    "ike.dh_group": AUDIT_ONLY,  # requires IKE SA KE payload parse
    "esp.encryption": INDIRECTLY_OBSERVABLE,  # feature-derived (ICV/len patterns)
    "esp.integrity": INDIRECTLY_OBSERVABLE,  # feature-derived 
    "esp.dh_group": INDIRECTLY_OBSERVABLE,  # via IKE CREATE_CHILD_SA (audit-derived feature)
    "esp.pfs": INDIRECTLY_OBSERVABLE,  # DH exchange presence during rekey
    "traffic.profile": INDIRECTLY_OBSERVABLE,  # feature/ML classification
    "traffic.duration": NOT_CURRENTLY_OBSERVABLE,  # planning property
    "traffic.port": NOT_CURRENTLY_OBSERVABLE,  # hidden inside ESP payload
    "capture_filter": NOT_CURRENTLY_OBSERVABLE,  # planning/capture metadata
}

# canonical variable -> (expected model path, observed source, future rule)
TRACEABILITY: Dict[str, Tuple[str, str, str]] = {
    "mode": (
        "ExpectedState.mode",
        "outer IP encap structure / swanctl config",
        "future: compare observed encap mode to planned mode",
    ),
    "address_family": (
        "ExpectedState.address_family",
        "outer header IP version",
        "future: compare v4/v6 signature",
    ),
    "ike.version": (
        "ExpectedState.ike.version",
        "audit/PCAP IKE exchange types (events.jsonl)",
        "future: rule requiring audit evidence",
    ),
    "ike.encryption": (
        "ExpectedState.ike.encryption",
        "audit/PCAP IKE SA payload parse",
        "future: audit-derived rule",
    ),
    "ike.integrity": (
        "ExpectedState.ike.integrity",
        "audit/PCAP IKE SA payload parse",
        "future: audit-derived rule",
    ),
    "ike.dh_group": (
        "ExpectedState.ike.dh_group",
        "audit/PCAP IKE KE payload parse",
        "future: audit-derived rule",
    ),
    "esp.encryption": (
        "ExpectedState.esp.encryption",
        "v2 feature vector (esp/ah/ike window features)",
        "future: feature-derived rule",
    ),
    "esp.integrity": (
        "ExpectedState.esp.integrity",
        "v2 feature vector (esp/ah/ike window features)",
        "future: feature-derived rule",
    ),
    "esp.dh_group": (
        "ExpectedState.esp.dh_group",
        "audit IKE CREATE_CHILD_SA payload + feature signal",
        "future: combined rule",
    ),
    "esp.pfs": (
        "ExpectedState.esp.pfs",
        "rekey DH-exchange presence (audit/feature)",
        "future: combined rule",
    ),
    "traffic.profile": (
        "ExpectedState.traffic.profile",
        "v2 feature vector / ML classification",
        "future: ML-derived rule",
    ),
    "traffic.duration": (
        "ExpectedState.traffic.duration",
        "NA (planning property)",
        "future: window-count rule",
    ),
    "traffic.port": (
        "ExpectedState.traffic.port",
        "NA (hidden inside ESP payload)",
        "future: rule marked NOT_CURRENTLY_OBSERVABLE",
    ),
    "capture_filter": (
        "ExpectedState.capture_filter",
        "NA (capture metadata)",
        "future: matching metadata only",
    ),
}


def classification_of(canonical_variable: str) -> str:
    try:
        return OBSERVABILITY[canonical_variable]
    except KeyError:
        raise KeyError(
            f"unknown canonical variable {canonical_variable!r}; known: "
            f"{sorted(OBSERVABILITY)}"
        )