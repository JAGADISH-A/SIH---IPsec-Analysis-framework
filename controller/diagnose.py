"""Deterministic IPsec root-cause classification for Sentinel.

Why this module exists
----------------------
Sentinel already reports the *failed stage* correctly (``FAILED@IPSEC``), but
every IKE-level fault collapsed into one generic message::

    FAILED@IPSEC -- "IKE SA is not established"

That message is a *symptom*. A wrong pre-shared key, disjoint IKE proposals and
a disjoint ESP proposal all end with "no IKE SA", and an operator cannot tell
them apart from the string alone. This module turns the raw strongSwan evidence
that Sentinel already collects into a specific, *deterministic* root cause.

Architecture
------------
::

    strongSwan evidence            (swanctl --list-sas + charon log)
              |
              v
    parse_sa_state()  /  parse_ike_evidence()
              |
              v
    classify_failure()      <-- pure function, no I/O, no lab, no network
              |
              v
    structured Sentinel result  ->  (later) Gemini explains it in prose

Gemini/LLM never participates in detection. There is no similarity scoring, no
confidence percentage and no probabilistic branch anywhere below: every
classification is a total function of the parsed evidence, and anything the
evidence does not pin down returns ``UNKNOWN_IPSEC_FAILURE`` /
``INSUFFICIENT_EVIDENCE`` rather than a guess.

The critical distinction: classification is driven by *protocol context* --
the exchange a notification occurred in, plus the observed SA state -- never by
the presence of a notification string alone. ``NO_PROPOSAL_CHOSEN`` is
therefore mapped by where it happened::

    NO_PROPOSAL_CHOSEN + IKE_SA_INIT      -> IKE_PROPOSAL_MISMATCH
    NO_PROPOSAL_CHOSEN + IKE_AUTH
        + IKE established                 -> ESP_PROPOSAL_MISMATCH
    NO_PROPOSAL_CHOSEN + IKE_AUTH
        + IKE NOT established              -> UNKNOWN (refuses to guess)
    NO_PROPOSAL_CHOSEN + exchange unknown -> UNKNOWN (refuses to guess)
"""

from __future__ import annotations

import ipaddress
import re

# --------------------------------------------------------------------------
# Root-cause vocabulary. These strings are part of Sentinel's result contract
# and are surfaced to operators, so they are declared once, here.
# --------------------------------------------------------------------------

IPSEC_VERIFICATION_PASSED = "IPSEC_VERIFICATION_PASSED"
AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
IKE_PROPOSAL_MISMATCH = "IKE_PROPOSAL_MISMATCH"
ESP_PROPOSAL_MISMATCH = "ESP_PROPOSAL_MISMATCH"
TRAFFIC_SELECTOR_MISMATCH = "TRAFFIC_SELECTOR_MISMATCH"
NAT_T_FAILURE = "NAT_T_FAILURE"
UNSUPPORTED_CONFIGURATION = "UNSUPPORTED_CONFIGURATION"
UNKNOWN_IPSEC_FAILURE = "UNKNOWN_IPSEC_FAILURE"

# ``confidence`` describes EVIDENCE QUALITY, never model certainty. There are
# deliberately no numeric values.
DETERMINISTIC = "DETERMINISTIC"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

# --------------------------------------------------------------------------
# strongSwan vocabulary
# --------------------------------------------------------------------------

#: Log name -> RFC 7208 notification name.
_NOTIFICATION_ALIASES = {
    "AUTHENTICATION_FAILED": "AUTH_FAILED",
    "NO_PROPOSAL_CHOSEN": "NO_PROPOSAL_CHOSEN",
    "INVALID_SYNTAX": "INVALID_SYNTAX",
    "INVALID_IKE_SPI": "INVALID_IKE_SPI",
    "AUTHENTICATION_NO_METHOD": "AUTHENTICATION_NO_METHOD",
    "TS_UNACCEPTABLE": "TS_UNACCEPTABLE",
    "TEMPORARY_FAILURE": "TEMPORARY_FAILURE",
    "CHILD_SA_NOT_FOUND": "CHILD_SA_NOT_FOUND",
}

#: Notifications that authenticate a specific IKE failure. Deliberately narrow.
_AUTH_NOTIFICATIONS = frozenset({"AUTH_FAILED"})

#: Notification meaning "the peer's proposal set had no overlap with mine".
_NO_PROPOSAL_NOTIFICATIONS = frozenset({"NO_PROPOSAL_CHOSEN"})

#: Notification meaning the peer rejected our traffic selectors outright. This
#: is a *negotiation-time* TS rejection, distinct from a TS that was accepted
#: and then fails to carry traffic in the data plane.
_TS_UNACCEPTABLE_NOTIFICATIONS = frozenset({"TS_UNACCEPTABLE"})

#: Exchanges that carry IKE_SA establishment. A notification seen here can only
#: be about IKE itself.
_IKE_EXCHANGES = frozenset({
    "IKE_SA_INIT",
    "IKE_AUTH",
    "IKE_AUTH_EAP",
    "CREATE_CHILD_SA",
    "REKEY_IKE",
})

# Explicit NAT negotiation failure markers. This set is intentionally small and
# explicit: ordinary NAT-T *success* on UDP/4500 emits none of them, so a
# working NAT-T path can never be classified as NAT_T_FAILURE. These strings
# require strongSwan to state that NAT detection/negotiation itself failed.
_NAT_FAILURE_MARKERS = (
    "nat detection failed",
    "nat_detection_failed",
    "n(natd_s_ip) payload mismatch",
    "nat-t negotiation failed",
    "natt negotiation failed",
)

# --------------------------------------------------------------------------
# Log parsing
# --------------------------------------------------------------------------

# ``15[ENC] parsed IKE_AUTH response 1 [ ... N(AUTH_FAILED) ]``
_EXCHANGE_LINE_RE = re.compile(
    r"\b(?:parsed|generating)\s+"
    r"(?P<exchange>IKE_SA_INIT|IKE_AUTH_EAP|IKE_AUTH|CREATE_CHILD_SA"
    r"|REKEY_IKE|REKEY_CHILD)\s+(?:request|response)\b"
)

# ``13[IKE] received AUTHENTICATION_FAILED notify error``
_NOTIFY_RECEIVED_RE = re.compile(
    r"\breceived\s+(?P<name>[A-Z][A-Z0-9_]+)\s+notify\b"
)

# ``[ ... N(NO_PROPOSAL_CHOSEN) ... ]`` payload listings
_NOTIFY_PAYLOAD_RE = re.compile(r"\bN\((?P<name>[A-Z][A-Z0-9_]+)\)")

# ``CHILD_SA gw-a-to-gw-b{3} established with SPIs ... and TS 2001:db8:99::/64
# === 2001:db8:99::/64``
_CHILD_TS_RE = re.compile(
    r"CHILD_SA\s+(?P<conn>\S+)\s+established\s+with\s+SPIs\b.*?"
    r"\band\s+TS\s+(?P<local>\S+)\s+===\s+(?P<remote>\S+)"
)

# strongSwan abbreviates NO_PROPOSAL_CHOSEN to NO_PROP inside payload listings.
_NOTIFY_SHORT_NAMES = {
    "NO_PROP": "NO_PROPOSAL_CHOSEN",
    "AUTH_FAILED": "AUTH_FAILED",
    "TS_UNACCEPTABLE": "TS_UNACCEPTABLE",
}

# IKE/CHILD states reported by ``swanctl --list-sas``.
IKE_ESTABLISHED = "ESTABLISHED"
IKE_NOT_ESTABLISHED = "NOT-ESTABLISHED"
IKE_NO_SA = "NO-SA"
CHILD_INSTALLED = "INSTALLED"
CHILD_NOT_INSTALLED = "NOT-INSTALLED"


def _normalize_notification(name: str) -> str:
    """Map a strongSwan log/payload token to its RFC notification name."""
    name = name.upper()
    if name in _NOTIFY_SHORT_NAMES:
        return _NOTIFY_SHORT_NAMES[name]
    return _NOTIFICATION_ALIASES.get(name, name)


def parse_sa_state(output: str) -> dict:
    """Parse ``swanctl --list-sas`` output into explicit SA state.

    Returns a dict with ``ike_state``, ``child_state``, ``mode`` and
    ``encapsulation``. ``encapsulation`` is one of ``UDP_4500`` (NAT-T),
    ``TUNNEL``, ``TRANSPORT``, ``NONE`` or ``UNKNOWN``, derived from the
    ``TRANSPORT-in-UDP`` / ``TUNNEL-in-UDP`` suffixes strongSwan prints.
    """
    text = output or ""
    has_established = "ESTABLISHED" in text
    has_installed = "INSTALLED" in text

    if has_established:
        ike_state = IKE_ESTABLISHED
    elif not text.strip():
        ike_state = IKE_NO_SA
    else:
        ike_state = IKE_NOT_ESTABLISHED

    if "TRANSPORT-in-UDP" in text:
        mode, encapsulation = "TRANSPORT", "UDP_4500"
    elif "TUNNEL-in-UDP" in text:
        mode, encapsulation = "TUNNEL", "UDP_4500"
    elif "TUNNEL" in text:
        mode, encapsulation = "TUNNEL", "NONE"
    elif "TRANSPORT" in text:
        mode, encapsulation = "TRANSPORT", "NONE"
    else:
        mode, encapsulation = None, "NONE"

    return {
        "ike_state": ike_state,
        "child_state": CHILD_INSTALLED if has_installed else CHILD_NOT_INSTALLED,
        "mode": mode,
        # NAT-T means IKE_SA/CHILD_SA are carried in UDP/4500.
        "nat_t": encapsulation == "UDP_4500",
        "encapsulation": encapsulation,
    }


def parse_ike_evidence(log_text: str) -> dict:
    """Extract exchange-scoped notification evidence from a charon log.

    A notification is attributed to the most recent exchange named in the log
    (``parsed``/``generating <EXCHANGE> request|response``). Notifications seen
    before any exchange marker get ``exchange=None``; that missing context is
    what forces the classifier to refuse a specific diagnosis.
    """
    events = []
    current_exchange = None

    for line in (log_text or "").splitlines():
        match = _EXCHANGE_LINE_RE.search(line)
        if match:
            current_exchange = match.group("exchange")

        for notify_match in _NOTIFY_RECEIVED_RE.finditer(line):
            events.append({
                "notification": _normalize_notification(notify_match.group("name")),
                "exchange": current_exchange,
                "raw_line": line.strip(),
                "source": "notify",
            })

        # Payload listings carry the notification inline, e.g.
        # ``parsed IKE_AUTH response 1 [ N(AUTH_FAILED) ]``. When the same line
        # also names the exchange, use that name; it is the stronger context.
        for notify_match in _NOTIFY_PAYLOAD_RE.finditer(line):
            raw_name = notify_match.group("name")
            if raw_name.upper() in ("NO_PROP", "AUTH_FAILED", "TS_UNACCEPTABLE"):
                events.append({
                    "notification": _normalize_notification(raw_name),
                    "exchange": match.group("exchange") if match else current_exchange,
                    "raw_line": line.strip(),
                    "source": "payload",
                })

    exchanges = sorted({e["exchange"] for e in events if e["exchange"]})
    notifications = sorted({e["notification"] for e in events})

    return {
        "notifications": notifications,
        "events": events,
        "exchanges": exchanges,
        # True when a notification was seen but we could not attribute it to an
        # exchange, i.e. the string alone is all we have.
        "has_unattributed_notification": any(
            e["exchange"] is None for e in events
        ),
        "ike_sa_established_in_log": bool(
            re.search(r"IKE_SA\s+\S+\s+established", log_text or "")
        ),
        "child_sa_established_in_log": bool(
            re.search(r"CHILD_SA\s+\S+\s+established", log_text or "")
        ),
        "child_sa_kept_ike_sa": "keeping IKE_SA" in (log_text or ""),
        "child_selectors": _parse_child_selectors(log_text or ""),
        "nat_failure_markers": _find_nat_failure_markers(log_text or ""),
    }


def _parse_child_selectors(log_text: str) -> list:
    """Installed CHILD_SA selector pairs, as raw ``local === remote`` strings."""
    return [
        f"{m.group('local')} === {m.group('remote')}"
        for m in _CHILD_TS_RE.finditer(log_text)
    ]


def _find_nat_failure_markers(log_text: str) -> list:
    lowered = log_text.lower()
    return [marker for marker in _NAT_FAILURE_MARKERS if marker in lowered]


def _notifications_in(evidence: dict, wanted: frozenset) -> list:
    """Events whose notification is in ``wanted``, attributed to an exchange."""
    return [
        e for e in evidence.get("events", [])
        if e.get("notification") in wanted and e.get("exchange") is not None
    ]


def _any_notification(evidence: dict, wanted: frozenset) -> bool:
    return any(e.get("notification") in wanted for e in evidence.get("events", []))


def _result(root_cause, confidence, reason, evidence, stage):
    return {
        "stage": stage,
        "root_cause": root_cause,
        "confidence": confidence,
        "reason": reason,
        "evidence": evidence,
    }


def _unknown(stage, reason, evidence):
    return _result(
        UNKNOWN_IPSEC_FAILURE, INSUFFICIENT_EVIDENCE, reason, evidence, stage
    )


# --------------------------------------------------------------------------
# Classifier
# --------------------------------------------------------------------------

def classify_failure(
    *,
    stage: str,
    sa_state: dict,
    ike_evidence: dict,
    nat: bool = False,
    connectivity: dict = None,
    probe_target: str = None,
) -> dict:
    """Classify a Sentinel pipeline failure from parsed strongSwan evidence.

    Pure function: no I/O, no lab access, no randomness, no model. The result
    always carries a ``root_cause`` and an evidence dict, so an operator can
    always answer "why did Sentinel say this?".
    """
    ike_state = (sa_state or {}).get("ike_state")
    child_state = (sa_state or {}).get("child_state")
    nat_t = bool((sa_state or {}).get("nat_t"))
    evidence = {
        "ike_state": ike_state,
        "child_state": child_state,
        "encapsulation": (sa_state or {}).get("encapsulation"),
        "nat_requested": bool(nat),
        "nat_t_negotiated": nat_t,
        "notifications": list((ike_evidence or {}).get("notifications", [])),
        "exchanges": list((ike_evidence or {}).get("exchanges", [])),
    }

    # -- 1. NAT-T negotiation/path failure -------------------------------
    # Checked FIRST and on explicit markers only, so a healthy NAT-T run on
    # UDP/4500 can never land here.
    if nat and (ike_evidence or {}).get("nat_failure_markers"):
        evidence["nat_failure_markers"] = list(
            ike_evidence["nat_failure_markers"]
        )
        return _result(
            NAT_T_FAILURE,
            DETERMINISTIC,
            "NAT-T negotiation failed: strongSwan reported "
            f"{', '.join(ike_evidence['nat_failure_markers'])} for a NAT "
            "deployment.",
            evidence,
            stage,
        )

    # -- 2. Authentication failure --------------------------------------
    # AUTH_FAILED is unambiguous wherever it appears: it can only be emitted
    # after the peer has decided the shared key/ID does not authenticate.
    if _any_notification(ike_evidence or {}, _AUTH_NOTIFICATIONS):
        return _result(
            AUTHENTICATION_FAILURE,
            DETERMINISTIC,
            "IKE authentication failed: an AUTH_FAILED notification was "
            "received, so the peers disagree on identity or pre-shared key.",
            evidence,
            "IPSEC",
        )

    # -- 3. IKE_AUTH payload can never negotiate IKE itself; treat as auth --
    if _any_notification(ike_evidence or {}, frozenset({"AUTHENTICATION_NO_METHOD"})):
        return _result(
            AUTHENTICATION_FAILURE,
            DETERMINISTIC,
            "IKE authentication failed: AUTHENTICATION_NO_METHOD means no "
            "configured authentication method was acceptable to the peer.",
            evidence,
            "IPSEC",
        )

    # -- 4. NO_PROPOSAL_CHOSEN, disambiguated by exchange + SA state ------
    no_proposal = _notifications_in(
        ike_evidence or {}, _NO_PROPOSAL_NOTIFICATIONS
    )
    if no_proposal:
        for event in no_proposal:
            exchange = event["exchange"]

            if exchange == "IKE_SA_INIT":
                return _result(
                    IKE_PROPOSAL_MISMATCH,
                    DETERMINISTIC,
                    "IKE proposal mismatch: NO_PROPOSAL_CHOSEN was returned in "
                    "IKE_SA_INIT, before authentication, so the peers' IKE "
                    "encryption/integrity/DH proposals had no overlap.",
                    evidence,
                    "IPSEC",
                )

            if exchange in _IKE_EXCHANGES and ike_state == IKE_ESTABLISHED:
                return _result(
                    ESP_PROPOSAL_MISMATCH,
                    DETERMINISTIC,
                    "ESP/CHILD_SA proposal mismatch: NO_PROPOSAL_CHOSEN was "
                    f"returned in {exchange} while the IKE_SA is ESTABLISHED, so "
                    "authentication succeeded and only the ESP "
                    "encryption/integrity/PFS proposals had no overlap.",
                    evidence,
                    "IPSEC",
                )

        # NO_PROPOSAL_CHOSEN present but we cannot attribute it to an exchange,
        # or it landed in IKE_AUTH without an established IKE_SA to prove the
        # failure was at the CHILD_SA layer. Refuse to guess.
        return _unknown(
            "IPSEC",
            "A NO_PROPOSAL_CHOSEN notification was seen but the evidence does "
            "not establish whether it occurred in IKE_SA_INIT (IKE proposal "
            "mismatch) or IKE_AUTH (ESP proposal mismatch): the exchange "
            "context is "
            + (
                "missing"
                if (ike_evidence or {}).get("has_unattributed_notification")
                else f"present ({', '.join(evidence['exchanges']) or 'none'})"
            )
            + f", and the observed IKE_SA state is {ike_state}. Sentinel does "
            "not guess a specific root cause from the notification alone.",
            evidence,
        )

    # -- 5. Negotiation-time TS rejection ---------------------------------
    if _any_notification(ike_evidence or {}, _TS_UNACCEPTABLE_NOTIFICATIONS):
        return _result(
            TRAFFIC_SELECTOR_MISMATCH,
            DETERMINISTIC,
            "Traffic-selector mismatch: the peer rejected the proposed traffic "
            "selectors with TS_UNACCEPTABLE during CHILD_SA negotiation.",
            evidence,
            "IPSEC",
        )

    # -- 6. Data-plane failure with SAs up -------------------------------
    # verify_ipsec passed, so IKE and CHILD are installed. A connectivity
    # failure here is only called a TS mismatch when the installed selectors
    # provably exclude the probed destination.
    if connectivity is not None and ike_state == IKE_ESTABLISHED \
            and child_state == CHILD_INSTALLED:
        verdict, detail = _classify_data_plane(
            (ike_evidence or {}).get("child_selectors", []),
            probe_target,
        )
        if verdict is TRAFFIC_SELECTOR_MISMATCH:
            evidence["child_selectors"] = list(
                (ike_evidence or {}).get("child_selectors", [])
            )
            evidence["probe_target"] = probe_target
            evidence["packet_loss"] = connectivity.get("packet_loss")
            return _result(
                TRAFFIC_SELECTOR_MISMATCH,
                DETERMINISTIC,
                "Traffic-selector mismatch: the IKE_SA is established and the "
                "CHILD_SA is installed, but the installed selector "
                f"{detail} does not cover the probed destination, so the "
                "data plane carries no traffic.",
                evidence,
                stage,
            )
        return _unknown(
            stage,
            "IPsec SAs are established but data-plane traffic failed "
            f"({detail}). The installed selectors are not shown to exclude the "
            "destination, so the evidence does not support a specific "
            "traffic-selector diagnosis.",
            evidence,
        )

    # -- 7. IKE up, CHILD down, no proposal notification ------------------
    if ike_state == IKE_ESTABLISHED and child_state != CHILD_INSTALLED:
        return _unknown(
            "IPSEC",
            "The IKE_SA is established but no CHILD_SA is installed, and no "
            "CHILD_SA negotiation notification was captured to explain why. "
            "Sentinel does not guess a proposal mismatch without the "
            "notification that proves it.",
            evidence,
        )

    # -- 8. Nothing specific --------------------------------------------
    return _unknown(
        stage,
        "No specific strongSwan notification (AUTH_FAILED, "
        "NO_PROPOSAL_CHOSEN, TS_UNACCEPTABLE) was captured for this failure. "
        f"Observed IKE_SA state: {ike_state}, CHILD_SA state: {child_state}. "
        "Sentinel reports insufficient evidence rather than a guessed root "
        "cause.",
        evidence,
    )


def _classify_data_plane(child_selectors, probe_target):
    """Decide whether installed selectors provably exclude ``probe_target``.

    Returns ``(verdict, detail)``. ``verdict`` is only
    ``TRAFFIC_SELECTOR_MISMATCH`` when the exclusion is proven from the logged
    selectors; otherwise the verdict is ``None`` and the detail explains what
    was actually observed.
    """
    if not child_selectors:
        return None, "no installed CHILD_SA selectors were captured"

    if not probe_target:
        return None, "no probed destination was available to test against"

    excluded = []
    for selector in child_selectors:
        local_part = selector.split("===")[0].strip()
        try:
            network = ipaddress.ip_network(local_part, strict=False)
        except ValueError:
            return None, (
                f"installed selector {local_part!r} is not a parsable network"
            )
        try:
            address = ipaddress.ip_address(probe_target)
        except ValueError:
            return None, f"probe target {probe_target!r} is not a parsable address"
        if address not in network:
            excluded.append(local_part)

    if excluded:
        return (
            TRAFFIC_SELECTOR_MISMATCH,
            f"{', '.join(sorted(set(excluded)))}",
        )
    return None, (
        f"installed selectors ({'; '.join(child_selectors)}) do cover the "
        f"probed destination {probe_target}"
    )