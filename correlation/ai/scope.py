"""The domain boundary: what this assistant will answer, and what it will not.

The boundary is enforced here, in code, *before* any model is called. That is
the whole point. An out-of-scope refusal must not be something a language
model produces, because a language model asked an out-of-scope question is
exactly the component that might comply. So the classifier is deterministic
vocabulary matching, and an out-of-scope question never reaches a prompt.

What counts as in scope
-----------------------
IPsec, IKE, ESP, AH, PFS, DH groups, IKE/ESP proposals, encryption, integrity,
authentication, tunnel and transport mode, IPv4/IPv6 and address family,
traffic selectors, SPI, sequence numbers, Security Associations, rekeying,
plus the products of this system: security findings, risk explanations,
expected-versus-observed comparisons, evidence, drift, chain of custody, and
ML traffic classification.

A question is also in scope when it points at the *selected context* even
without IPsec vocabulary -- "why is this MEDIUM?", "what happened here?" -- but
only because an assessment is actually selected. The same words with no
assessment selected are answered as a general explanation or refused, and the
refusal says the assessment is not attached.

Authority boundary
------------------
:class:`ScopeDecision` can only classify. It carries no severity, no score and
no finding, and it is computed from the question text plus the presence of
recorded context -- never from the content of an answer.
"""

from __future__ import annotations

import re
from typing import Sequence, Tuple

from .models import (
    INTENT_DECISION_REQUEST,
    INTENT_EVIDENCE,
    INTENT_EXPECTED_VS_OBSERVED,
    INTENT_GENERAL,
    INTENT_RISK,
    INTENT_TERMINOLOGY,
    OUT_OF_SCOPE_ANSWER,
    SCOPE_IN,
    SCOPE_OUT,
    MAX_QUESTION_CHARS,
    ScopeDecision,
)

#: IPsec and system vocabulary. Matched case-insensitively on word boundaries
#: where the term is a bare token, and as substrings where the term contains a
#: hyphen or a dot.
IPSEC_TERMS: Tuple[str, ...] = (
    "ipsec", "ike", "ikev1", "ikev2", "esp", "ah", "pfs", "perfect forward secrecy",
    "dh", "diffie-hellman", "modp", "ffdhe", "group14", "group19", "group20",
    "group21", "x25519", "curve25519", "swanctl", "strongswan", "charon",
    "sa", "security association", "spi", "sa pair",
    "proposal", "transform", "cipher", "aes", "aes-cbc", "aes-gcm", "3des",
    "des", "chacha", "poly1305", "hmac", "sha1", "sha256", "sha384", "sha512",
    "prf", "integrity", "encryption", "encrypt", "decrypt",
    "tunnel mode", "transport mode", "tunnel", "transport",
    "ipv4", "ipv6", "address family", "traffic selector", "selector",
    "sequence number", "rekey", "rekeying", "nat-t", "natt", "ike sa", "esp sa",
    "gateway", "endpoint", "auth method", "psk", "certificate", "pki",
    "attack", "attacker", "vulnerability", "vpn", "firewall",
)

#: Vocabulary of this product's own output. Present so an analyst can ask about
#: the assessment in the language the assessment uses.
SYSTEM_TERMS: Tuple[str, ...] = (
    "finding", "findings", "severity", "risk score", "risk", "score",
    "assessment", "evidence", "artifact", "chain of custody", "custody",
    "provenance", "drift", "baseline", "policy", "rule", "expected",
    "observed", "comparison", "compare", "unassessed", "configuration",
    "config", "classif", "ml", "model", "confidence", "anomaly", "traffic profile",
    "packet", "capture", "traffic", "analyst", "investigation", "pcap",
)

_TERMINOLOGY_TERMS: Tuple[str, ...] = (
    "what does", "what is", "what are", "explain", "meaning of", "means",
    "define", "difference between", "how does", "why is", "why does",
)

_RISK_TERMS: Tuple[str, ...] = (
    "why is this", "why so", "severity", "risk score", "how risky", "why medium",
    "why high", "why low", "why critical", "why info", "scored", "score of",
    "contribut", "rated", "classified as", "why did it", "justify",
)

_EXPECTED_OBSERVED_TERMS: Tuple[str, ...] = (
    "expected vs observed", "expected versus observed", "expected and observed",
    "what was expected", "what was observed", "difference between expected",
    "mismatch", "does not match", "doesn't match", "compare the", "compared to",
    "why did this configuration fail", "why did the configuration fail",
    "why did it fail", "what changed",
)

_EVIDENCE_TERMS: Tuple[str, ...] = (
    "evidence", "artifact", "pcap", "proof", "prove", "chain of custody",
    "custody", "provenance", "digest", "integrity", "where did this come from",
    "how do we know", "what supports",
)

#: A question that asks for a decision or an action. These are answered -- the
#: recorded finding and configuration are explained -- but the answer carries
#: an explicit non-decision statement and the guard rejects any imperative.
_DECISION_TERMS: Tuple[str, ...] = (
    "should i", "should we", "do i need to", "do we need to", "can i",
    "recommend", "advise", "is it safe to", "go ahead and", "fix it",
    "reconfigure", "re-configure", "change the configuration", "change the gateway",
    "update the gateway", "patch it", "turn on pfs", "enable pfs", "disable",
    "remediate", "mitigate it", "what would you do", "what should",
    "is this a problem", "can we ignore", "dismiss", "accept the risk",
    "downgrade", "upgrade the severity", "re-score", "rescore", "override",
)

#: Topics that are unambiguously outside the assessment domain even when the
#: sentence also contains a stray IPsec word ("and also tell me the weather").
_OFF_TOPIC: Tuple[str, ...] = (
    "weather", "forecast", "stock", "invest", "cryptocurrency", "bitcoin",
    "president", "election", "poem", "marketing plan", "python assignment",
    "homework", "recipe", "joke", "lyrics", "movie", "football",
    "write me a", "generate code", "hack into", "how do i hack",
    "my resume", "cover letter", "date ideas",
)

_WORD_SPLIT = re.compile(r"[^a-z0-9./+-]+")


def _normalise(question: str) -> str:
    return " ".join(_WORD_SPLIT.sub(" ", str(question or "").lower()).split())


def _find_terms(haystack: str, terms: Sequence[str]) -> Tuple[str, ...]:
    """Terms present in ``haystack``, in declaration order, de-duplicated.

    Multi-word terms are matched as substrings because collapsing punctuation
    already guarantees single spaces between words. Single-token terms are
    matched on token boundaries so ``sa`` does not fire on ``saturday`` and
    ``ah`` does not fire on ``ahead``.
    """
    hits = []
    for term in terms:
        needle = _normalise(term)
        if not needle:
            continue
        if " " in needle or "-" in needle or "/" in needle or "." in needle:
            if needle in haystack:
                hits.append(term)
            continue
        if re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", haystack):
            hits.append(term)
    return tuple(hits)


def classify(
    question: str,
    *,
    has_context: bool = False,
    has_finding: bool = False,
) -> ScopeDecision:
    """Decide whether this question is answerable here, and under which intent.

    ``has_context`` is "an assessment is selected and resolved"; ``has_finding``
    is "a specific finding within it is selected". Both are supplied by the
    caller from recorded state, never inferred from the question.
    """
    raw = str(question or "")
    if not raw.strip():
        return ScopeDecision(
            in_scope=False,
            intent=SCOPE_OUT,
            reason="the question is empty",
        )
    if len(raw) > MAX_QUESTION_CHARS:
        return ScopeDecision(
            in_scope=False,
            intent=SCOPE_OUT,
            reason=(
                f"the question is longer than {MAX_QUESTION_CHARS} characters, which is "
                "longer than a question can be useful at; the recorded context is "
                "unchanged and the assistant will not summarize an arbitrary paste"
            ),
        )

    text = _normalise(raw)
    ipsec_hits = _find_terms(text, IPSEC_TERMS)
    system_hits = _find_terms(text, SYSTEM_TERMS)
    off_topic = _find_terms(text, _OFF_TOPIC)
    decision_hits = _find_terms(text, _DECISION_TERMS)
    risk_hits = _find_terms(text, _RISK_TERMS)
    expected_hits = _find_terms(text, _EXPECTED_OBSERVED_TERMS)
    evidence_hits = _find_terms(text, _EVIDENCE_TERMS)
    terminology_hits = _find_terms(text, _TERMINOLOGY_TERMS)

    if off_topic and not ipsec_hits:
        return ScopeDecision(
            in_scope=False,
            intent=SCOPE_OUT,
            reason=(
                "the question is about a subject with no bearing on the IPsec "
                "assessment or its recorded evidence"
            ),
            matched_terms=off_topic,
        )

    # Scope is established by vocabulary or by a phrasing that only makes sense
    # about an assessment. A generic interrogative ("what is ...") deliberately
    # does not establish scope on its own, which is what keeps "what is the
    # weather" out even though "what is" matched. A decision verb is not
    # scope either: "recommend a restaurant" is a request for advice, not a
    # request for a verdict on an assessment, and answering it in scope would
    # put the assistant outside its declared domain.
    in_domain = bool(
        ipsec_hits
        or system_hits
        or risk_hits
        or expected_hits
        or evidence_hits
    )
    if not in_domain:
        return ScopeDecision(
            in_scope=False,
            intent=SCOPE_OUT,
            reason=(
                "the question does not reference IPsec, this assessment, or the "
                "evidence recorded for either"
            ),
            matched_terms=terminology_hits,
        )

    if decision_hits:
        return ScopeDecision(
            in_scope=True,
            intent=INTENT_DECISION_REQUEST,
            reason=(
                "the question asks for a decision or an action; the recorded "
                "finding and configuration are explained, and the decision is "
                "explicitly declined"
            ),
            matched_terms=decision_hits,
        )

    if risk_hits or ("why" in text and has_finding):
        return ScopeDecision(
            in_scope=True,
            intent=INTENT_RISK,
            reason="the question asks why the backend recorded this severity or score",
            matched_terms=risk_hits,
        )

    if expected_hits:
        return ScopeDecision(
            in_scope=True,
            intent=INTENT_EXPECTED_VS_OBSERVED,
            reason=(
                "the question asks for the expected-versus-observed comparison the "
                "comparison engine recorded"
            ),
            matched_terms=expected_hits,
        )

    if evidence_hits:
        return ScopeDecision(
            in_scope=True,
            intent=INTENT_EVIDENCE,
            reason=(
                "the question asks what evidence or provenance supports the recorded "
                "result"
            ),
            matched_terms=evidence_hits,
        )

    if terminology_hits and (ipsec_hits or not has_context):
        return ScopeDecision(
            in_scope=True,
            intent=INTENT_TERMINOLOGY,
            reason=(
                "the question asks what an IPsec term means, which is answerable "
                "from the protocol rather than from a specific assessment"
            ),
            matched_terms=terminology_hits,
        )

    if has_context:
        return ScopeDecision(
            in_scope=True,
            intent=INTENT_GENERAL,
            reason=(
                "the question references the selected IPsec assessment or its "
                "recorded findings"
            ),
            matched_terms=tuple(ipsec_hits or system_hits),
        )

    return ScopeDecision(
        in_scope=True,
        intent=INTENT_TERMINOLOGY,
        reason=(
            "the question references IPsec but no assessment is selected, so it is "
            "answered as a general IPsec explanation with no recorded values"
        ),
        matched_terms=tuple(ipsec_hits or system_hits),
    )


def out_of_scope_answer() -> str:
    """The one refusal text. A constant, so it cannot be generated or varied."""
    return OUT_OF_SCOPE_ANSWER
