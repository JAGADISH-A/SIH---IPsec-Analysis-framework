"""Output guardrails for generated explanations.

The prompt tells the model what not to do. This module is what makes that
binding. A prompt is advice; a guard is a gate, and the whole value of this
feature is that the explanation can be trusted to have been through a gate.

What the guard rejects
----------------------
``decision_language``
    The assistant stating or implying a security decision: reclassifying,
    rescoring, or instructing the analyst to change something. A generated
    explanation that recommends an action is the worst failure this feature can
    have, because the analyst has no way to tell it apart from the engine's own
    output.
``invented_severity``
    A severity word that no recorded severity in the context supports. This is
    how "I think this should be HIGH" is caught however politely it is phrased.
``invented_score``
    A risk score the engine did not produce.
``invented_identifier``
    Any finding id, rule id, evidence id, assessment id, SPI or dataset run id
    the context does not contain. Fabricated evidence references are the failure
    mode the no-hallucination rule exists to prevent.
``invented_algorithm``
    A specific cipher, hash or DH group named as the value of a configuration
    field the backend did not record. The check is per sentence, so an answer
    that correctly discusses a *different*, recorded field is unaffected.
``invented_confidence``
    A confidence figure the backend did not produce, or a confidence attributed
    to the assistant. ML confidence is backend data rendered in its own block;
    the assistant has no confidence of its own and may not imply that it does.

What happens on violation
-------------------------
The text is not repaired and not quietly passed through. A guarded response
replaces it with a deterministic explanation built from recorded values and
reports what fired. Silent repair would be worse than refusal: the analyst
would read a confident answer with no way to know the first one was wrong.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Pattern, Sequence, Set, Tuple, Union

from .models import (
    GUARD_CLEAN,
    GUARD_SUBSTITUTED,
    GuardReport,
    GroundingContext,
    ScopeDecision,
)

VIOLATION_DECISION = "decision_language"
VIOLATION_DISMISSAL = "dismissed_finding"
VIOLATION_SEVERITY = "invented_severity"
VIOLATION_SCORE = "invented_score"
VIOLATION_IDENTIFIER = "invented_identifier"
VIOLATION_ALGORITHM = "invented_algorithm"
VIOLATION_CONFIDENCE = "invented_confidence"

#: Reported in this order so a client rendering the first violation shows the
#: most serious one.
VIOLATION_ORDER: Tuple[str, ...] = (
    VIOLATION_DECISION,
    VIOLATION_DISMISSAL,
    VIOLATION_SEVERITY,
    VIOLATION_SCORE,
    VIOLATION_IDENTIFIER,
    VIOLATION_ALGORITHM,
    VIOLATION_CONFIDENCE,
)

SEVERITY_WORDS: Tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

#: Algorithm-shaped tokens the guard treats as a value assertion rather than as
#: prose. A token outside this set is treated as ordinary English, so words
#: like "none" in "none of these" cannot trip the check.
#:
#: The bare protocol names ``esp``, ``ah`` and ``pfs`` are deliberately absent.
#: They are nouns, not values: a sentence that says "the backend did not record
#: an ESP encryption value" names the protocol and asserts nothing about it, and
#: treating that as a fabricated algorithm would withhold a correct and
#: deliberately honest answer. An assertion about an ESP algorithm names a
#: cipher (``aes256``, ``3des``) or a mode, both of which are listed.
ALGORITHM_TOKENS = frozenset(
    {
        "aes", "aes128", "aes192", "aes256", "aes-cbc", "aes-gcm", "aes-ctr",
        "aes128gcm", "aes192gcm", "aes256gcm", "aes128ctr", "aes192ctr", "aes256ctr",
        "aes128cbc", "aes192cbc", "aes256cbc", "3des", "des", "camellia128",
        "camellia256", "blowfish", "serpent", "twofish", "arcfour", "rc4",
        "chacha20", "chacha20poly1305", "poly1305", "cbc", "gcm", "ctr", "ccm",
        "sha1", "sha256", "sha384", "sha512", "sha-1", "sha-256", "sha-384", "sha-512",
        "sm3", "blake2s", "blake2b",
        "hmac-sha1", "hmac sha1", "hmac-sha256", "hmac sha256", "hmac-sha384",
        "hmac sha384", "hmac-sha512", "hmac sha512",
        "modp1024", "modp1536", "modp2048", "modp3072", "modp4096", "modp8192",
        "modp20", "modp14", "modp15", "modp16", "modp17", "modp18", "modp19",
        "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192",
        "x25519", "x448", "curve25519", "curve448",
        "ikev1", "ikev2", "ipv4", "ipv6", "tunnel", "transport",
        "disabled", "enabled", "required", "optional",
    }
)

#: Configuration fields whose recorded value is a named algorithm, group or
#: flag, with the phrasings an analyst uses for them. When the context records
#: none of these, a generated sentence about that field must not name an
#: algorithm.
ALGORITHM_FIELDS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("esp_encryption", ("esp encryption", "esp.encryption", "esp encrypt")),
    ("esp_integrity", ("esp integrity", "esp.integrity")),
    ("esp_dh_group", ("esp dh group", "esp.dh_group", "esp dh", "esp pfs group")),
    ("esp_pfs", ("esp pfs", "esp.pfs", "perfect forward secrecy", " pfs")),
    ("ike_encryption", ("ike encryption", "ike.encryption", "ike encrypt")),
    ("ike_integrity", ("ike integrity", "ike.integrity")),
    ("ike_dh_group", ("ike dh group", "ike.dh_group", "ike dh")),
    ("ike_version", ("ike version", "ike.version")),
    ("address_family", ("address family", "address_family")),
    ("mode", (" ipsec mode", "tunnel mode", "transport mode")),
)

_ALGORITHM_VALUE = re.compile(
    r"\b(?:aes[\w-]*|3des|des|camellia[\w-]*|blowfish|serpent|twofish|arcfour|rc4|"
    r"chacha[\w-]*|poly1305|"
    r"modp\d+|ffdhe\d+|x25519|x448|curve25519|curve448|"
    r"sha-?\d+|sm3|blake2s|blake2b|"
    r"hmac(?:[\s-])?sha-?\d+|"
    r"ikev[12]|ah|esp|pfs|ipv[46]|tunnel|transport|"
    r"none|disabled|enabled|required|optional)\b",
    re.IGNORECASE,
)

#: ``(pattern, human label)`` pairs. The label is what the analyst is told, so
#: it names the failure rather than the regex.
_DECISION_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"\bi\s+(?:would\s+)?recommend\b", "the assistant recommending an action"),
    (r"\bwe\s+(?:should|recommend)\b", "the assistant recommending an action"),
    (r"\bmy\s+recommendation\b", "the assistant issuing a recommendation"),
    (r"\bi\s+think\s+this\s+should\b", "the assistant proposing a different severity"),
    (r"\b(?:this|it|the\s+finding)\s+should\s+be\s+(?:re)?(?:rated|classified|scored|"
     r"downgraded|upgraded|lowered|raised)\b", "the assistant proposing a severity change"),
    (r"\b(?:the\s+)?(?:correct|right|proper|appropriate)\s+(?:severity|score|rating|"
     r"classification)\s+is\b", "the assistant asserting the correct severity"),
    (r"\b(?:re)?(?:classify|reclassify|rate|rescore|re-score|downgrade|upgrade|"
     r"override|dismiss|waive|suppress)\s+(?:this|it|the\s+finding)\b",
     "the assistant proposing a risk decision"),
    (r"\b(?:set|change|adjust|raise|lower|increase|decrease)\s+the\s+"
     r"(?:severity|risk\s+score|score)\b", "the assistant changing a score"),
    (r"\byou\s+(?:should|must|need\s+to|ought\s+to)\s+\w+",
     "the assistant instructing the analyst to act"),
    (r"\bi\s+(?:will|can|would)\s+(?:apply|make|execute|run|change|modify|update|"
     r"reconfigure|restart|fix|remediate)\b", "the assistant claiming it can act"),
    (r"\b(?:go\s+ahead\s+and|feel\s+free\s+to)\s+\w+", "the assistant authorising an action"),
    (r"\b(?:turn|switch)\s+(?:on|off)\s+\w+", "the assistant instructing a config change"),
    (r"\b(?:enable|disable|remove|re-?enable)\s+(?:pfs|esp|ike|ah|nat-?t)\b",
     "the assistant instructing a config change"),
    (r"\b(?:re-?)?(?:configure|reboot|restart|reset)\s+(?:the|this|it)\s+"
     r"(?:gateway|testbed|swanctl|charon|connection|session|sa|tunnel|policy)\b",
     "the assistant instructing a change"),
    (r"\bneeds?\s+(?:a|an|to\s+be)\s+(?:reset|restart|reboot|fix|patch|repair|"
     r"remediation|attention)\b", "the assistant prescribing a remediation action"),
    (r"\b(?:apply|roll\s*out)\s+(?:the\s+)?(?:fix|patch|remediation|mitigation|"
     r"workaround)\b", "the assistant prescribing a remediation action"),
    (r"\b(?:mitigate|remediate|work\s+around)\s+(?:this|it|the\s+(?:finding|mismatch|"
     r"issue|problem|risk))\b", "the assistant prescribing a remediation action"),
    (r"\b(?:block|drop|allow|deny|blacklist|whitelist)\s+(?:this|that|all|every)\s+"
     r"[\w-]*\s*traffic\b", "the assistant prescribing a traffic change"),
    (r"\b(?:rotate|replace|renew)\s+(?:the\s+)?(?:key|keys|cert|certs|certificate|"
     r"certificates|secret|secrets)\b", "the assistant prescribing a key change"),
    (r"\bi\s+have\s+(?:changed|updated|applied|modified|fixed|disabled|enabled|"
     r"reconfigured)\b", "the assistant claiming to have changed something"),
    (r"\bthis\s+is\s+(?:not\s+)?a\s+(?:problem|vulnerability|risk|issue)\b",
     "the assistant making its own security judgement"),
    (r"\b(?:is|are)\s+safe\b", "the assistant making its own security judgement"),
    (r"\bvulnerable\b", "the assistant making its own security judgement"),
    (r"\bexploit(?:able|ed)\b", "the assistant making its own security judgement"),
    (r"\baccept\s+the\s+risk\b", "the assistant accepting risk on the analyst's behalf"),
)

#: Phrases that write off a finding the backend actually recorded. These are
#: kept apart from the general decision patterns because they are a distinct
#: failure: the assistant is not proposing a change, it is asserting that a
#: recorded finding is not a finding. The analyst is the one who may conclude
#: that, against evidence the assistant has not read.
_DISMISSAL_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"\bfalse\s+positives?\b", "the assistant dismissing a recorded finding as a false positive"),
    (r"\b(?:can|may|could|safe\s+to|ok\s+to|okay\s+to)\s+(?:be\s+)?"
     r"(?:ignore[d]?|dismiss(?:ed)?|accept(?:ed)?|skip(?:ped)?)\b",
     "the assistant dismissing a recorded finding"),
    (r"\bignore\s+(?:this|it|the|that)\b", "the assistant dismissing a recorded finding"),
    (r"\bno\s+action\s+(?:is\s+)?(?:required|needed|necessary)\b",
     "the assistant closing a recorded finding"),
    (r"\bnot\s+a\s+real\s+(?:issue|risk|problem|threat)\b",
     "the assistant dismissing a recorded finding"),
    (r"\b(?:benign|harmless|non-?issue|informational\s+only)\b",
     "the assistant dismissing a recorded finding"),
    (r"\b(?:expected|normal)\s+(?:behaviou?r|configuration|traffic)\b",
     "the assistant normalising a recorded mismatch"),
    (r"\bworking\s+as\s+intended\b", "the assistant normalising a recorded mismatch"),
    (r"\bby\s+design\b", "the assistant normalising a recorded mismatch"),
    (r"\bdoes\s*n[o']?t\s+need\s+(?:fixing|attention|action)\b",
     "the assistant closing a recorded finding"),
    (r"\bclear\s+(?:this|the)\s+finding\b", "the assistant closing a recorded finding"),
)

_CONFIDENCE_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"\b(?:my|our|assistant|ai)\s+confidence\b", "the assistant claiming its own confidence"),
    (r"\bi\s+am\s+\d+(?:\.\d+)?\s*(?:%|percent)\s+confident\b",
     "the assistant claiming its own confidence"),
    (r"\bconfidence\s+(?:of|=|:)\s*\d+(?:\.\d+)?\s*(?:%|percent)?\b",
     "an unsourced confidence figure"),
    (r"\b\d+(?:\.\d+)?\s*(?:%|percent)\s+(?:certain|confident)\b",
     "an unsourced confidence figure"),
)

_ID_PATTERNS: Tuple[Pattern, ...] = (
    re.compile(r"\bRISK-[A-Z0-9][A-Z0-9-]*\b"),
    re.compile(r"\b[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,}\b"),
    re.compile(r"\bev-[A-Za-z0-9_-]{2,}\b"),
    re.compile(r"\bdataset-\d{6,8}-\d{4,8}\b"),
    re.compile(r"\b0x[0-9a-fA-F]{4,16}\b"),
    re.compile(r"\b\d{1,6}:\d{1,6}:[A-Za-z0-9_.-]+\b"),
)

_SCORE_PATTERNS: Tuple[Pattern, ...] = (
    re.compile(
        r"\b(?:risk\s+)?score\b\s*(?:is|was|are|were|of|equals?|=|:|at|to)?\s*(\d{1,4})\b",
        re.IGNORECASE,
    ),
    re.compile(r"\brisk\b[^.!?\n]{0,20}?\b(\d{1,4})\b", re.IGNORECASE),
    re.compile(r"\bseverity\b[^.!?\n]{0,20}?\b(\d{1,4})\b", re.IGNORECASE),
    re.compile(r"\bcontribut(?:es|ed|ing)\s+(\d{1,4})\b", re.IGNORECASE),
    re.compile(r"\b(\d{1,4})\s+points?\b", re.IGNORECASE),
    re.compile(r"\bweight(?:ed)?\s+(\d{1,4})\b", re.IGNORECASE),
)

_SENTENCE = re.compile(r"[^.!?\n]+[.!?]?")
_SEVERITY_RE = re.compile(r"\b(" + "|".join(SEVERITY_WORDS) + r")\b", re.IGNORECASE)

#: A bare 8-hex-digit token is also a plausible SPI, but is far too weak a
#: signal to act on alone (a digest fragment, a timestamp, a word hash). It is
#: therefore never reported as an invented identifier; the SPI check relies on
#: the ``0x`` form and on the recorded value list.
_HEX8 = re.compile(r"\b[0-9a-fA-F]{8}\b")

_Labelled = Union[Tuple[str, str], Pattern]


def _label_hits(text: str, patterns: Sequence[_Labelled]) -> List[str]:
    """Human labels for every labelled pattern present in ``text``."""
    hits: List[str] = []
    for item in patterns:
        if isinstance(item, tuple):
            pattern, label = item
            if re.search(pattern, text, re.IGNORECASE):
                hits.append(label)
        else:
            if item.search(text):
                hits.append(item.pattern)
    return hits


def _normalise_token(token: str) -> str:
    """Fold an algorithm-shaped token to a comparable form.

    Ciphers are written many ways for the same algorithm -- ``AES-256-GCM``,
    ``aes_256_gcm``, ``aes-256``, ``AES 256 GCM`` -- and a model will pick one
    of them. Comparing the raw token against a set of canonical spellings
    would let an assertion through by formatting alone, which is the same defect
    as having no check at all.
    """
    return re.sub(r"[^a-z0-9]", "", str(token).lower())


#: ``ALGORITHM_TOKENS`` folded to the same form, so a variant spelling of a
#: known algorithm is still recognised as algorithm-shaped.
_NORMALISED_TOKENS = frozenset(
    _normalise_token(token) for token in ALGORITHM_TOKENS
)


def _sentences(text: str) -> List[str]:
    return [part.strip() for part in _SENTENCE.findall(text or "") if part.strip()]


class Guard:
    """Checks generated prose against one question's recorded context.

    Constructed per question because the whitelist is derived from that
    question's context. Holds no state between checks.
    """

    def __init__(self, context: GroundingContext) -> None:
        self._context = context
        self._allowed = context.identifiers()
        self._allowed_lower = {value.lower() for value in self._allowed}
        self._severities = self._recorded_severities(context)
        self._scores = self._recorded_scores(context)

    def check(self, text: str) -> GuardReport:
        """Every violation in ``text``, de-duplicated and ordered. Empty means clean."""
        body = str(text or "")
        if not body.strip():
            return GuardReport(status=GUARD_CLEAN, detail="empty answer")

        detail: List[str] = []
        found: Set[str] = set()

        for label in _label_hits(body, _DECISION_PATTERNS):
            found.add(VIOLATION_DECISION)
            detail.append(f"decision language: {label}")
        for label in _label_hits(body, _DISMISSAL_PATTERNS):
            found.add(VIOLATION_DISMISSAL)
            detail.append(f"finding dismissal: {label}")
        for label in _label_hits(body, _CONFIDENCE_PATTERNS):
            found.add(VIOLATION_CONFIDENCE)
            detail.append(f"confidence: {label}")

        bad_severity = self._bad_severity(body)
        if bad_severity:
            found.add(VIOLATION_SEVERITY)
            detail.append(
                "severity " + ", ".join(sorted(bad_severity)) + " is not a severity that "
                "any recorded finding or assessment in this context carries"
            )

        bad_score = self._bad_score(body)
        if bad_score:
            found.add(VIOLATION_SCORE)
            detail.append(
                "risk score " + ", ".join(str(value) for value in sorted(bad_score))
                + " is not a score the backend produced for this context"
            )

        bad_ids = self._bad_identifiers(body)
        if bad_ids:
            found.add(VIOLATION_IDENTIFIER)
            detail.append(
                "identifier " + ", ".join(sorted(bad_ids)) + " does not appear in the "
                "recorded context, so it must not be cited"
            )

        bad_algorithm = self._bad_algorithm(body)
        if bad_algorithm:
            found.add(VIOLATION_ALGORITHM)
            detail.append(
                "algorithm " + ", ".join(sorted(bad_algorithm))
                + " is named for a configuration field the backend did not record"
            )

        if not found:
            return GuardReport(status=GUARD_CLEAN)
        ordered = tuple(name for name in VIOLATION_ORDER if name in found)
        return GuardReport(
            status=GUARD_SUBSTITUTED,
            violations=ordered,
            detail="; ".join(detail),
        )

    @staticmethod
    def _recorded_severities(context: GroundingContext) -> frozenset:
        found = {value.upper() for value in (context.severity,) if value}
        if context.finding is not None and context.finding.severity:
            found.add(context.finding.severity.upper())
        for summary in context.finding_summaries:
            head = str(summary).split(" ", 1)[0].upper()
            if head in SEVERITY_WORDS:
                found.add(head)
        return frozenset(found)

    @staticmethod
    def _recorded_scores(context: GroundingContext) -> frozenset:
        found = set()
        if context.risk_score is not None:
            found.add(int(context.risk_score))
        if context.finding is not None:
            for value in (context.finding.score_contribution, context.finding.rule_weight):
                if value is not None:
                    found.add(int(value))
        return frozenset(found)

    def _bad_severity(self, body: str) -> Set[str]:
        if not self._severities:
            return set()
        return {
            word.upper()
            for word in _SEVERITY_RE.findall(body)
            if word.upper() not in self._severities
        }

    def _bad_score(self, body: str) -> Set[int]:
        if not self._scores:
            return set()
        found = set()
        for pattern in _SCORE_PATTERNS:
            for match in pattern.finditer(body):
                try:
                    value = int(match.group(1))
                except (TypeError, ValueError):
                    continue
                if value not in self._scores:
                    found.add(value)
        return found

    def _bad_identifiers(self, body: str) -> Set[str]:
        found = set()
        for pattern in _ID_PATTERNS:
            for match in pattern.finditer(body):
                token = match.group(0).strip().strip("`\"'")
                if not token or self._is_known(token):
                    continue
                found.add(token)
        return found

    def _is_known(self, token: str) -> bool:
        if token in self._allowed or token.lower() in self._allowed_lower:
            return True
        return bool(_HEX8.fullmatch(token))

    def _bad_algorithm(self, body: str) -> Set[str]:
        found = set()
        for sentence in _sentences(body):
            names = self._fields_named(sentence)
            if not names:
                continue
            for token in _ALGORITHM_VALUE.findall(sentence):
                if _normalise_token(token) not in _NORMALISED_TOKENS:
                    continue
                if self._token_matches_recorded(names, _normalise_token(token)):
                    continue
                found.add(token)
        return found

    def _fields_named(self, sentence: str) -> Set[str]:
        lowered = sentence.lower()
        return {
            key
            for key, phrases in ALGORITHM_FIELDS
            if any(phrase in lowered for phrase in phrases)
        }

    def _token_matches_recorded(self, names: Set[str], lowered_token: str) -> bool:
        """Whether any field the sentence names has this token as its value.

        A token is accepted if it matches the recorded value of any named
        field. A false accept costs a sentence of prose; a false reject costs a
        correct explanation, so the check errs towards accepting.
        """
        for key in names:
            for value in self._recorded_values(key):
                if _normalise_token(str(value)) == _normalise_token(lowered_token):
                    return True
        return False

    def _recorded_values(self, key: str) -> Tuple[Any, ...]:
        """Every value the context records for one field.

        A field's value is not always in the same place. The expected and
        observed mappings hold the declaration intent; a field that only the
        comparison engine judged, such as ``address_family``, appears solely on
        the comparison rows and on the finding. Reading only the mapping would
        report the backend's own recorded value as an invented one, which is
        the one thing this guard must never do.
        """
        values: List[Any] = []
        for mapping in (self._context.expected, self._context.observed):
            if key in mapping:
                values.append(mapping[key])
        for comparison in self._context.comparisons:
            if comparison.variable == key:
                values.extend((comparison.expected_value, comparison.observed_value))
        finding = self._context.finding
        if finding is not None and (finding.related_variable == key or key == "address_family"):
            values.extend((finding.expected_value, finding.observed_value))
        return tuple(value for value in values if value is not None)


def enforce(
    text: str,
    context: GroundingContext,
    scope: ScopeDecision,
    *,
    fallback: str,
) -> Tuple[str, GuardReport]:
    """Gate generated prose, substituting ``fallback`` when anything fired.

    ``fallback`` must itself be grounded: it is shown to the analyst as the
    answer, so it is built from recorded values only.
    """
    report = Guard(context).check(text)
    if report.clean:
        return text, report
    return fallback, report


def guard_report_dict(report: GuardReport) -> Dict[str, object]:
    return {
        "status": report.status,
        "violations": list(report.violations),
        "detail": report.detail,
        "clean": report.clean,
    }
