"""IPsec terminology, answered deterministically.

These entries are prose written here, not generated. That is deliberate: the
acceptance criterion "What does PFS mean?" must produce the same correct answer
on every deployment, with or without a model configured, and a definition is
exactly the kind of fact a model will paraphrase into something subtly wrong
under pressure.

The entries are also the vocabulary the scope classifier uses to recognise a
terminology question, so adding a term here makes it both answerable and
recognisable.

None of these entries is security advice. They describe what a protocol term
means and, where a term is weaker, what that means in the abstract. They never
say what an analyst should do, because that is a decision and this is an
explanatory layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from .models import JsonModel


@dataclass(frozen=True)
class GlossaryEntry(JsonModel):
    """One protocol term, its definition, and what it means for a recorded field."""

    key: str
    term: str
    definition: str
    relevance: str


def _e(key: str, term: str, definition: str, relevance: str) -> GlossaryEntry:
    return GlossaryEntry(key=key, term=term, definition=definition, relevance=relevance)


ENTRIES: Tuple[GlossaryEntry, ...] = (
    _e(
        "ike",
        "IKE (Internet Key Exchange)",
        "IKE is the negotiation protocol that sets up IPsec. The two endpoints "
        "authenticate each other, agree on which algorithms to use, and exchange "
        "keys over an untrusted network. It is not itself a protection for your "
        "data; it produces the keys and the negotiated parameters that the data "
        "protection then uses.",
        "A recorded IKE proposal covers IKE encryption, IKE integrity, the DH group "
        "used for key exchange, and the authentication method. IKE parameters are "
        "separate from ESP parameters and a finding can name either.",
    ),
    _e(
        "esp",
        "ESP (Encapsulating Security Payload)",
        "ESP is the protocol that actually protects the data. It encrypts the IP "
        "payload, adds an integrity check so tampering is detected, and carries "
        "sequence numbers so replayed packets can be rejected. ESP is what the "
        "data path runs on once IKE has finished negotiating.",
        "An ESP finding names ESP encryption, ESP integrity, the ESP DH/PFS group, "
        "or the observed presence of ESP traffic. ESP and IKE weaknesses are "
        "recorded as separate findings because they are separately configurable.",
    ),
    _e(
        "ah",
        "AH (Authentication Header)",
        "AH provides integrity and authentication for a packet but no encryption. "
        "It exists for cases where confidentiality is not required but tamper "
        "evidence is. It also does not work through NAT, because NAT rewrites the "
        "addresses AH authenticates.",
        "If a recorded finding concerns AH instead of ESP, the packet is protected "
        "but not encrypted, which is a different property from being encrypted "
        "with a weak algorithm.",
    ),
    _e(
        "pfs",
        "PFS (Perfect Forward Secrecy)",
        "PFS means that a new Diffie-Hellman exchange happens when a Security "
        "Association is rekeyed, rather than the session keys being derived again "
        "from the original key exchange. Its purpose is that if the long-term "
        "authentication key is later compromised, previously recorded traffic "
        "cannot be decrypted. PFS is a property of the rekey behaviour, not of the "
        "encryption algorithm.",
        "The recorded fields are the ESP DH group and the PFS flag. PFS can be "
        "switched off entirely, or enabled with a weak group, and those are "
        "different recorded conditions with different rule ids.",
    ),
    _e(
        "dh_group",
        "DH group (Diffie-Hellman group)",
        "A DH group is a named set of parameters for the key exchange. The group "
        "determines the size of the shared secret and therefore how hard it is to "
        "break from recorded traffic. The named groups differ by more than name: "
        "modp2048 and modp4096 are different mathematical problems with different "
        "resistance.",
        "A finding that names a DH group is comparing the observed group against a "
        "recorded expectation for that same field. The assistant can restate both "
        "recorded values; whether the pair is acceptable is the policy's call.",
    ),
    _e(
        "modp2048",
        "modp2048",
        "modp2048 is the 2048-bit MODP Diffie-Hellman group. It was the long-time "
        "IETF default and is still widely deployed, but 2048 bits is no longer "
        "considered sufficient for long-lived confidentiality by most current "
        "policies. It is a real, working group, not a broken one.",
        "When a recorded finding says a DH group is weak, the comparison is against "
        "the expected group for that field. A modp2048 observation is a recorded "
        "fact, not a diagnosis.",
    ),
    _e(
        "modp3072",
        "modp3072",
        "modp3072 is the 3072-bit MODP group. It is larger than modp2048 and is "
        "accepted by policies that no longer accept 2048-bit groups, at a higher "
        "cost in handshake time and CPU.",
        "A finding that contrasts an observed group with modp3072 is comparing two "
        "recorded values for one field.",
    ),
    _e(
        "modp4096",
        "modp4096",
        "modp4096 is the 4096-bit MODP group. It is the strongest of the commonly "
        "deployed MODP groups and is what many current policies require. Handshake "
        "cost is higher still, which is the trade-off the group size represents.",
        "When modp4096 appears as the expected value in a finding, it is the "
        "recorded requirement, not an opinion expressed by the assistant.",
    ),
    _e(
        "ike_esp_encryption",
        "IKE / ESP encryption",
        "The encryption algorithm determines confidentiality of the protected data "
        "and the cost of producing it. Modern policy generally requires an "
        "authenticated-encryption mode such as AES-GCM, and restricts the older "
        "cipher-block modes that provide confidentiality without an authentication "
        "tag of their own.",
        "A recorded finding about encryption names the observed algorithm and the "
        "expected algorithm for the same field. The assistant reports both; it does "
        "not decide which is acceptable.",
    ),
    _e(
        "integrity",
        "Integrity algorithm",
        "The integrity algorithm authenticates a packet so that any modification in "
        "transit is detected by the receiver. Without it, an attacker on the path "
        "can alter protected packets and the receiver will not know.",
        "Integrity is configured separately for IKE and for ESP. A finding that "
        "names one of them is about that field only.",
    ),
    _e(
        "tunnel_mode",
        "Tunnel mode",
        "In tunnel mode the entire original IP packet is encapsulated inside a new "
        "outer IP header. The original addresses are hidden from the network in "
        "between, which is the normal mode for site-to-site gateways. It also "
        "carries TCP/UDP inside ESP, so it is required for NAT traversal.",
        "Mode is a recorded expected/observed field. A mismatch in mode is a "
        "recorded configuration difference, not a symptom the assistant diagnoses.",
    ),
    _e(
        "transport_mode",
        "Transport mode",
        "In transport mode only the payload of the IP packet is protected and the "
        "original addresses are left in the clear, so a router on the path can see "
        "the endpoints. It is normally used between hosts rather than between "
        "gateways, and it does not carry TCP/UDP for NAT traversal.",
        "Transport mode is a valid configuration in the right place. Its presence "
        "in a recorded finding means the recorded expectation for that assessment "
        "was something else.",
    ),
    _e(
        "address_family",
        "Address family (IPv4 / IPv6)",
        "The address family is the IP version the SA protects. IPv4 and IPv6 are "
        "separate Security Associations with separate SPIs; protecting one says "
        "nothing about the other. A v4 tunnel carries no v6 traffic, and an "
        "observed IPv6 session with only IPv4 configuration configured is a real "
        "gap rather than a display artifact.",
        "An address-family finding compares the observed family against the "
        "configured family. A match means the recorded values are equal, nothing "
        "more.",
    ),
    _e(
        "spi",
        "SPI (Security Parameters Index)",
        "An SPI is a 32-bit number that identifies one direction of one Security "
        "Association. Each packet carries the SPI of the SA that protects it, which "
        "is how the receiving gateway knows which keys and which policy to use. It "
        "is an identifier, not a secret, and it is not unique across peers.",
        "The observed SPI is how a recorded assessment is joined to a packet. When "
        "a packet has no matching assessment it is shown as UNASSESSED, which "
        "means no recorded assessment observed that SPI, not that the packet was "
        "judged safe.",
    ),
    _e(
        "sequence_number",
        "Sequence number / replay",
        "Each protected packet carries a sequence number from a counter that "
        "increases across the SA. A receiver rejects a packet whose number it has "
        "already seen, which is what makes replay protection work. Gaps in the "
        "counter are normal and are caused by loss, not by an attack.",
        "A recorded sequence delta is an observed counter value. It says what the "
        "counter did; it is not by itself a replay finding.",
    ),
    _e(
        "sa",
        "SA (Security Association)",
        "An SA is the unidirectional record of how one direction of traffic is "
        "protected: the algorithms, the keys, the endpoints, the SPI and the "
        "counters. A protected conversation has at least two, one per direction, "
        "and they are set up separately.",
        "A recorded count of observed SAs is how many directions the backend "
        "observed. One direction only is a recorded fact about what was seen.",
    ),
    _e(
        "rekeying",
        "Rekeying",
        "Rekeying replaces the keys of an existing SA before they expire or before "
        "too much traffic has been protected under them. It limits how much data a "
        "single compromised key protects, and it is where the IKE and ESP DH groups "
        "are actually used if PFS is enabled.",
        "Rekey behaviour is not directly observed by a passive capture, so a finding "
        "about PFS describes the configured state rather than a measured one.",
    ),
    _e(
        "traffic_selector",
        "Traffic selector",
        "A traffic selector is the description of which packets an SA applies to: a "
        "source prefix, destination prefix, protocol and ports. Selectors are what "
        "decide which traffic actually passes through IPsec, so a correctly "
        "configured tunnel still leaves traffic unprotected if its selectors do not "
        "cover the traffic in question.",
        "Selectors are configuration. A passive capture shows what arrived, not "
        "which selector would have matched it, so a capture alone cannot prove a "
        "selector gap.",
    ),
    _e(
        "unassessed",
        "UNASSESSED",
        "UNASSESSED is this system's own label for a packet that no recorded "
        "assessment observed. The packet was captured and shown, but no assessment "
        "matched it, so nothing about its security was decided.",
        "UNASSESSED is not LOW, is not clean, and is not a judgement. It means the "
        "question was never asked of the backend for that packet.",
    ),
    _e(
        "severity",
        "Severity vs risk score",
        "Severity is a band label such as HIGH or MEDIUM; the risk score is a "
        "number. In this system the score is computed first and the severity is "
        "the band that score falls into, so the two are not independent opinions. "
        "An assessment can therefore be MEDIUM overall while containing a HIGH "
        "finding whose weight was partly absorbed by the per-category cap.",
        "Both the severity and the score are produced by the risk engine. The "
        "assistant restates them and never recomputes, rescores or revises either.",
    ),
    _e(
        "chain_of_custody",
        "Chain of custody",
        "The chain of custody is the recorded provenance of a decision: which "
        "capture it came from, what was normalized, what was compared, which rule "
        "fired, how it was scored, and which evidence artifacts it references. It "
        "exists so a reviewer can walk from a severity back to a packet capture "
        "without trusting the summary.",
        "The stages are produced by the analysis pipeline, not by the assistant. "
        "The assistant can describe what a stage means and can say which stages "
        "are recorded; it cannot add a stage that is missing.",
    ),
    _e(
        "drift",
        "Configuration drift",
        "Drift is a change in the deployed configuration compared with a validated "
        "baseline from an earlier point. It answers a different question from a "
        "finding: a finding compares observed against expected right now, while "
        "drift asks whether the current state still matches what was signed off "
        "before.",
        "Drift is only reported for fields a passive observation can actually "
        "compare. Encryption, DH, PFS and cipher parameters are not observable from "
        "a packet capture, so drift in those is reported as unsupported rather "
        "than as no drift.",
    ),
    _e(
        "ml_classification",
        "ML traffic classification",
        "The ML layer labels an observed traffic window with a profile such as "
        "voip, video, web, messaging, email or icmp, and reports the model's "
        "confidence in that label. It is a prediction about traffic shape, not a "
        "security decision, and it does not assign severity.",
        "A classification confidence is the model's own probability and is reported "
        "as recorded. It is not the assistant's confidence and is never presented "
        "as a judgement about the finding.",
    ),
)

BY_KEY: Dict[str, GlossaryEntry] = {entry.key: entry for entry in ENTRIES}

#: Which recorded configuration fields each term corresponds to.
#:
#: Used to append "In the selected assessment: <recorded value>" to a
#: definition, which is what turns a glossary answer into a grounded one. A term
#: deliberately absent from this table (``ah``, ``unassessed``, ``chain_of_custody``)
#: gets no such sentence: those have no counterpart among the fields an
#: assessment carries, and claiming they are "not recorded" would invent a gap.
RECORDED_FIELDS: Dict[str, Tuple[str, ...]] = {
    "ike": ("ike_version", "ike_dh_group", "ike_encryption"),
    "esp": ("esp_encryption", "esp_integrity"),
    "pfs": ("esp_pfs",),
    "dh_group": ("ike_dh_group", "esp_dh_group"),
    "modp2048": ("esp_dh_group", "ike_dh_group"),
    "modp3072": ("esp_dh_group", "ike_dh_group"),
    "modp4096": ("esp_dh_group", "ike_dh_group"),
    "ike_esp_encryption": ("esp_encryption", "ike_encryption"),
    "integrity": ("esp_integrity", "ike_integrity"),
    "tunnel_mode": ("mode",),
    "transport_mode": ("mode",),
    "address_family": ("address_family",),
    "rekeying": ("esp_pfs",),
}

#: Alternate spellings an analyst is likely to type, mapped to a canonical key.
ALIASES: Dict[str, str] = {
    "ipsec": "ike_esp_encryption",
    "pfs": "pfs",
    "perfect forward secrecy": "pfs",
    "forward secrecy": "pfs",
    "ike": "ike",
    "internet key exchange": "ike",
    "esp": "esp",
    "encapsulating security payload": "esp",
    "ah": "ah",
    "authentication header": "ah",
    "diffie hellman": "dh_group",
    "diffie-hellman": "dh_group",
    "dh": "dh_group",
    "dh group": "dh_group",
    "modp 2048": "modp2048",
    "modp2048": "modp2048",
    "modp 4096": "modp4096",
    "modp4096": "modp4096",
    "modp 3072": "modp3072",
    "modp3072": "modp3072",
    "encryption": "ike_esp_encryption",
    "encrypt": "ike_esp_encryption",
    "cipher": "ike_esp_encryption",
    "integrity": "integrity",
    "tunnel": "tunnel_mode",
    "tunnel mode": "tunnel_mode",
    "transport": "transport_mode",
    "transport mode": "transport_mode",
    "ipv4": "address_family",
    "ipv6": "address_family",
    "address family": "address_family",
    "spi": "spi",
    "security parameters index": "spi",
    "sequence number": "sequence_number",
    "sequence numbers": "sequence_number",
    "sa": "sa",
    "security association": "sa",
    "rekeying": "rekeying",
    "rekey": "rekeying",
    "traffic selector": "traffic_selector",
    "selectors": "traffic_selector",
    "unassessed": "unassessed",
    "severity": "severity",
    "risk score": "severity",
    "chain of custody": "chain_of_custody",
    "custody": "chain_of_custody",
    "drift": "drift",
    "classification": "ml_classification",
    "ml": "ml_classification",
    "ml classification": "ml_classification",
    "confidence": "ml_classification",
}


def lookup(text: str) -> Optional[GlossaryEntry]:
    """The single best glossary entry for a question, or ``None``.

    Longest alias wins so "perfect forward secrecy" beats "pfs"-adjacent
    shorter matches, and the order of :data:`ENTRIES` breaks ties so a question
    mentioning several terms always gets the same one.
    """
    if not text:
        return None
    haystack = " ".join(str(text).lower().replace("-", " ").replace("_", " ").split())
    padded = f" {haystack} "
    best_key: Optional[str] = None
    best_len = 0
    for alias, key in ALIASES.items():
        needle = alias.replace("-", " ")
        if f" {needle} " not in padded:
            continue
        if len(needle) > best_len:
            best_len = len(needle)
            best_key = key
    if best_key is None:
        return None
    return BY_KEY.get(best_key)


def render(entry: GlossaryEntry) -> str:
    """Term, definition and relevance, as three short labelled paragraphs.

    The term is repeated first because the most common question is a
    contraction: someone who typed "PFS" has not been told what the letters
    stand for, and an answer that opens "PFS means that ..." teaches them
    nothing they did not already have.
    """
    return (
        f"{entry.term}\n\n{entry.definition}"
        f"\n\nWhere this shows up: {entry.relevance}"
    )
