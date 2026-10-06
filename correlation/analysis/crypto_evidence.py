"""Area 2 -- runtime crypto evidence classification.

Answers, for each crypto property of the expected configuration, the only
question a passive capture can honestly answer: *can this backend establish
the runtime value from the evidence it actually has?*

The classification is deliberately conservative and is derived from the
Phase-1 finding that governs the whole observation path
(``ebpf/ipsec_state_builder`` refuses to infer encryption, integrity or IKE SA
state):

* ``esp.encryption`` / ``esp.integrity`` / ``esp.dh_group`` / ``esp.pfs``
  -- the ESP header (RFC 4303) carries SPI + sequence only. There is no
  algorithm identifier anywhere in the packet, and the payload is the thing
  being encrypted, so no byte pattern names the cipher. The negotiated values
  exist in the SPI's SA, which was negotiated inside an IKE exchange this
  pipeline does not decode. ``runtime_observable: false``, ``state: UNKNOWN``.
* ``ike.version`` -- the IKE header does carry a version field, but the
  observation path records IKE packet presence and timestamps only
  (``ike_seen`` / ``observed_ike_activity``), never the header contents, so
  this backend establishes no runtime value. ``state: UNKNOWN``.
* ``mode`` -- tunnel and transport mode place byte-identical protocol-50 ESP
  on the wire, so the wire cannot distinguish them. The one authoritative
  runtime source is the deployed SA report (``swanctl --list-sas``) surfaced
  as ``ObservedState.mode``; when it is present the value is OBSERVED, and
  when it is absent the value stays UNKNOWN. ``tunnel_seen`` is NEVER used
  for this: the state builder records it as "any traffic was observed"
  (``observation_start_ns is not None``).

Every property also carries its configured value with ``state: CONFIGURED``:
the configuration side is always answerable (it comes from the plan), which is
exactly why it must be kept separate from the runtime side.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ..models import ExpectedState, ObservedState
from .states import (
    STATE_CONFIGURED,
    STATE_NOT_AVAILABLE,
    STATE_OBSERVED,
    STATE_UNKNOWN,
    validate_state,
)

#: The properties the brief asks for, spelled as the canonical correlation
#: variables so one property name means the same thing everywhere.
ENCRYPTION = "esp.encryption"
INTEGRITY = "esp.integrity"
DH_GROUP = "esp.dh_group"
PFS = "esp.pfs"
IKE_VERSION = "ike.version"
MODE = "mode"

CRYPTO_PROPERTIES: Tuple[str, ...] = (
    ENCRYPTION,
    INTEGRITY,
    DH_GROUP,
    PFS,
    IKE_VERSION,
    MODE,
)

EVIDENCE_SOURCE_CONFIGURATION = "configuration"
EVIDENCE_SOURCE_OBSERVATION = "observation"
EVIDENCE_SOURCE_RUNTIME_SA_REPORT = "runtime_sa_report"

_NO_WIRE_EVIDENCE_REASON = {
    ENCRYPTION: (
        "The ESP header (RFC 4303) carries only SPI and sequence number; it "
        "names no algorithm, and the payload is the value being encrypted, so "
        "no byte pattern identifies the negotiated cipher. The SPI indexes an "
        "SA that was negotiated inside an IKE exchange this pipeline does not "
        "decode, so the packet format cannot establish it."
    ),
    INTEGRITY: (
        "The ESP header carries no integrity-algorithm identifier, and the "
        "authentication data verifies the packet rather than naming the "
        "algorithm that produced it (an AEAD combines both, so there is "
        "nothing separate to read either). The packet format cannot establish "
        "it."
    ),
    DH_GROUP: (
        "The Diffie-Hellman group is agreed inside the IKE key exchange and "
        "recorded in the SA; ESP packets carry no group identifier. The packet "
        "format cannot establish it."
    ),
    PFS: (
        "Perfect Forward Secrecy is a property of the rekey (a fresh DH "
        "exchange on every rekey). Observing it would require following IKE "
        "CREATE_CHILD_SA / rekey exchanges, which this pipeline does not "
        "decode, and an ESP packet exposes nothing about how its SA was "
        "derived. The packet format cannot establish it."
    ),
}

_IKE_VERSION_REASON = (
    "The IKE header does carry a version field, but the observation path "
    "records IKE packet presence and timestamps only (ike_seen / "
    "last_ike_timestamp_ns): no IKE header contents are parsed, so this "
    "backend establishes no runtime value for ike.version."
)

_MODE_WIRE_REASON = (
    "Tunnel and transport mode place byte-identical protocol-50 ESP on the "
    "wire, so ESP presence proves neither mode. The only authoritative runtime "
    "source is the deployed SA report (strongSwan swanctl --list-sas) exposed "
    "as ObservedState.mode, and it is absent from this snapshot."
)


@dataclass(frozen=True)
class CryptoProperty:
    """One crypto property, split into its configured and runtime halves."""

    name: str
    configured_value: Any
    configured_state: str
    runtime_value: Any
    state: str
    runtime_observable: bool
    evidence_source: str
    reason: str

    def __post_init__(self) -> None:
        validate_state(self.configured_state)
        validate_state(self.state)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "property": self.name,
            "configured_value": self.configured_value,
            "configured_state": self.configured_state,
            "runtime_value": self.runtime_value,
            "state": self.state,
            "runtime_observable": self.runtime_observable,
            "evidence_source": self.evidence_source,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CryptoEvidence:
    """The complete runtime-crypto-evidence product for one assessment."""

    state: str
    reason: str
    source: str
    properties: tuple = ()
    limitations: tuple = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "reason": self.reason,
            "source": self.source,
            "properties": [p.to_dict() for p in self.properties],
            "by_property": {p.name: p.to_dict() for p in self.properties},
            "runtime_established": [
                p.name for p in self.properties if p.state == STATE_OBSERVED
            ],
            "limitations": list(self.limitations),
        }


def _configured(expected: ExpectedState, name: str) -> Tuple[Any, str]:
    value = {
        ENCRYPTION: expected.esp.encryption,
        INTEGRITY: expected.esp.integrity,
        DH_GROUP: expected.esp.dh_group,
        PFS: expected.esp.pfs,
        IKE_VERSION: expected.ike.version,
        MODE: expected.mode,
    }[name]
    if value is None:
        return None, STATE_NOT_AVAILABLE
    return value, STATE_CONFIGURED


def analyze_crypto_evidence(
    expected: ExpectedState,
    observed: Optional[ObservedState] = None,
    *,
    source: str = "expected configuration + observed-state snapshot",
) -> CryptoEvidence:
    """Classify every crypto property for one assessment."""
    properties: List[CryptoProperty] = []

    for name in (ENCRYPTION, INTEGRITY, DH_GROUP, PFS, IKE_VERSION):
        configured, configured_state = _configured(expected, name)
        if name == IKE_VERSION:
            reason = _IKE_VERSION_REASON
        else:
            reason = _NO_WIRE_EVIDENCE_REASON[name]
        properties.append(
            CryptoProperty(
                name=name,
                configured_value=configured,
                configured_state=configured_state,
                runtime_value=None,
                state=STATE_UNKNOWN,
                runtime_observable=False,
                evidence_source=EVIDENCE_SOURCE_CONFIGURATION,
                reason=reason,
            )
        )

    configured, configured_state = _configured(expected, MODE)
    observed_mode = getattr(observed, "mode", None) if observed is not None else None
    if observed_mode in ("tunnel", "transport"):
        properties.append(
            CryptoProperty(
                name=MODE,
                configured_value=configured,
                configured_state=configured_state,
                runtime_value=observed_mode,
                state=STATE_OBSERVED,
                runtime_observable=True,
                evidence_source=EVIDENCE_SOURCE_RUNTIME_SA_REPORT,
                reason=(
                    "The deployed security association reported its "
                    f"encapsulation mode as {observed_mode!r} "
                    "(strongSwan swanctl --list-sas), recorded by the "
                    "observation path as ObservedState.mode. This is runtime "
                    "evidence from the SA report, not an inference from the "
                    "wire."
                ),
            )
        )
    else:
        properties.append(
            CryptoProperty(
                name=MODE,
                configured_value=configured,
                configured_state=configured_state,
                runtime_value=None,
                state=STATE_UNKNOWN,
                runtime_observable=True,
                evidence_source=EVIDENCE_SOURCE_CONFIGURATION,
                reason=_MODE_WIRE_REASON,
            )
        )

    limitations: List[str] = [
        "A configured value is never reported as a runtime value: "
        "runtime_value stays null until an observation establishes it.",
        "No property is ever resolved by matching the configuration against "
        "itself; the comparison layer owns MATCH/MISMATCH and this product "
        "only classifies evidence.",
    ]
    established = [p.name for p in properties if p.state == STATE_OBSERVED]
    return CryptoEvidence(
        state=STATE_OBSERVED if established else STATE_UNKNOWN,
        reason=(
            "Runtime crypto evidence exists for "
            f"{', '.join(established)}; every other property is UNKNOWN "
            "because the packet format does not expose it."
            if established
            else "No runtime crypto value could be established from this "
            "capture; every property reports its configured value alongside "
            "an explicit UNKNOWN runtime value."
        ),
        source=source,
        properties=tuple(properties),
        limitations=tuple(limitations),
    )
