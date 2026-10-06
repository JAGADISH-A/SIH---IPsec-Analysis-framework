"""The evidence-state vocabulary every analytical product must speak.

The security-analysis brief fixes seven states and requires them to stay
distinct:

    OBSERVED        established from runtime evidence in a captured artifact
    CONFIGURED      established from the authoritative configuration model
    INFERRED        derived by documented arithmetic from observed values
    ASSESSED        an analytical judgement made by this backend (never raw
                    sensor data, never a second score)
    UNKNOWN         asked about, but the evidence does not answer
    NOT_AVAILABLE   the source that would carry it does not record it
    NOT_APPLICABLE  the question does not apply to this assessment

Two rules are load-bearing and enforced here rather than in prose:

1. ``UNKNOWN`` is never rewritten as ``MATCH``/``MISMATCH`` and never turned
   into a negative security finding. A missing runtime value is a fact about
   the evidence, not a fact about the tunnel.
2. A state always travels with a ``reason``. A bare state string is not an
   analysis: a reader must be able to see why the backend said it.

:class:`EvidenceValue` is the small carrier type used wherever a producer
returns one value; producers that return a whole product (a crypto property,
for example) use the same field names in their own ``to_dict`` so the API
shape stays uniform.
"""

from dataclasses import dataclass
from typing import Any, Dict, Tuple

STATE_OBSERVED = "OBSERVED"
STATE_CONFIGURED = "CONFIGURED"
STATE_INFERRED = "INFERRED"
STATE_ASSESSED = "ASSESSED"
STATE_UNKNOWN = "UNKNOWN"
STATE_NOT_AVAILABLE = "NOT_AVAILABLE"
STATE_NOT_APPLICABLE = "NOT_APPLICABLE"

#: The complete vocabulary, in the order the brief states it.
VALID_STATES: Tuple[str, ...] = (
    STATE_OBSERVED,
    STATE_CONFIGURED,
    STATE_INFERRED,
    STATE_ASSESSED,
    STATE_UNKNOWN,
    STATE_NOT_AVAILABLE,
    STATE_NOT_APPLICABLE,
)

#: States that mean "the evidence does not establish this value". A producer
#: must never upgrade one of these into a negative security finding; the
#: assessment layer (``correlation.risk``) is the only place a security
#: judgement is made, and it may only do so from OBSERVED/CONFIGURED/INFERRED
#: evidence.
UNESTABLISHED_STATES: Tuple[str, ...] = (
    STATE_UNKNOWN,
    STATE_NOT_AVAILABLE,
    STATE_NOT_APPLICABLE,
)


def validate_state(value: Any) -> str:
    """Return ``value`` if it is a known state, else raise."""
    if value not in VALID_STATES:
        raise ValueError(f"state must be one of {VALID_STATES}, got {value!r}")
    return value


def is_established(state: Any) -> bool:
    """True when the state carries evidence rather than an evidence gap."""
    return state in VALID_STATES and state not in UNESTABLISHED_STATES


def _require_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


@dataclass(frozen=True)
class EvidenceValue:
    """One produced value together with everything needed to audit it.

    ``source`` names the producer or artifact that established the value -- it
    is provenance, not a URL. ``reason`` explains why the value has this
    state, in particular why an unestablished value is unestablished.
    ``runtime_observable`` records whether runtime (packet) evidence could
    establish the property at all; ``None`` means the question was not asked
    of this value (for example a purely computed duration).
    """

    value: Any
    state: str
    source: str
    reason: str
    runtime_observable: Any = None

    def __post_init__(self) -> None:
        validate_state(self.state)
        _require_text(self.source, "source")
        _require_text(self.reason, "reason")
        if self.runtime_observable is not None and not isinstance(
            self.runtime_observable, bool
        ):
            raise ValueError("runtime_observable must be a bool or None")

    @classmethod
    def of(
        cls,
        value: Any,
        state: str,
        source: str,
        reason: str,
        runtime_observable: Any = None,
    ) -> "EvidenceValue":
        return cls(
            value=value,
            state=validate_state(state),
            source=source,
            reason=reason,
            runtime_observable=runtime_observable,
        )

    @property
    def established(self) -> bool:
        return is_established(self.state)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "state": self.state,
            "source": self.source,
            "reason": self.reason,
            "runtime_observable": self.runtime_observable,
        }
