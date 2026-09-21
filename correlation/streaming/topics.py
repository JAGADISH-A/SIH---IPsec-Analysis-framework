"""Configurable Kafka topics (never hard-coded at use sites).

Default names mirror the design's canonical topic list; every name can be
overridden through ``StreamingConfig`` (``topic_prefix``) or an explicit
mapping (``EventTopicMap``).
"""

from dataclasses import dataclass, field, replace
from typing import Dict, Mapping, Optional

TOPIC_RAW = "ipsec.raw"
TOPIC_STATE = "ipsec.state"
TOPIC_FEATURES = "ipsec.features"
TOPIC_ML = "ipsec.ml"
TOPIC_CORRELATION = "ipsec.correlation"
TOPIC_RISK = "ipsec.risk"
TOPIC_XAI = "ipsec.xai"
TOPIC_RESPONSE = "ipsec.response"
TOPIC_AUDIT = "ipsec.audit"
TOPIC_EVIDENCE = "ipsec.evidence"

DEFAULT_TOPICS = (
    TOPIC_RAW,
    TOPIC_STATE,
    TOPIC_FEATURES,
    TOPIC_ML,
    TOPIC_CORRELATION,
    TOPIC_RISK,
    TOPIC_XAI,
    TOPIC_RESPONSE,
    TOPIC_AUDIT,
    TOPIC_EVIDENCE,
)


@dataclass(frozen=True)
class EventTopicMap:
    """Topic-name resolution with a configurable prefix."""

    raw: str = TOPIC_RAW
    state: str = TOPIC_STATE
    features: str = TOPIC_FEATURES
    ml: str = TOPIC_ML
    correlation: str = TOPIC_CORRELATION
    risk: str = TOPIC_RISK
    xai: str = TOPIC_XAI
    response: str = TOPIC_RESPONSE
    audit: str = TOPIC_AUDIT
    evidence: str = TOPIC_EVIDENCE

    @classmethod
    def with_prefix(cls, prefix: Optional[str]) -> "EventTopicMap":
        if not prefix or prefix == "-":
            return cls()
        sep = prefix.rstrip(".") + "."
        return cls(
            raw=sep + TOPIC_RAW,
            state=sep + TOPIC_STATE,
            features=sep + TOPIC_FEATURES,
            ml=sep + TOPIC_ML,
            correlation=sep + TOPIC_CORRELATION,
            risk=sep + TOPIC_RISK,
            xai=sep + TOPIC_XAI,
            response=sep + TOPIC_RESPONSE,
            audit=sep + TOPIC_AUDIT,
            evidence=sep + TOPIC_EVIDENCE,
        )

    def to_mapping(self) -> Dict[str, str]:
        return {
            "ipsec.raw": self.raw,
            "ipsec.state": self.state,
            "ipsec.features": self.features,
            "ipsec.ml": self.ml,
            "ipsec.correlation": self.correlation,
            "ipsec.risk": self.risk,
            "ipsec.xai": self.xai,
            "ipsec.response": self.response,
            "ipsec.audit": self.audit,
            "ipsec.evidence": self.evidence,
        }

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, str]) -> "EventTopicMap":
        return cls(
            raw=mapping.get("ipsec.raw", TOPIC_RAW),
            state=mapping.get("ipsec.state", TOPIC_STATE),
            features=mapping.get("ipsec.features", TOPIC_FEATURES),
            ml=mapping.get("ipsec.ml", TOPIC_ML),
            correlation=mapping.get("ipsec.correlation", TOPIC_CORRELATION),
            risk=mapping.get("ipsec.risk", TOPIC_RISK),
            xai=mapping.get("ipsec.xai", TOPIC_XAI),
            response=mapping.get("ipsec.response", TOPIC_RESPONSE),
            audit=mapping.get("ipsec.audit", TOPIC_AUDIT),
            evidence=mapping.get("ipsec.evidence", TOPIC_EVIDENCE),
        )

    def topic_for(self, canonical: str) -> str:
        return {
            TOPIC_RAW: self.raw,
            TOPIC_STATE: self.state,
            TOPIC_FEATURES: self.features,
            TOPIC_ML: self.ml,
            TOPIC_CORRELATION: self.correlation,
            TOPIC_RISK: self.risk,
            TOPIC_XAI: self.xai,
            TOPIC_RESPONSE: self.response,
            TOPIC_AUDIT: self.audit,
            TOPIC_EVIDENCE: self.evidence,
        }[canonical]