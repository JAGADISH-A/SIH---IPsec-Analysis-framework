"""Evidence reference model.

References evidence that is OWNED by the SIHPsec repository
(``D:\\sihipsec``). These references do NOT require the referenced file to
exist inside this workspace, and no PCAP files are copied or fabricated here.

The known repository PCAP pattern is::

    results/datasets/<run_id>/captures/<seq>/<experiment_id>.pcap

``audit_event_reference`` points into the audit Tap events journal, e.g.
``audit://tap-events.jsonl#<offset>`` — a documented reference, not a copy.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional

from ._base import JsonModel

# Documented evidence sources (Phase 1 discovery).
SOURCE_TRAINING_PCAP = "training_pcap"
SOURCE_LIVE_XDP = "live_xdp"
SOURCE_AUDIT_TAP = "audit_tap"
SOURCE_SWANCTL = "swanctl"
DOCUMENTED_SOURCES = (
    SOURCE_TRAINING_PCAP,
    SOURCE_LIVE_XDP,
    SOURCE_AUDIT_TAP,
    SOURCE_SWANCTL,
)


def _optional_str(value: Any, name: str) -> None:
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise ValueError(f"{name} must be a non-empty string or None")


@dataclass(frozen=True)
class EvidenceRef(JsonModel):
    """Immutable evidence reference (never requires the file to exist)."""

    pcap_path: Optional[str] = None
    capture_sequence: Optional[int] = None
    audit_event_reference: Optional[str] = None
    source: Optional[str] = None
    timestamp: Optional[str] = None

    def __post_init__(self) -> None:
        _optional_str(self.pcap_path, "pcap_path")
        _optional_str(self.audit_event_reference, "audit_event_reference")
        _optional_str(self.source, "source")
        _optional_str(self.timestamp, "timestamp")

        if self.source is not None and self.source not in DOCUMENTED_SOURCES:
            raise ValueError(
                f"source must be one of {DOCUMENTED_SOURCES} or None, got {self.source!r}"
            )
        if self.capture_sequence is not None:
            if not isinstance(self.capture_sequence, int) or isinstance(
                self.capture_sequence, bool
            ):
                raise ValueError("capture_sequence must be an integer or None")
            if self.capture_sequence < 1:
                raise ValueError(
                    f"capture_sequence must be >= 1, got {self.capture_sequence}"
                )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceRef":
        return cls(
            pcap_path=data.get("pcap_path"),
            capture_sequence=data.get("capture_sequence"),
            audit_event_reference=data.get("audit_event_reference"),
            source=data.get("source"),
            timestamp=data.get("timestamp"),
        )

    def exists_on_disk(self) -> bool:
        """Best-effort check; the reference is valid even when False."""
        import os

        return bool(self.pcap_path and os.path.isfile(self.pcap_path))