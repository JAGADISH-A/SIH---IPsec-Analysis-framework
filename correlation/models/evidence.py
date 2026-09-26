"""Evidence reference model.

References evidence that is OWNED by the SIHPsec repository
(``D:\\sihipsec``). These references do NOT require the referenced file to
exist inside this workspace, and no PCAP files are copied or fabricated here.

The known repository PCAP pattern is::

    results/datasets/<run_id>/captures/<seq>/<experiment_id>.pcap

``audit_event_reference`` points into the audit Tap events journal, e.g.
``audit://tap-events.jsonl#<offset>`` — a documented reference, not a copy.

Artifact vs reference
---------------------
An *artifact* is the actual PCAP (or observation log) file. An *EvidenceRef* is
only immutable metadata pointing at it. PCAP bytes are never embedded in an
audit event, an API response, a risk finding or a recommendation: this model
carries locations, digests and intervals, never payload.

Phase 15 added the linkage half of the model. Every new field is optional, so
a Phase-1 style ``EvidenceRef(pcap_path=..., capture_sequence=..., source=...)``
still round-trips byte-identically and still means "a reference, the file may
not exist here". When the linkage fields ARE supplied the reference becomes
self-verifying:

* ``evidence_id`` is a deterministic, content-addressed identity derived from
  the reference fields themselves (:meth:`derive_evidence_id`), so the same
  artifact bound to the same window always yields the same id, and a record
  edited after the fact is rejected on read;
* ``artifact_sha256`` pins the artifact bytes. :meth:`verify` re-hashes the real
  file read-only and reports ``valid`` / ``unavailable`` / ``invalid``. A changed
  artifact is reported ``invalid`` and is never silently repaired or replaced;
* ``run_id`` / ``experiment_id`` / ``sequence`` / ``window_index`` bind the
  reference to the exact analysis window, so evidence from another run,
  experiment or window is rejected instead of being attached to this one;
* ``capture_start_ns`` / ``capture_end_ns`` / ``packet_start`` / ``packet_end``
  locate the relevant interval inside the capture. Packet offsets stay ``None``
  when the capture metadata cannot establish them — they are never invented.

A reference is NOT authoritative on its own: PCAP proves bytes were observed,
never that an interpretation is correct. Authority stays with the observation
contract (``SOURCE_OBSERVED`` in :mod:`correlation.audit`).
"""

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

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

#: Artifact kinds a reference may point at. ``pcap`` is the primary target of
#: this milestone; the other documented sources are preserved rather than
#: redesign, so a reference can also locate the observation log that was derived
#: from a capture.
ARTIFACT_TYPE_PCAP = "pcap"
ARTIFACT_TYPE_XDP_JSONL = "xdp_jsonl"
ARTIFACT_TYPE_AUDIT_JSONL = "audit_jsonl"
ARTIFACT_TYPES = (
    ARTIFACT_TYPE_PCAP,
    ARTIFACT_TYPE_XDP_JSONL,
    ARTIFACT_TYPE_AUDIT_JSONL,
)

#: Verification outcomes. ``invalid`` means the artifact exists but no longer
#: matches ``artifact_sha256``; it is never repaired.
EVIDENCE_STATUS_VALID = "valid"
EVIDENCE_STATUS_UNAVAILABLE = "unavailable"
EVIDENCE_STATUS_INVALID = "invalid"
#: The reference carries no digest, so integrity cannot be asserted at all.
#: Reported instead of guessing.
EVIDENCE_STATUS_UNVERIFIED = "unverified"
EVIDENCE_STATUSES = (
    EVIDENCE_STATUS_VALID,
    EVIDENCE_STATUS_UNAVAILABLE,
    EVIDENCE_STATUS_INVALID,
    EVIDENCE_STATUS_UNVERIFIED,
)

_SHA256_HEX_LENGTH = 64


def _optional_str(value: Any, name: str) -> None:
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise ValueError(f"{name} must be a non-empty string or None")


def _optional_int(value: Any, name: str, *, minimum: Optional[int] = None) -> None:
    if value is None:
        return
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer or None")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")


def validate_sha256(value: Any, name: str = "artifact_sha256") -> Optional[str]:
    """Require a full 64-char lowercase hex digest, or None."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a 64-char hex string or None")
    if len(value) != _SHA256_HEX_LENGTH:
        raise ValueError(
            f"{name} must be exactly {_SHA256_HEX_LENGTH} hex characters, "
            f"got {len(value)}"
        )
    if any(ch not in "0123456789abcdef" for ch in value):
        raise ValueError(f"{name} must be lowercase hexadecimal, got {value!r}")
    return value


def sha256_file(path: str, *, chunk_size: int = 1 << 20) -> str:
    """Stream a file through SHA-256. Read-only: never writes or truncates."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def derive_evidence_id(payload: Dict[str, Any]) -> str:
    """Content-addressed ``evidence_id`` for a reference payload.

    Deterministic on purpose: the same artifact bound to the same window must
    always produce the same id so a replay is byte-identical, and a reference
    whose fields were edited after the fact no longer recomputes to its recorded
    id (mirroring :func:`correlation.audit.derive_event_id`).
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "ev-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class EvidenceRef(JsonModel):
    """Immutable evidence reference (never requires the file to exist).

    Phase-1 fields (all optional, unchanged): ``pcap_path``,
    ``capture_sequence``, ``audit_event_reference``, ``source``, ``timestamp``.

    Phase-15 linkage fields (all optional): artifact identity
    (``artifact_type`` / ``artifact_sha256`` / ``byte_size``), analysis-window
    binding (``run_id`` / ``experiment_id`` / ``sequence`` / ``window_index``),
    the capture interval (``capture_start_ns`` / ``capture_end_ns``) and the
    optional packet interval (``packet_start`` / ``packet_end``).
    """

    pcap_path: Optional[str] = None
    capture_sequence: Optional[int] = None
    audit_event_reference: Optional[str] = None
    source: Optional[str] = None
    timestamp: Optional[str] = None
    # -- artifact identity ---------------------------------------------------
    artifact_type: Optional[str] = None
    artifact_sha256: Optional[str] = None
    byte_size: Optional[int] = None
    # -- analysis-window binding --------------------------------------------
    run_id: Optional[str] = None
    experiment_id: Optional[str] = None
    sequence: Optional[int] = None
    window_index: Optional[int] = None
    # -- interval inside the capture ----------------------------------------
    capture_start_ns: Optional[int] = None
    capture_end_ns: Optional[int] = None
    packet_start: Optional[int] = None
    packet_end: Optional[int] = None

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

        _optional_str(self.artifact_type, "artifact_type")
        if self.artifact_type is not None and self.artifact_type not in ARTIFACT_TYPES:
            raise ValueError(
                f"artifact_type must be one of {ARTIFACT_TYPES} or None, "
                f"got {self.artifact_type!r}"
            )
        validate_sha256(self.artifact_sha256)
        _optional_int(self.byte_size, "byte_size", minimum=0)
        _optional_str(self.run_id, "run_id")
        _optional_str(self.experiment_id, "experiment_id")
        _optional_int(self.sequence, "sequence", minimum=1)
        _optional_int(self.window_index, "window_index", minimum=0)
        _optional_int(self.capture_start_ns, "capture_start_ns", minimum=0)
        _optional_int(self.capture_end_ns, "capture_end_ns", minimum=0)
        _optional_int(self.packet_start, "packet_start", minimum=0)
        _optional_int(self.packet_end, "packet_end", minimum=0)

        if self.capture_start_ns is not None and self.capture_end_ns is not None:
            if self.capture_end_ns < self.capture_start_ns:
                raise ValueError(
                    f"capture_end_ns ({self.capture_end_ns}) must be >= "
                    f"capture_start_ns ({self.capture_start_ns})"
                )
        if self.packet_start is not None and self.packet_end is not None:
            if self.packet_end < self.packet_start:
                raise ValueError(
                    f"packet_end ({self.packet_end}) must be >= packet_start "
                    f"({self.packet_start})"
                )
        if self.capture_sequence is not None and self.sequence is not None:
            if self.capture_sequence != self.sequence:
                raise ValueError(
                    f"capture_sequence ({self.capture_sequence}) and sequence "
                    f"({self.sequence}) describe the same capture ordinal and "
                    f"must agree"
                )
        # A pcap_path implies a pcap artifact; keep the two from disagreeing.
        if self.artifact_type is not None and self.pcap_path is not None:
            suffix = os.path.splitext(self.pcap_path)[1].lower()
            if self.artifact_type == ARTIFACT_TYPE_PCAP and suffix not in (
                ".pcap",
                ".pcapng",
            ):
                raise ValueError(
                    f"artifact_type 'pcap' contradicts pcap_path {self.pcap_path!r}"
                )
        if self.artifact_sha256 is not None and self.pcap_path is None:
            # A digest with no location cannot be located or verified.
            raise ValueError(
                "artifact_sha256 requires pcap_path so the artifact can be "
                "located and verified"
            )
        self._seal_evidence_id()

    # -- content-addressed identity -----------------------------------------

    def identity_payload(self) -> Dict[str, Any]:
        """The fields the ``evidence_id`` is derived from.

        Includes the artifact digest and the window binding, so the same bytes
        referenced from two different windows are two distinct references, and
        a reference retargeted at a different run produces a different id.
        """
        return {
            "pcap_path": self.pcap_path,
            "artifact_type": self.artifact_type,
            "artifact_sha256": self.artifact_sha256,
            "byte_size": self.byte_size,
            "source": self.source,
            "audit_event_reference": self.audit_event_reference,
            "run_id": self.run_id,
            "experiment_id": self.experiment_id,
            "sequence": self.sequence,
            "window_index": self.window_index,
            "capture_start_ns": self.capture_start_ns,
            "capture_end_ns": self.capture_end_ns,
            "packet_start": self.packet_start,
            "packet_end": self.packet_end,
        }

    def _seal_evidence_id(self) -> None:
        """Assign the derived id, or reject a record edited after the fact.

        The id is derived, never supplied: an ``evidence_id`` on a reference is
        always a function of the reference content, which is what makes the
        reference tamper-evident in the same way an audit ``event_id`` is.
        """
        object.__setattr__(self, "evidence_id", derive_evidence_id(self.identity_payload()))

    # -- construction --------------------------------------------------------

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceRef":
        """Rebuild a reference, rejecting a record edited after it was written.

        When the payload carries an ``evidence_id`` it is verified against the
        content, exactly like :meth:`correlation.audit.AuditEvent.from_dict`
        does for its ``event_id``. That is what makes a persisted reference
        tamper-evident rather than merely self-describing.
        """
        ref = cls(
            pcap_path=data.get("pcap_path"),
            capture_sequence=data.get("capture_sequence"),
            audit_event_reference=data.get("audit_event_reference"),
            source=data.get("source"),
            timestamp=data.get("timestamp"),
            artifact_type=data.get("artifact_type"),
            artifact_sha256=data.get("artifact_sha256"),
            byte_size=data.get("byte_size"),
            run_id=data.get("run_id"),
            experiment_id=data.get("experiment_id"),
            sequence=data.get("sequence"),
            window_index=data.get("window_index"),
            capture_start_ns=data.get("capture_start_ns"),
            capture_end_ns=data.get("capture_end_ns"),
            packet_start=data.get("packet_start"),
            packet_end=data.get("packet_end"),
        )
        recorded = data.get("evidence_id")
        if recorded is not None and recorded != ref.evidence_id:
            raise ValueError(
                f"evidence_id {recorded!r} does not match the reference content "
                f"(expected {ref.evidence_id!r}); this reference was modified "
                f"after it was written"
            )
        return ref

    def to_dict(self) -> Dict[str, Any]:
        # JsonModel.to_dict() uses dataclasses.asdict, which would emit a plain
        # field rather than the derived id; keep the derived id authoritative.
        payload = dataclasses_asdict(self)
        payload["evidence_id"] = self.evidence_id
        return payload

    # -- window binding ------------------------------------------------------

    def with_window(
        self,
        *,
        window_index: Optional[int] = None,
        run_id: Optional[str] = None,
        experiment_id: Optional[str] = None,
        sequence: Optional[int] = None,
        packet_start: Optional[int] = None,
        packet_end: Optional[int] = None,
        capture_start_ns: Optional[int] = None,
        capture_end_ns: Optional[int] = None,
    ) -> "EvidenceRef":
        """Return this artifact bound to one analysis window.

        Idempotent: re-binding the same window returns an equal reference, so
        repeated propagation cannot multiply references. The run/experiment are
        only overwritten when explicitly supplied, so a window binding can
        never silently re-parent an artifact to another run.
        """
        _reject_conflicting_window_bindings(
            artifact_run_id=self.run_id, artifact_experiment_id=self.experiment_id,
            artifact_sequence=self.sequence, artifact_window_index=self.window_index,
            run_id=run_id, experiment_id=experiment_id, sequence=sequence,
            window_index=window_index,
        )
        return EvidenceRef(
            pcap_path=self.pcap_path,
            capture_sequence=sequence if sequence is not None else self.capture_sequence,
            audit_event_reference=self.audit_event_reference,
            source=self.source,
            timestamp=self.timestamp,
            artifact_type=self.artifact_type,
            artifact_sha256=self.artifact_sha256,
            byte_size=self.byte_size,
            run_id=run_id if run_id is not None else self.run_id,
            experiment_id=experiment_id if experiment_id is not None else self.experiment_id,
            sequence=sequence if sequence is not None else self.sequence,
            window_index=window_index if window_index is not None else self.window_index,
            capture_start_ns=capture_start_ns if capture_start_ns is not None
            else self.capture_start_ns,
            capture_end_ns=capture_end_ns if capture_end_ns is not None
            else self.capture_end_ns,
            packet_start=packet_start if packet_start is not None else self.packet_start,
            packet_end=packet_end if packet_end is not None else self.packet_end,
        )

    # -- read-only verification ---------------------------------------------

    def exists_on_disk(self) -> bool:
        """Best-effort check; the reference is valid even when False."""
        return bool(self.pcap_path and os.path.isfile(self.pcap_path))

    def verify(self, evidence_root: Optional[str] = None) -> "EvidenceVerification":
        """Re-check the artifact read-only and report its integrity.

        Never writes, repairs or substitutes anything. A missing file is
        ``unavailable``; a file whose bytes no longer match ``artifact_sha256``
        is ``invalid``. A reference with no digest reports ``unverified``
        rather than claiming validity it cannot support.
        """
        if self.pcap_path is None:
            return EvidenceVerification(
                evidence_id=self.evidence_id,
                status=EVIDENCE_STATUS_UNAVAILABLE,
                detail="reference carries no artifact location",
            )
        if self.artifact_sha256 is None:
            exists = os.path.isfile(self.pcap_path)
            return EvidenceVerification(
                evidence_id=self.evidence_id,
                status=EVIDENCE_STATUS_UNAVAILABLE if not exists
                else EVIDENCE_STATUS_UNVERIFIED,
                detail=("no artifact_sha256 recorded; integrity cannot be asserted"
                        if exists else "artifact file is not present"),
                artifact_present=exists,
            )
        resolved = resolve_within_root(self.pcap_path, evidence_root)
        if resolved is None:
            return EvidenceVerification(
                evidence_id=self.evidence_id,
                status=EVIDENCE_STATUS_UNAVAILABLE,
                detail=(
                    "artifact is outside the evidence root or does not exist"
                    if evidence_root else "artifact file is not present"
                ),
            )
        try:
            actual = sha256_file(resolved)
            size = os.path.getsize(resolved)
        except OSError as error:
            return EvidenceVerification(
                evidence_id=self.evidence_id,
                status=EVIDENCE_STATUS_UNAVAILABLE,
                detail=f"artifact could not be read: {error.strerror or error}",
            )
        if actual != self.artifact_sha256:
            return EvidenceVerification(
                evidence_id=self.evidence_id,
                status=EVIDENCE_STATUS_INVALID,
                detail="artifact bytes do not match the recorded sha256",
                artifact_present=True,
                actual_sha256=actual,
                expected_sha256=self.artifact_sha256,
                byte_size=size,
            )
        detail = "artifact matches the recorded sha256"
        if self.byte_size is not None and size != self.byte_size:
            # Digest already proves identity; a size drift is reported, not fatal.
            detail = (
                f"artifact matches the recorded sha256 (size {size} != recorded "
                f"{self.byte_size})"
            )
        return EvidenceVerification(
            evidence_id=self.evidence_id,
            status=EVIDENCE_STATUS_VALID,
            detail=detail,
            artifact_present=True,
            actual_sha256=actual,
            expected_sha256=self.artifact_sha256,
            byte_size=size,
        )


@dataclass(frozen=True)
class EvidenceVerification(JsonModel):
    """Read-only integrity result for one :class:`EvidenceRef`."""

    evidence_id: str
    status: str
    detail: str
    artifact_present: bool = False
    actual_sha256: Optional[str] = None
    expected_sha256: Optional[str] = None
    byte_size: Optional[int] = None

    def __post_init__(self) -> None:
        if self.status not in EVIDENCE_STATUSES:
            raise ValueError(
                f"status must be one of {EVIDENCE_STATUSES}, got {self.status!r}"
            )
        validate_sha256(self.actual_sha256, "actual_sha256")
        validate_sha256(self.expected_sha256, "expected_sha256")
        _optional_str(self.detail, "detail")
        _optional_int(self.byte_size, "byte_size", minimum=0)


def resolve_within_root(
    relative_path: str, evidence_root: Optional[str]
) -> Optional[str]:
    """Resolve a recorded path against the evidence root, read-only.

    A relative path is joined onto the root; an absolute path is accepted only
    when it already lies inside the root. In both cases the resolved real path
    (symlinks followed) must still be inside the root, so a ``..`` escape or a
    symlink pointing outside is refused. Returns None when the path is missing
    or escapes. Callers must never hand a browser-supplied path to the
    filesystem; this only resolves paths recorded in a reference.
    """
    if evidence_root is None:
        candidate = relative_path
        if os.path.isfile(candidate):
            return candidate
        return None
    root_abs = os.path.abspath(evidence_root)
    if os.path.isabs(relative_path):
        candidate = os.path.abspath(relative_path)
    else:
        candidate = os.path.abspath(os.path.join(root_abs, relative_path))
    if candidate != root_abs and not candidate.startswith(root_abs + os.sep):
        return None
    if not os.path.isfile(candidate):
        return None
    try:
        real = os.path.realpath(candidate)
    except OSError:
        return None
    if real != root_abs and not real.startswith(root_abs + os.sep):
        return None
    return candidate


def _reject_conflicting_window_bindings(
    *,
    artifact_run_id: Optional[str],
    artifact_experiment_id: Optional[str],
    artifact_sequence: Optional[int],
    artifact_window_index: Optional[int],
    run_id: Optional[str],
    experiment_id: Optional[str],
    sequence: Optional[int],
    window_index: Optional[int],
) -> None:
    """Refuse to re-parent an already-bound reference to another identity."""
    if run_id is not None and artifact_run_id is not None and run_id != artifact_run_id:
        raise EvidenceIdentityMismatch(
            f"evidence is bound to run_id={artifact_run_id!r}; refusing to attach "
            f"it to run_id={run_id!r}"
        )
    if (
        experiment_id is not None
        and artifact_experiment_id is not None
        and experiment_id != artifact_experiment_id
    ):
        raise EvidenceIdentityMismatch(
            f"evidence is bound to experiment_id={artifact_experiment_id!r}; "
            f"refusing to attach it to experiment_id={experiment_id!r}"
        )
    if (
        sequence is not None
        and artifact_sequence is not None
        and sequence != artifact_sequence
    ):
        raise EvidenceIdentityMismatch(
            f"evidence is bound to sequence={artifact_sequence}; refusing to "
            f"attach it to sequence={sequence}"
        )
    if (
        window_index is not None
        and artifact_window_index is not None
        and window_index != artifact_window_index
    ):
        raise EvidenceIdentityMismatch(
            f"evidence is already bound to window_index="
            f"{artifact_window_index}; refusing to re-bind it to "
            f"window_index={window_index}"
        )


class EvidenceIdentityMismatch(ValueError):
    """Raised when evidence from another run/experiment/window is attached."""


def dataclasses_asdict(obj: Any) -> Dict[str, Any]:
    """dataclasses.asdict, but without the derived ``evidence_id`` field."""
    import dataclasses

    if not (dataclasses.is_dataclass(obj) and not isinstance(obj, type)):
        raise TypeError(f"not a dataclass instance: {type(obj).__name__}")
    fields = [f for f in dataclasses.fields(obj) if f.name != "evidence_id"]
    return {f.name: getattr(obj, f.name) for f in fields}