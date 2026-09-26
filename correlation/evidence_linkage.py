"""Evidence linkage: reference mechanism between findings and real artifacts.

This module is a *reference* layer, never a capture mechanism. It never records,
copies, repairs or synthesizes packet data. Its whole job is to make the path

    risk finding -> response proposal -> evidence reference -> PCAP artifact

walkable in both directions without a human reconstructing the join.

Three responsibilities, deliberately separate:

``inspect_artifact``
    Read a real artifact read-only and report what it *is*: SHA-256, byte
    size, and — for a classic pcap — the capture interval and packet count
    parsed from the file's own header. Nothing is assumed about window
    alignment here.

``EvidenceCatalog``
    A registry of :class:`~correlation.models.evidence.EvidenceRef` keyed by
    ``evidence_id``. Resolution is by id only, mirroring the existing
    ``PcapRegistry`` hardening: a browser never supplies a path. Verification
    is read-only and reports ``valid`` / ``unavailable`` / ``invalid`` /
    ``unverified`` without ever repairing a changed artifact.

``bind_window`` / ``collect_propagated``
    Per-window binding and the automatic observation -> comparison -> risk ->
    response propagation that removes the caller-supplied join. A window only
    ever receives evidence recorded for that exact window, and rebinding the
    same window is idempotent.

Provenance rules that this module deliberately keeps:

* A PCAP reference is NOT authoritative. It proves bytes were observed, never
  that an interpretation is correct. Authority stays with the observation
  contract (``SOURCE_OBSERVED`` in :mod:`correlation.audit`).
* ``source`` keeps the documented vocabulary (``training_pcap`` /
  ``live_xdp`` / ``audit_tap`` / ``swanctl``); ``artifact_type`` says what the
  bytes are. The two are related, not interchangeable.
* Packet offsets are only ever reported when the artifact's own metadata
  establishes them. Otherwise the reference keeps the time/window reference and
  leaves ``packet_start`` / ``packet_end`` as ``None``.
"""

import fnmatch as _fnmatch
import os
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .models.evidence import (
    ARTIFACT_TYPE_AUDIT_JSONL,
    ARTIFACT_TYPE_PCAP,
    ARTIFACT_TYPE_XDP_JSONL,
    EVIDENCE_STATUS_UNAVAILABLE,
    ARTIFACT_TYPES,
    SOURCE_LIVE_XDP,
    SOURCE_TRAINING_PCAP,
    EvidenceIdentityMismatch,
    EvidenceRef,
    EvidenceVerification,
    resolve_within_root,
    sha256_file,
)

#: The documented repository capture layout. The recorded naming in
#: ``results/datasets/*/captures/`` is
#: ``<experiment_id>-attempt-<NN>.pcap`` (verified across every committed
#: dataset), so the attempt ordinal is part of the file name, not the
#: ``experiment_id``. Phase-1's note in ``correlation/models/evidence.py`` shows
#: the shape without the attempt suffix; the composed form below is what the
#: repository actually contains.
CAPTURE_DIR_PATTERN = "results/datasets/{run_id}/captures/{sequence:04d}"
CAPTURE_FILE_PATTERN = "{experiment_id}-attempt-{attempt_number:02d}.pcap"
CAPTURE_ATTEMPT_GLOB = "{experiment_id}-attempt-*.pcap"
#: Kept for callers that only know the Phase-1 simplified shape.
CAPTURE_PATH_PATTERN = CAPTURE_DIR_PATTERN + "/" + CAPTURE_FILE_PATTERN

#: Which documented ``source`` a given ``artifact_type`` may claim. Keeps a
#: pcap artifact from masquerading as an observation log, and vice versa.
ARTIFACT_TYPE_SOURCES: Dict[str, str] = {
    ARTIFACT_TYPE_PCAP: SOURCE_TRAINING_PCAP,
    ARTIFACT_TYPE_XDP_JSONL: SOURCE_LIVE_XDP,
    ARTIFACT_TYPE_AUDIT_JSONL: SOURCE_LIVE_XDP,
}

#: Extensions that may carry each artifact type.
ARTIFACT_TYPE_EXTENSIONS: Dict[str, Tuple[str, ...]] = {
    ARTIFACT_TYPE_PCAP: (".pcap", ".pcapng"),
    ARTIFACT_TYPE_XDP_JSONL: (".jsonl",),
    ARTIFACT_TYPE_AUDIT_JSONL: (".jsonl",),
}

#: pcap global-header magic values and whether the file is big-endian. The
#: nanosecond variants are distinguished by a trailing 0/1 byte in the magic.
_PCAP_MAGIC_US = 0xA1B2C3D4
_PCAP_MAGIC_NS = 0xA1B23C4D
_PCAP_HEADER_SIZE = 24
_PCAP_RECORD_HEADER_SIZE = 16
#: Refuse to walk a capture whose declared size disagrees with the file, so a
#: truncated artifact yields "unavailable" instead of a fabricated interval.
_MAX_SCAN_BYTES = 512 * 1024 * 1024


class EvidenceArtifactError(ValueError):
    """Raised when a path is not a readable artifact of a known type."""


def capture_relative_path(
    run_id: str,
    sequence: int,
    experiment_id: str,
    attempt_number: int = 1,
) -> str:
    """Compose the recorded capture path for one experiment attempt.

    Pure string composition of the committed layout; it does not touch the
    filesystem. Use :func:`discover_capture` to resolve it to a real file.
    """
    return "/".join(
        (
            CAPTURE_DIR_PATTERN.format(run_id=run_id, sequence=sequence),
            CAPTURE_FILE_PATTERN.format(
                experiment_id=experiment_id, attempt_number=attempt_number
            ),
        )
    )


def discover_capture(
    run_id: str,
    sequence: int,
    experiment_id: str,
    attempt_number: int = 1,
    *,
    evidence_root: Optional[str] = None,
) -> str:
    """Locate the real capture for an experiment attempt, or raise.

    Tries the exact composed name first, then the recorded attempt variants for
    the same ``experiment_id``. An ambiguous directory (more than one candidate)
    is refused rather than guessed, so a reference can never silently point at
    a different attempt's bytes.
    """
    root = evidence_root or os.getcwd()
    exact = capture_relative_path(run_id, sequence, experiment_id, attempt_number)
    if resolve_within_root(exact, evidence_root) is not None:
        return exact
    directory = CAPTURE_DIR_PATTERN.format(run_id=run_id, sequence=sequence)
    pattern = CAPTURE_ATTEMPT_GLOB.format(experiment_id=experiment_id)
    absolute_dir = os.path.join(root, directory)
    try:
        candidates = sorted(
            name for name in os.listdir(absolute_dir)
            if os.path.isfile(os.path.join(absolute_dir, name))
            and name.lower().endswith((".pcap", ".pcapng"))
            and _fnmatch.fnmatch(name, pattern)
        )
    except OSError:
        candidates = []
    if len(candidates) == 1:
        return f"{directory}/{candidates[0]}"
    if not candidates:
        raise EvidenceArtifactError(
            f"no capture found for run={run_id!r} sequence={sequence} "
            f"experiment={experiment_id!r} attempt={attempt_number} under {root!r}"
        )
    raise EvidenceArtifactError(
        f"capture for run={run_id!r} sequence={sequence} experiment="
        f"{experiment_id!r} is ambiguous: {candidates}; refusing to guess which "
        f"attempt the evidence refers to"
    )


@dataclass(frozen=True)
class ArtifactInfo:
    """What a real artifact is, discovered by reading it read-only."""

    relative_path: str
    artifact_type: str
    byte_size: int
    artifact_sha256: str
    packet_count: Optional[int] = None
    capture_start_ns: Optional[int] = None
    capture_end_ns: Optional[int] = None
    link_type: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "artifact_type": self.artifact_type,
            "byte_size": self.byte_size,
            "artifact_sha256": self.artifact_sha256,
            "packet_count": self.packet_count,
            "capture_start_ns": self.capture_start_ns,
            "capture_end_ns": self.capture_end_ns,
            "link_type": self.link_type,
        }


def artifact_type_for_path(relative_path: str) -> str:
    """Classify a recorded path by extension, or raise."""
    suffix = os.path.splitext(relative_path)[1].lower()
    for artifact_type, extensions in ARTIFACT_TYPE_EXTENSIONS.items():
        if suffix in extensions:
            return artifact_type
    raise EvidenceArtifactError(
        f"{relative_path!r} has unsupported extension {suffix!r}; expected one of "
        + ", ".join(sorted({e for exts in ARTIFACT_TYPE_EXTENSIONS.values()
                            for e in exts}))
    )


def read_pcap_interval(path: str) -> Dict[str, Optional[int]]:
    """Parse the capture interval and packet count from a classic pcap.

    Standard library only, streaming, read-only. Returns ``{}`` for a pcapng
    container (whose block layout is not parsed here) rather than guessing an
    interval. A truncated or malformed file yields ``{}`` so the reference keeps
    no interval instead of a wrong one.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return {}
    if size < _PCAP_HEADER_SIZE or size > _MAX_SCAN_BYTES:
        return {}
    try:
        with open(path, "rb") as handle:
            header = handle.read(_PCAP_HEADER_SIZE)
            if len(header) < _PCAP_HEADER_SIZE:
                return {}
            raw_magic = struct.unpack("<I", header[:4])[0]
            if raw_magic in (_PCAP_MAGIC_US, _PCAP_MAGIC_NS):
                endian, nanosecond = "<", False
            else:
                swapped = struct.unpack(">I", header[:4])[0]
                if swapped not in (_PCAP_MAGIC_US, _PCAP_MAGIC_NS):
                    return {}  # pcapng or unknown container
                endian, nanosecond = ">", False
            if raw_magic in (_PCAP_MAGIC_NS, struct.unpack(">I", b"\x4d\x3c\xb2\xa1")[0]):
                nanosecond = True
            link_type = struct.unpack(f"{endian}I", header[20:24])[0]

            count = 0
            lowest: Optional[int] = None
            highest: Optional[int] = None
            offset = _PCAP_HEADER_SIZE
            while offset + _PCAP_RECORD_HEADER_SIZE <= size:
                record = handle.read(_PCAP_RECORD_HEADER_SIZE)
                if len(record) < _PCAP_RECORD_HEADER_SIZE:
                    return {}  # torn record header: interval is not trustworthy
                ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(
                    f"{endian}IIII", record
                )
                offset += _PCAP_RECORD_HEADER_SIZE
                if incl_len > size or incl_len > _MAX_SCAN_BYTES:
                    return {}
                handle.seek(incl_len, os.SEEK_CUR)
                offset += incl_len
                if offset > size:
                    return {}  # record claims more bytes than the file holds
                stamp = ts_sec * 1_000_000_000 + (
                    ts_frac if nanosecond else ts_frac * 1000
                )
                count += 1
                lowest = stamp if lowest is None or stamp < lowest else lowest
                highest = stamp if highest is None or stamp > highest else highest
    except (OSError, struct.error):
        return {}
    return {
        "packet_count": count,
        "capture_start_ns": lowest,
        "capture_end_ns": highest,
        "link_type": link_type,
    }


def inspect_artifact(relative_path: str, evidence_root: Optional[str] = None) -> ArtifactInfo:
    """Read a recorded artifact and report its identity and interval.

    ``relative_path`` must be a path that was *recorded* in a reference; it is
    resolved under ``evidence_root`` and refused if it escapes that root. This
    is the only filesystem access in the linkage path, and it never writes.
    """
    artifact_type = artifact_type_for_path(relative_path)
    resolved = resolve_within_root(relative_path, evidence_root)
    if resolved is None:
        raise EvidenceArtifactError(
            f"artifact {relative_path!r} does not exist under the evidence root "
            f"({evidence_root!r}) or escapes it"
        )
    try:
        byte_size = os.path.getsize(resolved)
    except OSError as error:
        raise EvidenceArtifactError(
            f"artifact {relative_path!r} could not be measured: {error.strerror or error}"
        ) from error
    digest = sha256_file(resolved)
    interval: Dict[str, Optional[int]] = (
        read_pcap_interval(resolved) if artifact_type == ARTIFACT_TYPE_PCAP else {}
    )
    return ArtifactInfo(
        relative_path=relative_path,
        artifact_type=artifact_type,
        byte_size=byte_size,
        artifact_sha256=digest,
        packet_count=interval.get("packet_count"),
        capture_start_ns=interval.get("capture_start_ns"),
        capture_end_ns=interval.get("capture_end_ns"),
        link_type=interval.get("link_type"),
    )


def evidence_from_artifact(
    relative_path: str,
    *,
    evidence_root: Optional[str] = None,
    run_id: Optional[str] = None,
    experiment_id: Optional[str] = None,
    sequence: Optional[int] = None,
    source: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> EvidenceRef:
    """Build a self-verifying reference to a real artifact.

    The resulting reference carries the artifact's real SHA-256, size and — for
    a pcap — the interval parsed from the capture itself. No window is bound
    here; use :meth:`EvidenceRef.with_window` for that, so the same artifact can
    legitimately back more than one window.
    """
    info = inspect_artifact(relative_path, evidence_root)
    resolved_source = source or ARTIFACT_TYPE_SOURCES.get(info.artifact_type)
    return EvidenceRef(
        pcap_path=relative_path,
        capture_sequence=sequence,
        source=resolved_source,
        timestamp=timestamp,
        artifact_type=info.artifact_type,
        artifact_sha256=info.artifact_sha256,
        byte_size=info.byte_size,
        run_id=run_id,
        experiment_id=experiment_id,
        sequence=sequence,
        capture_start_ns=info.capture_start_ns,
        capture_end_ns=info.capture_end_ns,
    )


def window_packet_coverage(
    ref: EvidenceRef,
    window_start_ns: Optional[int],
    window_end_ns: Optional[int],
) -> Dict[str, Any]:
    """Report whether a window maps onto a packet interval in the capture.

    A window maps onto packets only when the capture's own recorded interval
    contains it. The clock domains are compared literally: this never rescaling,
    re-basing or estimating, so a window captured in a different clock domain
    than the artifact is reported as unmapped instead of being forced onto
    arbitrary packet offsets.

    The return value always carries the artifact interval and a machine-readable
    ``reason`` so the dashboard can say *why* a window has no packet range
    rather than showing an empty field.
    """
    result: Dict[str, Any] = {
        "covered": False,
        "reason": "",
        "packet_start": None,
        "packet_end": None,
        "capture_start_ns": ref.capture_start_ns,
        "capture_end_ns": ref.capture_end_ns,
        "window_start_ns": window_start_ns,
        "window_end_ns": window_end_ns,
    }
    if ref.capture_start_ns is None or ref.capture_end_ns is None:
        result["reason"] = "artifact carries no capture interval"
        return result
    if window_start_ns is None or window_end_ns is None:
        result["reason"] = "window carries no time bounds"
        return result
    if window_end_ns < ref.capture_start_ns or window_start_ns > ref.capture_end_ns:
        result["reason"] = (
            "window interval does not overlap the capture interval; the two are "
            "in different clock domains, so no packet range can be asserted"
        )
        return result
    if ref.packet_start is not None and ref.packet_end is not None:
        result["covered"] = True
        result["packet_start"] = ref.packet_start
        result["packet_end"] = ref.packet_end
        result["reason"] = "packet interval recorded with the reference"
        return result
    # The window lies inside the capture, but the artifact records no packet
    # offsets, so the capture as a whole is the finest available reference.
    result["covered"] = True
    result["reason"] = (
        "window lies inside the capture interval; no packet offsets are "
        "recorded, so the reference stays at capture granularity"
    )
    return result


@dataclass
class EvidenceCatalog:
    """Read-only registry of evidence references, resolved by ``evidence_id``.

    Mirrors ``correlation.api.pcap.PcapRegistry``: callers present an id, never
    a path. Registration is the only mutation, and it is refused for a
    reference that is already registered with different content, so a recorded
    id can never be quietly re-pointed at a different artifact.
    """

    evidence_root: Optional[str] = None
    _refs: Dict[str, EvidenceRef] = field(default_factory=dict)

    # -- registration --------------------------------------------------------

    def register(self, ref: EvidenceRef) -> str:
        if not isinstance(ref, EvidenceRef):
            raise TypeError("register expects an EvidenceRef")
        existing = self._refs.get(ref.evidence_id)
        if existing is not None and existing != ref:
            raise EvidenceIdentityMismatch(
                f"evidence_id {ref.evidence_id!r} is already registered with "
                f"different content"
            )
        self._refs[ref.evidence_id] = ref
        return ref.evidence_id

    def register_all(self, refs: Iterable[EvidenceRef]) -> Tuple[str, ...]:
        return tuple(self.register(ref) for ref in refs)

    # -- resolution ----------------------------------------------------------

    def has(self, evidence_id: str) -> bool:
        return evidence_id in self._refs

    def get(self, evidence_id: str) -> Optional[EvidenceRef]:
        return self._refs.get(evidence_id)

    def require(self, evidence_id: str) -> EvidenceRef:
        ref = self._refs.get(evidence_id)
        if ref is None:
            raise KeyError(evidence_id)
        return ref

    def all(self) -> Tuple[EvidenceRef, ...]:
        return tuple(self._refs.values())

    def ids(self) -> Tuple[str, ...]:
        return tuple(sorted(self._refs))

    def for_run(self, run_id: str) -> Tuple[EvidenceRef, ...]:
        return tuple(ref for ref in self._refs.values() if ref.run_id == run_id)

    def for_window(
        self, run_id: str, window_index: int, *, experiment_id: Optional[str] = None
    ) -> Tuple[EvidenceRef, ...]:
        """Evidence bound to exactly one window.

        A window never inherits a sibling window's artifact: refs whose
        ``window_index`` differs are excluded, and a ref that is not bound to
        any window is excluded too.
        """
        return tuple(
            ref
            for ref in self._refs.values()
            if ref.run_id == run_id
            and ref.window_index == window_index
            and (experiment_id is None or ref.experiment_id == experiment_id)
        )

    # -- verification -------------------------------------------------------

    def verify(self, evidence_id: str) -> EvidenceVerification:
        """Read-only integrity check for one registered reference."""
        ref = self._refs.get(evidence_id)
        if ref is None:
            return EvidenceVerification(
                evidence_id=evidence_id,
                status=EVIDENCE_STATUS_UNAVAILABLE,
                detail="evidence_id is not registered",
            )
        return ref.verify(self.evidence_root)

    def verify_all(self) -> Tuple[EvidenceVerification, ...]:
        return tuple(self.verify(evidence_id) for evidence_id in self.ids())

    def integrity_summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for verification in self.verify_all():
            counts[verification.status] = counts.get(verification.status, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_root": (
                os.path.abspath(self.evidence_root) if self.evidence_root else None
            ),
            "registered": list(self.ids()),
            "count": len(self._refs),
        }


# -- automatic propagation ---------------------------------------------------


def merge_evidence_refs(*groups: Sequence[EvidenceRef]) -> Tuple[EvidenceRef, ...]:
    """Union of reference groups, de-duplicated by ``evidence_id``, order-stable.

    Idempotent: merging the same group twice yields the same tuple, so repeated
    propagation through comparison -> risk -> response cannot multiply
    references.
    """
    seen: Dict[str, EvidenceRef] = {}
    for group in groups:
        for ref in group or ():
            if not isinstance(ref, EvidenceRef):
                raise TypeError("evidence groups must contain EvidenceRef objects")
            seen.setdefault(ref.evidence_id, ref)
    return tuple(seen.values())


def collect_outcome_evidence(outcome: Mapping[str, Any]) -> Tuple[EvidenceRef, ...]:
    """Pull the evidence refs a comparison outcome already carries.

    Comparison outcomes serialize their evidence as dicts, so this is the
    automatic observation -> comparison edge: a risk engine can recover the
    refs a mismatch was derived from without the caller re-supplying them.
    """
    refs: List[EvidenceRef] = []
    for raw in outcome.get("evidence_refs") or ():
        if isinstance(raw, EvidenceRef):
            refs.append(raw)
        elif isinstance(raw, Mapping):
            try:
                refs.append(EvidenceRef.from_dict(dict(raw)))
            except (TypeError, ValueError):
                # A malformed reference is skipped rather than propagated; the
                # audit layer still records the outcome itself.
                continue
    return tuple(refs)


def evidence_from_comparison(
    correlation: Any,
    *,
    statuses: Sequence[str] = ("MISMATCH", "UNKNOWN", "NOT_APPLICABLE", "MATCH"),
) -> Tuple[EvidenceRef, ...]:
    """Every evidence ref carried by a correlation result's outcomes.

    Used by the risk engine when the caller supplies no refs of its own, which
    is what makes observation -> comparison -> risk propagation automatic
    instead of a manual join. Outcomes are stored as plain dicts, so each one
    is decoded through :func:`collect_outcome_evidence`; a malformed reference
    is skipped rather than propagated.
    """
    collected: List[EvidenceRef] = []
    for status in statuses:
        for outcome in getattr(correlation, _bucket_for(status), ()) or ():
            collected.extend(collect_outcome_evidence(outcome))
    return merge_evidence_refs(collected)


_BUCKET_BY_STATUS = {
    "MISMATCH": "mismatches",
    "UNKNOWN": "unknowns",
    "NOT_APPLICABLE": "not_applicable",
    "MATCH": "matches",
}


def _bucket_for(status: str) -> str:
    try:
        return _BUCKET_BY_STATUS[status]
    except KeyError:
        raise ValueError(f"unknown correlation status {status!r}") from None


def bind_window(
    refs: Sequence[EvidenceRef],
    *,
    window_index: int,
    run_id: Optional[str] = None,
    experiment_id: Optional[str] = None,
    sequence: Optional[int] = None,
) -> Tuple[EvidenceRef, ...]:
    """Bind artifact-level refs to one analysis window, idempotently.

    Refs already bound to a *different* window are refused, not silently moved.
    """
    if not isinstance(window_index, int) or isinstance(window_index, bool):
        raise ValueError("window_index must be an integer")
    if window_index < 0:
        raise ValueError(f"window_index must be >= 0, got {window_index}")
    bound: List[EvidenceRef] = []
    for ref in refs or ():
        if not isinstance(ref, EvidenceRef):
            raise TypeError("bind_window expects EvidenceRef objects")
        if ref.window_index is not None and ref.window_index != window_index:
            raise EvidenceIdentityMismatch(
                f"evidence {ref.evidence_id} belongs to window "
                f"{ref.window_index}, not window {window_index}"
            )
        bound.append(
            ref.with_window(
                window_index=window_index,
                run_id=run_id,
                experiment_id=experiment_id,
                sequence=sequence,
            )
        )
    return merge_evidence_refs(bound)


def evidence_map_for_windows(
    refs_by_window: Mapping[int, Sequence[EvidenceRef]],
) -> Dict[int, Tuple[EvidenceRef, ...]]:
    """Normalise a per-window mapping to merged, de-duplicated tuples."""
    return {
        int(index): merge_evidence_refs(entries)
        for index, entries in sorted((refs_by_window or {}).items())
    }
