"""PCAP evidence resolution + download (Phase 10).

Evidence downloads are ID-based, never path-based:

* callers present an ``evidence_id``; the API looks it up in a controlled
  registry that maps real evidence ids to recorded capture files;
* arbitrary filesystem paths, absolute paths, UNC paths, drive letters,
  ``..`` traversal and unexpected extensions are NEVER accepted;
* the resolved file must live under the configured evidence root AND its real
  (symlink-resolved) path must stay inside that root;
* only ``.pcap`` / ``.pcapng`` files are served, read-only;
* download activity is recorded (metrics counter + download log).

Never serve files not explicitly registered, and never fabricate a capture
for an evidence id that is not present.
"""

import ntpath
import os
import posixpath
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

ALLOWED_EXTENSIONS = (".pcap", ".pcapng")
ALLOWED_EVIDENCE_ID_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)


def validate_evidence_id(evidence_id: str) -> str:
    if not isinstance(evidence_id, str) or not evidence_id:
        raise ValueError("evidence_id must be a non-empty string")
    for ch in evidence_id:
        if ch not in ALLOWED_EVIDENCE_ID_CHARS:
            raise ValueError(
                f"evidence_id {evidence_id!r} contains disallowed character {ch!r}"
            )
    if ".." in evidence_id:
        raise ValueError("evidence_id may not contain '..'")
    return evidence_id


def _is_unsafe_path(filename: str) -> bool:
    """True when a registered filename is a traversal / absolute / UNC escape."""
    if not isinstance(filename, str) or not filename:
        return True
    name = filename.replace("\\", "/")
    if name.startswith("/") or name.startswith("//"):
        return True
    if ":" in name[:2]:
        return True  # drive letter or scheme prefix
    if ntpath.isabs(filename) or posixpath.isabs(filename):
        return True
    parts = name.split("/")
    if any(part == ".." for part in parts):
        return True
    if any(part in ("", ".") for part in parts[:-1]):
        return True
    if filename.lstrip().startswith("\\\\") and ntpath.splitdrive(filename)[0]:
        return True
    return False


def _within(root: str, candidate: str) -> bool:
    root_abs = os.path.abspath(os.path.join(os.path.abspath(root), ""))
    candidate_abs = os.path.abspath(candidate)
    return candidate_abs.startswith(root_abs + os.sep) or candidate_abs == root_abs


@dataclass
class PcapRegistry:
    """Evidence-id -> capture-file registry (the ONLY path source)."""

    root: str
    _mapping: Dict[str, str] = field(default_factory=dict)
    _references: Dict[str, Any] = field(default_factory=dict)

    def register(self, evidence_id: str, filename: str) -> str:
        validate_evidence_id(evidence_id)
        if _is_unsafe_path(filename):
            raise ValueError(
                f"filename {filename!r} is not a plain capture file name"
            )
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise ValueError(
                f"filename {filename!r} must end with one of "
                f"{ALLOWED_EXTENSIONS}"
            )
        self._mapping[evidence_id] = filename
        return filename

    def register_reference(self, ref: Any) -> str:
        """Register an ``EvidenceRef`` for metadata/verification lookups.

        This is deliberately separate from :meth:`register`: a reference is
        metadata about an artifact, not a path, so it is not accepted as a
        download source. The bytes served by :meth:`PcapService.download` still
        come only from the hardened ``register`` mapping.
        """
        from ..models.evidence import EvidenceRef

        if not isinstance(ref, EvidenceRef):
            raise TypeError("register_reference expects an EvidenceRef")
        # A registered reference must itself be a safe, id-addressed entry so
        # the metadata API cannot become a path oracle.
        validate_evidence_id(ref.evidence_id)
        self._references[ref.evidence_id] = ref
        return ref.evidence_id

    def reference(self, evidence_id: str) -> Optional[Any]:
        """The registered ``EvidenceRef`` for an id, or None."""
        try:
            validate_evidence_id(evidence_id)
        except ValueError:
            return None
        return self._references.get(evidence_id)

    def references(self) -> Dict[str, Any]:
        return dict(self._references)

    def resolve(self, evidence_id: str) -> Optional[str]:
        """Resolve + harden; returns an absolute path or None (404/deny)."""
        try:
            validate_evidence_id(evidence_id)
        except ValueError:
            return None
        filename = self._mapping.get(evidence_id)
        if filename is None:
            return None
        if _is_unsafe_path(filename):
            return None
        candidate = os.path.join(os.path.abspath(self.root), filename)
        if not _within(self.root, candidate):
            return None
        if not os.path.isfile(candidate):
            return None
        # symlink escape hardening: real path must stay under the root
        try:
            real = os.path.realpath(candidate)
        except OSError:
            return None
        if not _within(os.path.abspath(self.root), real):
            return None
        return candidate

    def has(self, evidence_id: str) -> bool:
        return evidence_id in self._mapping

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root": os.path.abspath(self.root),
            "registered": sorted(self._mapping),
            "references": sorted(self._references),
        }


@dataclass
class PcapService:
    """Read-only evidence download service."""

    registry: PcapRegistry
    _downloads: List[Dict[str, Any]] = field(default_factory=list)

    def download(self, evidence_id: str) -> Optional[bytes]:
        path = self.registry.resolve(evidence_id)
        if path is None:
            return None
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError:
            return None
        self._downloads.append(
            {"evidence_id": evidence_id, "bytes": len(data), "resolved_path": path}
        )
        return data

    def verify(self, evidence_id: str) -> Optional[Any]:
        """Read-only integrity report for a registered reference.

        Returns None when no reference is registered for the id. The bytes are
        never returned here and the artifact is never repaired: a changed
        artifact is reported as ``invalid``.
        """
        ref = self.registry.reference(evidence_id)
        if ref is None:
            return None
        return ref.verify(self.registry.root or None)

    def recent_downloads(self, limit: int = 20) -> List[Dict[str, Any]]:
        return list(self._downloads)[-limit:]

    @property
    def download_count(self) -> int:
        return len(self._downloads)