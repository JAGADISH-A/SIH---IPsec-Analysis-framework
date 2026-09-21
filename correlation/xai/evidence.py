"""Evidence explanation builder (Phase 7).

Preserves evidence references EXACTLY, aggregating the references that already
exist across the inputs (assessment-level refs, refs passed by the explain
caller, and refs carried by the risk findings / phase-4 outcomes). References
are deduplicated by a canonical key and sorted deterministically. Nothing is
ever fabricated.
"""

from typing import Any, Optional, Sequence, Tuple

from ..models.evidence import EvidenceRef
from .models import EvidenceSummary, PROVENANCE_EVIDENCE
from .templates import build_evidence_refs, evidence_limitation, evidence_source_counts


def build_evidence_summary(
    assessment_refs: Sequence,
    caller_refs: Sequence = (),
    finding_refs: Sequence = (),
) -> EvidenceSummary:
    """Deterministic EvidenceSummary from existing references only."""
    for collection in (assessment_refs, caller_refs, finding_refs):
        for ref in collection:
            if not isinstance(ref, EvidenceRef):
                raise ValueError(
                    "evidence references must be EvidenceRef objects; "
                    "refuse to fabricate or coerce arbitrary input"
                )
    refs = build_evidence_refs(assessment_refs, caller_refs, finding_refs)
    return EvidenceSummary(
        provenance=PROVENANCE_EVIDENCE,
        total_refs=len(refs),
        refs=tuple(dict(ref.to_dict()) for ref in refs),
        sources=tuple(sorted({ref.source or "unspecified" for ref in refs})),
        source_counts=evidence_source_counts(refs),
        limitation=evidence_limitation(len(refs)),
        fabricated=False,
    )


def refs_like(refs: Sequence) -> Tuple[EvidenceRef, ...]:
    """Materialize the tuple of EvidenceRef used as an EvidenceSummary input."""
    return tuple(refs)