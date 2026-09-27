"""Chain of custody for security findings (read-only, derived, deterministic).

The custody layer answers the auditor's question -- *prove the finding to me* --
by assembling, for exactly one finding in exactly one assessment, the ordered
authoritative inputs, the rule that fired, the observed/expected/derived split,
the content-addressed evidence, the derivation steps and the integrity checks.

It is a presentation and verification layer over objects the pipeline already
produced. It runs no detection, changes no score, invents no evidence, proposes
no control and mutates nothing. See :mod:`correlation.custody.models` for the
authority vocabulary and :mod:`correlation.custody.builder` for the mapping rules
and the observation-honesty guarantees.
"""

from .builder import build_chain_of_custody, canonical_digest  # noqa: F401
from .models import (  # noqa: F401
    AUTHORITY_DERIVED,
    AUTHORITY_OBSERVATION,
    AUTHORITY_PLAN,
    AUTHORITY_PROPOSED,
    AUDIT_LINKED,
    AUDIT_LINKAGE_STATUSES,
    AUDIT_UNAVAILABLE,
    CATEGORY_AUTHORITY,
    CHECK_FAIL,
    CHECK_NOT_APPLICABLE,
    CHECK_PASS,
    CHECK_STATUSES,
    CHECK_UNAVAILABLE,
    CUSTODY_COMPONENT,
    CUSTODY_COMPONENT_VERSION,
    CUSTODY_SCHEMA_VERSION,
    FACT_CATEGORIES,
    FACT_CONFIGURED,
    FACT_DERIVED,
    FACT_EXPECTED,
    FACT_OBSERVED,
    FACT_RECOMMENDED,
    AUTHORITATIVE_CATEGORIES,
    ChainOfCustody,
    CustodyEvidenceLink,
    CustodyFact,
    CustodyIntegrityCheck,
    CustodyProvenanceArtifact,
    CustodyRecommendation,
    CustodyRuleRef,
    CustodyStep,
    facts_by_category,
    validate_category,
    validate_check_status,
)
