"""Phase 4: Expected-vs-Observed deterministic comparison engine.

Public surface:

    ComparisonEngine            ``compare(expected, observed, ...) -> CorrelationResult``
    ComparisonEngineOptions     engine configuration (clock domains; no thresholds)
    ComparisonOutcome           one per-variable comparison payload
    aggregate_status            deterministic overall-status pure function
    IdentityMismatchError       identity-safety failure raised before any comparison

Rule logic lives in ``rules.py``, evidence/discrepancy payloads in
``discrepancy.py``, and clock-domain abstraction in ``clock.py``.
"""

from .clock import (  # noqa: F401
    CLOCK_DOMAIN_LIVE_MONOTONIC_NS,
    CLOCK_DOMAIN_PCAP_EPOCH_NS,
    CLOCK_DOMAIN_UTC_EPOCH_NS,
    CLOCK_DOMAINS,
    ClockAlignment,
    ClockDomainError,
    domains_are_compatible,
    translate_ns,
    validate_clock_domain,
)
from .discrepancy import (  # noqa: F401
    COMPARISON_STATUSES,
    ComparisonOutcome,
    bucket_outcomes,
)
from .engine import (  # noqa: F401
    COMPARISON_ENGINE_VERSION,
    IdentityMismatchError,
    aggregate_status,
    assert_identity_compatible,
    identity_mismatch_reason,
)
from .engine import ComparisonEngine, ComparisonEngineOptions

__all__ = [
    "CLOCK_DOMAIN_LIVE_MONOTONIC_NS",
    "CLOCK_DOMAIN_PCAP_EPOCH_NS",
    "CLOCK_DOMAIN_UTC_EPOCH_NS",
    "CLOCK_DOMAINS",
    "ClockAlignment",
    "ClockDomainError",
    "domains_are_compatible",
    "translate_ns",
    "validate_clock_domain",
    "COMPARISON_STATUSES",
    "ComparisonOutcome",
    "bucket_outcomes",
    "COMPARISON_ENGINE_VERSION",
    "IdentityMismatchError",
    "aggregate_status",
    "assert_identity_compatible",
    "identity_mismatch_reason",
    "ComparisonEngine",
    "ComparisonEngineOptions",
]