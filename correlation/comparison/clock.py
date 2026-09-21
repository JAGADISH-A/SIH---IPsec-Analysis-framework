"""Explicit clock-domain handling for expected-vs-observed comparison.

Phase 1 discovered the clock-domain mismatch between the two observation
surfaces:

* live state/event timestamps come from ``bpf_ktime_get_ns()`` — a
  **boot-time monotonic** clock (``LIVE_MONOTONIC_NS``),
* offline PCAP timestamps are **epoch-based** (``PCAP_EPOCH_NS``),
* planning/campaign timestamps are wall-clock **UTC** (``UTC_EPOCH_NS``).

Phase 4 NEVER invents an offset and NEVER performs automatic clock
synchronization. A cross-domain comparison requires an EXPLICIT
``ClockAlignment`` supplied by the caller (the audit/instrumentation layer that
owns the calibration). Without a valid alignment, time-dependent comparisons
return ``UNKNOWN``.

    value_in_to_domain_ns = value_in_from_domain_ns + offset_ns
"""

from dataclasses import dataclass
from typing import Optional

CLOCK_DOMAIN_LIVE_MONOTONIC_NS = "LIVE_MONOTONIC_NS"
CLOCK_DOMAIN_PCAP_EPOCH_NS = "PCAP_EPOCH_NS"
CLOCK_DOMAIN_UTC_EPOCH_NS = "UTC_EPOCH_NS"
CLOCK_DOMAINS = (
    CLOCK_DOMAIN_LIVE_MONOTONIC_NS,
    CLOCK_DOMAIN_PCAP_EPOCH_NS,
    CLOCK_DOMAIN_UTC_EPOCH_NS,
)


class ClockDomainError(ValueError):
    """Raised when a timestamp or alignment references an unknown clock domain
    or when two timestamps in different domains are compared without a valid
    alignment."""


def validate_clock_domain(domain: str) -> str:
    if domain not in CLOCK_DOMAINS:
        raise ClockDomainError(
            f"unknown clock domain {domain!r}; known: {CLOCK_DOMAINS}"
        )
    return domain


@dataclass(frozen=True)
class ClockAlignment:
    """Explicit, caller-supplied translation between two clock domains.

    ``offset_ns`` is sign-sensitive: ``value_in_to_domain = value_in_from_domain + offset_ns``.
    ``description`` is a human-readable provenance note explaining who measured
    the offset (e.g. "bpf ktime vs system boot time measured on host 2026-09-19").
    """

    from_domain: str
    to_domain: str
    offset_ns: int
    description: str = ""

    def __post_init__(self) -> None:
        validate_clock_domain(self.from_domain)
        validate_clock_domain(self.to_domain)
        if self.from_domain == self.to_domain:
            raise ClockDomainError(
                f"ClockAlignment from_domain and to_domain must differ "
                f"({self.from_domain!r} == {self.to_domain!r})"
            )
        if isinstance(self.offset_ns, bool) or not isinstance(self.offset_ns, int):
            raise ClockDomainError("offset_ns must be an integer expression")

    def aligned_ns(self, value_ns: int) -> int:
        """Translate ``value_ns`` (in ``from_domain``) into ``to_domain``."""
        if isinstance(value_ns, bool) or not isinstance(value_ns, int):
            raise ClockDomainError(f"value_ns must be an integer, got {value_ns!r}")
        return value_ns + self.offset_ns


def domains_are_compatible(
    window_domain: str,
    observed_domain: str,
    alignment: Optional[ClockAlignment],
) -> bool:
    """True when values in ``window_domain`` can be compared with values in
    ``observed_domain`` — either the same domain, or a valid alignment that
    connects the window domain to the observed domain."""
    window_domain = validate_clock_domain(window_domain)
    observed_domain = validate_clock_domain(observed_domain)
    if window_domain == observed_domain:
        return True
    if alignment is None:
        return False
    return (
        alignment.from_domain == window_domain
        and alignment.to_domain == observed_domain
    )


def translate_ns(value_ns: int, window_domain: str, alignment: ClockAlignment) -> int:
    """Translate ``value_ns`` from ``window_domain`` into the alignment target
    domain using a validated alignment."""
    if not domains_are_compatible(window_domain, alignment.to_domain, alignment):
        raise ClockDomainError(
            f"alignment {alignment.from_domain}->{alignment.to_domain} does not "
            f"connect window domain {window_domain} to observed domain "
            f"{alignment.to_domain!r}"
        )
    return value_ns + alignment.offset_ns