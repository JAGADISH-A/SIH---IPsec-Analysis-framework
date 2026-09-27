"""Passive SA / tunnel identity contract (multi-SA correlation).

Why this model exists
---------------------
A gateway may carry several simultaneous IPsec Security Associations that share
one transport:

    Gateway
       +-- SA-A -> peer A -> UDP/4500 -> SPI-A
       +-- SA-B -> peer B -> UDP/4500 -> SPI-B
       +-- SA-C -> peer C -> UDP/4500 -> SPI-C

UDP/500 and UDP/4500 are therefore *transport indicators*, never tunnel
identifiers.  Anything that keys a "tunnel" on a UDP port collapses distinct
SAs into one false tunnel.  This model carries the most specific identity the
passive evidence actually supports, and it preserves uncertainty instead of
inventing a name.

RFC 4303 SA selector
--------------------
An IPsec SA is selected by ``(destination address, security protocol, SPI)``.
That triple is the strongest identity a passive observer can reach for ESP/AH,
so it is the primary correlation key here.  The *outer source* address is
carried as well because it disambiguates direction, and the unordered endpoint
pair is what ties both directions of one SA together.

IKE is different on purpose
---------------------------
IKE packets carry **no SPI**, so an IKE exchange cannot be joined to an ESP SA
from passive evidence alone.  IKE is therefore modelled as its own identity
kind (``:data:`KIND_IKE_CONTEXT``) rather than being forced into the ESP SA
shape.  :attr:`SaIdentity.joins_spi` is ``False`` for it, so no downstream
layer can quietly pretend an IKE context *is* an SA.

Uncertainty is a value, not an error
------------------------------------
Three states, all of them legitimate outputs:

``RESOLVED``    the evidence uniquely identifies one SA.
``AMBIGUOUS``   several SAs remain possible; ``candidates`` lists them.
``UNKNOWN``     the evidence cannot name any SA; ``reason`` says why.

Nothing here raises because evidence was thin, and nothing here falls back to a
UDP port.  A caller that needs a single SA can check
:attr:`SaIdentity.is_resolved`; a caller that wants to group *all* observations
can use :attr:`SaIdentity.group_key`, which is stable for resolved and
ambiguous identities alike so ambiguous traffic is preserved in its own bucket
instead of being merged into a neighbouring SA.

Never authoritative
-------------------
An :class:`SaIdentity` is an *observation*.  It is derived exclusively from
observed packet evidence (outer addresses, protocol, SPI, ports, timestamps).
Expected configuration is never consulted, and no field may be filled from a
plan.  Like every other observation in this project it carries no authority over
the network.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from ._base import JsonModel

__all__ = [
    "DIRECTION_INBOUND",
    "DIRECTION_OUTBOUND",
    "KIND_AH_SA",
    "KIND_ESP_SA",
    "KIND_IKE_CONTEXT",
    "KIND_UNRESOLVED",
    "PROTO_AH",
    "PROTO_ESP",
    "PROTO_IKE",
    "PROTO_IKE_NAT_T",
    "REASON_AMBIGUOUS_KEPT_SEPARATE",
    "REASON_AMBIGUOUS_PEER_SET",
    "REASON_IKE_HAS_NO_SPI",
    "REASON_MULTIPLE_SAS_ON_PEER",
    "REASON_NO_OUTER_ENDPOINTS",
    "REASON_NO_SPI_AVAILABLE",
    "REASON_SPI_REUSED_ACROSS_PEERS",
    "SA_AMBIGUOUS_GROUP_PREFIX",
    "SA_DIRECTIONS",
    "SA_KINDS",
    "SA_REASONS",
    "SA_STATES",
    "SA_UNKNOWN_GROUP",
    "STATE_AMBIGUOUS",
    "STATE_RESOLVED",
    "STATE_UNKNOWN",
    "SaIdentity",
    "endpoint_pair",
    "format_spi",
]

# -- resolution states --------------------------------------------------------
STATE_RESOLVED = "RESOLVED"
STATE_AMBIGUOUS = "AMBIGUOUS"
STATE_UNKNOWN = "UNKNOWN"
SA_STATES = (STATE_RESOLVED, STATE_AMBIGUOUS, STATE_UNKNOWN)

# -- identity kinds -----------------------------------------------------------
KIND_ESP_SA = "ESP_SA"
KIND_AH_SA = "AH_SA"
KIND_IKE_CONTEXT = "IKE_CONTEXT"
KIND_UNRESOLVED = "UNRESOLVED"
SA_KINDS = (KIND_ESP_SA, KIND_AH_SA, KIND_IKE_CONTEXT, KIND_UNRESOLVED)

# -- explicit, machine-readable uncertainty reasons ----------------------------
# These are part of the contract: a consumer can branch on them, and a report
# can quote them verbatim instead of paraphrasing "something went wrong".
REASON_NO_OUTER_ENDPOINTS = "no_outer_endpoints"
REASON_NO_SPI_AVAILABLE = "no_spi_available"
REASON_MULTIPLE_SAS_ON_PEER = "multiple_sas_on_peer"
REASON_SPI_REUSED_ACROSS_PEERS = "spi_reused_across_peers"
REASON_AMBIGUOUS_PEER_SET = "ambiguous_peer_set"
REASON_AMBIGUOUS_KEPT_SEPARATE = "ambiguous_kept_separate"
REASON_IKE_HAS_NO_SPI = "ike_carries_no_spi"
SA_REASONS = (
    REASON_NO_OUTER_ENDPOINTS,
    REASON_NO_SPI_AVAILABLE,
    REASON_MULTIPLE_SAS_ON_PEER,
    REASON_SPI_REUSED_ACROSS_PEERS,
    REASON_AMBIGUOUS_PEER_SET,
    REASON_AMBIGUOUS_KEPT_SEPARATE,
    REASON_IKE_HAS_NO_SPI,
)

# -- direction labels (observed, never inferred from configuration) ------------
DIRECTION_OUTBOUND = "OUTBOUND"
DIRECTION_INBOUND = "INBOUND"
SA_DIRECTIONS = (DIRECTION_OUTBOUND, DIRECTION_INBOUND)

#: Bucket keys used by :attr:`SaIdentity.group_key` when identity is not
#: resolved.  Uncertain traffic gets its own bucket so it stays visible as its
#: own record instead of being merged into a neighbouring SA or dropped.
SA_AMBIGUOUS_GROUP_PREFIX = "sa-ambiguous:"
SA_UNKNOWN_GROUP = "sa-unknown"

#: Protocol labels this contract can resolve an identity for.
PROTO_ESP = "ESP"
PROTO_AH = "AH"
PROTO_IKE = "IKE"
PROTO_IKE_NAT_T = "IKE-NAT-T"

#: IP protocol numbers for the two encapsulating security protocols.
IPPROTO_ESP = 50
IPPROTO_AH = 51
IPPROTO_UDP = 17

#: Transport ports.  Recorded as context, never used as an identity component.
UDP_500 = 500
UDP_4500 = 4500


def format_spi(spi: int) -> str:
    """Canonical lowercase hex form of a 32-bit SPI (``0x%08x``).

    Matches ``ebpf.ipsec_state_builder._hexspi`` so a state-builder SPI string
    and a correlation SPI string are the same token.
    """
    return "0x%08x" % (int(spi) & 0xFFFFFFFF)


def endpoint_pair(src: Optional[str], dst: Optional[str]) -> Optional[Tuple[str, str]]:
    """Order-independent outer endpoint pair, or ``None`` if either is absent.

    An SA is bidirectional, so its endpoint pair is the *unordered* set.  This is
    what ties the two directions of one SA together without relying on which
    side the capture point happens to sit on.
    """
    if not src or not dst:
        return None
    return (src, dst) if src <= dst else (dst, src)


@dataclass(frozen=True)
class SaIdentity(JsonModel):
    """Immutable passive identity for one observed packet/flow/SA.

    Two identifiers, because IPsec really has two levels:

    ``sa_group_id``  the **bidirectional** SA/tunnel relationship, keyed by the
        unordered outer endpoint pair plus the security protocol.  This is what
        a "tunnel" is operationally, and it is the level 100 ms feature windows
        and RF results are attributed to.
    ``sa_id``        the **child SA** selected by the RFC 4303 triple
        ``(destination address, security protocol, SPI)``.  A NAT-T SA has one
        of these per direction, so a single tunnel normally contributes two.

    ``sa_id`` is a deterministic, human-readable token derived only from
    observed evidence, and is ``None`` unless :attr:`state` is ``RESOLVED``.
    """

    state: str = STATE_UNKNOWN
    kind: str = KIND_UNRESOLVED
    sa_id: Optional[str] = None
    sa_group_id: Optional[str] = None
    reason: Optional[str] = None
    protocol: Optional[str] = None
    outer_src: Optional[str] = None
    outer_dst: Optional[str] = None
    peer: Optional[str] = None
    spi: Optional[str] = None
    direction: Optional[str] = None
    transport_port: Optional[int] = None
    ip_protocol: Optional[int] = None
    candidates: Tuple[str, ...] = ()
    evidence_fields: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.state not in SA_STATES:
            raise ValueError(f"state must be one of {SA_STATES}, got {self.state!r}")
        if self.kind not in SA_KINDS:
            raise ValueError(f"kind must be one of {SA_KINDS}, got {self.kind!r}")
        if self.reason is not None and self.reason not in SA_REASONS:
            raise ValueError(f"reason must be one of {SA_REASONS} or None, got {self.reason!r}")
        if self.state == STATE_RESOLVED:
            if not self.sa_id:
                raise ValueError("a RESOLVED SaIdentity requires a non-empty sa_id")
            if self.kind == KIND_UNRESOLVED:
                raise ValueError("a RESOLVED SaIdentity requires a concrete kind")
            if not self.sa_group_id:
                raise ValueError(
                    "a RESOLVED SaIdentity requires an sa_group_id: an SA is "
                    "bidirectional and both directions share one group"
                )
        else:
            # An unresolved identity must never carry an invented name.
            if self.sa_id is not None:
                raise ValueError(
                    f"a {self.state} SaIdentity must not carry an sa_id "
                    f"(got {self.sa_id!r}); naming an SA requires evidence"
                )
            if not self.reason:
                raise ValueError(
                    f"a {self.state} SaIdentity requires an explicit reason"
                )
        if self.kind in (KIND_ESP_SA, KIND_AH_SA) and self.state == STATE_RESOLVED:
            if not self.spi:
                raise ValueError(
                    f"a RESOLVED {self.kind} requires an observed SPI; SPI is "
                    "the RFC 4303 SA selector"
                )
        if self.candidates and self.state != STATE_AMBIGUOUS:
            raise ValueError(
                f"candidates are only meaningful for {STATE_AMBIGUOUS}, got "
                f"state={self.state!r}"
            )
        for name in ("transport_port", "ip_protocol"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
                raise ValueError(f"{name} must be an integer or None")
        if self.transport_port is not None and not (0 <= self.transport_port <= 65535):
            raise ValueError(
                f"transport_port must be within [0, 65535], got {self.transport_port}"
            )
        if self.direction is not None and self.direction not in SA_DIRECTIONS:
            raise ValueError(
                f"direction must be one of {SA_DIRECTIONS} or None, got {self.direction!r}"
            )

    # -- derived helpers ---------------------------------------------------- #

    @property
    def is_resolved(self) -> bool:
        return self.state == STATE_RESOLVED

    @property
    def is_ambiguous(self) -> bool:
        return self.state == STATE_AMBIGUOUS

    @property
    def is_unknown(self) -> bool:
        return self.state == STATE_UNKNOWN

    @property
    def joins_spi(self) -> bool:
        """True when this identity is SPI-selectable (ESP/AH).

        ``False`` for an IKE context, so no caller can join an IKE exchange to
        an ESP SA that passive evidence cannot prove.
        """
        return self.kind in (KIND_ESP_SA, KIND_AH_SA)

    @property
    def group_key(self) -> str:
        """Stable bucket key for grouping observations, resolved or not.

        Resolved identities bucket per **SA group** -- the bidirectional
        relationship, not the individual child SA.  A NAT-T SA has one SPI per
        direction (RFC 4303), and both directions describe the same tunnel, so
        one feature window must contain both directions exactly as the single-SA
        baseline did.  Ambiguous identities bucket per candidate *set* and
        unknown ones share a single bucket, so uncertain traffic is preserved
        and visible instead of being merged into a neighbouring SA or dropped.
        """
        if self.state == STATE_RESOLVED:
            return self.sa_group_id or self.sa_id or ""
        if self.state == STATE_AMBIGUOUS:
            return SA_AMBIGUOUS_GROUP_PREFIX + "+".join(sorted(self.candidates))
        return SA_UNKNOWN_GROUP

    @property
    def endpoint_pair(self) -> Optional[Tuple[str, str]]:
        return endpoint_pair(self.outer_src, self.outer_dst)

    def with_observation(self, *, direction: Optional[str] = None,
                         transport_port: Optional[int] = None) -> "SaIdentity":
        """Return a copy carrying additional observed context.

        ``direction`` / ``transport_port`` are recorded but never change
        :attr:`sa_id`: an SA is bidirectional, and the transport port is not an
        identifier.  Returns a new instance; the receiver is never mutated.
        """
        from dataclasses import replace

        return replace(
            self,
            direction=direction if direction is not None else self.direction,
            transport_port=(
                transport_port if transport_port is not None else self.transport_port
            ),
        )

    @classmethod
    def unknown(cls, reason: str, *, kind: str = KIND_UNRESOLVED,
                **context: Any) -> "SaIdentity":
        """Build an explicit ``UNKNOWN`` identity with a reason."""
        return cls(state=STATE_UNKNOWN, kind=kind, reason=reason, **context)

    @classmethod
    def ambiguous(cls, reason: str, candidates: Tuple[str, ...], *,
                  kind: str = KIND_UNRESOLVED, **context: Any) -> "SaIdentity":
        """Build an explicit ``AMBIGUOUS`` identity listing candidate SAs."""
        return cls(
            state=STATE_AMBIGUOUS,
            kind=kind,
            reason=reason,
            candidates=tuple(candidates),
            **context,
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SaIdentity":
        """Read an identity; a record without one becomes explicit ``UNKNOWN``.

        Backward compatibility: artifacts recorded before SA identity existed
        have no ``sa_identity`` field.  They load as ``UNKNOWN`` with
        ``REASON_NO_OUTER_ENDPOINTS`` rather than failing to load, and the
        original bytes are never rewritten.

        Accepts either the enclosing record (``{"sa_identity": {...}}``) or a
        bare identity mapping, so ``SaIdentity.from_dict(x.to_dict())`` is a
        true round-trip rather than silently producing ``UNKNOWN``.
        """
        if isinstance(data, cls):
            return data
        if not isinstance(data, dict):
            raise TypeError(
                f"sa_identity must be a mapping or SaIdentity, got {type(data).__name__}"
            )
        if "state" in data or "kind" in data:
            raw: Any = data
        else:
            raw = data.get("sa_identity")
            if raw is None:
                return cls.unknown(REASON_NO_OUTER_ENDPOINTS)
        if isinstance(raw, cls):
            return raw
        if not isinstance(raw, dict):
            raise TypeError(
                f"sa_identity must be a mapping or SaIdentity, got {type(raw).__name__}"
            )
        candidates = tuple(raw.get("candidates") or ())
        evidence = tuple(raw.get("evidence_fields") or ())
        return cls(
            state=raw.get("state", STATE_UNKNOWN),
            kind=raw.get("kind", KIND_UNRESOLVED),
            sa_id=raw.get("sa_id"),
            sa_group_id=raw.get("sa_group_id"),
            reason=raw.get("reason"),
            protocol=raw.get("protocol"),
            outer_src=raw.get("outer_src"),
            outer_dst=raw.get("outer_dst"),
            peer=raw.get("peer"),
            spi=raw.get("spi"),
            direction=raw.get("direction"),
            transport_port=raw.get("transport_port"),
            ip_protocol=raw.get("ip_protocol"),
            candidates=candidates,
            evidence_fields=evidence,
        )


#: A minimal, explicit identity for a record that carries no SA evidence at all
#: (an old artifact, or a non-IPsec observation).  Kept as a factory so the
#: reason is never lost by accident.
def no_sa_identity() -> SaIdentity:
    return SaIdentity.unknown(REASON_NO_OUTER_ENDPOINTS)
