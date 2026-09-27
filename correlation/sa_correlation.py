"""Deterministic passive SA / tunnel correlation (multi-SA capable).

This is the single place where a packet observation becomes an SA identity.  It
reuses the existing event contract (:class:`ebpf.xdp_window_aggregator.PacketEvent`)
and adds no new observation path: same events in, identities out.

Algorithm
---------
Two deterministic phases over the same event batch.

**Phase 1 -- index.**  Build two indexes from observed evidence only:

* ``spis_by_peer`` -- for each (unordered endpoint pair, security protocol),
  the set of SPIs actually observed on that pair.
* ``peer_of_spi``  -- for each SPI, the set of endpoint pairs it was seen on.

**Phase 2 -- resolve.**  Per event, using the RFC 4303 SA selector
``(destination address, security protocol, SPI)`` as the strongest evidence:

=========================================  ==========================================
observed                                   result
=========================================  ==========================================
ESP/AH + SPI, SPI seen on exactly 1 peer   ``RESOLVED`` -- the SA itself
ESP/AH + SPI, SPI seen on >1 peer          ``AMBIGUOUS`` ``spi_reused_across_peers``
ESP/AH, no SPI, 1 SPI known for that peer  ``RESOLVED`` -- inferred from the sole SA
ESP/AH, no SPI, >1 SPI known for that peer ``AMBIGUOUS`` ``multiple_sas_on_peer``
ESP/AH, no SPI, 0 SPI known for that peer  ``UNKNOWN`` ``no_spi_available``
IKE / IKE-NAT-T (carries no SPI)           IKE context, never joined to an ESP SA
no outer src and no outer dst              ``UNKNOWN`` ``no_outer_endpoints``
=========================================  ==========================================

Three properties are deliberate:

1. **A UDP port is never an identity.**  ``transport_port`` is recorded as
   context only.  Two SAs behind one UDP/4500 flow resolve to two different
   ``sa_id`` values.
2. **Uncertainty is preserved, never resolved by guessing.**  When several SAs
   stay possible the result is ``AMBIGUOUS`` with the candidate set, not a
   coin flip and not a merge into the nearest SA.
3. **No clock, no plan, no randomness.**  Identity depends only on the event
   bytes, so the same batch always yields the same identities.  Expected
   configuration is never read; a plan sample can never leak into an observed
   identity.

Direction is observed, not derived from configuration: the capture-point
address (when supplied) anchors ``OUTBOUND``/``INBOUND``; otherwise direction
stays ``None``.  Direction is recorded but is not part of ``sa_id``, because an
SA is bidirectional and the per-direction SPI already selects the child SA.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Dict, List, Optional, Tuple

from ebpf.xdp_window_aggregator import (
    TYPE_AH,
    TYPE_ESP,
    TYPE_IKE,
    TYPE_IKE_NAT_T,
    PacketEvent,
)

from .models.sa_identity import (
    DIRECTION_INBOUND,
    IPPROTO_ESP,
    DIRECTION_OUTBOUND,
    KIND_AH_SA,
    KIND_ESP_SA,
    KIND_IKE_CONTEXT,
    KIND_UNRESOLVED,
    PROTO_AH,
    PROTO_ESP,
    PROTO_IKE,
    PROTO_IKE_NAT_T,
    REASON_AMBIGUOUS_PEER_SET,
    REASON_IKE_HAS_NO_SPI,
    REASON_MULTIPLE_SAS_ON_PEER,
    REASON_NO_OUTER_ENDPOINTS,
    REASON_NO_SPI_AVAILABLE,
    REASON_SPI_REUSED_ACROSS_PEERS,
    SaIdentity,
    endpoint_pair,
    format_spi,
)

__all__ = [
    "SaResolver",
    "read_pcap_events",
    "resolve_event_identities",
    "sa_id_for",
    "sa_group_id_for",
]

#: Protocol label + identity kind per observed event type.
_EVENT_PROTOCOL = {
    TYPE_ESP: (PROTO_ESP, KIND_ESP_SA),
    TYPE_AH: (PROTO_AH, KIND_AH_SA),
    TYPE_IKE: (PROTO_IKE, KIND_IKE_CONTEXT),
    TYPE_IKE_NAT_T: (PROTO_IKE_NAT_T, KIND_IKE_CONTEXT),
}

#: Protocol labels whose identity is SPI-selectable.
_SPI_PROTOCOLS = (PROTO_ESP, PROTO_AH)


def _as_packet_event(event: Any) -> PacketEvent:
    """Accept a :class:`PacketEvent` or a raw event dict, like the live seam."""
    if isinstance(event, PacketEvent):
        return event
    if isinstance(event, Mapping):
        return PacketEvent.from_dict(dict(event))
    raise TypeError(
        f"event must be a PacketEvent or mapping, got {type(event).__name__}"
    )


def _spi_or_none(spi: Any) -> Optional[int]:
    """Return a usable SPI, treating ``0`` / ``None`` / non-positive as absent.

    The parity harness in ``controller.live_features`` emits ``spi: 0`` because
    the v2 feature vector does not consume SPI, and XDP reports 0 when the
    parse failed.  Both mean *no SPI evidence*, never "SPI zero".
    """
    if spi is None or isinstance(spi, bool):
        return None
    try:
        value = int(spi)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    return value & 0xFFFFFFFF


def sa_id_for(spi: Optional[str], peer: Optional[str], protocol: Optional[str]) -> str:
    """Deterministic ``sa_id`` for one SPI-selectable child SA.

    Readable on purpose: it is what a dashboard column and a report quote.
    Uniqueness follows from the RFC 4303 selector -- the same (peer, protocol,
    SPI) triple *is* one SA, so distinct SAs cannot collide.
    """
    parts = ["sa", (protocol or "unk").lower().replace("-", ""), peer or "nopeer"]
    if spi:
        parts.append(spi)
    return ":".join(parts)


def sa_group_id_for(peer: Optional[str], protocol: Optional[str],
                    pair: Optional[Tuple[str, str]] = None) -> str:
    """Deterministic ``sa_group_id`` for the bidirectional SA/tunnel.

    One gateway may hold several of these at once, all sharing UDP/4500.  The
    UDP port is deliberately absent: it is transport, not identity.

    The group is keyed on the *tunnel*, not on one direction of it, so both
    directions of a single SA collapse together.  When the capture point is
    known the remote peer makes the readable, stable form
    ``sa:esp:192.168.100.2``.  When it is not, the whole canonical (sorted)
    endpoint pair is used instead -- still direction-agnostic, so it groups the
    same traffic correctly, and it never guesses which side is the peer.
    """
    label = peer or ("-".join(pair) if pair else "nopeer")
    return ":".join(["sa", (protocol or "unk").lower().replace("-", ""), label])


def _peer_of_pair(pair: Optional[Tuple[str, str]],
                  capture_ip: Optional[str]) -> Optional[str]:
    """The remote endpoint, relative to the observed capture point.

    Returns ``None`` when the capture point is unknown or is not one of the two
    observed endpoints -- in which case neither side can honestly be called the
    peer, and the caller must fall back to the whole pair.
    """
    if pair is None or not capture_ip:
        return None
    if capture_ip == pair[0]:
        return pair[1]
    if capture_ip == pair[1]:
        return pair[0]
    return None


def _observed_direction(src: str, dst: str,
                        capture_ip: Optional[str]) -> Optional[str]:
    """Observed direction relative to the capture point, or ``None``.

    ``capture_ip`` is the *observed* capture-point address (the mirror's own
    address).  A packet sourced from it is outbound, one destined to it is
    inbound.  With no capture point known, direction is left unstated rather
    than guessed.
    """
    if not capture_ip:
        return None
    if src == capture_ip:
        return DIRECTION_OUTBOUND
    if dst == capture_ip:
        return DIRECTION_INBOUND
    return None


class SaResolver:
    """Resolve observed events to passive SA identities.

    Usage is two-phase and the phases are cheap and deterministic::

        resolver = SaResolver(capture_ip="192.168.100.1")
        resolver.index(events)          # phase 1
        identities = resolver.resolve_all(events)   # phase 2

    :meth:`resolve` works without a prior :meth:`index` call; it then simply
    has no cross-event evidence and reports ``UNKNOWN no_spi_available`` for
    SPI-less ESP/AH, which is the honest single-event answer.
    """

    def __init__(self, capture_ip: Optional[str] = None):
        self.capture_ip = capture_ip or None
        self._spis_by_peer: Dict[Tuple[Tuple[str, str], str], set] = {}
        self._peer_of_spi: Dict[str, set] = {}
        self._ike_peers: set = set()
        self._indexed = False
        #: How many events carried no usable outer endpoint pair.
        self.unidentifiable_events = 0

    # -- phase 1 ------------------------------------------------------------ #

    def index(self, events: Iterable[Any]) -> "SaResolver":
        """Index every event's observable SA evidence.  Returns ``self``."""
        self._spis_by_peer.clear()
        self._peer_of_spi.clear()
        self._ike_peers.clear()
        self.unidentifiable_events = 0
        for event in events:
            packet = _as_packet_event(event)
            pair = endpoint_pair(packet.src, packet.dst)
            if pair is None:
                self.unidentifiable_events += 1
                continue
            protocol, _kind = _EVENT_PROTOCOL.get(packet.type, (None, None))
            if protocol is None:
                continue
            if protocol in _SPI_PROTOCOLS:
                spi = _spi_or_none(packet.spi)
                if spi is None:
                    continue
                token = format_spi(spi)
                self._spis_by_peer.setdefault((pair, protocol), set()).add(token)
                self._peer_of_spi.setdefault(token, set()).add(pair)
            else:
                self._ike_peers.add((pair, protocol))
        self._indexed = True
        return self

    # -- phase 2 ------------------------------------------------------------ #

    def resolve(self, event: Any) -> SaIdentity:
        """Resolve one event to a passive :class:`SaIdentity`."""
        packet = _as_packet_event(event)
        protocol, kind = _EVENT_PROTOCOL.get(packet.type, (None, None))
        direction = _observed_direction(packet.src, packet.dst, self.capture_ip)
        port = packet.dport or packet.sport or None
        pair = endpoint_pair(packet.src, packet.dst)

        identity = self._resolve_core(packet, protocol, kind, pair, port)
        return identity.with_observation(direction=direction, transport_port=port)

    def _resolve_core(self, packet: PacketEvent, protocol: Optional[str],
                      kind: Optional[str], pair: Optional[Tuple[str, str]],
                      port: Optional[int]) -> SaIdentity:
        peer = _peer_of_pair(pair, self.capture_ip)
        context: Dict[str, Any] = {
            "protocol": protocol,
            "outer_src": packet.src or None,
            "outer_dst": packet.dst or None,
            "peer": peer,
            "ip_protocol": packet.proto or None,
        }

        if pair is None or protocol is None:
            # No outer endpoints, or a protocol this contract does not model.
            return SaIdentity.unknown(
                REASON_NO_OUTER_ENDPOINTS,
                kind=KIND_UNRESOLVED,
                **context,
            )

        if kind == KIND_IKE_CONTEXT:
            return self._resolve_ike(protocol, kind, pair, context)

        return self._resolve_spi_sa(packet, protocol, kind, pair, context)

    # -- ESP / AH ----------------------------------------------------------- #

    def _resolve_spi_sa(self, packet: PacketEvent, protocol: str, kind: str,
                        pair: Tuple[str, str], context: Dict[str, Any]) -> SaIdentity:
        peer = context["peer"]
        group_id = sa_group_id_for(peer, protocol, pair)
        spi = _spi_or_none(packet.spi)
        if spi is not None:
            token = format_spi(spi)
            # RFC 4303: SPI alone is only unique per destination.  If the same
            # SPI showed up on a different peer it cannot select one SA.
            peers = self._peer_of_spi.get(token, set())
            if len(peers) > 1:
                candidates = tuple(
                    sorted(
                        sa_id_for(token, _peer_of_pair(other, self.capture_ip), protocol)
                        for other in peers
                    )
                )
                return SaIdentity.ambiguous(
                    REASON_SPI_REUSED_ACROSS_PEERS,
                    candidates,
                    kind=kind,
                    spi=token,
                    evidence_fields=("spi", "outer_src", "outer_dst", "protocol"),
                    **context,
                )
            return SaIdentity(
                state="RESOLVED",
                kind=kind,
                sa_id=sa_id_for(token, peer, protocol),
                sa_group_id=group_id,
                protocol=protocol,
                outer_src=context["outer_src"],
                outer_dst=context["outer_dst"],
                peer=peer,
                spi=token,
                ip_protocol=context["ip_protocol"],
                evidence_fields=("spi", "outer_src", "outer_dst", "protocol"),
            )

        # No SPI on this packet.  The peer alone may still name exactly one SA.
        known = self._spis_by_peer.get((pair, protocol), set())
        if len(known) == 1:
            token = next(iter(known))
            return SaIdentity(
                state="RESOLVED",
                kind=kind,
                sa_id=sa_id_for(token, peer, protocol),
                sa_group_id=group_id,
                protocol=protocol,
                outer_src=context["outer_src"],
                outer_dst=context["outer_dst"],
                peer=peer,
                spi=token,
                ip_protocol=context["ip_protocol"],
                evidence_fields=("spi_from_peer", "outer_src", "outer_dst", "protocol"),
            )
        if len(known) > 1:
            candidates = tuple(sorted(sa_id_for(t, peer, protocol) for t in known))
            return SaIdentity.ambiguous(
                REASON_MULTIPLE_SAS_ON_PEER,
                candidates,
                kind=kind,
                evidence_fields=("outer_src", "outer_dst", "protocol"),
                **context,
            )
        return SaIdentity.unknown(
            REASON_NO_SPI_AVAILABLE,
            kind=kind,
            evidence_fields=("outer_src", "outer_dst", "protocol"),
            **context,
        )

    # -- IKE ---------------------------------------------------------------- #

    def _resolve_ike(self, protocol: str, kind: str, pair: Tuple[str, str],
                     context: Dict[str, Any]) -> SaIdentity:
        """IKE identity is a peer-level context, never an SA.

        IKE carries no SPI, so the strongest honest identity is
        ``(peer, NAT-T or not)``.  ``joins_spi`` is False by construction, and
        the reason is recorded so a report never presents an IKE context as an
        established SA.
        """
        sa_id = "sa:" + protocol.lower().replace("-", "") + ":" + (
            context["peer"] or "-".join(pair)
        )
        return SaIdentity(
            state="RESOLVED",
            kind=kind,
            sa_id=sa_id,
            sa_group_id=sa_id,
            reason=REASON_IKE_HAS_NO_SPI,
            protocol=protocol,
            outer_src=context["outer_src"],
            outer_dst=context["outer_dst"],
            peer=context["peer"],
            ip_protocol=context["ip_protocol"],
            evidence_fields=("outer_src", "outer_dst", "protocol"),
        )

    # -- batch helpers ------------------------------------------------------ #

    def resolve_all(self, events: Iterable[Any]) -> List[Tuple[Any, SaIdentity]]:
        """Resolve every event, preserving input order."""
        return [(event, self.resolve(event)) for event in events]

    def identities(self, events: Iterable[Any]) -> List[SaIdentity]:
        """Just the identities, in input order."""
        return [identity for _event, identity in self.resolve_all(events)]

    @property
    def known_sa_ids(self) -> Tuple[str, ...]:
        """Every SA the indexed evidence supports, sorted."""
        found: set = set()
        for (pair, protocol), spis in self._spis_by_peer.items():
            for token in spis:
                found.add(
                    sa_id_for(token, _peer_of_pair(pair, self.capture_ip), protocol)
                )
        return tuple(sorted(found))

    def evidence_summary(self) -> Dict[str, Any]:
        """Counts a report or the API can quote about indexed evidence."""
        return {
            "indexed_sa_count": len(self.known_sa_ids),
            "known_sa_ids": list(self.known_sa_ids),
            "peer_protocol_groups": len(self._spis_by_peer),
            "unique_spis": len(self._peer_of_spi),
            "unidentifiable_events": self.unidentifiable_events,
        }


def read_pcap_events(path: str) -> List[Dict[str, Any]]:
    """Read a capture into the live event shape, keeping the SPI.

    Uses :func:`controller.features.read_pcap_esp_with_spi`, so a
    UDP/4500-encapsulated capture -- which is what a NAT'd gateway actually
    emits -- is decoded, and every frame carries the SPI that identifies its
    SA.  The v2 feature vector never reads the SPI, which is why the general
    parity harness in :mod:`controller.live_features` zeroes it; SA correlation
    needs it, so this reader keeps it.

    Passive: it reads a file and returns observations.  Nothing here configures,
    enforces or reports anything back to the network.
    """
    import ipaddress

    from controller.features import read_pcap_esp_with_spi

    events: List[Dict[str, Any]] = []
    for timestamp, incl_len, _ip_total, src, dst, spi in read_pcap_esp_with_spi(path):
        events.append({
            "ts": round(timestamp * 1_000_000_000),
            "type": TYPE_ESP,
            "src": str(ipaddress.ip_address(src)),
            "dst": str(ipaddress.ip_address(dst)),
            "proto": IPPROTO_ESP,
            "len": incl_len,
            # ``None`` when the header was unreadable: the honest "no SPI
            # evidence" value.  It resolves to UNKNOWN, never to SPI zero.
            "spi": spi,
            "seq": 0,
        })
    return events


def resolve_event_identities(
    events: Iterable[Any], *, capture_ip: Optional[str] = None
) -> Tuple[SaResolver, List[SaIdentity]]:
    """Convenience: index then resolve a whole batch.

    Returns the populated resolver (so its evidence summary is available) and
    the identities in input order.
    """
    event_list = list(events)
    resolver = SaResolver(capture_ip=capture_ip)
    resolver.index(event_list)
    return resolver, resolver.identities(event_list)
