"""Area 1 -- complete Security Association analysis.

Producer of the SA section of the analytical product. It consumes ONLY the
existing ``ObservedState`` (the ``ipsec_state_builder`` snapshot) and reports,
per SPI, exactly what that snapshot establishes:

* direction and packet/byte counters     -> OBSERVED
* first/last observed packet timestamps  -> OBSERVED
* sequence progression                   -> OBSERVED, or NOT_AVAILABLE when the
                                            snapshot recorded none
* SA age at the snapshot                 -> INFERRED (arithmetic on two observed
                                            timestamps)
* data-plane establishment               -> OBSERVED (ESP packets carried under
                                            the SPI)
* IKE SA establishment                   -> NOT_AVAILABLE (the builder does not
                                            parse IKE exchanges)
* lifetime / rekey                       -> NOT_AVAILABLE -- the builder's
                                            ``sa_snapshot()`` carries no
                                            lifetime, expiry or rekey field, so
                                            a lifetime would have to be
                                            fabricated from configuration.

Nothing here is a security judgement: this module reports evidence state; the
risk engine is the only place a finding is created.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..models import ObservedState
from .states import (
    STATE_INFERRED,
    STATE_NOT_AVAILABLE,
    STATE_OBSERVED,
    STATE_UNKNOWN,
    EvidenceValue,
)

#: Why no lifetime/rekey value is ever produced. Named once so the SA product,
#: the metadata product and the report all say the same thing.
LIFETIME_UNAVAILABLE_REASON = (
    "ebpf/ipsec_state_builder.py::sa_snapshot() records identity, endpoint, "
    "packet counters and timestamps only: it has no lifetime, expiry, rekey "
    "count or rekey interval field. Deriving one from the expected "
    "configuration would report the configured value as if it had been "
    "observed, so no lifetime is produced."
)

IKE_SA_UNAVAILABLE_REASON = (
    "The observation path counts IKE packets and timestamps them "
    "(ike_seen / observed_ike_activity) but does not parse IKE exchange types, "
    "SPIs or the SA_INIT/CREATE_CHILD_SA state machine, so IKE SA "
    "establishment cannot be stated from this snapshot."
)

SEQUENCE_NOT_RECORDED_REASON = (
    "The snapshot carries first_sequence=0 and last_sequence=0 with a "
    "non-zero packet_count. RFC 4303 starts the ESP sequence at 1 and never "
    "sends 0, so 0 here means 'no sequence was recorded', not 'sequence zero' "
    "-- sequence progression is therefore NOT_AVAILABLE for this SPI."
)

SEQUENCE_NO_PACKETS_REASON = (
    "No ESP packet was observed under this SPI, so there is no sequence to "
    "report."
)

DIRECTION_UNAVAILABLE_REASON = (
    "The state builder records a direction only when it first saw a packet "
    "for this SPI with a known direction; none was recorded."
)


def _nanoseconds_to_seconds(value: Optional[int]) -> Optional[float]:
    if value is None:
        return None
    return round(value / 1_000_000_000, 9)


def _sequence_recorded(spi) -> bool:
    """True when the snapshot actually recorded sequence numbers for ``spi``.

    The builder writes 0 for "absent"; senders start at 1 (RFC 4303), so a
    pair of zeros with traffic present means the field was never populated.
    """
    first = getattr(spi, "first_sequence", None)
    last = getattr(spi, "last_sequence", None)
    if first in (None, 0) and last in (None, 0):
        return False
    return True


@dataclass(frozen=True)
class SaAssociation:
    """One SPI's share of the Security Association analysis."""

    spi: str
    direction: EvidenceValue
    data_plane_established: EvidenceValue
    first_observed_packet_ns: EvidenceValue
    last_observed_packet_ns: EvidenceValue
    packet_count: int
    sequence: EvidenceValue
    age_seconds: EvidenceValue
    lifetime: EvidenceValue
    rekey: EvidenceValue
    sa_identity: EvidenceValue
    active: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "spi": self.spi,
            "active": self.active,
            "packet_count": self.packet_count,
            "direction": self.direction.to_dict(),
            "data_plane_established": self.data_plane_established.to_dict(),
            "first_observed_packet_ns": self.first_observed_packet_ns.to_dict(),
            "last_observed_packet_ns": self.last_observed_packet_ns.to_dict(),
            "sequence": self.sequence.to_dict(),
            "age_seconds": self.age_seconds.to_dict(),
            "lifetime": self.lifetime.to_dict(),
            "rekey": self.rekey.to_dict(),
            "sa_identity": self.sa_identity.to_dict(),
        }


@dataclass(frozen=True)
class SaAnalysis:
    """The complete SA analysis product for one assessment."""

    state: str
    reason: str
    source: str
    associations: tuple = ()
    summary: Optional[Dict[str, Any]] = None
    limitations: tuple = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "reason": self.reason,
            "source": self.source,
            "associations": [a.to_dict() for a in self.associations],
            "summary": dict(self.summary or {}),
            "limitations": list(self.limitations),
        }


def _sa_identity_value(spi_id: str, snapshots: List[Dict[str, Any]]) -> EvidenceValue:
    for snap in snapshots:
        if str(snap.get("spi")) != spi_id:
            continue
        state = snap.get("sa_identity_state")
        if state == "RESOLVED":
            reason = (
                "The state builder attributed this SPI to an SA and recorded "
                "the identity token."
            )
        else:
            detail = snap.get("sa_identity_reason") or "no identity reason was recorded"
            reason = (
                f"The state builder recorded this SPI's SA as "
                f"{state or 'unlabelled'}: {detail}. No id is invented in "
                "this state."
            )
        return EvidenceValue.of(
            {
                "sa_id": snap.get("sa_id"),
                "sa_group_id": snap.get("sa_group_id"),
                "identity_state": state,
                "identity_reason": snap.get("sa_identity_reason"),
                "endpoint_conflict": snap.get("endpoint_conflict"),
            },
            STATE_OBSERVED if state == "RESOLVED" else STATE_UNKNOWN,
            "observed-state snapshot (sa_snapshots)",
            reason,
        )
    return EvidenceValue.of(
        None,
        STATE_NOT_AVAILABLE,
        "observed-state snapshot (sa_snapshots)",
        "The snapshot recorded no sa_snapshots entry for this SPI, so no SA "
        "identity token exists to report.",
    )


def _association(spi, *, snapshot_ns: int, snapshots: List[Dict[str, Any]]) -> SaAssociation:
    spi_id = str(spi.spi)
    sequence_recorded = _sequence_recorded(spi)

    if spi.packet_count <= 0:
        sequence = EvidenceValue.of(
            None,
            STATE_NOT_AVAILABLE,
            "observed-state snapshot (spis[].sequence)",
            SEQUENCE_NO_PACKETS_REASON,
            runtime_observable=True,
        )
    elif not sequence_recorded:
        sequence = EvidenceValue.of(
            None,
            STATE_NOT_AVAILABLE,
            "observed-state snapshot (spis[].sequence)",
            SEQUENCE_NOT_RECORDED_REASON,
            runtime_observable=True,
        )
    else:
        sequence = EvidenceValue.of(
            {
                "first_sequence": spi.first_sequence,
                "last_sequence": spi.last_sequence,
                "highest_sequence": spi.highest_sequence,
                "sequence_delta": spi.sequence_delta,
            },
            STATE_OBSERVED,
            "observed-state snapshot (spis[].sequence)",
            "The state builder recorded the ESP sequence numbers of the "
            "packets it saw under this SPI.",
            runtime_observable=True,
        )

    if spi.packet_count > 0:
        established = EvidenceValue.of(
            True,
            STATE_OBSERVED,
            "observed-state snapshot (spis[].packet_count)",
            f"{spi.packet_count} ESP packet(s) were carried under this SPI, so "
            "the data-plane security association was established and carrying "
            "traffic during the observation.",
            runtime_observable=True,
        )
    else:
        established = EvidenceValue.of(
            None,
            STATE_NOT_AVAILABLE,
            "observed-state snapshot (spis[].packet_count)",
            "No packet was observed under this SPI, so establishment cannot be "
            "stated from this snapshot.",
            runtime_observable=True,
        )

    if spi.first_seen_ns > 0:
        first = EvidenceValue.of(
            spi.first_seen_ns,
            STATE_OBSERVED,
            "observed-state snapshot (spis[].first_seen_ns)",
            "Timestamp of the first packet seen under this SPI.",
            runtime_observable=True,
        )
        age = EvidenceValue.of(
            _nanoseconds_to_seconds(max(0, snapshot_ns - spi.first_seen_ns)),
            STATE_INFERRED,
            "observed-state snapshot (spis[].first_seen_ns, timestamp_ns)",
            "Age of this SPI's traffic at the snapshot instant, computed as "
            "snapshot timestamp_ns - first_seen_ns. It is arithmetic on two "
            "observed timestamps, not a negotiated SA lifetime.",
        )
    else:
        first = EvidenceValue.of(
            None,
            STATE_NOT_AVAILABLE,
            "observed-state snapshot (spis[].first_seen_ns)",
            "The snapshot recorded no first-seen timestamp for this SPI.",
            runtime_observable=True,
        )
        age = EvidenceValue.of(
            None,
            STATE_NOT_AVAILABLE,
            "observed-state snapshot (spis[].first_seen_ns)",
            "Without a first-seen timestamp there is nothing to compute an age "
            "from.",
        )

    if spi.last_seen_ns > 0:
        last = EvidenceValue.of(
            spi.last_seen_ns,
            STATE_OBSERVED,
            "observed-state snapshot (spis[].last_seen_ns)",
            "Timestamp of the last packet seen under this SPI.",
            runtime_observable=True,
        )
    else:
        last = EvidenceValue.of(
            None,
            STATE_NOT_AVAILABLE,
            "observed-state snapshot (spis[].last_seen_ns)",
            "The snapshot recorded no last-seen timestamp for this SPI.",
            runtime_observable=True,
        )

    if spi.direction:
        direction = EvidenceValue.of(
            spi.direction,
            STATE_OBSERVED,
            "observed-state snapshot (spis[].direction)",
            "Direction the state builder saw the first packet of this SPI "
            "travel in.",
            runtime_observable=True,
        )
    else:
        direction = EvidenceValue.of(
            None,
            STATE_NOT_AVAILABLE,
            "observed-state snapshot (spis[].direction)",
            DIRECTION_UNAVAILABLE_REASON,
            runtime_observable=True,
        )

    unavailable = EvidenceValue.of(
        None, STATE_NOT_AVAILABLE, "observed-state snapshot", LIFETIME_UNAVAILABLE_REASON
    )
    return SaAssociation(
        spi=spi_id,
        direction=direction,
        data_plane_established=established,
        first_observed_packet_ns=first,
        last_observed_packet_ns=last,
        packet_count=spi.packet_count,
        sequence=sequence,
        age_seconds=age,
        lifetime=unavailable,
        rekey=unavailable,
        sa_identity=_sa_identity_value(spi_id, snapshots),
        active=bool(spi.active),
    )


def analyze_sa(observed: Optional[ObservedState], *, source: str = "observed-state snapshot") -> SaAnalysis:
    """Analyse every SPI in ``observed``.

    ``source`` names the artifact the snapshot was read from, so the product
    carries its own provenance instead of relying on the bundle's source list.
    """
    limitations: List[str] = [
        "This analysis reports the observation only; it makes no security "
        "claim and contributes no score.",
        "Lifetime and rekey are NOT_AVAILABLE for every association because "
        "the state builder records none (see the lifetime reason on each "
        "association).",
    ]

    if observed is None or (
        observed.timestamp_ns == 0 and not observed.spis
    ):
        return SaAnalysis(
            state=STATE_NOT_AVAILABLE,
            reason=(
                "No ipsec_state_builder snapshot was supplied for this "
                "assessment, so no security association was observed. An "
                "assessment without a snapshot reports this rather than "
                "borrowing one from another capture."
            ),
            source=source,
            associations=(),
            summary={"association_count": 0, "observed": False},
            limitations=tuple(limitations),
        )

    snapshots = list(getattr(observed, "sa_snapshots", None) or [])
    associations = tuple(
        _association(spi, snapshot_ns=observed.timestamp_ns, snapshots=snapshots)
        for spi in observed.spis
    )

    start_ns = getattr(observed, "observation_start_ns", None)
    last_ns = getattr(observed, "last_packet_timestamp_ns", None)
    summary: Dict[str, Any] = {
        "observed": True,
        "association_count": len(associations),
        "total_packets": sum(a.packet_count for a in associations),
        "snapshot_timestamp_ns": observed.timestamp_ns,
        "observation_start_ns": start_ns,
        "last_packet_timestamp_ns": last_ns,
        "observation_window_seconds": (
            _nanoseconds_to_seconds(last_ns - start_ns)
            if isinstance(start_ns, int) and isinstance(last_ns, int)
            and last_ns >= start_ns
            else None
        ),
        "active_timeout_ms": getattr(observed, "active_timeout_ms", None),
        "outer_endpoint_pairs": list(
            getattr(observed, "outer_endpoint_pairs", None) or []
        ),
        "spi_less_esp_packets": getattr(observed, "spi_less_esp_packets", None),
        "sa_snapshots_recorded": bool(snapshots),
        "sa_groups_recorded": bool(getattr(observed, "sa_groups", None) or []),
        "esp_seen": observed.esp_seen,
        "ah_seen": observed.ah_seen,
        "ike_sa_established": EvidenceValue.of(
            None,
            STATE_NOT_AVAILABLE,
            "observed-state snapshot",
            IKE_SA_UNAVAILABLE_REASON,
            runtime_observable=True,
        ).to_dict(),
    }

    if start_ns is None:
        limitations.append(
            "The snapshot recorded no observation_start_ns, so no observation "
            "window is reported."
        )
    if not snapshots:
        limitations.append(
            "sa_snapshots is empty in this artifact: the state builder only "
            "fills it once correlation has attributed a SPI to an SA, so SA "
            "identity is NOT_AVAILABLE here."
        )

    if not associations:
        state = STATE_OBSERVED
        reason = (
            "A snapshot was present but recorded no SPI, so the analysis "
            "reports zero associations rather than an invented one."
        )
    else:
        state = STATE_OBSERVED
        reason = (
            f"{len(associations)} security association(s) derived from the "
            "recorded SPI state of this snapshot."
        )

    return SaAnalysis(
        state=state,
        reason=reason,
        source=source,
        associations=associations,
        summary=summary,
        limitations=tuple(limitations),
    )
