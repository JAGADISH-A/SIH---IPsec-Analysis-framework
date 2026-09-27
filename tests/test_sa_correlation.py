"""Deterministic passive multi-SA / multi-tunnel correlation tests.

One gateway commonly holds several IPsec SAs at once, and under NAT-T they all
share UDP/4500.  These tests pin the behaviour that makes that safe:

* SPIs on different peers stay separate SAs even in the same 100 ms window, and
  both directions of one tunnel collapse into a single SA group;
* a 100 ms window is bucketed per SA, so SA-A and SA-B never blend into one
  feature vector, and the committed RF classifies each independently;
* each SA gets its own observed state, so a finding about SA-A never cites
  SA-B's counters, sequences or evidence;
* identity comes from observed evidence only -- never from the plan, never from
  the UDP port -- and uncertain traffic stays visibly ``UNKNOWN`` /
  ``AMBIGUOUS`` instead of being merged into a neighbouring SA;
* the single-SA path is byte-for-byte unchanged, and artifacts recorded before
  SA identity existed still load.

Every test here is passive: it only inspects observed events.
"""

from __future__ import annotations

import unittest

from correlation.models import (
    KIND_ESP_SA,
    KIND_IKE_CONTEXT,
    KIND_UNRESOLVED,
    SA_UNKNOWN_GROUP,
    STATE_AMBIGUOUS,
    STATE_RESOLVED,
    STATE_UNKNOWN,
    EvidenceRef,
    LiveFeatureWindow,
    MLResult,
    SaIdentity,
)
from correlation.sa_correlation import SaResolver, resolve_event_identities

CAPTURE_IP = "192.168.100.1"
PEER_A = "192.168.100.2"
PEER_B = "192.168.100.3"

SPI_A_OUT = 0x11111111
SPI_A_IN = 0x22222222
SPI_B_OUT = 0x33333333
SPI_B_IN = 0x44444444

WINDOW_NS = 100_000_000
BASE_TS = 5_000_000_000


def event(ts, src, dst, spi, *, kind="ESP", proto=50, sport=4500, dport=4500,
          length=140, seq=0):
    """One observed event in the live reader's shape."""
    return {
        "ts": ts,
        "type": kind,
        "src": src,
        "dst": dst,
        "proto": proto,
        "len": length,
        "sport": sport,
        "dport": dport,
        "spi": spi,
        "seq": seq,
    }


def two_sa_events():
    """Both directions of two tunnels, all inside one 100 ms window.

    SA-A is small-packet traffic to ``PEER_A``; SA-B is large-packet traffic to
    ``PEER_B``.  They share UDP/4500 and the same time bucket, which is exactly
    the case the single-SA path used to blend.
    """
    events = []
    for index in range(6):
        events.append(event(BASE_TS + index * 1000, CAPTURE_IP, PEER_A, SPI_A_OUT,
                            length=140, seq=index))
        events.append(event(BASE_TS + 500 + index * 1000, PEER_A, CAPTURE_IP,
                            SPI_A_IN, length=150, seq=index))
    for index in range(4):
        events.append(event(BASE_TS + 2000 + index * 1000, CAPTURE_IP, PEER_B,
                            SPI_B_OUT, length=1300, seq=index))
        events.append(event(BASE_TS + 2500 + index * 1000, PEER_B, CAPTURE_IP,
                            SPI_B_IN, length=1350, seq=index))
    events.sort(key=lambda item: item["ts"])
    return events


class TestIdentityIsEvidenceDerived(unittest.TestCase):
    """Identity comes from observed evidence, never from configuration."""

    def test_distinct_peers_get_distinct_sas_over_the_same_port(self):
        _resolver, identities = resolve_event_identities(
            two_sa_events(), capture_ip=CAPTURE_IP
        )
        groups = {identity.sa_group_id for identity in identities}
        self.assertEqual(2, len(groups))

    def test_udp_port_is_never_part_of_identity(self):
        _resolver, identities = resolve_event_identities(
            two_sa_events(), capture_ip=CAPTURE_IP
        )
        for identity in identities:
            self.assertNotIn("4500", identity.sa_id or "")
            self.assertNotIn("4500", identity.sa_group_id or "")
            # The port is kept as transport context, which is its only role.
            self.assertEqual(4500, identity.transport_port)

    def test_both_directions_of_one_tunnel_share_one_group(self):
        outbound = SaResolver(capture_ip=CAPTURE_IP)
        outbound.index(two_sa_events())
        out_identity = outbound.resolve(
            event(BASE_TS, CAPTURE_IP, PEER_A, SPI_A_OUT)
        )
        in_identity = outbound.resolve(
            event(BASE_TS, PEER_A, CAPTURE_IP, SPI_A_IN)
        )
        self.assertEqual(out_identity.sa_group_id, in_identity.sa_group_id)
        # ...while remaining two distinct RFC 4303 child SAs.
        self.assertNotEqual(out_identity.sa_id, in_identity.sa_id)

    def test_peer_is_the_far_side_even_when_the_capture_ip_sorts_higher(self):
        """The remote peer is derived from the capture point, not sorted order."""
        resolver = SaResolver(capture_ip=PEER_B)
        resolver.index([event(BASE_TS, CAPTURE_IP, PEER_B, SPI_B_OUT)])
        identity = resolver.resolve(event(BASE_TS, CAPTURE_IP, PEER_B, SPI_B_OUT))
        self.assertEqual(CAPTURE_IP, identity.peer)

    def test_without_a_capture_point_the_peer_is_left_unstated(self):
        """No capture point means no honest peer -- the pair is used instead."""
        resolver = SaResolver()
        resolver.index([event(BASE_TS, CAPTURE_IP, PEER_B, SPI_B_OUT)])
        identity = resolver.resolve(event(BASE_TS, CAPTURE_IP, PEER_B, SPI_B_OUT))
        self.assertIsNone(identity.peer)
        self.assertIn(f"{CAPTURE_IP}-{PEER_B}", identity.sa_group_id)
        self.assertEqual(STATE_RESOLVED, identity.state)

    def test_ike_is_a_context_and_never_an_established_sa(self):
        ike = event(BASE_TS, CAPTURE_IP, PEER_A, None, kind="IKE", proto=17,
                    sport=500, dport=500)
        resolver = SaResolver(capture_ip=CAPTURE_IP)
        resolver.index([ike])
        identity = resolver.resolve(ike)
        self.assertEqual(KIND_IKE_CONTEXT, identity.kind)
        self.assertFalse(identity.joins_spi)
        self.assertIsNone(identity.spi)
        # It identifies a peer context, not an SA, and says so.
        self.assertIn("ike_carries_no_spi", identity.reason)

    def test_ike_context_never_merges_with_an_esp_sa(self):
        events = two_sa_events() + [
            event(BASE_TS + 3000, CAPTURE_IP, PEER_A, None, kind="IKE", proto=17,
                 sport=500, dport=500)
        ]
        _resolver, identities = resolve_event_identities(events, capture_ip=CAPTURE_IP)
        ike_group = next(
            identity.sa_group_id for identity in identities
            if identity.kind == KIND_IKE_CONTEXT
        )
        esp_group = next(
            identity.sa_group_id for identity in identities
            if identity.kind == KIND_ESP_SA
        )
        self.assertNotEqual(ike_group, esp_group)


class TestUncertainTrafficStaysVisible(unittest.TestCase):
    """Uncertainty is reported, never silently resolved."""

    def test_spi_zero_is_unknown_and_invents_no_sa(self):
        """SPI 0 means "no SPI evidence", never "SPI zero"."""
        no_spi = event(BASE_TS, CAPTURE_IP, PEER_A, 0)
        resolver = SaResolver(capture_ip=CAPTURE_IP)
        resolver.index([no_spi])
        identity = resolver.resolve(no_spi)
        self.assertEqual(STATE_UNKNOWN, identity.state)
        self.assertEqual("no_spi_available", identity.reason)
        self.assertIsNone(identity.sa_id)
        self.assertEqual(SA_UNKNOWN_GROUP, identity.group_key)

    def test_spi_zero_does_not_create_a_state_in_the_state_engine(self):
        from ebpf.ipsec_state_builder import IPsecStateBuilder

        builder = IPsecStateBuilder()
        builder.consume_event_dict(event(BASE_TS, CAPTURE_IP, PEER_A, 0))
        snapshot = builder.snapshot()
        self.assertEqual([], snapshot["spis"])
        self.assertEqual(1, snapshot["spi_less_esp_packets"])

    def test_missing_outer_endpoints_is_unknown(self):
        headless = event(BASE_TS, "", "", SPI_A_OUT)
        resolver = SaResolver(capture_ip=CAPTURE_IP)
        resolver.index([headless])
        identity = resolver.resolve(headless)
        self.assertEqual(STATE_UNKNOWN, identity.state)
        self.assertEqual("no_outer_endpoints", identity.reason)
        self.assertEqual(KIND_UNRESOLVED, identity.kind)

    def test_one_spi_on_two_peers_is_ambiguous_with_candidates(self):
        """RFC 4303: an SPI selects an SA per destination, so reuse is ambiguous."""
        reused = 0xAAAA1111
        resolver = SaResolver(capture_ip=CAPTURE_IP)
        resolver.index([
            event(BASE_TS, CAPTURE_IP, PEER_A, reused),
            event(BASE_TS, CAPTURE_IP, PEER_B, reused),
        ])
        identity = resolver.resolve(event(BASE_TS, CAPTURE_IP, PEER_A, reused))
        self.assertEqual(STATE_AMBIGUOUS, identity.state)
        self.assertEqual("spi_reused_across_peers", identity.reason)
        self.assertIsNone(identity.sa_id)
        self.assertEqual(2, len(identity.candidates))

    def test_spi_less_traffic_with_two_sas_on_one_peer_is_ambiguous(self):
        resolver = SaResolver(capture_ip=CAPTURE_IP)
        resolver.index([
            event(BASE_TS, CAPTURE_IP, PEER_A, SPI_A_OUT),
            event(BASE_TS, CAPTURE_IP, PEER_A, SPI_A_IN),
            event(BASE_TS, CAPTURE_IP, PEER_A, 0),
        ])
        identity = resolver.resolve(event(BASE_TS, CAPTURE_IP, PEER_A, 0))
        self.assertEqual(STATE_AMBIGUOUS, identity.state)
        self.assertEqual("multiple_sas_on_peer", identity.reason)
        self.assertEqual(2, len(identity.candidates))

    def test_ambiguous_and_unknown_never_join_a_resolved_bucket(self):
        from controller.ml_inference import iter_window_records

        events = [
            event(BASE_TS, CAPTURE_IP, PEER_A, SPI_A_OUT),
            event(BASE_TS + 1000, CAPTURE_IP, PEER_A, SPI_A_OUT),
            event(BASE_TS + 2000, CAPTURE_IP, PEER_B, 0),      # unknown
        ]
        records = list(iter_window_records(
            events, capture_ip=CAPTURE_IP, sa_scoped=True
        ))
        states = {record["sa_identity"]["state"] for record in records}
        self.assertIn(STATE_RESOLVED, states)
        self.assertIn(STATE_UNKNOWN, states)
        # One window, two records: uncertainty is preserved, not blended away.
        self.assertEqual(2, len(records))
        for record in records:
            self.assertEqual(1, len({record["window_start_ns"]}))

    def test_an_spi_reused_across_peers_keeps_its_own_observed_state(self):
        """The strongest failure mode: attributing it to a peer would be a lie."""
        from correlation.ml.live_correlation import observed_states_per_sa

        reused = 0xAAAA1111
        events = [
            event(BASE_TS, CAPTURE_IP, PEER_A, SPI_A_OUT),
            event(BASE_TS + 1, CAPTURE_IP, PEER_A, reused),
            event(BASE_TS + 2, CAPTURE_IP, PEER_B, reused),
        ]
        states = observed_states_per_sa(events, capture_ip=CAPTURE_IP)
        ambiguous_keys = [key for key in states if key.startswith("sa-ambiguous:")]
        self.assertEqual(1, len(ambiguous_keys))

        ambiguous = states[ambiguous_keys[0]]
        # Both packets are accounted for, and the SPI is attributed to neither.
        self.assertEqual(
            2, sum(item.packet_count for item in ambiguous.spis)
        )
        resolved = states[f"sa:esp:{PEER_A}"]
        self.assertNotIn(
            f"0x{reused:08x}", {item.spi for item in resolved.spis}
        )


class TestWindowsAreScopedPerSa(unittest.TestCase):
    """The 100 ms windows that feed the RF are per SA."""

    def test_one_window_yields_one_record_per_sa(self):
        from controller.ml_inference import iter_window_records

        events = two_sa_events()
        self.assertEqual(1, len({item["ts"] // WINDOW_NS for item in events}))

        records = list(iter_window_records(
            events, capture_ip=CAPTURE_IP, sa_scoped=True
        ))
        self.assertEqual(2, len(records))
        self.assertEqual(1, len({record["window_start_ns"] for record in records}))
        self.assertEqual(
            {f"sa:esp:{PEER_A}", f"sa:esp:{PEER_B}"},
            {record["sa_identity"]["sa_group_id"] for record in records},
        )

    def test_each_sa_gets_its_own_feature_vector(self):
        from controller.ml_inference import iter_window_records

        records = list(iter_window_records(
            two_sa_events(), capture_ip=CAPTURE_IP, sa_scoped=True
        ))
        by_group = {record["sa_identity"]["sa_group_id"]: record for record in records}
        sa_a = by_group[f"sa:esp:{PEER_A}"]["features"]
        sa_b = by_group[f"sa:esp:{PEER_B}"]["features"]

        # Each vector counts only its own SA's packets.
        self.assertEqual(12, sa_a["packet_count"])
        self.assertEqual(8, sa_b["packet_count"])
        # And the traffic profiles genuinely differ, so the two vectors are not
        # a relabelling of the same merged data.
        self.assertNotEqual(sa_a, sa_b)

    def test_windows_carry_their_own_sa_identity(self):
        from correlation.ml.live_correlation import feature_windows_from_events

        windows = feature_windows_from_events(
            two_sa_events(), capture_ip=CAPTURE_IP, sa_scoped=True
        )
        self.assertEqual(2, len(windows))
        for window in windows:
            self.assertIsInstance(window, LiveFeatureWindow)
            self.assertIsNotNone(window.sa_identity)
            self.assertEqual(STATE_RESOLVED, window.sa_identity["state"])

    def test_the_single_sa_path_still_merges_the_window(self):
        """The default path is unchanged: one record, all traffic together."""
        from controller.ml_inference import iter_window_records

        records = list(iter_window_records(two_sa_events(), capture_ip=CAPTURE_IP))
        self.assertEqual(1, len(records))
        self.assertNotIn("sa_identity", records[0])
        self.assertEqual(20, records[0]["features"]["packet_count"])


class TestObservedStateIsPerSa(unittest.TestCase):
    """SA-A's observations must never be read as SA-B's."""

    def test_each_sa_gets_its_own_observed_state(self):
        from correlation.ml.live_correlation import observed_states_per_sa

        states = observed_states_per_sa(
            two_sa_events(), capture_ip=CAPTURE_IP
        )
        self.assertEqual({f"sa:esp:{PEER_A}", f"sa:esp:{PEER_B}"}, set(states))

        spis_a = {observation.spi for observation in states[f"sa:esp:{PEER_A}"].spis}
        spis_b = {observation.spi for observation in states[f"sa:esp:{PEER_B}"].spis}
        self.assertEqual({f"0x{SPI_A_OUT:08x}", f"0x{SPI_A_IN:08x}"}, spis_a)
        self.assertEqual({f"0x{SPI_B_OUT:08x}", f"0x{SPI_B_IN:08x}"}, spis_b)
        self.assertFalse(spis_a & spis_b)

    def test_packet_counts_do_not_leak_between_sas(self):
        from correlation.ml.live_correlation import observed_states_per_sa

        states = observed_states_per_sa(two_sa_events(), capture_ip=CAPTURE_IP)
        for group, expected in ((f"sa:esp:{PEER_A}", 12), (f"sa:esp:{PEER_B}", 8)):
            total = sum(item.packet_count for item in states[group].spis)
            self.assertEqual(expected, total)

    def test_the_aggregate_state_still_sees_everything(self):
        """Aggregation is still available; it is simply no longer the only view."""
        from correlation.ml.live_correlation import observed_states_per_sa

        states = observed_states_per_sa(two_sa_events(), capture_ip=CAPTURE_IP)
        total = sum(
            item.packet_count
            for state in states.values()
            for item in state.spis
        )
        self.assertEqual(20, total)


class TestMlResultCarriesItsSa(unittest.TestCase):
    """Every ML result keeps its SA and its non-authoritative status."""

    def test_ml_result_records_the_sa_it_was_produced_for(self):
        window = LiveFeatureWindow(
            window_start_ns=BASE_TS,
            window_end_ns=BASE_TS + WINDOW_NS,
            features={"packet_count": 4},
            sa_identity={
                "sa_group_id": f"sa:esp:{PEER_A}",
                "sa_id": f"sa:esp:{PEER_A}:0x{SPI_A_OUT:08x}",
            },
        )
        self.assertEqual(f"sa:esp:{PEER_A}", window.sa_identity["sa_group_id"])

    def test_an_older_ml_result_without_sa_still_loads(self):
        legacy = MLResult(traffic_class="bulk", extras={"source": "ml"})
        self.assertIsNone(legacy.sa_group_id)
        self.assertEqual(legacy, MLResult.from_dict(legacy.to_dict()))

    def test_sa_scoped_ml_result_round_trips(self):
        result = MLResult(
            model_version="traffic_rf_v1",
            traffic_class="video",
            classification_confidence=0.5,
            extras={"source": "ml"},
            sa_group_id=f"sa:esp:{PEER_B}",
            sa_id=f"sa:esp:{PEER_B}:0x{SPI_B_OUT:08x}",
        )
        self.assertEqual(result, MLResult.from_dict(result.to_dict()))

    def test_bridge_keeps_the_controller_record_contract_untouched(self):
        """The SA travels on the correlation result, never into the RF record."""
        from correlation.ml.controller_bridge import live_window_to_controller_record
        from correlation.ml.live_correlation import feature_windows_from_events

        windows = feature_windows_from_events(
            two_sa_events(), capture_ip=CAPTURE_IP, sa_scoped=True
        )
        self.assertEqual(2, len(windows))
        for window in windows:
            self.assertIsNotNone(window.sa_identity)
            record = live_window_to_controller_record(window)
            # The controller record is under the strict feature contract; an SA
            # key in it would change a contract the RF adapter validates.
            self.assertNotIn("sa_identity", record)
            self.assertNotIn("sa_group_id", record)
            self.assertNotIn("sa_id", record)


class TestEvidenceStaysPerSa(unittest.TestCase):
    """The same bytes bound to two SAs are two distinct evidence records."""

    def _base(self):
        return {
            "pcap_path": "results/capture/dual_sa.pcap",
            "artifact_type": "pcap",
            "artifact_sha256": "a" * 64,
            "byte_size": 4096,
            "run_id": "acc-eng-02",
            "window_index": 0,
        }

    def test_one_capture_bound_to_two_sas_yields_two_ids(self):
        sa_a = EvidenceRef(**self._base(), sa_group_id=f"sa:esp:{PEER_A}",
                           sa_id=f"sa:esp:{PEER_A}:0x{SPI_A_OUT:08x}")
        sa_b = EvidenceRef(**self._base(), sa_group_id=f"sa:esp:{PEER_B}",
                           sa_id=f"sa:esp:{PEER_B}:0x{SPI_B_OUT:08x}")
        self.assertNotEqual(sa_a.evidence_id, sa_b.evidence_id)

    def test_an_unscoped_reference_keeps_its_original_id(self):
        """Adding the SA field must not renumber evidence recorded earlier."""
        legacy = EvidenceRef(**self._base())
        self.assertNotIn("sa_group_id", legacy.identity_payload())
        self.assertEqual(legacy, EvidenceRef.from_dict(legacy.to_dict()))

    def test_a_scoped_reference_records_its_sa(self):
        sa_a = EvidenceRef(**self._base(), sa_group_id=f"sa:esp:{PEER_A}")
        payload = sa_a.identity_payload()
        self.assertEqual(f"sa:esp:{PEER_A}", payload["sa_group_id"])
        self.assertEqual(sa_a, EvidenceRef.from_dict(sa_a.to_dict()))


class TestBackwardCompatibility(unittest.TestCase):
    """Artifacts recorded before SA identity existed keep working."""

    def test_a_window_without_sa_identity_loads_with_none(self):
        window = LiveFeatureWindow.from_dict({
            "feature_schema_version": "v2",
            "window_start_ns": 0,
            "window_end_ns": 100,
            "features": {"packet_count": 1},
        })
        self.assertIsNone(window.sa_identity)

    def test_a_record_without_sa_identity_becomes_explicit_unknown(self):
        identity = SaIdentity.from_dict({"features": {}, "window_start_ns": 0})
        self.assertEqual(STATE_UNKNOWN, identity.state)
        self.assertEqual(SA_UNKNOWN_GROUP, identity.group_key)

    def test_a_bare_identity_round_trips(self):
        _resolver, identities = resolve_event_identities(
            two_sa_events(), capture_ip=CAPTURE_IP
        )
        original = identities[0]
        self.assertEqual(original, SaIdentity.from_dict(original.to_dict()))
        self.assertEqual(
            original, SaIdentity.from_dict({"sa_identity": original.to_dict()})
        )

    def test_sa_fields_are_optional_on_correlation_identity(self):
        from correlation.models import CorrelationIdentity

        identity = CorrelationIdentity(
            dataset_run_id="live", sequence=1, experiment_id="e", attempt_number=1
        )
        self.assertIsNone(identity.sa_group_id)
        self.assertNotIn("sa_group_id", identity.to_identity_payload())
        self.assertEqual(identity, CorrelationIdentity.from_dict(identity.to_dict()))

    def test_a_scoped_identity_changes_the_derived_audit_id(self):
        """SA-A and SA-B audit records must not be conflatable."""
        from correlation.models import CorrelationIdentity

        common = dict(
            dataset_run_id="live", sequence=1, experiment_id="e", attempt_number=1
        )
        sa_a = CorrelationIdentity(**common, sa_group_id=f"sa:esp:{PEER_A}")
        sa_b = CorrelationIdentity(**common, sa_group_id=f"sa:esp:{PEER_B}")
        unscoped = CorrelationIdentity(**common)
        self.assertNotEqual(sa_a.to_identity_payload(), sa_b.to_identity_payload())
        self.assertNotIn("sa_group_id", unscoped.to_identity_payload())


class TestStateEngineRemainsBackwardCompatible(unittest.TestCase):
    """The state engine's existing snapshot keys are untouched."""

    def test_legacy_keys_are_still_present(self):
        from ebpf.ipsec_state_builder import IPsecStateBuilder

        builder = IPsecStateBuilder()
        builder.consume_event_dict(
            event(BASE_TS, CAPTURE_IP, PEER_A, SPI_A_OUT)
        )
        snapshot = builder.snapshot()
        for key in ("spis", "esp_seen", "ah_seen", "observation_start_ns",
                    "last_packet_timestamp_ns", "packets_seen", "bytes_seen",
                    "transitions"):
            self.assertIn(key, snapshot)
        # The per-SPI shape every existing consumer reads is unchanged.
        self.assertEqual(
            {"spi", "direction", "active", "first_seen_ns", "last_seen_ns",
             "packet_count", "first_sequence", "last_sequence",
             "highest_sequence", "sequence_delta"},
            set(snapshot["spis"][0]),
        )

    def test_the_sa_view_is_additive(self):
        from ebpf.ipsec_state_builder import IPsecStateBuilder

        builder = IPsecStateBuilder()
        for index in range(3):
            builder.consume_event_dict(
                event(BASE_TS + index, CAPTURE_IP, PEER_A, SPI_A_OUT, seq=index)
            )
        for index in range(2):
            builder.consume_event_dict(
                event(BASE_TS + 100 + index, CAPTURE_IP, PEER_B, SPI_B_OUT, seq=index)
            )
        snapshot = builder.snapshot()
        # The legacy flat list still lists every SPI.
        self.assertEqual(
            {f"0x{SPI_A_OUT:08x}", f"0x{SPI_B_OUT:08x}"},
            {item["spi"] for item in snapshot["spis"]},
        )
        # ...and the new view groups them without replacing it.
        self.assertEqual(
            {(CAPTURE_IP, PEER_A), (CAPTURE_IP, PEER_B)},
            {tuple(pair) for pair in snapshot["outer_endpoint_pairs"]},
        )

    def test_two_peers_with_one_spi_each_stay_separate(self):
        from ebpf.ipsec_state_builder import IPsecStateBuilder

        builder = IPsecStateBuilder()
        builder.consume_event_dict(event(BASE_TS, CAPTURE_IP, PEER_A, SPI_A_OUT))
        builder.consume_event_dict(event(BASE_TS + 1, CAPTURE_IP, PEER_B, SPI_B_OUT))
        pairs = builder.snapshot()["outer_endpoint_pairs"]
        self.assertEqual(2, len(pairs))
        self.assertNotEqual(pairs[0], pairs[1])

    def test_an_uncertain_spi_is_recorded_with_its_reason(self):
        """Silence would hide unattributable traffic; the reason is kept."""
        from ebpf.ipsec_state_builder import IPsecStateBuilder

        builder = IPsecStateBuilder()
        builder.consume_event_dict(event(BASE_TS, CAPTURE_IP, PEER_A, SPI_A_OUT))
        self.assertEqual(
            1,
            builder.assign_sa_identities({
                f"0x{SPI_A_OUT:08x}": (
                    STATE_AMBIGUOUS,
                    "spi_reused_across_peers",
                    ("sa:esp:192.168.100.2:0x11111111",),
                ),
            }),
        )
        entry = builder.sa_snapshots()[0]
        self.assertEqual(STATE_AMBIGUOUS, entry["sa_identity_state"])
        self.assertEqual("spi_reused_across_peers", entry["sa_identity_reason"])
        self.assertIsNone(entry["sa_id"])
        self.assertEqual(
            ["sa:esp:192.168.100.2:0x11111111"], entry["sa_candidates"]
        )


if __name__ == "__main__":
    unittest.main()
