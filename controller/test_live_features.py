"""Live feature bridge tests: schema parity, L2/L3, offline parity.

Run either as:

    .venv/bin/python -m controller.test_live_features

or:

    .venv/bin/python -m unittest controller.test_live_features

The offline/live parity assertion is the core guarantee: the event stream
reconstructed from a PCAP (the exact shape ``xdp_monitor.c`` emits) fed through
``LiveFeatureExtractor`` must reproduce ``controller.features.extract_features``
for the same capture, feature-for-feature, because both share the single
``summarize_capture`` computation.
"""

import json
import tempfile
import unittest
from pathlib import Path

from ebpf.xdp_window_aggregator import WINDOW_SIZE_MS

from controller import features as feats
from controller.dataset_artifacts import (
    FEATURE_COLUMNS,
    FEATURE_KEYS,
    FLOAT_FEATURES,
    INT_FEATURES,
    FEATURE_SCHEMA_VERSION,
    assert_feature_keys,
)
from controller.live_features import (
    ETHERNET_HEADER_BYTES,
    LiveFeatureExtractor,
    extract_record,
    iterate_capture_as_live_events,
)

PACAP_DIR = Path(__file__).resolve().parent / "testdata"
FIXTURE = PACAP_DIR / "wan_side_esp_ike_sample.pcap"
GATEWAY_A = "192.168.100.1"

#: The completed ground-truth run whose five real WAN-side captures back the
#: strongest parity check.
RUN_DIR = Path(__file__).resolve().parent.parent / "results" / "datasets" \
    / "dataset-20260916-231246"

REMOVED_IN_V2 = {
    "ike_sa_init_count", "ike_auth_count", "ike_create_child_sa_count",
    "ike_informational_count", "ike_version",
}
LABEL_OR_METADATA = {
    "dataset_schema_version", "dataset_run_id", "experiment_id",
    "attempt_number", "sequence", "traffic_profile", "security_posture",
    "configuration_id", "mode", "address_family", "pcap_path", "captured_at",
    "ipsec_configuration",
}


def esp_event(ts_s, src=GATEWAY_A, dst="192.168.100.2", l2_len=154):
    return {"ts": round(ts_s * 1_000_000_000), "type": "ESP", "src": src,
            "dst": dst, "proto": 50, "len": l2_len, "spi": 1, "seq": 1}


def ike_event(ts_s, l2_len=500, port=500):
    return {"ts": round(ts_s * 1_000_000_000),
            "type": "IKE-NAT-T" if port == 4500 else "IKE",
            "src": GATEWAY_A, "dst": "192.168.100.2", "proto": 17,
            "len": l2_len, "sport": port, "dport": port}


def other_event(ts_s):
    return {"ts": round(ts_s * 1_000_000_000), "type": "OTHER", "src": "0.0.0.0",
            "dst": "0.0.0.0", "proto": 0, "len": 90, "sport": 0, "dport": 0}


class TestRecordShape(unittest.TestCase):
    def test_metadata_stays_outside_features(self):
        snap = extract_record([esp_event(1.0), ike_event(1.01)])
        self.assertEqual(set(snap) - {"features"},
                         set(LiveFeatureExtractor().snapshot()) - {"features"})
        self.assertEqual(snap["feature_schema_version"], "v2")
        self.assertEqual(snap["feature_schema_version"], FEATURE_SCHEMA_VERSION)
        self.assertSetEqual(set(snap["features"]), FEATURE_KEYS)
        self.assertEqual(len(snap["features"]), 59)
        self.assertEqual(len(set(FEATURE_COLUMNS)), 59, "schema has no dupes")

    def test_no_label_or_metadata_leak(self):
        snap = extract_record([esp_event(1.0), ike_event(1.01)])
        self.assertTrue(LABEL_OR_METADATA.isdisjoint(snap["features"]))
        self.assertTrue(REMOVED_IN_V2.isdisjoint(snap["features"]))

    def test_feature_types_match_schema(self):
        snap = extract_record([esp_event(1.0), ike_event(1.01, 500)])
        for name in INT_FEATURES:
            self.assertIsInstance(snap["features"][name], int, name)
            self.assertIsNot(snap["features"][name], True, name)
        for name in FLOAT_FEATURES:
            # The shared computation may return an integral value as an int
            # (Python >= 3.12 statistics yields int for exact means); the
            # schema contract is that the column is numeric (float64 in
            # parquet).  Never a bool and never a string.
            self.assertIsInstance(snap["features"][name], (int, float), name)
            self.assertIsNot(snap["features"][name], True, name)

    def test_empty_stream_produces_valid_zero_record(self):
        snap = extract_record([])
        self.assertEqual(snap["window_start_ns"], 0)
        self.assertEqual(snap["window_end_ns"], 0)
        self.assertEqual(snap["features"]["packet_count"], 0)
        self.assertEqual(snap["features"]["ike_packet_count"], 0)
        # The record is schema-complete (validated, not an exception).
        assert_feature_keys(snap["features"])
        for name in FLOAT_FEATURES:
            self.assertEqual(snap["features"][name], 0.0, name)
        for name in INT_FEATURES:
            self.assertEqual(snap["features"][name], 0, name)


class TestSizeAndDirection(unittest.TestCase):
    def test_l2_len_converted_to_l3(self):
        # len=154 (L2) => ip_total=140 (L3), exactly matching the offline parse.
        snap = extract_record([esp_event(0.0, l2_len=154),
                               esp_event(0.02, l2_len=154)],
                              capture_ip=GATEWAY_A)
        self.assertEqual(snap["features"]["mean_packet_size"], 140.0)
        self.assertEqual(snap["features"]["total_bytes"], 280)
        self.assertEqual(snap["features"]["min_packet_size"], 140)
        self.assertEqual(snap["features"]["max_packet_size"], 140)
        # 20 ms gap => one burst under the default 50 ms gate, none at 10 ms.
        self.assertEqual(snap["features"]["burst_count"], 1)
        self.assertEqual(snap["features"]["burst_count_10ms"], 0)
        self.assertEqual(snap["features"]["burst_count_50ms"], 1)
        self.assertEqual(snap["features"]["burst_count_200ms"], 1)

    def test_direction_anchored_to_capture_point(self):
        snap = extract_record([
            esp_event(0.0, src="192.168.100.1", dst="192.168.100.2"),
            esp_event(0.01, src="192.168.100.2", dst="192.168.100.1"),
            esp_event(0.02, src="203.0.113.9", dst="198.51.100.7"),
        ], capture_ip=GATEWAY_A)
        self.assertEqual(snap["features"]["outbound_packet_count"], 1)
        self.assertEqual(snap["features"]["inbound_packet_count"], 1)
        # Unknown sources are counted in totals but not attributed.
        self.assertEqual(snap["features"]["packet_count"], 3)

    def test_unknown_sources_leave_directional_fields_zero(self):
        snap = extract_record([esp_event(0.0, src="203.0.113.9",
                                         dst="198.51.100.7")],
                              capture_ip=GATEWAY_A)
        self.assertEqual(snap["features"]["outbound_packet_count"], 0)
        self.assertEqual(snap["features"]["inbound_packet_count"], 0)


class TestIkeBlock(unittest.TestCase):
    def test_ike_types_combine_and_esp_stays_separate(self):
        snap = extract_record([
            esp_event(0.0, l2_len=154),
            ike_event(0.01, l2_len=460, port=500),
            ike_event(0.02, l2_len=500, port=4500),
        ], capture_ip=GATEWAY_A)
        self.assertEqual(snap["features"]["packet_count"], 1)
        self.assertEqual(snap["features"]["ike_packet_count"], 2)
        self.assertEqual(snap["features"]["ike_datagram_bytes"], 460 - 14 + 500 - 14)
        self.assertEqual(snap["features"]["ike_min_packet_size"], 446)
        self.assertEqual(snap["features"]["ike_max_packet_size"], 486)

    def test_ah_and_other_are_not_features(self):
        snap = extract_record([
            esp_event(0.0),
            ike_event(0.01),
            {"ts": round(0.02 * 1e9), "type": "AH", "src": GATEWAY_A,
             "dst": "192.168.100.2", "proto": 51, "len": 110, "spi": 1, "seq": 1},
            other_event(0.03),
        ], capture_ip=GATEWAY_A)
        self.assertEqual(snap["features"]["packet_count"], 1)
        self.assertEqual(snap["features"]["ike_packet_count"], 1)
        # AH/OTHER contribute nothing to any of the 59 columns.
        self.assertEqual(snap["features"]["total_bytes"], 154 - 14)


class TestWindowBoundariesAndEpochs(unittest.TestCase):
    def test_span_covers_first_and_last_windows(self):
        ns = 100 * 1_000_000
        window_ns = WINDOW_SIZE_MS * 1_000_000
        snap = extract_record([esp_event(ns / 1e9), esp_event((ns + window_ns + 1) / 1e9)])
        self.assertEqual(snap["window_start_ns"],
                         (int(ns / window_ns) * window_ns))
        self.assertEqual(snap["window_end_ns"],
                         ((int((ns + window_ns + 1) / window_ns) + 1) * window_ns))

    def test_reset_starts_clean_epoch(self):
        ext = LiveFeatureExtractor(capture_ip=GATEWAY_A)
        ext.accept_dict(esp_event(0.0))
        ext.reset()
        self.assertEqual(ext.features()["packet_count"], 0)
        self.assertEqual(ext.window_start_ns, 0)
        self.assertEqual(ext.window_end_ns, 0)


class TestOfflineLiveParity(unittest.TestCase):
    def test_fixture_parity_exact(self):
        offline = feats.extract_features(str(FIXTURE), capture_ip=GATEWAY_A)
        live = extract_record(iterate_capture_as_live_events(str(FIXTURE)),
                              capture_ip=GATEWAY_A)
        self.assertEqual(live["features"], offline)

    def test_fixture_parity_exact_with_nominal_duration(self):
        offline = feats.extract_features(str(FIXTURE), capture_ip=GATEWAY_A,
                                         nominal_duration=30.0)
        live = extract_record(iterate_capture_as_live_events(str(FIXTURE)),
                              capture_ip=GATEWAY_A, nominal_duration=30.0)
        self.assertEqual(live["features"], offline)

    @unittest.skipUnless(RUN_DIR.is_dir(),
                         "ground-truth dataset directory not present")
    def test_real_run_captures_parity(self):
        pcaps = sorted(RUN_DIR.glob("captures/*/*.pcap"))
        self.assertGreaterEqual(len(pcaps), 1)
        for path in pcaps:
            with self.subTest(pcap=path.name):
                offline = feats.extract_features(str(path),
                                                 capture_ip=GATEWAY_A,
                                                 nominal_duration=30.0)
                live = extract_record(
                    iterate_capture_as_live_events(str(path)),
                    capture_ip=GATEWAY_A, nominal_duration=30.0)
                self.assertEqual(live["features"], offline)


class TestCli(unittest.TestCase):
    def test_main_emits_valid_jsonl(self):
        events = [esp_event(0.0), ike_event(0.01), esp_event(0.02)]
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                         delete=False) as ev_in:
            for e in events:
                ev_in.write(json.dumps(e) + "\n")
            ev_in_path = ev_in.name
        out_path = ev_in_path + ".out"
        try:
            from controller.live_features import main
            rc = main(["--events", ev_in_path, "--output", out_path,
                       "--capture-ip", GATEWAY_A])
            self.assertEqual(rc, 0)
            lines = [line for line in Path(out_path).read_text().splitlines()
                     if line.strip()]
            self.assertEqual(len(lines), 1)
            record = json.loads(lines[0])
            self.assertEqual(record["feature_schema_version"], "v2")
            self.assertSetEqual(set(record["features"]), FEATURE_KEYS)
        finally:
            Path(ev_in_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)