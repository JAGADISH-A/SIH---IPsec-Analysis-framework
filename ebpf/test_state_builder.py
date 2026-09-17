"""Unit tests for the observed IPsec state builder (ipsec_state_builder.py).

Fully synthetic: the builder is fed crafted packet events and window records.
No live XDP or network is needed.
"""

import json
import unittest

from ebpf.xdp_window_aggregator import PacketEvent
from ebpf.ipsec_state_builder import (
    IPsecStateBuilder,
    STATE_ACTIVE_TIMEOUT_MS,
    TRANSITION_ACTIVE,
    TRANSITION_INACTIVE,
    TRANSITION_SPI_OBSERVED,
    TRANSITION_TRAFFIC_OBSERVED,
)

GW_A = "192.168.100.1"
GW_B = "192.168.100.2"

TIMEOUT_NS = STATE_ACTIVE_TIMEOUT_MS * 1_000_000


def esp(ts, spi=0x1111, seq=1, src=GW_A, dst=GW_B, length=154):
    return PacketEvent(ts=ts, type="ESP", src=src, dst=dst, proto=50,
                       length=length, spi=spi, seq=seq)


def ike_nat_t(ts, src=GW_A, dst=GW_B, length=126):
    return PacketEvent(ts=ts, type="IKE-NAT-T", src=src, dst=dst, proto=17,
                       length=length, sport=4500, dport=4500)


def ike(ts, src=GW_A, dst=GW_B, length=126):
    return PacketEvent(ts=ts, type="IKE", src=src, dst=dst, proto=17,
                       length=length, sport=500, dport=500)


def ah(ts, src=GW_A, dst=GW_B, length=100):
    return PacketEvent(ts=ts, type="AH", src=src, dst=dst, proto=51,
                       length=length, spi=0x55, seq=1)


def transition_types(snapshot):
    return [t["type"] for t in snapshot["transitions"]]


class TestInitialState(unittest.TestCase):
    def test_empty_initial_state(self):
        b = IPsecStateBuilder()
        s = b.snapshot(now_ns=0)
        self.assertFalse(s["active"])
        self.assertFalse(s["tunnel_seen"])
        self.assertIsNone(s["last_packet_timestamp_ns"])
        self.assertEqual(s["packets_seen"], 0)
        self.assertEqual(s["bytes_seen"], 0)
        self.assertFalse(s["ike_seen"])
        self.assertFalse(s["ike_nat_t_seen"])
        self.assertFalse(s["esp_seen"])
        self.assertFalse(s["ah_seen"])
        self.assertFalse(s["observed_ike_activity"])
        self.assertEqual(s["spis"], [])
        self.assertEqual(s["endpoints"], {"a": GW_A, "b": GW_B})

    def test_first_esp_creates_observed_state(self):
        b = IPsecStateBuilder()
        b.consume_event(esp(1000, spi=0xAAAA, seq=1))
        s = b.snapshot(now_ns=1000)
        self.assertTrue(s["esp_seen"])
        self.assertTrue(s["active"])
        self.assertTrue(s["tunnel_seen"])
        self.assertEqual(s["packets_seen"], 1)
        self.assertEqual(s["last_packet_timestamp_ns"], 1000)
        self.assertEqual(len(s["spis"]), 1)
        self.assertIn(TRANSITION_TRAFFIC_OBSERVED, transition_types(s))
        self.assertIn(TRANSITION_SPI_OBSERVED, transition_types(s))


class TestTrafficState(unittest.TestCase):
    def test_a_to_b_direction(self):
        b = IPsecStateBuilder()
        b.consume_event(esp(10, src=GW_A, dst=GW_B))
        b.consume_event(esp(11, src=GW_A, dst=GW_B))
        s = b.snapshot()
        self.assertEqual(s["packets_a_to_b"], 2)
        self.assertEqual(s["packets_b_to_a"], 0)
        self.assertEqual(s["bytes_a_to_b"], 308)
        self.assertEqual(s["bytes_b_to_a"], 0)

    def test_b_to_a_direction(self):
        b = IPsecStateBuilder()
        b.consume_event(esp(10, src=GW_B, dst=GW_A))
        s = b.snapshot()
        self.assertEqual(s["packets_a_to_b"], 0)
        self.assertEqual(s["packets_b_to_a"], 1)

    def test_ike_nat_t_activity_recorded(self):
        b = IPsecStateBuilder()
        b.consume_event(ike_nat_t(500))
        s = b.snapshot(now_ns=500)
        self.assertTrue(s["ike_nat_t_seen"])
        self.assertFalse(s["ike_seen"])
        self.assertEqual(s["last_ike_nat_t_timestamp_ns"], 500)
        self.assertTrue(s["observed_ike_activity"])

    def test_esp_activity_recorded(self):
        b = IPsecStateBuilder()
        b.consume_event(esp(700, spi=0xBBBB, seq=9))
        s = b.snapshot(now_ns=700)
        self.assertTrue(s["esp_seen"])
        self.assertEqual(s["last_esp_timestamp_ns"], 700)
        self.assertFalse(s["ah_seen"])

    def test_ah_activity_recorded(self):
        b = IPsecStateBuilder()
        b.consume_event(ah(800))
        s = b.snapshot(now_ns=800)
        self.assertTrue(s["ah_seen"])
        self.assertEqual(s["last_ah_timestamp_ns"], 800)


class TestSpiState(unittest.TestCase):
    def test_spi_first_observation(self):
        b = IPsecStateBuilder()
        b.consume_event(esp(100, spi=0xDEADBEEF, seq=7))
        s = b.snapshot(now_ns=100)
        spi = s["spis"][0]
        self.assertEqual(spi["spi"], "0xdeadbeef")
        self.assertEqual(spi["direction"], "A_TO_B")
        self.assertEqual(spi["first_seen_ns"], 100)
        self.assertEqual(spi["last_seen_ns"], 100)
        self.assertEqual(spi["packet_count"], 1)
        self.assertEqual(spi["first_sequence"], 7)

    def test_multiple_packets_same_spi(self):
        b = IPsecStateBuilder()
        for seq in (1, 2, 3):
            b.consume_event(esp(100 + seq, spi=0x1234, seq=seq))
        spi = b.snapshot(now_ns=103)["spis"][0]
        self.assertEqual(spi["packet_count"], 3)
        self.assertEqual(spi["first_sequence"], 1)
        self.assertEqual(spi["last_sequence"], 3)
        self.assertEqual(spi["highest_sequence"], 3)
        self.assertEqual(spi["sequence_delta"], 2)

    def test_multiple_spis(self):
        b = IPsecStateBuilder()
        b.consume_event(esp(1, spi=0x1111, seq=1, src=GW_A))
        b.consume_event(esp(2, spi=0x2222, seq=1, src=GW_B))
        s = b.snapshot(now_ns=2)
        self.assertEqual(len(s["spis"]), 2)
        directions = {spi["spi"]: spi["direction"] for spi in s["spis"]}
        self.assertEqual(directions["0x00001111"], "A_TO_B")
        self.assertEqual(directions["0x00002222"], "B_TO_A")

    def test_spi_change_rekey_transition(self):
        b = IPsecStateBuilder()
        # Old SPI active in the first period.
        for seq in range(1, 4):
            b.consume_event(esp(1000 + seq, spi=0xAAAA, seq=seq))
        # Rekey: new SPI takes over well after the old one went quiet.
        for seq in range(1, 3):
            b.consume_event(esp(TIMEOUT_NS + 2000 + seq, spi=0xBBBB, seq=seq))
        s = b.snapshot(now_ns=TIMEOUT_NS + 2002)
        by_spi = {spi["spi"]: spi for spi in s["spis"]}
        self.assertEqual(set(by_spi), {"0x0000aaaa", "0x0000bbbb"})
        self.assertFalse(by_spi["0x0000aaaa"]["active"])   # old, gone quiet
        self.assertTrue(by_spi["0x0000bbbb"]["active"])     # new
        # The new SPI is an observed transition, not an error.
        spi_events = [t for t in s["transitions"] if t["type"] == TRANSITION_SPI_OBSERVED]
        self.assertEqual(spi_events[-1]["spi"], "0x0000bbbb")
        self.assertIn("0x0000aaaa", spi_events[-1]["known_spis"])

    def test_new_spi_does_not_inherit_old_sequence(self):
        b = IPsecStateBuilder()
        b.consume_event(esp(10, spi=0xAAAA, seq=100))
        b.consume_event(esp(11, spi=0xAAAA, seq=101))
        b.consume_event(esp(12, spi=0xBBBB, seq=1))   # new SA starts at 1
        by_spi = {spi["spi"]: spi for spi in b.snapshot(now_ns=12)["spis"]}
        self.assertEqual(by_spi["0x0000aaaa"]["first_sequence"], 100)
        self.assertEqual(by_spi["0x0000bbbb"]["first_sequence"], 1)
        self.assertEqual(by_spi["0x0000bbbb"]["last_sequence"], 1)
        self.assertEqual(by_spi["0x0000bbbb"]["sequence_delta"], 0)


class TestSequenceState(unittest.TestCase):
    def test_sequence_progression(self):
        b = IPsecStateBuilder()
        for seq in (10, 11, 12, 13):
            b.consume_event(esp(seq, spi=0x1, seq=seq))
        spi = b.snapshot(now_ns=13)["spis"][0]
        self.assertEqual(spi["first_sequence"], 10)
        self.assertEqual(spi["last_sequence"], 13)
        self.assertEqual(spi["highest_sequence"], 13)
        self.assertEqual(spi["sequence_delta"], 3)

    def test_sequence_wraparound(self):
        b = IPsecStateBuilder()
        for i, seq in enumerate([0xFFFFFFFE, 0xFFFFFFFF, 0x00000000, 0x00000001]):
            b.consume_event(esp(100 + i, spi=0x1, seq=seq))
        spi = b.snapshot(now_ns=103)["spis"][0]
        self.assertEqual(spi["first_sequence"], 0xFFFFFFFE)
        self.assertEqual(spi["last_sequence"], 1)
        self.assertEqual(spi["highest_sequence"], 0xFFFFFFFF)
        # Small forward step across the wrap, not a ~4e9 jump.
        self.assertEqual(spi["sequence_delta"], 3)


class TestActiveInactive(unittest.TestCase):
    def test_active_timeout(self):
        b = IPsecStateBuilder()
        b.consume_event(esp(1000, spi=0x1, seq=1))
        self.assertTrue(b.snapshot(now_ns=1000 + TIMEOUT_NS)["active"])
        self.assertFalse(b.snapshot(now_ns=1000 + TIMEOUT_NS + 1)["active"])

    def test_inactive_then_reactivated_transition(self):
        b = IPsecStateBuilder()
        b.consume_event(esp(1000, spi=0x1, seq=1))
        s1 = b.snapshot(now_ns=1000)
        self.assertTrue(s1["active"])
        s2 = b.snapshot(now_ns=1000 + TIMEOUT_NS + 1)
        self.assertFalse(s2["active"])
        self.assertIn(TRANSITION_INACTIVE, transition_types(s2))
        b.consume_event(esp(1000 + 2 * TIMEOUT_NS, spi=0x1, seq=2))
        s3 = b.snapshot(now_ns=1000 + 2 * TIMEOUT_NS)
        self.assertTrue(s3["active"])
        self.assertIn(TRANSITION_ACTIVE, transition_types(s3))

    def test_configurable_active_timeout(self):
        b = IPsecStateBuilder(active_timeout_ms=50)
        b.consume_event(esp(0, spi=0x1, seq=1))
        self.assertTrue(b.snapshot(now_ns=50_000_000)["active"])
        self.assertFalse(b.snapshot(now_ns=50_000_001)["active"])
        self.assertEqual(b.snapshot(now_ns=0)["active_timeout_ms"], 50)


class TestTerminologyAndSerialization(unittest.TestCase):
    def test_no_false_ike_sa_establishment_claim(self):
        b = IPsecStateBuilder()
        b.consume_event(ike_nat_t(10))
        s = b.snapshot(now_ns=10)
        for key in ("ike_sa_established", "sa_established"):
            self.assertNotIn(key, s)
        blob = json.dumps(s).lower()
        self.assertNotIn("established", blob)
        # Only an observation is reported.
        self.assertTrue(s["observed_ike_activity"])

    def test_no_cryptographic_inference(self):
        b = IPsecStateBuilder()
        b.consume_event(esp(10, spi=0x1, seq=1))
        s = b.snapshot(now_ns=10)
        for key in ("algorithm", "cipher", "encryption", "authentication",
                    "encryption_strength"):
            self.assertNotIn(key, s)
        blob = json.dumps(s).upper()
        for token in ("AES", "SHA", "CHACHA", "GCM"):
            self.assertNotIn(token, blob)

    def test_snapshot_json_serialization(self):
        b = IPsecStateBuilder()
        b.consume_event(esp(10, spi=0xA1B2C3D4, seq=1))
        b.consume_event(esp(20, spi=0xA1B2C3D4, seq=2))
        s = b.snapshot(now_ns=20)
        text = json.dumps(s)
        again = json.loads(text)
        self.assertEqual(again["spis"][0]["spi"], "0xa1b2c3d4")
        self.assertEqual(again["packets_seen"], 2)
        self.assertEqual(again["endpoints"]["a"], GW_A)


class TestWindowInput(unittest.TestCase):
    def test_window_input_updates_aggregate_only(self):
        b = IPsecStateBuilder()
        b.consume_window({
            "window_start_ns": 100, "window_end_ns": 200,
            "total_packets": 4, "total_bytes": 600,
            "esp_packets": 3, "ike_nat_t_packets": 1,
            "packets_a_to_b": 2, "packets_b_to_a": 2,
            "bytes_a_to_b": 300, "bytes_b_to_a": 300,
            "unique_esp_spi_count": 2,
        })
        s = b.snapshot(now_ns=200)
        self.assertEqual(s["packets_seen"], 4)
        self.assertEqual(s["bytes_seen"], 600)
        self.assertEqual(s["packets_a_to_b"], 2)
        self.assertEqual(s["packets_b_to_a"], 2)
        self.assertTrue(s["esp_seen"])
        self.assertTrue(s["ike_nat_t_seen"])
        # unique_esp_spi_count is NOT turned into invented SPI entries.
        self.assertEqual(s["spis"], [])
        self.assertIn(TRANSITION_TRAFFIC_OBSERVED, transition_types(s))

    def test_empty_window_is_ignored(self):
        b = IPsecStateBuilder()
        b.consume_window({"window_start_ns": 0, "window_end_ns": 100,
                          "total_packets": 0, "total_bytes": 0})
        s = b.snapshot(now_ns=100)
        self.assertEqual(s["packets_seen"], 0)
        self.assertFalse(s["active"])

    def test_events_and_windows_share_state_model(self):
        # Event path and window path produce the same aggregate fields for the
        # same traffic (proving there is no separate implementation).
        ev = IPsecStateBuilder()
        ev.consume_event(esp(100, spi=0x1, seq=1, length=154))
        ev_snap = ev.snapshot(now_ns=100)

        win = IPsecStateBuilder()
        win.consume_window({"window_start_ns": 0, "window_end_ns": 100,
                            "total_packets": 1, "total_bytes": 154,
                            "esp_packets": 1, "packets_a_to_b": 1,
                            "bytes_a_to_b": 154})
        win_snap = win.snapshot(now_ns=100)
        for key in ("packets_seen", "bytes_seen", "packets_a_to_b",
                    "bytes_a_to_b", "esp_seen", "active"):
            self.assertEqual(ev_snap[key], win_snap[key], key)


class TestConfigurationAndReset(unittest.TestCase):
    def test_custom_endpoints(self):
        b = IPsecStateBuilder(endpoints={"10.0.0.1": "A_TO_B", "10.0.0.2": "B_TO_A"})
        b.consume_event(esp(1, src="10.0.0.1", dst="10.0.0.2"))
        s = b.snapshot(now_ns=1)
        self.assertEqual(s["endpoints"], {"a": "10.0.0.1", "b": "10.0.0.2"})
        self.assertEqual(s["packets_a_to_b"], 1)

    def test_reset(self):
        b = IPsecStateBuilder()
        b.consume_event(esp(1, spi=0x1, seq=1))
        b.reset()
        s = b.snapshot(now_ns=1)
        self.assertEqual(s["packets_seen"], 0)
        self.assertEqual(s["spis"], [])
        self.assertEqual(s["transitions"], [])
        self.assertFalse(s["active"])


if __name__ == "__main__":
    unittest.main()
