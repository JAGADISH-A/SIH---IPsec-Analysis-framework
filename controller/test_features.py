"""Feature-extractor regression tests (L2/L3 size semantics, schema parity).

Run either as:

    .venv/bin/python -m controller.test_features

or:

    .venv/bin/python -m unittest controller.test_features

The PCAP fixture ``testdata/wan_side_esp_ike_sample.pcap`` is a verbatim
prefix of a real WAN-side mirror capture taken during the completed dataset
run ``dataset-20260916-231246`` (sample 1, voip / STRONG).  It contains four
IKE negotiation frames (IKE_SA_INIT on UDP 500, IKE_AUTH on UDP 4500) and
four ESP data frames as observed on the wire.
"""

import unittest
from pathlib import Path

from controller import features as feats
from controller.dataset_artifacts import FEATURE_KEYS, FEATURE_SCHEMA_VERSION

PACAP_DIR = Path(__file__).resolve().parent / "testdata"
FIXTURE = PACAP_DIR / "wan_side_esp_ike_sample.pcap"

GATEWAY_A = "192.168.100.1"     # capture point for the fixture run
ETHERNET_HEADER_BYTES = 14       # linktype 1 pcap framing


class TestPcapFixtureIsPresent(unittest.TestCase):
    def test_fixture_exists_and_is_nonempty(self):
        self.assertTrue(FIXTURE.is_file(),
                        f"missing real-pcap fixture at {FIXTURE}")
        self.assertGreater(FIXTURE.stat().st_size, 0)


class TestL2L3Relationship(unittest.TestCase):
    """On the WAN-side mirror the pcap incl_len is the full L2 Ethernet frame
    and ip_total is the L3 outer-IP total length, so incl_len = ip_total + 14.
    The features are derived from ip_total (L3).  This pins the semantics
    deploy-time feature stages must match on live XDP ``len`` (= L2).
    """

    def test_esp_frames_are_ethernet_framed(self):
        frames = feats.read_pcap(str(FIXTURE))
        self.assertGreater(len(frames), 0)
        for timestamp, incl_len, ip_total, _src, _dst in frames:
            self.assertEqual(incl_len, ip_total + ETHERNET_HEADER_BYTES,
                             f"frame at t={timestamp} is not Ethernet-framed")

    def test_ike_frames_are_ethernet_framed(self):
        frames = feats.read_pcap_ike(str(FIXTURE))
        self.assertGreater(len(frames), 0)
        for timestamp, incl_len, ip_total, *_rest in frames:
            self.assertEqual(incl_len, ip_total + ETHERNET_HEADER_BYTES,
                             f"IKE frame at t={timestamp} is not Ethernet-framed")

    def test_known_esp_frame_size(self):
        frame = feats.read_pcap(str(FIXTURE))[0]
        self.assertEqual(frame[1], 154)   # incl_len (L2)
        self.assertEqual(frame[2], 140)   # ip_total (L3)

    def test_extract_features_uses_l3_sizes(self):
        extracted = feats.extract_features(str(FIXTURE), capture_ip=GATEWAY_A)
        ip_total_sizes = [f[2] for f in feats.read_pcap(str(FIXTURE))]
        incl_len_sizes = [f[1] for f in feats.read_pcap(str(FIXTURE))]
        self.assertEqual(extracted["mean_packet_size"], 140.0)
        # The feature sizes come from ip_total, never from the L2 incl_len.
        self.assertNotEqual(extracted["mean_packet_size"],
                            sum(incl_len_sizes) / len(incl_len_sizes))
        self.assertEqual(extracted["total_bytes"], sum(ip_total_sizes))
        self.assertEqual(extracted["min_packet_size"], min(ip_total_sizes))

    def test_direction_is_anchored_to_capture_point(self):
        extracted = feats.extract_features(str(FIXTURE), capture_ip=GATEWAY_A)
        # Fixture prefix includes the bidirectional pre-traffic probe
        # (2 outbound + 2 inbound ESP frames).
        self.assertEqual(extracted["outbound_packet_count"], 2)
        self.assertEqual(extracted["inbound_packet_count"], 2)


class TestFeatureSchemaParity(unittest.TestCase):
    """The extractor output must always match the declared artifact schema."""

    def test_extractor_matches_feature_columns(self):
        extracted = feats.extract_features(str(FIXTURE), capture_ip=GATEWAY_A)
        self.assertEqual(set(extracted), FEATURE_KEYS)
        self.assertEqual(len(extracted), 59)
        self.assertEqual(FEATURE_SCHEMA_VERSION, "v2")

    def test_ike_exchange_and_version_are_not_ml_features(self):
        excluded = {
            "ike_sa_init_count",
            "ike_auth_count",
            "ike_create_child_sa_count",
            "ike_informational_count",
            "ike_version",
        }
        extracted = feats.extract_features(str(FIXTURE), capture_ip=GATEWAY_A)
        self.assertTrue(excluded.isdisjoint(extracted),
                        f"live-unobservable features leaked: {excluded & set(extracted)}")
        # The size/count IKE stats stay: they are live-producible.
        self.assertEqual(extracted["ike_packet_count"], 4)
        self.assertEqual(extracted["ike_min_packet_size"], 320)
        self.assertEqual(extracted["ike_max_packet_size"], 500)


if __name__ == "__main__":
    unittest.main(verbosity=2)