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

class TestNatTFramingOnUdp4500(unittest.TestCase):
    """UDP/4500 carries BOTH IKE and ESP; the reader must not conflate them.

    RFC 3948 shares one port between the two and separates them with a
    four-byte non-ESP marker of 00 00 00 00, which occupies exactly the
    position where an ESP SPI would sit.  These tests pin the rule that
    "leading word == 0" means IKE, matching classify_nat_t_udp() in
    ebpf/xdp_monitor.bpf.c, so the PCAP reader and the live XDP classifier
    can never disagree about the same bytes.
    """

    LINKTYPE = 1  # Ethernet

    def _udp4500(self, payload):
        import struct

        udp_len = 8 + len(payload)
        udp = struct.pack(">HHHH", 4500, 4500, udp_len, 0) + payload
        ihl = 20
        total = ihl + len(udp)
        ip = struct.pack(
            ">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 17, 0,
            bytes([10, 20, 1, 10]), bytes([10, 30, 1, 20]),
        )
        eth = b"\x02" * 6 + b"\x02" * 6 + b"\x08\x00"
        return eth + ip + udp

    def test_ike_marker_frame_is_not_counted_as_esp(self):
        import struct

        # RFC 3948 non-ESP marker followed by an ISAKMP header.
        ike = struct.pack(">I", 0) + bytes(range(1, 33))
        self.assertIsNone(feats._natt_esp_length(self._udp4500(ike), 14 + 20))

    def test_esp_frame_on_4500_is_recognized_with_its_payload_length(self):
        import struct

        esp = struct.pack(">II", 0xCE575EC4, 7) + bytes(100)
        self.assertEqual(
            feats._natt_esp_length(self._udp4500(esp), 14 + 20), len(esp),
        )

    def test_ike_marker_never_yields_a_spi(self):
        """An IKE header must not be reported as an ESP SPI.

        Stepping over the marker and reading four bytes of the IKE header
        would produce a real-looking number that resolves against no SA.
        """
        import struct

        ike = struct.pack(">I", 0) + struct.pack(">I", 0x9FFB7F8E) + bytes(16)
        self.assertIsNone(feats._natt_esp_start(self._udp4500(ike), 14 + 20))

    def test_esp_on_4500_yields_its_real_spi(self):
        import struct

        spi = 0xCE575EC4
        esp = struct.pack(">II", spi, 1) + bytes(16)
        frame = self._udp4500(esp)
        # ip_total is the OUTER IP length here (this reader reports frame
        # identity, not ESP payload size, which read_pcap handles separately).
        self.assertEqual(feats._esp_ipv4(frame, 14), (
            20 + 8 + len(esp),
            bytes([10, 20, 1, 10]),
            bytes([10, 30, 1, 20]),
            spi,
        ))

    def test_non_4500_udp_is_never_esp(self):
        import struct

        # Ordinary UDP/500 negotiation must not be folded into ESP statistics.
        payload = struct.pack(">II", 0x9FFB7F8E, 0) + bytes(32)
        frame = bytearray(self._udp4500(payload))
        struct.pack_into(">H", frame, 14 + 20, 500)  # sport
        struct.pack_into(">H", frame, 14 + 22, 500)  # dport
        self.assertIsNone(feats._natt_esp_length(bytes(frame), 14 + 20))
