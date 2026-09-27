"""Unit tests for ``read_pcap_esp_with_spi``.

The real multi-SA capture is marker-less strongSwan, so it cannot exercise the
RFC 3948 non-ESP marker path that other peers emit.  These tests build frames by
hand to cover both framings, plus the link types and failure modes that decide
whether an SA resolves or silently degrades to ``UNKNOWN``.

The behaviour that matters most: a frame whose SPI cannot be read must be
reported with ``spi=None`` rather than dropped or, worse, given an invented
value.  A wrong SPI would attribute one SA's traffic to another.
"""

import struct
import tempfile
import unittest
from pathlib import Path

from controller import features as feats

V6_A = "20010db8000000000000000000000001"
V6_B = "20010db8000000000000000000000002"

SPI_A = 0xC68118C9
SPI_B = 0xC054B297


def _ip4(src, dst, proto, payload):
    total = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, 0, 0, 64, proto, 0,
        bytes(int(p) for p in src.split(".")),
        bytes(int(p) for p in dst.split(".")),
    )
    return header + payload


def _ip6(src, dst, next_header, payload):
    # ``src``/``dst`` are bare 32 hex-digit addresses; ``::`` shorthand is
    # expanded by the caller so this stays a plain fromhex().
    return (
        struct.pack("!IHBB", 0x60000000, len(payload), next_header, 64)
        + bytes.fromhex(src)
        + bytes.fromhex(dst)
        + payload
    )


def _udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _esp(spi, seq=1, body=b"\xaa" * 24):
    return struct.pack("!II", spi, seq) + body


def _ethernet(ethertype, payload):
    return b"\x02" * 6 + b"\x04" * 6 + struct.pack("!H", ethertype) + payload


def _sll2(protocol, payload):
    # LINUX_SLL2 is exactly 20 bytes: protocol, reserved, if_index, hatype,
    # pkttype, halen, then an 8-byte address.  The network layer starts at 20.
    return (
        struct.pack("!HHIHBB", protocol, 0, 1, 1, 0, 6) + b"\x00" * 8 + payload
    )


def _write_pcap(frames, linktype=1, tmp=None):
    """Write a little-endian microsecond pcap; returns its path."""
    out = Path(tmp) / "capture.pcap"
    out.write_bytes(
        struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype)
        + b"".join(
            struct.pack("<IIII", 1_700_000_000 + i, 500_000, len(f), len(f)) + f
            for i, f in enumerate(frames)
        )
    )
    return out


class TestNativeEsp(unittest.TestCase):
    def test_ipv4_native_esp_reads_the_spi(self):
        frame = _ethernet(0x0800, _ip4("10.0.0.1", "10.0.0.2", 50, _esp(SPI_A)))
        with tempfile.TemporaryDirectory() as tmp:
            rec = feats.read_pcap_esp_with_spi(_write_pcap([frame], tmp=tmp))
        self.assertEqual(len(rec), 1)
        self.assertEqual(rec[0][5], SPI_A)
        self.assertEqual(rec[0][3], b"\x0a\x00\x00\x01")
        self.assertEqual(rec[0][4], b"\x0a\x00\x00\x02")

    def test_two_sas_on_one_link_stay_distinguishable(self):
        frames = [
            _ethernet(0x0800, _ip4("10.0.0.1", "10.0.0.2", 50, _esp(SPI_A))),
            _ethernet(0x0800, _ip4("10.0.0.1", "10.0.0.3", 50, _esp(SPI_B))),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            rec = feats.read_pcap_esp_with_spi(_write_pcap(frames, tmp=tmp))
        self.assertEqual([r[5] for r in rec], [SPI_A, SPI_B])

    def test_ipv6_native_esp_reads_the_spi(self):
        frame = _ethernet(
            0x86DD,
            _ip6(V6_A, V6_B, 50, _esp(SPI_A)),
        )
        with tempfile.TemporaryDirectory() as tmp:
            rec = feats.read_pcap_esp_with_spi(_write_pcap([frame], tmp=tmp))
        self.assertEqual(len(rec), 1)
        self.assertEqual(rec[0][5], SPI_A)


class TestNatT(unittest.TestCase):
    """UDP/4500, with and without the optional RFC 3948 non-ESP marker."""

    def test_ipv4_natt_without_marker_reads_the_spi(self):
        frame = _ethernet(
            0x0800,
            _ip4("10.0.0.1", "10.0.0.2", 17, _udp(4500, 4500, _esp(SPI_A))),
        )
        with tempfile.TemporaryDirectory() as tmp:
            rec = feats.read_pcap_esp_with_spi(_write_pcap([frame], tmp=tmp))
        self.assertEqual(rec[0][5], SPI_A)

    def test_ipv4_natt_with_marker_still_reads_the_spi(self):
        """The marker case strongSwan omits but other peers emit.

        Reading the SPI at a fixed offset gives 0 here, which the identity
        resolver turns into ``UNKNOWN no_spi_available`` and the whole tunnel
        silently becomes unresolvable.
        """
        frame = _ethernet(
            0x0800,
            _ip4("10.0.0.1", "10.0.0.2", 17,
                 _udp(4500, 4500, b"\x00\x00\x00\x00" + _esp(SPI_A))),
        )
        with tempfile.TemporaryDirectory() as tmp:
            rec = feats.read_pcap_esp_with_spi(_write_pcap([frame], tmp=tmp))
        self.assertEqual(len(rec), 1)
        self.assertEqual(rec[0][5], SPI_A)

    def test_marker_and_no_marker_agree_on_the_spi(self):
        plain = _ethernet(
            0x0800,
            _ip4("10.0.0.1", "10.0.0.2", 17, _udp(4500, 4500, _esp(SPI_A))),
        )
        marked = _ethernet(
            0x0800,
            _ip4("10.0.0.1", "10.0.0.2", 17,
                 _udp(4500, 4500, b"\x00" * 4 + _esp(SPI_A))),
        )
        with tempfile.TemporaryDirectory() as tmp:
            rec = feats.read_pcap_esp_with_spi(_write_pcap([plain, marked], tmp=tmp))
        self.assertEqual([r[5] for r in rec], [SPI_A, SPI_A])

    def test_ipv6_natt_with_marker_reads_the_spi(self):
        frame = _ethernet(
            0x86DD,
            _ip6(V6_A, V6_B, 17,
                 _udp(4500, 4500, b"\x00" * 4 + _esp(SPI_B))),
        )
        with tempfile.TemporaryDirectory() as tmp:
            rec = feats.read_pcap_esp_with_spi(_write_pcap([frame], tmp=tmp))
        self.assertEqual(rec[0][5], SPI_B)

    def test_other_udp_ports_are_ignored(self):
        frame = _ethernet(
            0x0800, _ip4("10.0.0.1", "10.0.0.2", 17, _udp(500, 500, _esp(SPI_A)))
        )
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                feats.read_pcap_esp_with_spi(_write_pcap([frame], tmp=tmp)), []
            )


class TestLinkTypes(unittest.TestCase):
    def test_linux_sll2_is_decoded(self):
        """What ``tcpdump -i any`` writes, i.e. the real in-container capture."""
        frame = _sll2(0x0800, _ip4("10.0.0.1", "10.0.0.2", 17,
                                    _udp(4500, 4500, _esp(SPI_A))))
        with tempfile.TemporaryDirectory() as tmp:
            rec = feats.read_pcap_esp_with_spi(
                _write_pcap([frame], linktype=276, tmp=tmp)
            )
        self.assertEqual(rec[0][5], SPI_A)

    def test_raw_ipv4_linktype(self):
        frame = _ip4("10.0.0.1", "10.0.0.2", 50, _esp(SPI_A))
        with tempfile.TemporaryDirectory() as tmp:
            rec = feats.read_pcap_esp_with_spi(
                _write_pcap([frame], linktype=101, tmp=tmp)
            )
        self.assertEqual(rec[0][5], SPI_A)

    def test_raw_ipv6_linktype(self):
        frame = _ip6(V6_A, V6_B, 17,
                     _udp(4500, 4500, _esp(SPI_A)))
        with tempfile.TemporaryDirectory() as tmp:
            rec = feats.read_pcap_esp_with_spi(
                _write_pcap([frame], linktype=127, tmp=tmp)
            )
        self.assertEqual(rec[0][5], SPI_A)

    def test_unsupported_linktype_is_rejected(self):
        frame = _ip4("10.0.0.1", "10.0.0.2", 50, _esp(SPI_A))
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                feats.read_pcap_esp_with_spi(
                    _write_pcap([frame], linktype=113, tmp=tmp)
                )


class TestDegradation(unittest.TestCase):
    def test_truncated_esp_reports_no_spi_rather_than_zero(self):
        """A too-short payload must yield None, not a fabricated SPI.

        ``None`` is what the identity resolver needs: it becomes
        ``UNKNOWN no_spi_available``.  A ``0`` would be indistinguishable from
        a parsed value.
        """
        frame = _ethernet(
            0x0800, _ip4("10.0.0.1", "10.0.0.2", 50, b"\x01\x02")
        )
        with tempfile.TemporaryDirectory() as tmp:
            rec = feats.read_pcap_esp_with_spi(_write_pcap([frame], tmp=tmp))
        self.assertEqual(len(rec), 1)
        self.assertIsNone(rec[0][5])

    def test_non_esp_traffic_is_skipped(self):
        frames = [
            _ethernet(0x0800, _ip4("10.0.0.1", "10.0.0.2", 6, b"\x00" * 40)),
            _ethernet(0x0800, _ip4("10.0.0.1", "10.0.0.2", 50, _esp(SPI_A))),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            rec = feats.read_pcap_esp_with_spi(_write_pcap(frames, tmp=tmp))
        self.assertEqual([r[5] for r in rec], [SPI_A])

    def test_records_come_back_in_time_order(self):
        frames = [
            _ethernet(0x0800, _ip4("10.0.0.1", "10.0.0.2", 50, _esp(SPI_A))),
            _ethernet(0x0800, _ip4("10.0.0.1", "10.0.0.3", 50, _esp(SPI_B))),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "capture.pcap"
            pcap.write_bytes(
                struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
                + struct.pack("<IIII", 1_700_000_002, 0, len(frames[1]), len(frames[1]))
                + frames[1]
                + struct.pack("<IIII", 1_700_000_001, 0, len(frames[0]), len(frames[0]))
                + frames[0]
            )
            rec = feats.read_pcap_esp_with_spi(pcap)
        self.assertEqual([r[5] for r in rec], [SPI_A, SPI_B])

    def test_empty_capture_yields_no_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                feats.read_pcap_esp_with_spi(_write_pcap([], tmp=tmp)), []
            )


if __name__ == "__main__":
    unittest.main()
