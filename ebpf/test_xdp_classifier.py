"""Focused classification tests for the real XDP/eBPF ``xdp_monitor`` classifier.

These tests load the ACTUAL BPF program (``ebpf/xdp_monitor.bpf.c``) into the
running kernel and inject crafted Ethernet/IP frames through a dedicated veth
pair (never the testbed's interfaces).  The classification is read back from
the BPF ring buffer via the monitor's JSONL event stream.

Required environment:
  * root (BPF program/map loading needs CAP_SYS_ADMIN / CAP_BPF)
  * ``ebpf/xdp_monitor`` built (``make -C ebpf``)
  * ``/sys/kernel/btf/vmlinux`` present (CO-RE loader)

When the environment cannot load the program the tests skip cleanly (a plain
development host), so the suite stays green without BPF privileges.

Coverage maps directly to the repository's classifier requirements:

  1. IPv4 ESP                     -> type ``ESP``, family 4, SPI/seq preserved
  2. IPv4 UDP/IKE (500)           -> type ``IKE``
  3. IPv4 UDP/NAT-T (4500)        -> type ``IKE-NAT-T``
  4. IPv6 ESP                     -> type ``ESP``, family 6, SPI/seq preserved
  5. IPv6 UDP/IKE (500)           -> type ``IKE``
  6. IPv6 UDP/NAT-T (4500)        -> type ``IKE-NAT-T``
  7. truncated IPv4               -> ``OTHER`` (safe bounds bail-out)
  8. truncated IPv6               -> ``OTHER`` (safe bounds bail-out)
  9. non-IP traffic (ARP)         -> ``OTHER``
 10. unsupported next header      -> ``OTHER`` (IPv4 ICMP, IPv6 ICMPv6,
                                     IPv6 hop-by-hop extension header)

The IPv4 behaviour is asserted byte-for-byte unchanged (same event schema
fields ``src``/``dst``/``proto``/``spi``/``seq``); IPv6 adds ``family`` and the
``src6``/``dst6`` fields in the shared event struct.
"""

import json
import os
import signal
import socket
import struct
import subprocess
import time
import unittest
from pathlib import Path

XDP_MONITOR = Path(__file__).resolve().parent / "xdp_monitor"
VETH_L = "clsobs0"
VETH_R = "clsobs1"

_DST_MAC = bytes.fromhex("aabbcc000001")
_SRC_MAC = bytes.fromhex("aabbcc000002")

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_ARP = 0x0806


def _eth(ethertype, payload):
    return _DST_MAC + _SRC_MAC + struct.pack("!H", ethertype) + payload


def _ipv4(proto, saddr, daddr, payload=b"", ihl=5, ttl=64):
    ver_ihl = (4 << 4) | ihl
    total_len = ihl * 4 + len(payload)
    return struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, 0, total_len, 0x1, 0x40, ttl, proto, 0,      # checksum ignored
        socket.inet_aton(saddr), socket.inet_aton(daddr),
    ) + payload


def _ipv6(nexthdr, saddr, daddr, payload=b"", ver=6):
    first = (ver << 28) | 0          # version nibble + traffic class + flow label
    return struct.pack(
        "!IHBB16s16s",
        first, len(payload), nexthdr, 64,
        socket.inet_pton(socket.AF_INET6, saddr),
        socket.inet_pton(socket.AF_INET6, daddr),
    ) + payload


def _udp(sport, dport, payload=b"\x00" * 12):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _esp(spi, seq, payload=b"\x00" * 32):
    return struct.pack("!II", spi, seq) + payload


def _arp():
    # 28-byte ARP payload after the 14-byte Ethernet header.  Never parsed by
    # the classifier: any non-IP ethertype must land in OTHER.
    return _eth(ETH_P_ARP, b"\x00" * 28)


def _cli():
    """Build frame always; returns (label, frame, expectation) tuples."""
    return None


class _XdpClassifierHarness(unittest.TestCase):
    """Per-test lifecycle for a dedicated veth pair + xdp_monitor process."""

    MONITOR_READY = False

    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("root required to load the XDP/eBPF program")
        if not XDP_MONITOR.is_file() or not os.access(XDP_MONITOR, os.X_OK):
            self.skipTest("ebpf/xdp_monitor not built (run: make -C ebpf)")
        if not os.path.exists("/sys/kernel/btf/vmlinux"):
            self.skipTest("/sys/kernel/btf/vmlinux not available (CO-RE loader)")

        self._cleanup_veth()
        add = subprocess.run(
            ["ip", "link", "add", VETH_L, "type", "veth", "peer", "name", VETH_R],
            capture_output=True, text=True,
        )
        if add.returncode != 0:
            self.skipTest(f"could not create veth pair: {add.stderr.strip()}")
        # Disable IPv6 on the pair BEFORE bring-up so the kernel stack emits no
        # MLD/NDP/DAD multicast of its own - the XDP hook would otherwise
        # observe that unrelated link noise as OTHER events.
        for dev in (VETH_L, VETH_R):
            subprocess.run(
                ["sysctl", "-w", f"net/ipv6/conf/{dev}/disable_ipv6=1"],
                capture_output=True, text=True,
            )
        for dev in (VETH_L, VETH_R):
            subprocess.run(["ip", "link", "set", dev, "up"], check=True)

        self.events_path = Path(f"/tmp/{VETH_L}-{os.getpid()}-events.jsonl")
        self.mon_log_path = Path(f"/tmp/{VETH_L}-{os.getpid()}-monitor.err")
        self.events_path.touch()
        self.mon_log_path.touch()

        self._events_fh = self.events_path.open("w")
        self._err_fh = self.mon_log_path.open("w")
        self.monitor = subprocess.Popen(
            [str(XDP_MONITOR), VETH_L, "--json"],
            stdout=self._events_fh,
            stderr=self._err_fh,
        )
        try:
            self._wait_attached()
        except Exception:
            self._stop_monitor()
            raise

    def tearDown(self):
        self._stop_monitor()
        self._cleanup_veth()
        for fh in (getattr(self, "_events_fh", None), getattr(self, "_err_fh", None)):
            if fh is not None:
                fh.close()
        for path in (self.events_path, self.mon_log_path):
            try:
                path.unlink()
            except OSError:
                pass

    def _wait_attached(self, deadline_s=15):
        deadline = time.time() + deadline_s
        while time.time() < deadline:
            if self.monitor.poll() is not None:
                getattr(self, "_attach_failed", self._attach_failed)(
                    f"xdp_monitor exited early rc={self.monitor.returncode}")
                return
            probe = subprocess.run(
                ["ip", "-d", "link", "show", "dev", VETH_L],
                capture_output=True, text=True,
            )
            # Match the attached-program marker "prog/xdp" specifically: the
            # device name itself (e.g. a peer containing "xdp") must NOT create
            # a false "attached" reading before the program is really attached.
            if "prog/xdp" in probe.stdout:
                return
            time.sleep(0.2)
        raise AssertionError("xdp_monitor did not attach within deadline; "
                             f"log: {self.mon_log_path.read_text(errors='replace')}")

    def _attach_failed(self, message):
        raise AssertionError(message)

    def _stop_monitor(self):
        if getattr(self, "monitor", None) and self.monitor.poll() is None:
            self.monitor.send_signal(signal.SIGINT)
            try:
                self.monitor.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.monitor.kill()
                self.monitor.wait()

    def _cleanup_veth(self):
        for dev in (VETH_L, VETH_R):
            subprocess.run(["ip", "link", "del", dev], capture_output=True)

    def _inject(self, frames):
        """Send raw L2 frames from VETH_R so they arrive on VETH_L's XDP hook."""
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind((VETH_R, 0))
        for frame in frames:
            sock.send(frame)
        sock.close()
        time.sleep(1.0)

    def collect(self, frames):
        """Inject `frames` and return the parsed JSONL events (all of them)."""
        self._inject(frames)
        events_path = self.get_events_file()
        events = [json.loads(line) for line in events_path.read_text().splitlines()
                  if line.strip() and line.strip().lstrip().startswith("{")]
        self.assertGreaterEqual(len(events), len(frames),
                                "fewer ring-buffer events than injected frames")
        return events

    def get_events_file(self):
        # Re-read while the monitor may still be flushing; the last poll drains
        # up to 250 ms, and we already waited 1 s after injection.
        return self.events_path


class TestIpv4Esp(_XdpClassifierHarness):
    def test_ipv4_esp_classification(self):
        frames = [
            _eth(ETH_P_IP, _ipv4(50, "10.1.1.1", "10.2.2.2",
                                 payload=_esp(spi=0x12345678, seq=7))),
        ]
        events = self.collect(frames)
        esp = [e for e in events if e["type"] == "ESP"]
        self.assertEqual(len(esp), 1, [e for e in events if e["type"] != "ESP"])
        ev = esp[0]
        self.assertEqual(ev["family"], 4)
        self.assertEqual(ev["src"], "10.1.1.1")
        self.assertEqual(ev["dst"], "10.2.2.2")
        self.assertEqual(ev["proto"], 50)
        self.assertEqual(ev["spi"], 0x12345678)
        self.assertEqual(ev["seq"], 7)


class TestIpv4UdpIke(_XdpClassifierHarness):
    def test_ipv4_ike(self):
        events = self.collect([
            _eth(ETH_P_IP, _ipv4(17, "10.1.1.1", "10.2.2.2", _udp(500, 500))),
        ])
        ike = [e for e in events if e["type"] == "IKE"]
        self.assertEqual(len(ike), 1, events)
        ev = ike[0]
        self.assertEqual(ev["family"], 4)
        self.assertEqual(ev["proto"], 17)
        self.assertEqual(ev["src"], "10.1.1.1")
        self.assertEqual(ev["dst"], "10.2.2.2")
        self.assertEqual(ev["sport"], 500)
        self.assertEqual(ev["dport"], 500)

    def test_ipv4_ike_nat_t(self):
        events = self.collect([
            _eth(ETH_P_IP, _ipv4(17, "10.1.1.1", "10.2.2.2", _udp(4500, 4500))),
        ])
        natt = [e for e in events if e["type"] == "IKE-NAT-T"]
        self.assertEqual(len(natt), 1, events)
        self.assertEqual(natt[0]["family"], 4)
        self.assertEqual(natt[0]["sport"], 4500)
        self.assertEqual(natt[0]["dport"], 4500)


class TestIpv6Esp(_XdpClassifierHarness):
    def test_ipv6_esp_classification(self):
        events = self.collect([
            _eth(ETH_P_IPV6,
                 _ipv6(50, "2001:db8:1::1", "2001:db8:2::2",
                       payload=_esp(spi=0xDEADBEEF, seq=42))),
        ])
        esp = [e for e in events if e["type"] == "ESP"]
        self.assertEqual(len(esp), 1, [e for e in events if e["type"] != "ESP"])
        ev = esp[0]
        self.assertEqual(ev["family"], 6)
        self.assertEqual(ev["src"], "2001:db8:1::1")
        self.assertEqual(ev["dst"], "2001:db8:2::2")
        self.assertEqual(ev["proto"], 50)
        self.assertEqual(ev["spi"], 0xDEADBEEF)
        self.assertEqual(ev["seq"], 42)


class TestIpv6UdpIke(_XdpClassifierHarness):
    def test_ipv6_ike(self):
        events = self.collect([
            _eth(ETH_P_IPV6,
                 _ipv6(17, "2001:db8:1::1", "2001:db8:2::2", _udp(500, 500))),
        ])
        ike = [e for e in events if e["type"] == "IKE"]
        self.assertEqual(len(ike), 1, events)
        ev = ike[0]
        self.assertEqual(ev["family"], 6)
        self.assertEqual(ev["proto"], 17)
        self.assertEqual(ev["src"], "2001:db8:1::1")
        self.assertEqual(ev["dst"], "2001:db8:2::2")
        self.assertEqual(ev["sport"], 500)
        self.assertEqual(ev["dport"], 500)

    def test_ipv6_ike_nat_t(self):
        events = self.collect([
            _eth(ETH_P_IPV6,
                 _ipv6(17, "2001:db8:1::1", "2001:db8:2::2", _udp(4500, 4500))),
        ])
        natt = [e for e in events if e["type"] == "IKE-NAT-T"]
        self.assertEqual(len(natt), 1, events)
        self.assertEqual(natt[0]["family"], 6)
        self.assertEqual(natt[0]["sport"], 4500)
        self.assertEqual(natt[0]["dport"], 4500)


class TestTruncated(_XdpClassifierHarness):
    def test_truncated_ipv4(self):
        # Only 8 bytes of the IPv4 header follow the Ethernet header, so the
        # (ip + 1) bounds check must bail to OTHER with no src/dst read.
        truncated = _eth(ETH_P_IP, b"\x45\x00\x00\x3c\x00\x01\x00\x00")
        events = self.collect([truncated])
        other = [e for e in events if e["type"] == "OTHER"]
        self.assertEqual(len(other), 1, events)
        self.assertEqual(other[0]["family"], 0)
        self.assertEqual(other[0]["proto"], 0)
        self.assertEqual(other[0]["src"], "0.0.0.0")

    def test_truncated_ipv6(self):
        # Only 12 bytes of the IPv6 header follow the Ethernet header; the
        # (ip6 + 1) bounds check must bail to OTHER.
        truncated = _eth(ETH_P_IPV6, b"\x60\x00\x00\x00\x00\x00\x3a\x40" + b"\x00" * 4)
        events = self.collect([truncated])
        other = [e for e in events if e["type"] == "OTHER"]
        self.assertEqual(len(other), 1, events)
        self.assertEqual(other[0]["family"], 0)


class TestNonIp(_XdpClassifierHarness):
    def test_arp_is_other(self):
        events = self.collect([_arp()])
        other = [e for e in events if e["type"] == "OTHER"]
        self.assertEqual(len(other), 1, events)
        self.assertEqual(other[0]["family"], 0)
        self.assertEqual(other[0]["proto"], 0)


class TestUnsupportedNextHeader(_XdpClassifierHarness):
    def test_ipv4_icmp_is_other(self):
        events = self.collect([
            _eth(ETH_P_IP, _ipv4(1, "10.1.1.1", "10.2.2.2", b"\x08\x00")),
        ])
        other = [e for e in events if e["type"] == "OTHER"]
        self.assertEqual(len(other), 1, events)
        self.assertEqual(other[0]["family"], 4)
        self.assertEqual(other[0]["proto"], 1)

    def test_ipv6_icmpv6_is_other(self):
        events = self.collect([
            _eth(ETH_P_IPV6, _ipv6(58, "2001:db8:1::1", "2001:db8:2::2")),
        ])
        other = [e for e in events if e["type"] == "OTHER"]
        self.assertEqual(len(other), 1, events)
        self.assertEqual(other[0]["family"], 6)
        self.assertEqual(other[0]["proto"], 58)

    def test_ipv6_hop_by_hop_extension_not_traversed(self):
        # nexthdr 0 = hop-by-hop options.  Extension headers are a documented
        # non-goal of the lightweight classifier; a packet whose first next
        # header is an extension header must NOT be silently flagged as ESP
        # (i.e. no spi/seq fields in the emitted event).
        events = self.collect([
            _eth(ETH_P_IPV6,
                 _ipv6(0, "2001:db8:1::1", "2001:db8:2::2", b"\x00\x00\x00\x00\x00\x00\x00\x00")),
        ])
        other = [e for e in events if e["type"] == "OTHER"]
        self.assertEqual(len(other), 1, events)
        self.assertNotIn("spi", other[0])
        self.assertNotIn("seq", other[0])

    def test_ipv4_udp_non_ike_port_is_other(self):
        events = self.collect([
            _eth(ETH_P_IP, _ipv4(17, "10.1.1.1", "10.2.2.2", _udp(53, 53))),
        ])
        other = [e for e in events if e["type"] == "OTHER"]
        self.assertEqual(len(other), 1, events)
        self.assertEqual(other[0]["family"], 4)
        self.assertEqual(other[0]["proto"], 17)


class TestSchemaFields(_XdpClassifierHarness):
    def test_family_field_present_on_all_events(self):
        frames = [
            _eth(ETH_P_IP, _ipv4(50, "10.1.1.1", "10.2.2.2", _esp(1, 1))),
            _eth(ETH_P_IPV6, _ipv6(50, "2001:db8:1::1", "2001:db8:2::2", _esp(2, 2))),
        ]
        events = self.collect(frames)
        by_type = {}
        for e in events:
            self.assertIn("family", e)
            by_type.setdefault(e["type"], []).append(e)
        self.assertEqual(len(by_type["ESP"]), 2)
        families = sorted(e["family"] for e in by_type["ESP"])
        self.assertEqual(families, [4, 6])

    def test_ipv4_fields_preserved_with_schema_extension(self):
        # The IPv4 event must carry the exact original fields SRC/DST/SPI/SEQ;
        # the new family/src6/dst6 fields are additive.
        events = self.collect([
            _eth(ETH_P_IP, _ipv4(50, "10.9.9.9", "10.8.8.8", _esp(0x0A0A0A0A, 99))),
        ])
        ev = events[0]
        self.assertEqual(ev["src"], "10.9.9.9")
        self.assertEqual(ev["dst"], "10.8.8.8")
        self.assertEqual(ev["spi"], 0x0A0A0A0A)
        self.assertEqual(ev["seq"], 99)


if __name__ == "__main__":
    unittest.main()