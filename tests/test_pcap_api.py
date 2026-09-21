"""Phase 10 — PCAP evidence registry + download API tests."""

import os
import tempfile
import unittest

from correlation.api import live, pcap as pcap_mod, v1
from correlation.api.pcap import PcapRegistry, PcapService
from correlation.api.routes import ApiError

PCAP_MAGIC = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 20


class PcapTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        with open(os.path.join(root, "capture-1.pcap"), "wb") as handle:
            handle.write(PCAP_MAGIC)
        self.registry = PcapRegistry(root=root)
        self.registry.register("evidence-1", "capture-1.pcap")
        self.service = PcapService(self.registry)
        self.addCleanup(self.tmp.cleanup)


class TestPcapRegistry(PcapTestCase):
    def test_register_and_resolve(self):
        self.assertTrue(self.registry.has("evidence-1"))
        resolved = self.registry.resolve("evidence-1")
        self.assertTrue(resolved.endswith("capture-1.pcap"))
        self.assertTrue(os.path.isfile(resolved))

    def test_register_validates_id_and_extension(self):
        with self.assertRaises(ValueError):
            self.registry.register("bad/id", "x.pcap")
        with self.assertRaises(ValueError):
            self.registry.register("ok", "script.sh")
        # re-registering an id only swaps the recorded filename (no error)
        self.registry.register("evidence-1", "capture-1.pcap")

    def test_resolve_missing_returns_none(self):
        self.assertIsNone(self.registry.resolve("missing"))

    def test_to_dict(self):
        info = self.registry.to_dict()
        self.assertEqual(info["registered"], ["evidence-1"])


class TestPcapService(PcapTestCase):
    def test_download_returns_bytes_and_records(self):
        data = self.service.download("evidence-1")
        self.assertEqual(data, PCAP_MAGIC)
        self.assertEqual(self.service.download_count, 1)
        self.assertEqual(self.service.recent_downloads()[0]["evidence_id"],
                         "evidence-1")

    def test_download_missing_is_none(self):
        self.assertIsNone(self.service.download("nope"))


class TestV1EvidenceHandlers(PcapTestCase):
    def test_evidence_metadata(self):
        ctx = live.Phase10Context(pcap=self.service)
        metadata, content_type = v1.handle_v1_get(ctx, "/api/v1/evidence/evidence-1")
        self.assertEqual(metadata["evidence_id"], "evidence-1")
        self.assertEqual(metadata["read_only"], True)
        self.assertEqual(metadata["extension_locked"], True)
        self.assertEqual(content_type, "application/json")

    def test_pcap_download_descriptor(self):
        ctx = live.Phase10Context(pcap=self.service)
        descriptor, _ = v1.handle_v1_get(ctx, "/api/v1/evidence/evidence-1/pcap")
        self.assertEqual(descriptor["evidence_id"], "evidence-1")

    def test_unknown_evidence_404(self):
        ctx = live.Phase10Context(pcap=self.service)
        with self.assertRaises(ApiError) as raised:
            v1.handle_v1_get(ctx, "/api/v1/evidence/missing")
        self.assertEqual(raised.exception.status, 404)

    def test_pcap_bytes_via_service(self):
        data = self.service.download("evidence-1")
        self.assertEqual(data[:4], b"\xd4\xc3\xb2\xa1")
        self.assertEqual(v1.CONTENT_TYPE_PCAP,
                         "application/vnd.tcpdump.pcap")


if __name__ == "__main__":
    unittest.main()