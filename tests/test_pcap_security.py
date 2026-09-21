"""Phase 10 — PCAP path-traversal / allow / extension security tests."""

import os
import tempfile
import unittest

from correlation.api.pcap import (
    PcapRegistry,
    _is_unsafe_path,
    _within,
    validate_evidence_id,
)


class TestValidateEvidenceId(unittest.TestCase):
    def test_allowlist_characters(self):
        self.assertEqual(validate_evidence_id("evidence-1.A_b"), "evidence-1.A_b")
        for ch in ":/\\?%#@*$\"'`| <>!&;=":
            with self.assertRaises(ValueError):
                validate_evidence_id(f"e{ch}")

    def test_traversal_rejected(self):
        with self.assertRaises(ValueError):
            validate_evidence_id("../../etc/passwd")
        with self.assertRaises(ValueError):
            validate_evidence_id("a..b")

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            validate_evidence_id("")
            validate_evidence_id(None)


class TestUnsafePath(unittest.TestCase):
    def test_plain_names_are_safe(self):
        self.assertFalse(_is_unsafe_path("capture-1.pcap"))
        self.assertFalse(_is_unsafe_path("sub/dir capture.pcapng"))

    def test_traversal_absolute_unc(self):
        self.assertTrue(_is_unsafe_path("../x.pcap"))
        self.assertTrue(_is_unsafe_path("a/../../x.pcap"))
        self.assertTrue(_is_unsafe_path("/etc/passwd"))
        self.assertTrue(_is_unsafe_path("C:/x.pcap"))
        self.assertTrue(_is_unsafe_path(r"C:\\x.pcap"))
        self.assertTrue(_is_unsafe_path(r"\\server\share\x.pcap"))
        self.assertTrue(_is_unsafe_path("http://x.pcap"))
        self.assertTrue(_is_unsafe_path(""))
        self.assertTrue(_is_unsafe_path(None))


class TestWithinRoot(unittest.TestCase):
    def test_within(self):
        with tempfile.TemporaryDirectory() as root:
            inside = os.path.join(root, "a.pcap")
            self.assertTrue(_within(root, inside))
            outside = os.path.join(root, "..", "escape.pcap")
            self.assertFalse(_within(root, outside))


class TestRegistryHardenResolve(unittest.TestCase):
    def test_traversal_filename_never_resolves(self):
        with tempfile.TemporaryDirectory() as root:
            registry = PcapRegistry(root=root)
            with self.assertRaises(ValueError):
                registry.register("ev", "../x.pcap")
            with self.assertRaises(ValueError):
                registry.register("ev", "C:\\x.pcap")
            with self.assertRaises(ValueError):
                registry.register("ev", "/etc/x.pcap")

    def test_missing_file_and_bad_extension_denied(self):
        with tempfile.TemporaryDirectory() as root:
            registry = PcapRegistry(root=root)
            with self.assertRaises(ValueError):
                registry.register("ev", "capture.png")
            # only .pcap/.pcapng names may be registered
            for name in ("a.pcap", "b.pcapng"):
                registry.register(name[:-5], name)
            # a registered-but-missing capture never resolves (no fabrication)
            registry.register("ghost", "missing.pcap")
            self.assertIsNone(registry.resolve("ghost"))

    def test_symlink_escape_blocked_or_skipped(self):
        with tempfile.TemporaryDirectory() as root:
            outside = tempfile.TemporaryDirectory()
            try:
                link = os.path.join(root, "cap.pcap")
                os.symlink(os.path.join(outside.name, "secret.pcap"), link)
                registry = PcapRegistry(root=root)
                registry.register("ev", "cap.pcap")
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported on this platform")
            else:
                self.assertIsNone(registry.resolve("ev"))
            finally:
                outside.cleanup()


class TestNoFabrication(unittest.TestCase):
    def test_unregistered_id_never_produced(self):
        with tempfile.TemporaryDirectory() as root:
            registry = PcapRegistry(root=root)
            self.assertIsNone(registry.resolve("ghost"))
            self.assertFalse(registry.has("ghost"))


if __name__ == "__main__":
    unittest.main()