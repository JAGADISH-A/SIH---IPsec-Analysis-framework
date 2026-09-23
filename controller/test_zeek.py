"""Unit tests for the Zeek evidence-path integration (zeek.py).

The testbed policy is that Zeek is never silently installed on the testbed
host; the evidence path uses the containerised upstream Zeek image replayed
over recorded PCAPs.  These tests exercise the detection and the offline
observation seam without requiring Zeek, docker or any image to exist.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from controller import zeek as zeek_mod


class TestAvailabilityContract(unittest.TestCase):
    def test_report_has_stable_schema(self):
        report = zeek_mod.zeek_availability()
        for key in ("installed", "binaries", "candidates",
                    "container_image", "image_present",
                    "evidence_available", "note"):
            self.assertIn(key, report)

    def test_binaries_are_queried_but_never_installed(self):
        with mock.patch.object(zeek_mod.shutil, "which",
                               return_value=None):
            report = zeek_mod.zeek_availability()
            self.assertFalse(report["installed"])
            self.assertIn("no silent install", report["note"].lower())

    def test_image_present_detection(self):
        with mock.patch.object(zeek_mod, "_docker_image_present",
                               return_value=True):
            report = zeek_mod.zeek_availability()
            self.assertTrue(report["image_present"])
            self.assertEqual(report["evidence_available"], "container")

    def test_image_absent_detection(self):
        with mock.patch.object(zeek_mod, "_docker_image_present",
                               return_value=False):
            report = zeek_mod.zeek_availability()
            self.assertFalse(report["image_present"])
            self.assertIsNone(report["evidence_available"])

    def test_docker_image_present_invokes_inspect(self):
        with mock.patch.object(zeek_mod.shutil, "which",
                               return_value="/usr/bin/docker"), \
                mock.patch.object(
                    zeek_mod.subprocess, "run",
                    return_value=mock.Mock(returncode=0)) as run:
            self.assertTrue(zeek_mod._docker_image_present("zeek/zeek:x"))
            run.assert_called_once()
            argv = run.call_args[0][0]
            self.assertIn("inspect", argv)
            self.assertIn("zeek/zeek:x", argv)


class TestOfflineObservation(unittest.TestCase):
    def _make_pcap(self, tmp):
        pcap = Path(tmp) / "sample.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
        return pcap

    def test_offline_refuses_when_image_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            pcap = self._make_pcap(tmp)
            with mock.patch.object(zeek_mod, "_docker_image_present",
                                   return_value=False):
                with self.assertRaises(RuntimeError):
                    zeek_mod.zeek_observe_offline(pcap)

    def test_offline_missing_pcap(self):
        with mock.patch.object(zeek_mod, "_docker_image_present",
                               return_value=True):
            with self.assertRaises(FileNotFoundError):
                zeek_mod.zeek_observe_offline("/nonexistent/xyz.pcap")

    def test_offline_run_and_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            pcap = self._make_pcap(tmp)
            out = Path(tmp) / "zeek_out"
            out.mkdir()
            (out / "conn.log").write_text(
                "#separator \\x09\n"
                "#close\t2026\n"
                "1\tA\t1.1.1.1\t0\t2.2.2.2\t0\tunknown_transport\t-\t-"
                "\t-\t-\tOTH\tT\tT\t0\t-\t1\t128\t1\t128\t-\t50\n")
            with mock.patch.object(zeek_mod, "_docker_image_present",
                                   return_value=True), \
                    mock.patch.object(
                        zeek_mod, "_zeek_version", return_value="zeek 9.0.0"), \
                    mock.patch.object(
                        zeek_mod.subprocess, "run",
                        return_value=mock.Mock(returncode=0, stdout="",
                                               stderr="")) as run:
                summary = zeek_mod.zeek_observe_offline(
                    pcap, output_dir=str(out))
            self.assertEqual(summary["exit_code"], 0)
            self.assertEqual(summary["zeek_version"], "zeek 9.0.0")
            self.assertEqual(summary["log_files"], ["conn.log"])
            self.assertEqual(summary["conn_records"], 1)
            argv = run.call_args[0][0]
            self.assertIn("zeek", argv)
            self.assertIn("-C", argv)
            self.assertIn("-r", argv)

    def test_conn_records_count_data_rows_only(self):
        log = "".join([
            "#separator \\x09\n",
            "#fields\tts\tproto\n",
            "#types\ttime\tenum\n",
            "1\tudp\n",
            "2\ticmp\n",
        ])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "conn.log"
            path.write_text(log)
            self.assertEqual(zeek_mod._count_conn_records(path), 2)


class TestAuditWiring(unittest.TestCase):
    def test_record_zeek_observation_writes_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            events_path = Path(tmp) / "events.jsonl"
            out = Path(tmp) / "zeek_out"
            out.mkdir()
            (out / "conn.log").write_text("1\tC\t1.1.1.1\t0\t2.2.2.2\t0"
                                          "\tunknown_transport\t-\t-\t-\t-"
                                          "\tOTH\tT\tT\t0\t-\t1\t128\t1\t128"
                                          "\t-\t50\n")
            pcap = Path(tmp) / "sample.pcap"
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
            with mock.patch.object(zeek_mod, "_docker_image_present",
                                   return_value=True), \
                    mock.patch.object(
                        zeek_mod, "_zeek_version",
                        return_value="zeek 9.0.0"), \
                    mock.patch.object(
                        zeek_mod.subprocess, "run",
                        return_value=mock.Mock(returncode=0, stdout="",
                                               stderr="")) as run:
                record, summary = zeek_mod.record_zeek_observation(
                    pcap, output_dir=str(out), audit_path=str(events_path))
            self.assertEqual(record["event_type"], "zeek_event")
            self.assertEqual(record["exit_code"], 0)
            self.assertEqual(record["conn_records"], 1)
            events = [json.loads(line)
                      for line in events_path.read_text().splitlines()]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "zeek_event")
            # trailer: the fake docker run must not have actually launched
            self.assertIn("-C", run.call_args[0][0])


class TestLiveSeam(unittest.TestCase):
    def test_live_seam_requires_some_presence(self):
        with mock.patch.object(zeek_mod, "_docker_image_present",
                               return_value=False), \
                mock.patch.object(zeek_mod.shutil, "which",
                                  return_value=None):
            with self.assertRaises(RuntimeError):
                zeek_mod.zeek_observe("audit-tap0")

    def test_live_seam_is_wired_but_not_consumed(self):
        with mock.patch.object(zeek_mod, "_docker_image_present",
                               return_value=True):
            with self.assertRaises(NotImplementedError):
                zeek_mod.zeek_observe("audit-tap0", mode="tunnel",
                                      address_family="ipv6")


if __name__ == "__main__":
    unittest.main()