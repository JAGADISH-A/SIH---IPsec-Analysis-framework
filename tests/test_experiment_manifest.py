"""Controller experiment manifest (the testbed -> analytics seam, controller half)."""

import json
import os
import tempfile
import time
import unittest
from unittest import mock

from controller import experiment_manifest as mod


class TestExperimentManifest(unittest.TestCase):
    def test_write_collects_real_spis_and_clear(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = os.path.join(tmp, "live_events.jsonl")
            now = int(time.time_ns())
            with open(journal, "w", encoding="utf-8") as fh:
                for _ in range(3):
                    fh.write(json.dumps({
                        "ts": now, "src": "10.0.0.1", "dst": "10.0.0.2",
                        "proto": 50, "len": 1020, "spi": "0x0badf00d", "seq": 1
                    }) + "\n")
            manifest = os.path.join(tmp, "experiment.json")

            config = {
                "mode": "tunnel", "address_family": "ipv4",
                "ike": {"version": 2, "encryption": "aes256",
                        "integrity": "sha256", "dh_group": "modp2048"},
                "esp": {"encryption": "aes256gcm16", "integrity": None,
                        "dh_group": "modp2048", "pfs": True},
                "traffic": {"profile": "icmp", "duration": 30, "port": 20000},
            }
            result = {
                "status": "PASS",
                "ipsec": {"status": "ESTABLISHED", "mode": "tunnel"},
                "connectivity": {"status": "PASS", "loss_percent": 0.0},
                "observation": {"status": "live"},
                "traffic": {"status": "PASS", "packets_per_second": 100},
            }

            with mock.patch.object(mod, "manifest_path", return_value=os.path.join(tmp, mod.MANIFEST_FILE)):
                with mock.patch.object(mod, "_journal_path", return_value=journal):
                    self.assertTrue(mod.write_current("job-9", config, result, now))

                    raw = json.loads(open(os.path.join(tmp, mod.MANIFEST_FILE), encoding="utf-8").read())
                    self.assertEqual(raw["run"]["job_id"], "job-9")
                    self.assertEqual(raw["run"]["assessment_id"], "testbed-job-9:1:current")
                    self.assertEqual(raw["observed"]["spis"], [0x0BADF00D])
                    self.assertEqual(raw["observed"]["summary"]["packets"], 3)
                    self.assertIn(
                        raw["posture"]["band"],
                        ("STRONG", "GOOD", "MEDIUM", "WEAK", "WORST"),
                    )

                    # Same path write when a previous manifest exists replaces atomically.
                    result["status"] = "FAIL"
                    mod.write_current("job-9", config, result, now)
                    raw = json.loads(open(os.path.join(tmp, mod.MANIFEST_FILE), encoding="utf-8").read())
                    self.assertEqual(raw["run"]["status"], "FAIL")

                    # Clear removes the manifest (stale-run protection).
                    self.assertTrue(mod.clear())
                    self.assertFalse(os.path.exists(os.path.join(tmp, mod.MANIFEST_FILE)))


if __name__ == "__main__":
    unittest.main()