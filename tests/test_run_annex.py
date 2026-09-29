"""Current-run annex: live journal -> current experiment assessment binding.

Covers the controller -> analytics seam end-to-end at the API layer:
a real manifest + a live journal make the running store register the current
run (same engines the recorded store uses), bind live packet risk to it, and
unregister cleanly restoring the recorded store when the journal goes quiet.
"""

import json
import os
import time
import unittest

from correlation.api.capture_feed import CaptureFeedService, build_risk_index
from correlation.api.run_annex import CurrentRunAnnex
from correlation.api.store import build_store

SCHEMA = "testbed-experiment-manifest/v1"


def _manifest(job_id="job-00001", esp_integrity=None, spi=0x0badf00d,
              posture="STRONG", status="PASS"):
    now = int(time.time_ns())
    run_id = f"testbed-{job_id}"
    return {
        "schema": SCHEMA,
        "run": {
            "dataset_run_id": run_id,
            "sequence": 1,
            "slot": "current",
            "assessment_id": f"{run_id}:1:current",
            "experiment_id": f"{run_id}-exp-0001",
            "job_id": job_id,
            "source": "testbed-frontend",
            "started_at_ns": now - 5_000_000_000,
            "completed_at_ns": now,
            "status": status,
        },
        "config": {
            "mode": "tunnel",
            "address_family": "ipv4",
            "ike": {
                "version": 2,
                "encryption": "aes256",
                "integrity": "sha256",
                "dh_group": "modp2048",
            },
            "esp": {
                "encryption": "aes256gcm16",
                "integrity": esp_integrity,
                "dh_group": "modp2048",
                "pfs": True,
            },
            "traffic": {"profile": "icmp", "duration": 30, "port": 20000},
        },
        "observed": {
            "ipsec": {"status": "ESTABLISHED"},
            "connectivity": {"status": "PASS", "loss_percent": 0.0},
            "observation": {"status": "live"},
            "traffic": {"status": "PASS", "packets_per_second": 100},
            "spis": [spi],
            "spi_stats": {
                str(spi): {
                    "first_seen_ns": now - 4_000_000_000,
                    "last_seen_ns": now,
                    "packet_count": 42,
                    "distinct_sequences": 42,
                }
            },
            "summary": {
                "packets": 42,
                "bytes": 42880,
                "esp": 42,
                "esp_seen": True,
                "tunnel_seen": True,
                "first_ts_ns": now - 4_000_000_000,
                "last_ts_ns": now,
            },
            "journal_events": 42,
        },
        "posture": {"band": posture, "score": 10},
        "journal": {"path": "/unused", "byte_size": 4096},
        "manifest_sha256": "0" * 64,
    }


def _event(ts_ns, spi="0x0badf00d", pkts_len=1020):
    return json.dumps(
        {
            "ts": ts_ns,
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "proto": 50,
            "len": pkts_len,
            "spi": spi,
            "seq": 1,
        }
    )


def _feed(tmp, events):
    journal = os.path.join(tmp, "live_events.jsonl")
    with open(journal, "w", encoding="utf-8") as fh:
        for line in events:
            fh.write(line + "\n")
    store = build_store()
    return CaptureFeedService(journal, risk_index=build_risk_index(store)), store


class TestCurrentRunAnnex(unittest.TestCase):
    def test_inert_without_manifest(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            now = int(time.time_ns())
            feed, store = _feed(tmp, [_event(now)])
            annex = CurrentRunAnnex(store=store, feed=feed)
            baseline_headers = list(store.headers)
            status = annex.sync()
            self.assertFalse(status["active"])
            self.assertFalse(annex.is_active())
            self.assertEqual(len(store.headers), len(baseline_headers))

    def test_register_binds_and_unregister_restores(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            now = int(time.time_ns())
            feed, store = _feed(tmp, [_event(now), _event(now + 1000)])
            manifest = _manifest()
            manifest_path = os.path.join(tmp, "experiment.json")
            with open(manifest_path, "w", encoding="utf-8") as fh:
                json.dump(manifest, fh)

            baseline_headers = [dict(h) for h in store.headers]
            baseline_bundles = set(store.bundles.keys())
            assessment_id = manifest["run"]["assessment_id"]
            spi = manifest["observed"]["spis"][0]

            annex = CurrentRunAnnex(store=store, feed=feed, manifest_path=manifest_path)
            # Manifest present but journal already quiet -> must stay inert.
            original_now_ms = feed._now_ms

            def _far_future():
                return original_now_ms() + feed.freshness_window_ms * 10

            feed._now_ms = _far_future
            status = annex.sync()
            self.assertFalse(status["active"])

            feed._now_ms = original_now_ms
            status = annex.sync()
            self.assertTrue(status["active"], status)
            self.assertTrue(annex.is_active())
            self.assertIn(assessment_id, store.bundles)
            self.assertNotIn(assessment_id, baseline_bundles)
            self.assertGreaterEqual(len(store.headers), len(baseline_headers) + 1)

            # Live packet risk must bind to the current run, not a stale one.
            row = feed._view(
                {"protocol": 50, "classification": "ESP", "spi": spi, "len": 1020},
                _event(now, spi=str(spi), pkts_len=1020),
                offset=0,
            )
            self.assertTrue(row["risk"]["present"])
            self.assertEqual(row["risk"]["assessments"][0]["assessment_id"],
                             assessment_id)

            # Let the journal go quiet -> the running store is restored.
            feed._now_ms = _far_future
            annex.sync()
            self.assertFalse(annex.is_active())
            self.assertNotIn(assessment_id, store.bundles)
            self.assertNotIn(assessment_id, baseline_bundles)
            self.assertEqual([h["assessment_id"] for h in store.headers],
                             [h["assessment_id"] for h in baseline_headers])
            self.assertNotIn(spi, feed.risk_index)

    def test_projection_extends_to_spis_observed_while_the_run_continues(self):
        """A live run keeps producing new SA traffic after the first read.

        The assessment is registered once, but the per-SPI projection must grow
        with the journal, otherwise every packet captured after the first poll
        reads UNASSESSED for the whole run.
        """
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            now = int(time.time_ns())
            # Journal starts with a record that carries no SPI: nothing to
            # project yet, exactly like a run whose traffic has not started.
            feed, store = _feed(tmp, [json.dumps(
                {"ts": now, "src": "10.0.0.1", "dst": "10.0.0.2",
                 "proto": 0, "len": 64, "spi": None, "seq": 0}
            )])
            baseline = set(feed.risk_index)
            manifest = _manifest(spi=0)
            manifest["observed"]["spis"] = []      # start manifest: no SPI yet
            manifest["observed"]["journal_events"] = 0  # write_start: pre-traffic
            manifest["run"]["observation_start_bytes"] = 0
            manifest_path = os.path.join(tmp, "experiment.json")
            with open(manifest_path, "w", encoding="utf-8") as fh:
                json.dump(manifest, fh)

            annex = CurrentRunAnnex(store=store, feed=feed,
                                    manifest_path=manifest_path)
            self.assertTrue(annex.sync()["active"])
            self.assertEqual(set(feed.risk_index), baseline)

            # The journal grows with new SAs while the manifest is unchanged.
            with open(feed.path, "a", encoding="utf-8") as fh:
                fh.write(_event(now + 1000, spi=0x11111111) + "\n")
                fh.write(_event(now + 2000, spi=0x22222222) + "\n")

            status = annex.sync()
            self.assertTrue(status["active"], status)
            self.assertEqual(status["projected_spis"], 2)
            for spi in (0x11111111, 0x22222222):
                self.assertIn(spi, feed.risk_index)
                self.assertEqual(
                    feed.risk_index[spi][0]["assessment_id"],
                    manifest["run"]["assessment_id"],
                )
                self.assertIsNotNone(feed.risk_index[spi][0]["severity"])

            # A re-projection must not leave a vanished SPI carrying the verdict,
            # and must leave the pre-existing recorded-plan entries untouched.
            with open(feed.path, "w", encoding="utf-8") as fh:
                fh.write(_event(now + 3000, spi=0x33333333) + "\n")
            annex.sync()
            self.assertNotIn(0x22222222, feed.risk_index)
            self.assertIn(0x33333333, feed.risk_index)
            self.assertTrue(baseline.issubset(set(feed.risk_index)))


if __name__ == "__main__":
    unittest.main()