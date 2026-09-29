"""Continuous dataset-run live boundary (controller -> capture feed).

A dataset run ("Automated Experiment Run") is one continuous live session: the
topology, XDP monitor and journal stay alive across samples.  The controller
must therefore publish ONE run-spanning boundary -- opened at the first live
observation, re-anchored when the journal is truncated by a monitor restart,
and closed only when the run stops -- so the experiment-gated capture feed
serves LIVE rows for the whole run instead of closing between experiments.

These tests exercise the controller-side session API directly and prove the
resulting capture feed verdict (open -> rows, closed -> zero rows) without a
lab, using the same ``CurrentRunAnnex`` the live deployment uses.
"""

import json
import os
import tempfile
import unittest
from unittest import mock

from controller import dataset_api
from controller import experiment_manifest as manifest_mod
from correlation.api.capture_feed import CaptureFeedService
from correlation.api.run_annex import CurrentRunAnnex

RUN_ID = "dataset-20260930-030000"

CONFIG = {
    "mode": "tunnel",
    "address_family": "ipv4",
    "ike": {
        "version": 2,
        "encryption": "aes256",
        "integrity": "sha256",
        "dh_group": "modp2048",
    },
    "esp": {
        "encryption": "aes128gcm16",
        "integrity": None,
        "dh_group": "modp2048",
        "pfs": True,
    },
    "traffic": {"profile": "voip", "duration": 30},
}


def _event(spi, seq, index=0):
    return {
        "ts": 17260803212308 + index,
        "type": "ESP",
        "src": "192.168.100.1",
        "dst": "192.168.100.2",
        "proto": 50,
        "len": 154,
        "spi": spi,
        "seq": seq,
    }


class TestContinuousSession(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.journal = os.path.join(self.tmp.name, "live_events.jsonl")
        with open(self.journal, "wb"):
            pass
        self.manifest = os.path.join(self.tmp.name, "experiment.json")
        for name, value in (
            ("manifest_path", lambda: self.manifest),
            ("_journal_path", lambda: self.journal),
        ):
            patcher = mock.patch.object(manifest_mod, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(manifest_mod.close_run_session)

    def _append(self, events):
        with open(self.journal, "ab") as handle:
            for event in events:
                handle.write(json.dumps(event).encode("utf-8") + b"\n")

    def _manifest(self):
        with open(self.manifest, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def _feed(self):
        annex = CurrentRunAnnex(
            store=None, feed=None, manifest_path=self.manifest
        )
        return CaptureFeedService(
            self.journal,
            boundary_provider=annex.boundary,
            experiment_gated=True,
            freshness_window_ms=8000,
        )

    def test_open_publishes_boundary_and_feed_serves_own_rows(self):
        self._append([_event(0x999, index) for index in range(5)])
        manifest_mod.begin_run_session(RUN_ID)
        self.assertTrue(
            manifest_mod.publish_session_boundary(
                CONFIG, {"status": "live", "action": "started"}
            )
        )
        raw = self._manifest()
        self.assertEqual(raw["schema"], manifest_mod.SCHEMA)
        self.assertNotIn("ended_at_ns", raw["run"])
        self.assertEqual(raw["journal"]["path"], self.journal)

        self._append([_event(0x222, 1, 100), _event(0x222, 2, 101)])
        page = self._feed().poll(cursor=0, limit=200)
        self.assertEqual(page["count"], 2)
        self.assertEqual([ev["spi"] for ev in page["events"]], [0x222, 0x222])

    def test_reanchor_after_monitor_restart(self):
        self._append([_event(0x999, index) for index in range(5)])
        manifest_mod.begin_run_session(RUN_ID)
        manifest_mod.publish_session_boundary(
            CONFIG, {"status": "live", "action": "started"}
        )
        self._append([_event(0x111, 1, 10)])

        with open(self.journal, "wb"):
            pass
        self.assertTrue(
            manifest_mod.publish_session_boundary(
                CONFIG, {"status": "live", "action": "started"}
            )
        )
        self.assertEqual(self._manifest()["journal"]["observation_start_bytes"], 0)

        self._append([_event(0x333, 1, 20), _event(0x333, 2, 21)])
        page = self._feed().poll(cursor=0, limit=200)
        self.assertEqual([ev["spi"] for ev in page["events"]], [0x333, 0x333])

    def test_reuse_keeps_the_open_boundary(self):
        manifest_mod.begin_run_session(RUN_ID)
        self.assertTrue(
            manifest_mod.publish_session_boundary(
                CONFIG, {"status": "live", "action": "started"}
            )
        )
        self._append([_event(0x222, 1)])
        self.assertFalse(
            manifest_mod.publish_session_boundary(
                CONFIG, {"status": "live", "action": "reuse"}
            )
        )

    def test_close_ends_boundary_and_feed(self):
        manifest_mod.begin_run_session(RUN_ID)
        manifest_mod.publish_session_boundary(
            CONFIG, {"status": "live", "action": "started"}
        )
        self._append([_event(0x222, 1)])
        self.assertTrue(
            manifest_mod.close_run_session(result={"status": "PASS"})
        )
        self.assertIn("ended_at_ns", self._manifest()["run"])

        page = self._feed().poll(cursor=0, limit=200)
        self.assertEqual(page["count"], 0)
        self.assertEqual(page["events"], [])
        self.assertFalse(page["current"])

    def test_non_live_observation_never_publishes(self):
        manifest_mod.begin_run_session(RUN_ID)
        self.assertFalse(
            manifest_mod.publish_session_boundary(
                CONFIG,
                {
                    "status": "not-applicable",
                    "reason": "transport has no sensor",
                },
            )
        )
        self.assertFalse(os.path.exists(self.manifest))

    def test_inactive_process_is_a_noop(self):
        self.assertFalse(
            manifest_mod.publish_session_boundary(
                CONFIG, {"status": "live", "action": "started"}
            )
        )
        self.assertFalse(manifest_mod.close_run_session())
        self.assertFalse(manifest_mod.session_active())
        self.assertFalse(os.path.exists(self.manifest))

    def test_worker_arms_live_session_only_for_real_pipeline(self):
        class _Run:
            status = "RUNNING"

        class _Lock:
            def release(self, *args, **kwargs):
                pass

        def _worker(runner):
            return dataset_api._run_dataset_worker(
                self.tmp.name,
                RUN_ID,
                _Lock(),
                run_attempt_fn=runner,
                cleanup_fn=None,
                collector_fn=object(),
                max_attempts_per_sequence=1,
            )

        with mock.patch.object(
            dataset_api.executor_mod,
            "execute_dataset_run",
            return_value=_Run(),
        ) as execute:
            _worker(None)
            self.assertTrue(execute.call_args.kwargs["live_session"])
            execute.reset_mock()
            _worker(lambda *args, **kwargs: None)
            self.assertFalse(execute.call_args.kwargs["live_session"])


if __name__ == "__main__":
    unittest.main()
