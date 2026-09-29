"""Live audit-tail experiment-boundary gate tests.

Sentinel's "Live activity" screen reads ``/api/v1/audit/events``. The live
contract is now the same as the capture feed:

* with the boundary gate ON (the default) and no active experiment on THIS
  journal, the tail reports zero LIVE rows (``current: false``) no matter how
  much recorded history the journal holds;
* with an experiment active, only that run's events are served (``run_id`` is
  the immutable boundary capturing the experiment's observation start);
* an experiment that has ended closes the tail immediately;
* with the gate OFF (explicit legacy opt-out for recorded-demo replay) the
  whole journal is served as before.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

from correlation.api.audit_routes import AUDIT_EVENTS_PATH
from correlation.api.capture_feed import CaptureFeedService
from correlation.api.run_annex import CurrentRunAnnex
from correlation.api.v1 import handle_v1_audit

REPO_ROOT = Path(__file__).resolve().parents[1]
HEALTHY_JOURNAL = REPO_ROOT / "tests/fixtures/audit/analysis_events_acc-eng-02.jsonl"
RUN_ID = "acc-eng-02"


def _store():
    from correlation.api.audit_store import AuditStore

    return AuditStore(str(HEALTHY_JOURNAL))


class _Ctx:
    def __init__(self, store, annex):
        self.audit_store = store
        self.annex = annex


def _manifest(dataset_run_id, journal_path, *, ended=False):
    run = {
        "dataset_run_id": dataset_run_id,
        "sequence": 7,
        "assessment_id": f"{dataset_run_id}-assessment",
        "experiment_id": f"{dataset_run_id}-exp-0001",
        "observation_start_bytes": 4096,
        "status": "completed" if ended else "running",
    }
    if ended:
        run["ended_at_ns"] = 2_000_000_000_000
    return {
        "run": run,
        "journal": {"path": journal_path, "byte_size": 4096},
        "manifest_sha256": "0" * 64,
    }


class TestLiveAuditGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.journal = os.path.join(self.tmp.name, "live_events.jsonl")
        with open(self.journal, "w", encoding="utf-8") as handle:
            handle.write("\n")

    def _feed(self, gated):
        return CaptureFeedService(self.journal, experiment_gated=gated)

    def _annex(self, gated, manifest=None):
        feed = self._feed(gated)
        path = None
        if manifest is not None:
            path = os.path.join(self.tmp.name, "experiment.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(manifest, handle)
        return CurrentRunAnnex(
            store=_store(), feed=feed, manifest_path=path
        ), feed

    def _payload(self, ctx):
        return handle_v1_audit(ctx, AUDIT_EVENTS_PATH, {"limit": 200})

    def test_gated_no_manifest_serves_zero_rows_never_history(self):
        annex, _ = self._annex(True, manifest=None)
        payload = self._payload(_Ctx(_store(), annex))
        self.assertEqual(0, payload["total"])
        self.assertEqual([], payload["events"])
        self.assertFalse(payload["current"])
        self.assertEqual("gated-closed", payload["state"])

    def test_gated_ended_manifest_closes_the_tail(self):
        annex, _ = self._annex(
            True,
            manifest=_manifest(RUN_ID, self.journal, ended=True),
        )
        payload = self._payload(_Ctx(_store(), annex))
        self.assertEqual(0, payload["total"])
        self.assertEqual([], payload["events"])
        self.assertFalse(payload["current"])

    def test_gated_active_manifest_forces_current_run_only(self):
        annex, _ = self._annex(True, manifest=_manifest(RUN_ID, self.journal))
        payload = self._payload(_Ctx(_store(), annex))
        # The fixture journal holds the recorded acc-eng-02 run, so the active
        # experiment's run boundary is honoured: only that run's events.
        self.assertEqual(RUN_ID, payload["filters"]["run_id"])
        self.assertGreater(payload["total"], 0)
        self.assertTrue(
            all(event["dataset_run_id"] == RUN_ID for event in payload["events"])
        )

    def test_gated_manifest_for_other_journal_is_not_current(self):
        other = os.path.join(self.tmp.name, "other.jsonl")
        annex, _ = self._annex(True, manifest=_manifest(RUN_ID, other))
        scope = annex.experiment_scope()
        self.assertIsNone(scope)
        payload = self._payload(_Ctx(_store(), annex))
        self.assertEqual(0, payload["total"])
        self.assertFalse(payload["current"])

    def test_legacy_opt_out_serves_the_whole_journal(self):
        annex, _ = self._annex(False, manifest=None)
        payload = self._payload(_Ctx(_store(), annex))
        self.assertGreater(payload["total"], 0)
        self.assertNotIn("state", payload)
        self.assertNotIn("run_id", payload["filters"])


if __name__ == "__main__":
    unittest.main()