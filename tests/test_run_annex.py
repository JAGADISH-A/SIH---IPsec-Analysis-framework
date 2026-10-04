"""Current-run annex: live journal -> current experiment assessment binding.

Covers the controller -> analytics seam end-to-end at the API layer:
a real manifest + a live journal make the running store register the current
run (same engines the recorded store uses), bind live packet risk to it, and
unregister cleanly restoring the recorded store when the journal goes quiet.
"""

import json
import os
import tempfile
import time
import unittest

from correlation.api.capture_feed import CaptureFeedService, build_risk_index
from correlation.api.run_annex import CurrentRunAnnex
from correlation.api.store import AssessmentStore, build_store

SCHEMA = "testbed-experiment-manifest/v1"


def _manifest(job_id="job-00001", esp_integrity=None, spi=0x0badf00d,
              posture="STRONG", status="PASS", ended=False, traffic=True):
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
            "ended_at_ns": now + 1_000_000 if ended else None,
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
                "packets": 42 if traffic else 0,
                "bytes": 42880 if traffic else 0,
                "esp": 42 if traffic else 0,
                "esp_seen": bool(traffic),
                "ah": 0,
                "tunnel_seen": bool(traffic),
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


class TestLiveRunDriftBridge(unittest.TestCase):
    """A completed live experiment is compared with the recorded baseline.

    The annex calls the existing ``_attach_drift`` and nothing else: the
    ObservedState the live run already carries is handed to the same comparison
    the recorded cases use. These tests pin the seam and the lifecycle around it
    -- in-flight runs are not compared, the completed observation is, and the
    completed assessment stays reachable -- while every verdict asserted here is
    one the real comparison produced for a real manifest and journal.
    """

    BASELINE_STATE = "results/e2e-verification/parser/tunnel_v4/state.jsonl"
    BASELINE_ID = "baseline-e2e-tunnel-v4"
    IPV4_A, IPV4_B = "10.20.1.10", "10.20.1.20"
    IPV6_A, IPV6_B = "2001:db8:20::10", "2001:db8:20::20"

    def _registry(self, path=BASELINE_STATE, baseline_id=BASELINE_ID):
        from correlation.artifacts import load_observed_state
        from correlation.drift.comparison import validate_baseline
        from correlation.drift.registry import BaselineRegistry

        state, _ = load_observed_state(path)
        registry = BaselineRegistry()
        registry.register(validate_baseline(
            state, baseline_id=baseline_id,
            validated_by="sec-ops@ipsec-testbed",
            validated_at="2026-09-20T09:00:00Z",
        ))
        return registry

    def _esp(self, ts, src, dst):
        return json.dumps({
            "ts": ts, "type": "ESP", "src": src, "dst": dst,
            "family": 6 if ":" in src else 4, "proto": 50,
            "len": 154, "spi": "0x1", "seq": 1,
        })

    def _annex(self, tmp, manifest, events, *, baseline=True):
        journal = os.path.join(tmp, "live_events.jsonl")
        with open(journal, "w", encoding="utf-8") as fh:
            for line in events:
                fh.write(line + "\n")
        manifest_path = os.path.join(tmp, "experiment.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
        kwargs = ({"baselines": self._registry(), "baseline_id": self.BASELINE_ID}
                  if baseline else {})
        store = build_store(**kwargs)
        feed = CaptureFeedService(journal, risk_index=build_risk_index(store))
        annex = CurrentRunAnnex(store=store, feed=feed, manifest_path=manifest_path)
        return annex, store, feed, manifest_path

    def _stale(self, feed):
        """Retire the journal's freshness so the boundary gate stops serving."""
        original = feed._now_ms
        feed._now_ms = lambda: original() + feed.freshness_window_ms * 10
        return original

    def _run(self, manifest, events, *, baseline=True):
        with tempfile.TemporaryDirectory() as tmp:
            annex, store, feed, mpath = self._annex(
                tmp, manifest, events, baseline=baseline
            )
            yield_store = store
            annex.sync()
            return yield_store, annex, feed, mpath

    # -- in-flight vs completed --------------------------------------------

    def test_an_in_flight_run_is_not_compared(self):
        """A partial manifest must never produce a verdict."""
        now = int(time.time_ns())
        manifest = _manifest()
        events = [self._esp(now, self.IPV4_A, self.IPV4_B)]
        store, annex, _feed, _p = self._run(manifest, events)
        aid = manifest["run"]["assessment_id"]
        self.assertIn(aid, store.bundles)
        self.assertNotIn(aid, store.drift_inputs)

    def test_a_finished_run_is_compared_against_the_baseline(self):
        manifest = _manifest(ended=True)
        now = int(time.time_ns())
        events = [self._esp(now, self.IPV4_A, self.IPV4_B)]
        store, _annex, _feed, _p = self._run(manifest, events)
        aid = manifest["run"]["assessment_id"]
        drift = store.drift_inputs[aid]
        self.assertEqual(drift.baseline_id, self.BASELINE_ID)
        self.assertEqual(drift.current_run_id, manifest["run"]["dataset_run_id"])
        self.assertEqual(drift.current_sequence, manifest["run"]["sequence"])
        self.assertTrue(drift.baseline_validated_by)

    def test_assessment_id_is_the_exact_controller_assessment_id(self):
        manifest = _manifest(job_id="job-abc123", ended=True)
        now = int(time.time_ns())
        events = [self._esp(now, self.IPV4_A, self.IPV4_B)]
        store, _annex, _feed, _p = self._run(manifest, events)
        expected = "testbed-job-abc123:1:current"
        self.assertEqual(manifest["run"]["assessment_id"], expected)
        self.assertIn(expected, store.bundles)
        self.assertIn(expected, store.drift_inputs)

    # -- verdicts, decided by the existing comparison -----------------------

    def test_a_matching_address_family_is_no_drift(self):
        manifest = _manifest(ended=True)
        now = int(time.time_ns())
        events = [self._esp(now, self.IPV4_A, self.IPV4_B)]
        store, _annex, _feed, _p = self._run(manifest, events)
        drift = store.drift_inputs[manifest["run"]["assessment_id"]]
        self.assertEqual(drift.status, "no_drift")
        self.assertEqual(drift.changed_fields, ())
        self.assertIsNone(drift.risk)
        self.assertEqual(drift.unchanged_variables,
                         ("address_family", "esp.presence", "ah.presence"))

    def test_a_genuinely_different_address_family_is_drift(self):
        """IPv4 baseline against real observed IPv6 endpoints."""
        manifest = _manifest(ended=True)
        now = int(time.time_ns())
        events = [self._esp(now, self.IPV6_A, self.IPV6_B)]
        store, _annex, _feed, _p = self._run(manifest, events)
        drift = store.drift_inputs[manifest["run"]["assessment_id"]]

        self.assertEqual(drift.status, "drift")
        self.assertEqual([c.variable for c in drift.changed_fields],
                         ["address_family"])
        change = drift.changed_fields[0]
        self.assertEqual((change.baseline_value, change.current_value),
                         ("ipv4", "ipv6"))
        self.assertEqual(drift.unchanged_variables,
                         ("esp.presence", "ah.presence"))
        # The finding and its severity come from the existing risk subsystem.
        self.assertIsNotNone(drift.risk)
        self.assertTrue(drift.risk.findings)
        self.assertTrue(all(f.finding_id.startswith("RISK-DRIFT-")
                            for f in drift.risk.findings))
        self.assertTrue(all(f.severity for f in drift.risk.findings))

    def test_address_family_comes_from_real_packets_not_the_configured_label(self):
        """The configured family is not evidence; the observed packets are."""
        manifest = _manifest(ended=True)
        self.assertEqual(manifest["config"]["address_family"], "ipv4")
        now = int(time.time_ns())
        events = [self._esp(now, self.IPV6_A, self.IPV6_B)]
        store, _annex, _feed, _p = self._run(manifest, events)
        aid = manifest["run"]["assessment_id"]
        observed = store.custody_inputs[aid].observed
        self.assertEqual(observed.endpoints,
                         {"a": self.IPV6_A, "b": self.IPV6_B})
        # And that real observation is what the comparison read.
        self.assertEqual(store.drift_inputs[aid].status, "drift")
        self.assertEqual(
            store.drift_inputs[aid].changed_fields[0].current_value, "ipv6")

    def test_an_observation_with_no_traffic_is_indeterminate(self):
        """No IPsec packet observed claims neither drift nor agreement."""
        manifest = _manifest(ended=True, traffic=False)
        now = int(time.time_ns())
        events = [self._esp(now, self.IPV4_A, self.IPV4_B)]
        store, _annex, _feed, _p = self._run(manifest, events)
        drift = store.drift_inputs[manifest["run"]["assessment_id"]]
        self.assertEqual(drift.status, "indeterminate")
        self.assertEqual(drift.changed_fields, ())

    def test_no_configured_baseline_leaves_the_finished_run_unattached(self):
        manifest = _manifest(ended=True)
        now = int(time.time_ns())
        events = [self._esp(now, self.IPV4_A, self.IPV4_B)]
        store, _annex, _feed, _p = self._run(manifest, events, baseline=False)
        aid = manifest["run"]["assessment_id"]
        self.assertIn(aid, store.bundles)
        self.assertNotIn(aid, store.drift_inputs)
        self.assertEqual(
            [a for a, p in store.drift_parent.items() if p == aid], []
        )

    # -- lifecycle ----------------------------------------------------------

    def test_the_closed_gate_persists_the_completed_assessment(self):
        """After the gate closes the comparison must stay reachable."""
        manifest = _manifest(ended=False)
        now = int(time.time_ns())
        events = [self._esp(now, self.IPV4_A, self.IPV4_B)]
        with tempfile.TemporaryDirectory() as tmp:
            annex, store, feed, mpath = self._annex(tmp, manifest, events)
            aid = manifest["run"]["assessment_id"]
            self.assertTrue(annex.sync()["active"])
            self.assertNotIn(aid, store.drift_inputs)

            # The controller finishes the run: the manifest gains ended_at_ns.
            manifest["run"]["ended_at_ns"] = int(time.time_ns())
            manifest["observed"]["summary"]["esp_seen"] = True
            with open(mpath, "w", encoding="utf-8") as fh:
                json.dump(manifest, fh)
            restore = self._stale(feed)
            try:
                status = annex.sync()
            finally:
                feed._now_ms = restore

            self.assertFalse(status["active"])
            self.assertEqual(status.get("finalized_assessment_id"), aid)
            self.assertIn(aid, store.bundles)
            self.assertIn(aid, store.drift_inputs)
            self.assertEqual(store.drift_inputs[aid].status, "no_drift")

    def test_finalizing_repeatedly_does_not_duplicate_the_assessment(self):
        manifest = _manifest(ended=True)
        now = int(time.time_ns())
        events = [self._esp(now, self.IPV4_A, self.IPV4_B)]
        with tempfile.TemporaryDirectory() as tmp:
            annex, store, feed, _p = self._annex(tmp, manifest, events)
            aid = manifest["run"]["assessment_id"]
            for _ in range(3):
                restore = self._stale(feed)
                try:
                    annex.sync()
                finally:
                    feed._now_ms = restore
            bundles = len(store.bundles)
            drift_keys = set(store.drift_inputs)
            for _ in range(3):
                restore = self._stale(feed)
                try:
                    annex.sync()
                finally:
                    feed._now_ms = restore
            self.assertEqual(len(store.bundles), bundles)
            self.assertEqual(set(store.drift_inputs), drift_keys)
            self.assertEqual(
                [h for h in store.headers if h["assessment_id"] == aid],
                [h for h in store.headers if h["assessment_id"] == aid][:1],
            )

    def test_the_transition_from_in_flight_to_completed_is_not_a_duplicate(self):
        """The final comparison replaces the transient one."""
        manifest = _manifest(ended=False)
        now = int(time.time_ns())
        events = [self._esp(now, self.IPV6_A, self.IPV6_B)]
        with tempfile.TemporaryDirectory() as tmp:
            annex, store, feed, mpath = self._annex(tmp, manifest, events)
            aid = manifest["run"]["assessment_id"]
            annex.sync()
            transient = len([h for h in store.headers
                             if h["assessment_id"] == aid])
            manifest["run"]["ended_at_ns"] = int(time.time_ns())
            with open(mpath, "w", encoding="utf-8") as fh:
                json.dump(manifest, fh)
            restore = self._stale(feed)
            try:
                annex.sync()
            finally:
                feed._now_ms = restore
            self.assertEqual(
                len([h for h in store.headers if h["assessment_id"] == aid]),
                transient,
            )
            self.assertEqual(store.drift_inputs[aid].status, "drift")

    def test_a_completed_assessment_survives_the_next_experiment(self):
        manifest_a = _manifest(job_id="job-aaaa", ended=True)
        now = int(time.time_ns())
        events_a = [self._esp(now, self.IPV6_A, self.IPV6_B)]
        with tempfile.TemporaryDirectory() as tmp:
            annex, store, feed, mpath = self._annex(tmp, manifest_a, events_a)
            aid_a = manifest_a["run"]["assessment_id"]
            restore = self._stale(feed)
            try:
                annex.sync()
            finally:
                feed._now_ms = restore
            self.assertIn(aid_a, store.drift_inputs)

            manifest_b = _manifest(job_id="job-bbbb", ended=False)
            with open(mpath, "w", encoding="utf-8") as fh:
                json.dump(manifest_b, fh)
            annex.sync()
            aid_b = manifest_b["run"]["assessment_id"]
            self.assertNotEqual(aid_a, aid_b)
            self.assertTrue(annex.sync()["active"])
            # The completed run is still there, and the new one is separate.
            self.assertIn(aid_a, store.drift_inputs)
            self.assertIn(aid_b, store.bundles)

    def test_recorded_cases_still_default_to_the_recorded_plan_run(self):
        import inspect

        from correlation.api.store import DATASET_RUN_ID

        self.assertEqual(
            inspect.signature(AssessmentStore._attach_drift)
            .parameters["run_id"].default,
            DATASET_RUN_ID,
        )


if __name__ == "__main__":
    unittest.main()
