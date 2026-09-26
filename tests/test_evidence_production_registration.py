"""Production registration of recorded evidence (final-audit remediation).

Two production gaps were found by running the real testbed paths, not by
reading them:

1. ``correlation/api/store.py`` built every assessment's evidence references
   with ``sequence=0``. ``EvidenceRef`` refuses a capture sequence below 1, and
   ``correlation/artifacts.py:evidence_ref_for`` swallowed the resulting
   ``ValueError`` behind a bare ``except Exception``, so **every** dashboard
   assessment reported ``"No evidence references were supplied."`` while a real
   recorded artifact sat right there on disk.
2. ``correlation/api/pcap.py:PcapRegistry.register`` — the *only* thing allowed
   to map an evidence id onto a real file, and therefore the only source of the
   bytes behind ``/api/v1/evidence/{id}/pcap`` — had no production caller, so
   every recorded reference reported ``downloadable: false`` and every download
   404'd.

The fixes are deliberately minimal: the store passes the assessment's own real
sequence, the swallowed exception is narrowed to "the artifact is absent", and
``register_journal_evidence`` additionally records the download mapping for a
reference whose path it has *already* validated as inside the evidence root.

Every test here runs against real recorded artifacts and the real production
functions: the real analysis journal written by ``correlation.audit.audit_run``
from a real correlation run over real recorded live events, and the real
``results/datasets/acc-eng-02/captures/0001/...pcap``. The invariants pinned
here are the ones the evidence architecture depends on:

* references are per-window and content-addressed, so window N can never
  inherit window N+1's capture;
* the download mapping stays id-keyed — no path from a request ever reaches it;
* the served bytes hash to the digest recorded in the journal;
* evidence is never authoritative; the observation/state builder is;
* registration is deterministic and idempotent;
* a missing artifact yields *no* reference, never a fabricated one;
* audit records carry a reference, never capture bytes.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

PLAN_PATH = "results/datasets/acc-eng-02/staging/plan.json"
LIVE_EVENTS = "results/observed-state/live_events_full.jsonl"
MODEL_PATH = "results/ml/model_traffic_rf_v1.joblib"
#: A real recorded capture from the committed dataset run.
REAL_PCAP = "results/datasets/acc-eng-02/captures/0001/acc-eng-02-exp-0001-attempt-01.pcap"
RECORDED_AT = "2026-09-26T00:00:00+00:00"


def _require(relative: str) -> str:
    path = REPO_ROOT / relative
    if not path.exists():
        raise unittest.SkipTest(f"required recorded artifact missing: {relative}")
    return str(path)


class TestDashboardEvidenceIsNoLongerEmpty(unittest.TestCase):
    """Finding 1: the store's real references were silently dropped."""

    @classmethod
    def setUpClass(cls):
        from correlation.api import build_store

        cls.store = build_store()

    def test_recorded_assessments_carry_real_evidence_references(self):
        from correlation import artifacts
        from correlation.api.store import RECORDED_CASES

        known = {case.state_path for case in RECORDED_CASES}
        known |= {case.window_path for case in RECORDED_CASES}
        known.discard(None)
        known.add(artifacts.REAL_ML_WINDOW_PATH)
        self.assertTrue(known, "the recorded cases must name real artifacts")

        with_evidence = 0
        for header in self.store.headers:
            bundle = self.store.bundles[header["assessment_id"]]
            evidence = bundle["evidence"]
            if evidence["total_refs"]:
                with_evidence += 1
                self.assertIsNone(evidence["limitation"])
                for ref in evidence["refs"]:
                    self.assertIn(ref["pcap_path"], known)
                    self.assertGreaterEqual(ref["capture_sequence"], 1)
            else:
                # An assessment with no recorded artifact says so; it never
                # borrows another capture's bytes.
                self.assertEqual(
                    evidence["limitation"],
                    "No evidence references were supplied.",
                )
        self.assertGreaterEqual(with_evidence, 10)

    def test_every_reference_points_at_a_file_that_really_exists(self):
        for header in self.store.headers:
            bundle = self.store.bundles[header["assessment_id"]]
            for ref in bundle["evidence"]["refs"]:
                self.assertTrue(
                    os.path.isfile(REPO_ROOT / ref["pcap_path"]),
                    f"{ref['pcap_path']} is referenced but absent",
                )

    def test_an_invalid_capture_sequence_is_raised_not_swallowed(self):
        from correlation import artifacts

        with self.assertRaises(ValueError):
            artifacts.evidence_ref_for(
                REAL_PCAP, run_id="acc-eng-02", sequence=0
            )

    def test_a_missing_artifact_yields_no_reference_rather_than_a_fake_one(self):
        from correlation import artifacts

        self.assertIsNone(
            artifacts.evidence_ref_for(
                "results/datasets/acc-eng-02/captures/0001/not-recorded.pcap",
                run_id="acc-eng-02",
                sequence=1,
            )
        )
        self.assertIsNone(
            artifacts.evidence_ref_for(
                "results/datasets/acc-eng-02/captures/0001/state.jsonl",
                run_id="acc-eng-02",
                sequence=1,
            )
        )


class TestRealJournalRegistration(unittest.TestCase):
    """Finding 2: the download mapping had no production caller."""

    _built: dict = {}

    @classmethod
    def setUpClass(cls):
        """One real correlation run -> one real analysis journal.

        Expensive (the RF is loaded for real), so it is built once and shared.
        """
        if cls._built:
            return
        from correlation.audit import AuditJournal, audit_run
        from correlation.evidence_linkage import evidence_from_artifact
        from correlation.ml.live_correlation import (
            correlate_live_events,
            read_event_jsonl,
        )

        # Deliberately repo-relative: the download registry accepts only a
        # validated path inside the evidence root, never an absolute one.
        _require(REAL_PCAP)
        ref = evidence_from_artifact(
            REAL_PCAP,
            evidence_root=str(REPO_ROOT),
            run_id="acc-eng-02",
            sequence=1,
            experiment_id="acc-eng-02-exp-0001",
        )
        run = correlate_live_events(
            read_event_jsonl(_require(LIVE_EVENTS)),
            plan_path=_require(PLAN_PATH),
            sequence=1,
            run_id="acc-eng-02",
            experiment_id="acc-eng-02-exp-0001",
            attempt_number=1,
            endpoints={"a": "192.168.100.1", "b": "192.168.100.2"},
            model_path=_require(MODEL_PATH),
        )
        tmp = tempfile.TemporaryDirectory()
        cls._tmp = tmp
        journal_path = os.path.join(tmp.name, "analysis.jsonl")
        events = audit_run(
            run,
            journal=AuditJournal(journal_path),
            evidence_refs=[ref],
            recorded_at=RECORDED_AT,
        )
        cls._built = {
            "journal_path": journal_path,
            "ref": ref,
            "windows": len(run.results),
            "events": events,
            "bytes": Path(journal_path).read_text(encoding="utf-8"),
        }

    @classmethod
    def tearDownClass(cls):
        tmp = getattr(cls, "_tmp", None)
        if tmp is not None:
            tmp.cleanup()

    def _context(self, root: str = None):
        from correlation.api.audit_store import AuditStore
        from correlation.api.live import Phase10Context
        from correlation.api.pcap import PcapRegistry, PcapService
        from correlation.audit import AuditJournal

        built = self._built
        context = Phase10Context()
        context.pcap = PcapService(
            PcapRegistry(root=os.path.abspath(root or str(REPO_ROOT)))
        )
        context.attach_audit_store(
            AuditStore(journal=AuditJournal(built["journal_path"]))
        )
        return context

    def _register(self, context):
        from correlation.api.evidence_routes import register_journal_evidence

        return register_journal_evidence(
            context.audit_store,
            context.pcap.registry,
            root=context.pcap.registry.root,
        )

    def test_the_real_run_records_evidence_on_every_analysis_event(self):
        built = self._built
        self.assertGreater(built["windows"], 0)
        self.assertTrue(built["events"])
        self.assertTrue(
            all(event.evidence_refs for event in built["events"]),
            "audit_run was given a real reference; every event must carry it",
        )

    def test_audit_records_carry_a_reference_never_capture_bytes(self):
        line = self._built["bytes"].splitlines()[0]
        self.assertLess(len(line), 4096)
        payload = json.loads(line)
        refs = payload["evidence_refs"]
        self.assertTrue(refs)
        # a path + digest + size, never the artifact itself
        self.assertIn("pcap_path", refs[0])
        self.assertIn("artifact_sha256", refs[0])
        self.assertIn("byte_size", refs[0])
        self.assertNotIn("bytes", refs[0])
        self.assertNotIn("data", refs[0])
        self.assertNotIn("payload", refs[0])

    def test_registration_populates_the_download_mapping(self):
        context = self._context()
        summary = self._register(context)

        self.assertEqual([], summary["skipped"])
        self.assertEqual(self._built["windows"], summary["registered"])
        # the finding: register() now has a production caller
        self.assertEqual(
            summary["registered"], len(context.pcap.registry._mapping)
        )
        for evidence_id in context.pcap.registry._mapping:
            self.assertIsNotNone(context.pcap.registry.resolve(evidence_id))

    def test_the_api_reports_downloadable_valid_and_non_authoritative(self):
        from correlation.api.evidence_routes import (
            handle_evidence_id,
            handle_evidence_list,
        )

        context = self._context()
        self._register(context)
        listing = handle_evidence_list(context)
        self.assertEqual(self._built["windows"], listing["evidence_count"])
        self.assertTrue(listing["read_only"])

        evidence_id = sorted(context.pcap.registry.references())[0]
        payload = handle_evidence_id(context, evidence_id)
        self.assertTrue(payload["downloadable"])
        self.assertEqual("valid", payload["integrity"]["status"])
        self.assertTrue(payload["integrity"]["matches_recorded"])
        self.assertFalse(payload["authoritative"])
        self.assertEqual("observation/state-builder", payload["authoritative_source"])
        self.assertTrue(payload["read_only"])

    def test_the_served_bytes_hash_to_the_digest_recorded_in_the_journal(self):
        context = self._context()
        self._register(context)
        evidence_id = sorted(context.pcap.registry.references())[0]
        ref = context.pcap.registry.reference(evidence_id)

        data = context.pcap.download(evidence_id)
        self.assertIsNotNone(data)
        self.assertEqual(ref.byte_size, len(data))
        self.assertEqual(ref.artifact_sha256, hashlib.sha256(data).hexdigest())

        verification = context.pcap.verify(evidence_id)
        self.assertEqual("valid", verification.status)
        self.assertTrue(verification.artifact_present)
        self.assertEqual(ref.artifact_sha256, verification.actual_sha256)
        self.assertEqual(ref.artifact_sha256, verification.expected_sha256)
        self.assertEqual(ref.byte_size, verification.byte_size)

    def test_registration_is_deterministic_and_idempotent(self):
        first = self._context()
        self._register(first)
        second = self._context()
        self._register(second)

        self.assertEqual(
            sorted(first.pcap.registry._mapping),
            sorted(second.pcap.registry._mapping),
        )
        again = self._register(first)
        self.assertEqual(self._built["windows"], again["registered"])
        self.assertEqual([], again["skipped"])
        self.assertEqual(
            self._built["windows"], len(first.pcap.registry._mapping)
        )

    def test_each_window_gets_its_own_reference(self):
        context = self._context()
        self._register(context)
        ids = sorted(context.pcap.registry.references())
        self.assertEqual(self._built["windows"], len(set(ids)))
        paths = {
            context.pcap.registry.reference(i).pcap_path for i in ids
        }
        self.assertEqual({self._built["ref"].pcap_path}, paths)

    def test_downloads_still_refuse_traversal_and_unknown_ids(self):
        context = self._context()
        self._register(context)
        self.assertIsNone(context.pcap.download("../../../etc/passwd"))
        self.assertIsNone(context.pcap.download("/etc/passwd"))
        self.assertIsNone(context.pcap.download("..%2f..%2fetc%2fpasswd"))
        self.assertIsNone(context.pcap.download("ev-not-registered"))
        self.assertIsNone(context.pcap.download(""))

    def test_a_reference_outside_the_evidence_root_is_skipped_not_registered(self):
        from correlation.api.evidence_routes import register_journal_evidence
        from correlation.api.pcap import PcapRegistry
        from correlation.models.evidence import EvidenceRef

        with tempfile.TemporaryDirectory() as outside:
            rogue = Path(outside) / "rogue.pcap"
            rogue.write_bytes(b"\xd4\xc3\xb2\xa1not a real capture")
            ref = EvidenceRef(
                pcap_path=str(rogue),
                capture_sequence=1,
                artifact_type="pcap",
                artifact_sha256="0" * 64,
                byte_size=rogue.stat().st_size,
            )
            registry = PcapRegistry(root=str(REPO_ROOT))
            store = _StoreWithRefs([ref])
            summary = register_journal_evidence(
                store, registry, root=str(REPO_ROOT)
            )

        self.assertEqual(0, summary["registered"])
        self.assertEqual(1, len(summary["skipped"]))
        self.assertIn("does not resolve inside", summary["skipped"][0]["reason"])
        self.assertEqual({}, registry._mapping)
        self.assertEqual({}, registry._references)

    def test_evidence_health_reflects_the_real_registry_state(self):
        context = self._context()
        summary = self._register(context)
        context.note_evidence_registered(
            summary["registered"], context.pcap.registry.root
        )
        component = context.health._components["evidence"]
        self.assertEqual("healthy", component.status)
        self.assertIn(str(summary["registered"]), component.detail)

        empty = self._context()
        empty.note_evidence_registered(0, empty.pcap.registry.root)
        component = empty.health._components["evidence"]
        self.assertEqual("unavailable", component.status)
        self.assertNotIn("healthy", component.detail)


class _StoreWithRefs:
    """Minimal store stand-in exposing only what registration reads."""

    def __init__(self, refs):
        self._refs = list(refs)

    def select(self):
        from types import SimpleNamespace

        return [SimpleNamespace(evidence_refs=tuple(self._refs))]


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
