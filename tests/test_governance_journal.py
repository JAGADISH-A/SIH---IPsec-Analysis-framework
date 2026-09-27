"""Phase 9: the governance journal -- persistence, not just an in-memory chain.

``AuditLedger`` used to hold its hash chain in memory and nothing else, so the
assessment/recommendation/authorization/approval record died with the process and
``/api/v1/responses/<id>/evidence`` could never resolve a lifecycle. These tests
pin the durable behaviour:

* every append is persisted as one JSONL line, flushed and fsync'd;
* an existing journal is verified and *continued*, never rewritten;
* a tampered or truncated journal is refused, never repaired;
* the ``audit_tap`` references a governance event carries resolve against the
  real observation journal (``results/audit/events.jsonl``);
* the read-only API surface reports the chain's real state.

The negative tests are the point: a journal that cannot be vouched for must
fail loudly rather than quietly continue a chain nobody can trust.
"""

import json
import os
import sys
import tempfile
import unittest

from correlation.models import CorrelationIdentity, EvidenceRef
from correlation.response import ACTION_REQUIRE_REVIEW
from correlation.response.audit import (
    GENESIS_HASH,
    DEFAULT_OBSERVATION_JOURNAL,
    AuditIntegrityError,
    AuditLedger,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def identity(**overrides):
    base = dict(
        dataset_run_id="dataset-20260916-231246",
        sequence=1,
        experiment_id="exp-governance",
        attempt_number=1,
        window_index=0,
        window_start_ns=1_000_000_000,
        window_end_ns=60_000_000_000,
    )
    base.update(overrides)
    return CorrelationIdentity(**base)


def audit_tap_ref(offset=0):
    """The documented reference form for a line in the observation journal."""
    return EvidenceRef(
        audit_event_reference=f"audit://tap-events.jsonl#{offset}",
        source="audit_tap",
    )


def append(ledger, *, event_type="RECOMMENDATION_CREATED", recommendation_id="RR-1",
           principal="system:planner", evidence_refs=(), timestamp=0):
    return ledger.append(
        timestamp=timestamp,
        assessment_identity=identity(),
        event_type=event_type,
        principal=principal,
        recommendation_id=recommendation_id,
        reason="recorded for the audit trail",
        policy_version="response-policy-v1",
        action=ACTION_REQUIRE_REVIEW,
        previous_status="NOT_EVALUATED",
        new_status="RECOMMENDED",
        evidence_refs=evidence_refs,
    )


class TempJournal(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = os.path.join(self._dir.name, "audit", "governance.jsonl")

    def lines(self):
        with open(self.path, "r", encoding="utf-8") as handle:
            return [line for line in handle.read().splitlines() if line.strip()]


class TestPersistence(TempJournal):
    def test_in_memory_ledger_writes_nothing(self):
        ledger = AuditLedger()
        self.assertIsNone(ledger.path)
        append(ledger)
        self.assertFalse(os.path.exists(self.path))

    def test_append_creates_journal_parent_and_one_line(self):
        ledger = AuditLedger(path=self.path)
        append(ledger)
        self.assertTrue(os.path.isdir(os.path.dirname(self.path)))
        self.assertEqual(len(self.lines()), 1)

    def test_persisted_line_is_the_event_verbatim(self):
        ledger = AuditLedger(path=self.path)
        event = append(ledger)
        record = json.loads(self.lines()[0])
        self.assertEqual(record, event.to_dict())
        self.assertEqual(record["previous_hash"], GENESIS_HASH)
        self.assertEqual(record["event_hash"], event.event_hash)

    def test_each_append_appends_one_line_never_rewrites(self):
        ledger = AuditLedger(path=self.path)
        first = append(ledger)
        first_line = self.lines()[0]
        append(ledger, event_type="AUTHORIZATION_CHECKED", recommendation_id="RR-1")
        self.assertEqual(len(self.lines()), 2)
        # The first line is byte-identical: append-only means append-only.
        self.assertEqual(self.lines()[0], first_line)
        self.assertEqual(first.event_hash, json.loads(first_line)["event_hash"])

    def test_persisted_events_carry_evidence_refs(self):
        ledger = AuditLedger(path=self.path)
        append(ledger, evidence_refs=[audit_tap_ref(3)])
        record = json.loads(self.lines()[0])
        self.assertEqual(len(record["evidence_refs"]), 1)
        self.assertEqual(record["evidence_refs"][0]["source"], "audit_tap")

    def test_persist_rejects_a_non_event(self):
        ledger = AuditLedger(path=self.path)
        with self.assertRaises(TypeError):
            ledger._persist({"event_id": "EVT-0001"})

    def test_response_engine_keeps_the_persisted_ledger(self):
        """The engine appends through the injected ledger, so it persists too."""
        from correlation.response.engine import ResponseEngine

        ledger = AuditLedger(path=self.path)
        engine = ResponseEngine(ledger=ledger)
        self.assertIs(engine.ledger, ledger)
        engine.ledger.append(
            timestamp=0,
            assessment_identity=identity(),
            event_type="RECOMMENDATION_CREATED",
            principal="system:planner",
            reason="recommended",
            policy_version="response-policy-v1",
            action=ACTION_REQUIRE_REVIEW,
            previous_status="NOT_EVALUATED",
            new_status="RECOMMENDED",
        )
        self.assertEqual(len(self.lines()), 1)


class TestReopen(TempJournal):
    def test_open_missing_file_is_an_empty_ledger(self):
        ledger = AuditLedger.open(self.path)
        self.assertEqual(len(ledger), 0)
        self.assertEqual(ledger.last_hash(), GENESIS_HASH)
        self.assertFalse(os.path.exists(self.path))

    def test_reopen_continues_the_chain(self):
        ledger = AuditLedger(path=self.path)
        first = append(ledger)
        second = append(ledger, event_type="AUTHORIZATION_CHECKED")

        reopened = AuditLedger.open(self.path)
        self.assertEqual(len(reopened), 2)
        self.assertEqual(reopened.last_hash(), second.event_hash)
        # The next event links onto the persisted chain, not onto genesis.
        third = append(reopened, event_type="APPROVED")
        self.assertEqual(third.previous_hash, second.event_hash)
        self.assertNotEqual(third.previous_hash, first.previous_hash)
        self.assertTrue(reopened.verify())
        self.assertEqual(len(self.lines()), 3)

    def test_reopen_is_idempotent(self):
        ledger = AuditLedger(path=self.path)
        append(ledger)
        before = self.lines()
        AuditLedger.open(self.path)
        AuditLedger.open(self.path)
        self.assertEqual(self.lines(), before)

    def test_read_journal_round_trips_events(self):
        ledger = AuditLedger(path=self.path)
        append(ledger, evidence_refs=[audit_tap_ref(0)])
        reread = ledger.read_journal()
        self.assertEqual([event.to_dict() for event in reread], ledger.to_dicts())

    def test_read_journal_without_a_path_is_an_error(self):
        with self.assertRaises(ValueError):
            AuditLedger().read_journal()

    def test_blank_lines_are_skipped(self):
        ledger = AuditLedger(path=self.path)
        append(ledger)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write("\n\n")
        self.assertEqual(len(AuditLedger.open(self.path)), 1)


class TestFailClosed(TempJournal):
    def test_corrupt_line_raises(self):
        ledger = AuditLedger(path=self.path)
        append(ledger)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write("{not json\n")
        with self.assertRaises(ValueError):
            AuditLedger.open(self.path)

    def test_tampered_event_is_refused_not_repaired(self):
        ledger = AuditLedger(path=self.path)
        append(ledger)
        lines = self.lines()
        record = json.loads(lines[0])
        record["reason"] = "quietly rewritten"
        rewritten = json.dumps(record, sort_keys=True)
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(rewritten + "\n")
        with self.assertRaises(AuditIntegrityError):
            AuditLedger.open(self.path)
        # The file is left exactly as found: nothing repairs or rewrites it.
        self.assertEqual(self.lines()[0], rewritten)

    def test_reordered_journal_is_refused(self):
        ledger = AuditLedger(path=self.path)
        append(ledger)
        append(ledger, event_type="AUTHORIZATION_CHECKED")
        reordered = "\n".join(reversed(self.lines())) + "\n"
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(reordered)
        with self.assertRaises(AuditIntegrityError):
            AuditLedger.open(self.path)

    def test_dropped_event_breaks_the_chain(self):
        """A silently shortened history must not verify over the remainder."""
        ledger = AuditLedger(path=self.path)
        append(ledger)
        append(ledger, event_type="AUTHORIZATION_CHECKED")
        # Read before truncating: open(mode="w") empties the file immediately.
        kept = self.lines()[1]
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(kept + "\n")
        with self.assertRaises(AuditIntegrityError):
            AuditLedger.open(self.path)


class TestObservationLink(TempJournal):
    def test_audit_tap_refs_are_collected(self):
        ledger = AuditLedger(path=self.path)
        append(ledger, evidence_refs=[audit_tap_ref(0), audit_tap_ref(7)])
        append(ledger, event_type="AUTHORIZATION_CHECKED",
               evidence_refs=[audit_tap_ref(12)])
        self.assertEqual(
            ledger.audit_tap_refs(),
            ["audit://tap-events.jsonl#0", "audit://tap-events.jsonl#7",
             "audit://tap-events.jsonl#12"],
        )

    def test_non_audit_tap_sources_are_not_collected(self):
        ledger = AuditLedger(path=self.path)
        append(ledger, evidence_refs=[
            EvidenceRef(pcap_path="results/x.pcap", source="training_pcap"),
            EvidenceRef(source="swanctl"),
        ])
        self.assertEqual(ledger.audit_tap_refs(), [])

    def test_verify_against_the_real_observation_journal(self):
        """The committed journal resolves references that point inside it."""
        journal = os.path.join(REPO_ROOT, DEFAULT_OBSERVATION_JOURNAL)
        with open(journal, "r", encoding="utf-8") as handle:
            recorded = len([line for line in handle.read().splitlines() if line.strip()])
        self.assertGreater(recorded, 0)

        ledger = AuditLedger(path=self.path)
        append(ledger, evidence_refs=[audit_tap_ref(0), audit_tap_ref(recorded - 1)])
        report = ledger.verify_against(journal)
        self.assertEqual(report["events"], recorded)
        self.assertEqual(report["referenced"], 2)
        self.assertEqual(report["resolved"], 2)
        self.assertEqual(report["unresolved"], 0)

    def test_reference_past_the_end_of_the_committed_journal_is_reported(self):
        """The demo store cites ``#2048``; the committed journal is shorter.

        That is a real, honest "unresolved" — the link is reported, never
        silently re-pointed at some other observation.
        """
        journal = os.path.join(REPO_ROOT, DEFAULT_OBSERVATION_JOURNAL)
        with open(journal, "r", encoding="utf-8") as handle:
            recorded = len([line for line in handle.read().splitlines() if line.strip()])
        self.assertGreater(2048, recorded, "expected the committed journal to be short")

        ledger = AuditLedger(path=self.path)
        append(ledger, evidence_refs=[audit_tap_ref(2048)])
        report = ledger.verify_against(journal)
        self.assertEqual(report["referenced"], 1)
        self.assertEqual(report["resolved"], 0)
        self.assertEqual(report["unresolved"], 1)
        self.assertTrue(ledger.verify())

    def test_out_of_range_reference_is_reported_not_repaired(self):
        ledger = AuditLedger(path=self.path)
        append(ledger, evidence_refs=[audit_tap_ref(10_000_000)])
        journal = os.path.join(self._dir.name, "events.jsonl")
        with open(journal, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"event_type": "x"}) + "\n")
        report = ledger.verify_against(journal)
        self.assertEqual(report["referenced"], 1)
        self.assertEqual(report["resolved"], 0)
        self.assertEqual(report["unresolved"], 1)
        # The chain itself is still intact: a bad reference is not tampering.
        self.assertTrue(ledger.verify())

    def test_missing_observation_journal_reports_every_reference_unresolved(self):
        ledger = AuditLedger(path=self.path)
        append(ledger, evidence_refs=[audit_tap_ref(0)])
        report = ledger.verify_against(os.path.join(self._dir.name, "absent.jsonl"))
        self.assertEqual(report["events"], 0)
        self.assertEqual(report["resolved"], 0)
        self.assertEqual(report["unresolved"], 1)

    def test_malformed_pointer_is_unresolvable(self):
        ledger = AuditLedger(path=self.path)
        append(ledger, evidence_refs=[
            EvidenceRef(audit_event_reference="audit://tap-events.jsonl#latest",
                        source="audit_tap"),
        ])
        journal = os.path.join(self._dir.name, "events.jsonl")
        with open(journal, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"event_type": "x"}) + "\n")
        report = ledger.verify_against(journal)
        self.assertEqual(report["unresolved"], 1)


class TestReadOnlyApi(unittest.TestCase):
    """The persisted chain must be inspectable without becoming a write surface."""

    def setUp(self):
        from correlation.api.live import Phase10Context
        from correlation.api.pcap import PcapRegistry, PcapService

        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = os.path.join(self._dir.name, "governance.jsonl")
        self.ledger = AuditLedger(path=self.path)
        append(self.ledger, evidence_refs=[audit_tap_ref(0)])
        append(self.ledger, event_type="AUTHORIZATION_CHECKED", principal="analyst:jagan")

        self.context = Phase10Context()
        self.context.pcap = PcapService(PcapRegistry(root=self._dir.name))
        self.context.attach_governance(
            self.ledger,
            os.path.join(REPO_ROOT, DEFAULT_OBSERVATION_JOURNAL),
        )

    def test_list_reports_the_chain_and_its_links(self):
        from correlation.api.evidence_routes import handle_governance_list

        payload = handle_governance_list(self.context)
        self.assertTrue(payload["read_only"])
        self.assertTrue(payload["chain_verified"])
        self.assertIsNone(payload["chain_detail"])
        self.assertEqual(payload["event_count"], 2)
        # The journal is identified by filename, never by its absolute host
        # location: this API is unauthenticated, and /tmp/... would disclose
        # the deploy layout and the service account.
        self.assertEqual(payload["journal"], "governance.jsonl")
        self.assertFalse(os.path.isabs(payload["journal"]))
        self.assertFalse(payload["host_path_disclosed"])
        self.assertEqual([e["event_id"] for e in payload["events"]],
                         ["EVT-0001", "EVT-0002"])
        self.assertEqual(payload["events"][0]["principal"], "system:planner")
        self.assertEqual(payload["events"][1]["principal"], "analyst:jagan")

    def test_event_detail_carries_evidence_and_its_observation_target(self):
        from correlation.api.evidence_routes import handle_governance_event

        payload = handle_governance_event(self.context, "EVT-0001")
        self.assertEqual(payload["event_type"], "RECOMMENDATION_CREATED")
        self.assertEqual(payload["evidence_count"], 1)
        self.assertEqual(len(payload["evidence"]), 1)
        self.assertTrue(payload["observation_journal"].endswith("events.jsonl"))
        self.assertFalse(os.path.isabs(payload["observation_journal"]))
        # A capture justifies a decision; it never authorizes it.
        self.assertFalse(payload["evidence"][0]["authoritative"])

    def test_unknown_event_is_404(self):
        from correlation.api.evidence_routes import handle_governance_event
        from correlation.api.routes import ApiError

        with self.assertRaises(ApiError) as caught:
            handle_governance_event(self.context, "EVT-9999")
        self.assertEqual(caught.exception.status, 404)

    def test_without_a_ledger_the_route_reports_absence(self):
        from correlation.api.evidence_routes import handle_governance_list
        from correlation.api.live import Phase10Context
        from correlation.api.routes import ApiError

        bare = Phase10Context()
        with self.assertRaises(ApiError) as caught:
            handle_governance_list(bare)
        self.assertEqual(caught.exception.status, 503)
        self.assertIn("governance", caught.exception.detail)

    def test_routes_reach_the_response_lifecycle(self):
        from correlation.api.v1 import handle_v1_get

        body, content_type = handle_v1_get(self.context, "/api/v1/governance")
        self.assertEqual(content_type, "application/json")
        self.assertEqual(body["event_count"], 2)

        body, _ = handle_v1_get(self.context, "/api/v1/governance/EVT-0002")
        self.assertEqual(body["event_type"], "AUTHORIZATION_CHECKED")

        from correlation.api.routes import ApiError
        with self.assertRaises(ApiError):
            handle_v1_get(self.context, "/api/v1/governance/EVT-0002/evidence")

    def test_summary_reports_the_governance_journal(self):
        summary = self.context.summary()
        self.assertEqual(summary["governance_journal"], self.path)
        self.assertEqual(summary["governance_events"], 2)

    def test_attached_ledger_resolves_the_response_lifecycle(self):
        """The reason audit #5 existed: the lifecycle is now resolvable."""
        from correlation.api.audit_store import AuditStore

        store = AuditStore(None)
        store.response_ledger = self.ledger
        lifecycle = store.response_lifecycle("RR-1")
        self.assertTrue(lifecycle["available"])
        self.assertTrue(lifecycle["chain_verified"])
        self.assertEqual(
            [record["event_type"] for record in lifecycle["events"]],
            ["RECOMMENDATION_CREATED", "AUTHORIZATION_CHECKED"],
        )


if __name__ == "__main__":
    unittest.main()
