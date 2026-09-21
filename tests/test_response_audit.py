"""Phase 9 append-only audit ledger tests (SHA-256 chain integrity)."""

import unittest

from correlation.models import CorrelationIdentity
from correlation.response import (
    ACTION_REQUIRE_REVIEW,
    ResponseAuditEvent,
)
from correlation.response.audit import (
    GENESIS_HASH,
    AuditIntegrityError,
    AuditLedger,
)


def identity(**overrides):
    base = dict(
        dataset_run_id="dataset-20260916-231246",
        sequence=1,
        experiment_id="exp-response",
        attempt_number=1,
        window_index=0,
        window_start_ns=1_000_000_000,
        window_end_ns=60_000_000_000,
    )
    base.update(overrides)
    return CorrelationIdentity(**base)


def append(ledger, *, timestamp=0, event_type="RECOMMENDATION_CREATED",
           recommendation_id="RR-1", principal="system:planner",
           previous_status="NOT_EVALUATED", new_status="RECOMMENDED", **kwargs):
    return ledger.append(
        timestamp=timestamp,
        assessment_identity=identity(),
        event_type=event_type,
        principal=principal,
        recommendation_id=recommendation_id,
        reason="recommended",
        policy_version="response-policy-v1",
        action=ACTION_REQUIRE_REVIEW,
        previous_status=previous_status,
        new_status=new_status,
        **kwargs,
    )


class TestChain(unittest.TestCase):
    def test_genesis_hash(self):
        self.assertEqual(GENESIS_HASH, "0" * 64)

    def test_first_event_uses_genesis(self):
        ledger = AuditLedger()
        event = append(ledger)
        self.assertEqual(event.previous_hash, GENESIS_HASH)
        self.assertNotEqual(event.event_hash, GENESIS_HASH)
        self.assertEqual(ledger.last_hash(), event.event_hash)

    def test_chain_when_verify(self):
        ledger = AuditLedger()
        a = append(ledger, event_type="RECOMMENDATION_CREATED")
        b = append(ledger, event_type="APPROVAL_REQUESTED",
                   principal="analyst-1", previous_status="RECOMMENDED",
                   new_status="PENDING_APPROVAL")
        self.assertEqual(b.previous_hash, a.event_hash)
        self.assertTrue(ledger.verify())

    def test_empty_ledger(self):
        ledger = AuditLedger()
        self.assertEqual(len(ledger), 0)
        self.assertEqual(ledger.last_hash(), GENESIS_HASH)
        self.assertTrue(ledger.verify())
        self.assertIsNone(ledger.last_event())

    def test_event_ids_sequential(self):
        ledger = AuditLedger()
        for index in range(3):
            event = append(ledger)
            self.assertEqual(event.event_id, f"EVT-{index + 1:04d}")

    def test_append_only_no_mutation(self):
        ledger = AuditLedger()
        a = append(ledger)
        b = append(ledger)
        self.assertEqual(tuple(ledger.events())[0].to_dict(), a.to_dict())
        self.assertTrue(ledger.verify())

    def test_for_assessment(self):
        ledger = AuditLedger()
        append(ledger)
        self.assertTrue(len(ledger.for_assessment("dataset-20260916-231246", 1)) == 1)
        self.assertEqual(ledger.for_assessment("other-run", 1), [])

    def test_for_recommendation(self):
        ledger = AuditLedger()
        append(ledger, recommendation_id="RR-1")
        append(ledger, recommendation_id="RR-2")
        self.assertEqual([e.recommendation_id for e in ledger.for_recommendation("RR-1")],
                         ["RR-1"])


class TestIntegrity(unittest.TestCase):
    def _ledger_with_events(self, count=3):
        ledger = AuditLedger()
        for i in range(count):
            append(ledger, timestamp=i)
        return ledger

    def _swap(self, ledger, index, **updates):
        from dataclasses import replace
        event = ledger.events()[index]
        events = list(ledger._events)
        events[index] = replace(event, **updates)
        ledger._events = events

    def test_unmodified_verifies(self):
        self.assertTrue(self._ledger_with_events().verify())

    def test_tamper_event_hash(self):
        ledger = self._ledger_with_events()
        self._swap(ledger, 1, event_hash="f" * 64)
        with self.assertRaises(AuditIntegrityError):
            ledger.verify()

    def test_tamper_reason(self):
        ledger = self._ledger_with_events()
        self._swap(ledger, 0, reason="tampered")
        with self.assertRaises(AuditIntegrityError):
            ledger.verify()

    def test_tamper_reorder(self):
        ledger = self._ledger_with_events()
        events = list(ledger._events)
        events[0], events[1] = events[1], events[0]
        ledger._events = events
        with self.assertRaises(AuditIntegrityError):
            ledger.verify()

    def test_tamper_pointer(self):
        ledger = self._ledger_with_events()
        self._swap(ledger, 1, previous_hash="0" * 64)
        with self.assertRaises(AuditIntegrityError):
            ledger.verify()


class TestSerialization(unittest.TestCase):
    def test_to_dicts_round_trip(self):
        ledger = AuditLedger()
        append(ledger)
        append(ledger)
        dicts = ledger.to_dicts()
        self.assertTrue(ledger.verify())
        restored = AuditLedger.from_dicts(dicts)
        self.assertEqual(restored.to_dicts(), dicts)
        self.assertTrue(restored.verify())

    def test_from_dicts_rejects_tampered(self):
        ledger = AuditLedger()
        append(ledger)
        dicts = ledger.to_dicts()
        dicts[0]["event_hash"] = "0" * 64
        with self.assertRaises(AuditIntegrityError):
            AuditLedger.from_dicts(dicts)

    def test_clone(self):
        ledger = AuditLedger()
        append(ledger)
        clone = ledger.clone()
        append(ledger)
        self.assertEqual(len(clone), 1)
        self.assertEqual(len(ledger), 2)


if __name__ == "__main__":
    unittest.main()