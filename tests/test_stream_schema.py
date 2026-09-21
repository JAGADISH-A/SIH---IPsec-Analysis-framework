"""Phase 10 — stream schema / identity / partitioning contract tests."""

import json
import unittest

from correlation.streaming.models import (
    EVENT_TYPES,
    EVENT_TYPE_AUDIT,
    EVENT_TYPE_CORRELATION,
    EVENT_TYPE_EVIDENCE,
    EVENT_TYPE_FEATURE_WINDOW,
    EVENT_TYPE_PACKET,
    STREAM_SCHEMA_VERSION,
    StreamEvent,
    make_payload_event,
)
from correlation.streaming.partitioning import partition_for, partition_key
from correlation.streaming.schema import (
    default_event_type_to_topic,
    deserialize_jsonl,
    roundtrip_identity,
    schema_contract,
    serialize_jsonl,
    topic_for_event_type,
    validate_event,
)
from correlation.models import CorrelationIdentity


def event(**overrides) -> StreamEvent:
    base = dict(
        dataset_run_id="dataset-20260916-231246",
        sequence=7,
        experiment_id="exp-phase10",
        attempt_number=1,
        event_type=EVENT_TYPE_PACKET,
        window_index=3,
        window_start_ns=300_000_000,
        window_end_ns=400_000_000,
        source="live_xdp",
        created_at=400_000_000,
        payload={"proto": 17, "length": 74},
    )
    base.update(overrides)
    return StreamEvent(**base)


class TestEventVocabulary(unittest.TestCase):
    def test_fourteen_explicit_event_types(self):
        required = {
            "ipsec.packet", "ipsec.ike", "ipsec.state", "feature.window",
            "ml.result", "correlation.result", "risk.assessment",
            "xai.explanation", "response.recommendation", "response.approval",
            "response.authorization", "response.execution", "audit.event",
            "evidence.reference",
        }
        self.assertEqual(set(EVENT_TYPES), required)

    def test_schema_version_is_fixed(self):
        self.assertEqual(event(schema_version="stream-schema-v1").schema_version,
                         "stream-schema-v1")
        with self.assertRaises(ValueError):
            event(schema_version="stream-schema-v0")


class TestEventConstruction(unittest.TestCase):
    def test_requires_identity_spine(self):
        with self.assertRaises(ValueError):
            StreamEvent(
                dataset_run_id="", sequence=1, experiment_id="x",
                attempt_number=1, event_type=EVENT_TYPE_PACKET,
            )
        with self.assertRaises(ValueError):
            StreamEvent(
                dataset_run_id="run", sequence=0, experiment_id="x",
                attempt_number=1, event_type=EVENT_TYPE_PACKET,
            )
        with self.assertRaises(ValueError):
            StreamEvent(
                dataset_run_id="run", sequence=1, experiment_id="x",
                attempt_number=0, event_type=EVENT_TYPE_PACKET,
            )

    def test_window_fields_validated(self):
        with self.assertRaises(ValueError):
            event(window_end_ns=100_000_000, window_start_ns=200_000_000)
        with self.assertRaises(ValueError):
            event(window_end_ns=100_000_000, window_index=2)

    def test_correlation_identity_roundtrip(self):
        e = event()
        identity = e.correlation_identity()
        self.assertEqual(identity.dataset_run_id, e.dataset_run_id)
        self.assertEqual(identity.attempt_number, e.attempt_number)
        restored = StreamEvent.from_identity(identity, e.event_type, payload=e.payload)
        self.assertEqual(restored.dataset_run_id, e.dataset_run_id)


class TestDeterministicSerialization(unittest.TestCase):
    def test_canonical_is_deterministic_sorted(self):
        e = event(payload={"z": 1, "a": 2})
        blob = json.loads(e.canonical())
        self.assertEqual(blob["payload"], {"a": 2, "z": 1})
        self.assertEqual(e.canonical(), e.canonical())
        self.assertEqual(e.canonical(), e.to_jsonl().rstrip("\n"))

    def test_event_identity_is_sha256(self):
        e = event()
        self.assertEqual(len(e.event_identity), 64)
        self.assertTrue(e.event_identity.isalnum())
        self.assertNotEqual(e.event_identity, event(payload={"p": 1}).event_identity)

    def test_attempt_isolation_changes_identity(self):
        e1 = event(attempt_number=1)
        e2 = event(attempt_number=2)
        self.assertNotEqual(e1.event_identity, e2.event_identity)

    def test_jsonl_roundtrip(self):
        events = [event(sequence=i, payload={"i": i}) for i in range(1, 4)]
        lines = serialize_jsonl(events)
        restored = deserialize_jsonl(lines.splitlines())
        self.assertEqual([e.to_dict() for e in restored],
                         [e.to_dict() for e in events])
        self.assertEqual(StreamEvent.from_jsonl(lines.splitlines()[0]), events[0])

    def test_make_payload_event(self):
        identity = event().correlation_identity()
        e = make_payload_event(identity, EVENT_TYPE_PACKET, {"p": 1},
                               source="s", created_at=5)
        self.assertEqual(e.payload, {"p": 1})


class TestSchemaContract(unittest.TestCase):
    def test_contract_marks_v1_forbidden(self):
        contract = schema_contract()
        self.assertEqual(contract["schema_version"], "stream-schema-v1")
        self.assertTrue(contract["feature_contract"]["no_v1_feature_columns"])
        self.assertEqual(contract["pickle"], "forbidden")

    def test_validate_event_rejects_bad_type(self):
        with self.assertRaises(ValueError):
            event(event_type="not.a.real.type")
        with self.assertRaises(ValueError):
            StreamEvent(
                dataset_run_id="r", sequence=1, experiment_id="x",
                attempt_number=1, event_type="bogus",
            )

    def test_validate_event_ok(self):
        e = event()
        validate_event(e)

    def test_roundtrip_identity_has_no_payload(self):
        e = event()
        out = roundtrip_identity(e)
        self.assertNotIn("payload", out)
        self.assertEqual(out["event_type"], e.event_type)


class TestTopicMapping(unittest.TestCase):
    def test_default_mapping_covers_all_event_types(self):
        mapping = default_event_type_to_topic()
        self.assertEqual(set(mapping), set(EVENT_TYPES))
        self.assertEqual(mapping[EVENT_TYPE_PACKET], "ipsec.raw")
        self.assertEqual(mapping[EVENT_TYPE_CORRELATION], "ipsec.correlation")
        self.assertEqual(mapping[EVENT_TYPE_AUDIT], "ipsec.audit")
        self.assertEqual(mapping[EVENT_TYPE_EVIDENCE], "ipsec.evidence")
        self.assertEqual(mapping[EVENT_TYPE_FEATURE_WINDOW], "ipsec.features")

    def test_topic_for_event_type(self):
        self.assertEqual(topic_for_event_type(EVENT_TYPE_PACKET),
                         "ipsec.raw")
        with self.assertRaises(ValueError):
            topic_for_event_type("bogus")


class TestPartitioning(unittest.TestCase):
    def test_partition_key_stable_and_attempt_isolated(self):
        e = event()
        self.assertEqual(partition_key(e), partition_key(e))
        self.assertEqual(
            partition_key(e),
            "dataset-20260916-231246|exp-phase10|1",
        )
        self.assertNotEqual(partition_key(e), partition_key(event(attempt_number=2)))

    def test_partition_for_deterministic_in_range(self):
        e = event()
        for partitions in (1, 8, 64):
            p = partition_for(e, partitions)
            self.assertIn(p, range(partitions))
            self.assertEqual(p, partition_for(e, partitions))

    def test_partition_requires_positive_count(self):
        with self.assertRaises(ValueError):
            partition_for(event(), 0)


if __name__ == "__main__":
    unittest.main()