"""Unit tests for the audit event store (controller/audit.py)."""

import json
import tempfile
import unittest
from pathlib import Path

from controller import audit as audit_mod


class TestRecordEvent(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.events_path = Path(self._tmp.name) / "audit" / "events.jsonl"

    def test_append_is_durable_jsonl(self):
        event = {
            "event_type": audit_mod.EVENT_TAP_STATE,
            "observed_at": "2026-09-17T00:00:00+00:00",
            "source": {"container": "clab-ipsec-gw-a"},
            "data": {"tap_present": "yes"},
        }
        first = audit_mod.record_event(event, path=self.events_path)
        second = audit_mod.record_event(
            dict(event, data={"tap_present": "no"}), path=self.events_path,
        )
        lines = self.events_path.read_text().splitlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            self.assertTrue(line.strip())
            json.loads(line)  # strict JSONL, one object per line
        self.assertEqual(first["event_id"] != second["event_id"], True)
        self.assertEqual(
            first["audit_schema_version"], audit_mod.AUDIT_EVENTS_SCHEMA_VERSION
        )
        self.assertIn("recorded_at", first)

    def test_requires_required_fields(self):
        with self.assertRaises(ValueError):
            audit_mod.record_event({"data": {}}, path=self.events_path)
        with self.assertRaises(TypeError):
            audit_mod.record_event([], path=self.events_path)

    def test_read_events_roundtrip(self):
        audit_mod.record_event({
            "event_type": audit_mod.EVENT_ESP_PACKET,
            "observed_at": "2026-09-17T00:00:01+00:00",
            "data": {"spi": "0xc8d12d4a", "sequence": 1},
        }, path=self.events_path)
        audit_mod.record_event({
            "event_type": audit_mod.EVENT_IKE_PACKET,
            "observed_at": "2026-09-17T00:00:02+00:00",
            "data": {"ike_exchange_type": 34},
        }, path=self.events_path)
        events = audit_mod.read_events(self.events_path)
        self.assertEqual([e["event_type"] for e in events],
                         [audit_mod.EVENT_ESP_PACKET, audit_mod.EVENT_IKE_PACKET])
        self.assertEqual(events[0]["data"]["spi"], "0xc8d12d4a")

    def test_read_events_empty_and_corrupt(self):
        self.assertEqual(audit_mod.read_events(self.events_path), [])
        if not self.events_path.exists():
            self.events_path.parent.mkdir(parents=True)
        self.events_path.write_text("{not json}\n")
        with self.assertRaises(ValueError):
            audit_mod.read_events(self.events_path)


if __name__ == "__main__":
    unittest.main()