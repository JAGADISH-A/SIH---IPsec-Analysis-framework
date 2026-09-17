"""Audit event store for the IPsec testbed (append-only JSONL).

The audit layer records normalized, schema-versioned observation events
from the passive TAP layer -- TAP state, per-packet IPsec metadata extracted
by TShark, and (optionally) Zeek events -- into a single append-only JSONL
file.  Every record is version-tagged so the schema can evolve without
breaking existing logs, and each append is flushed + ``fsync``'d using the
same durability convention as the dataset staging log in
``dataset_artifacts.py``.

The consumption flow this layer supports is::

    TShark / Zeek
          |
          v
    normalized audit event (dict)
          |
          v
    record_event(event)   # this module
          |
          v
    results/audit/events.jsonl   (append-only JSONL)
"""

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

AUDIT_EVENTS_SCHEMA_VERSION = "v1"

# Canonical event types emitted by the observation layer.
EVENT_OBSERVATION_SESSION_START = "observation_session_start"
EVENT_OBSERVATION_SESSION_END = "observation_session_end"
EVENT_TAP_STATE = "tap_state"
EVENT_ESP_PACKET = "ipsec_esp_observation"
EVENT_IKE_PACKET = "ipsec_ike_observation"
EVENT_ZEEK = "zeek_event"

DEFAULT_AUDIT_DIR = Path(__file__).resolve().parent.parent / "results" / "audit"
DEFAULT_EVENTS_FILENAME = "events.jsonl"


def utcnow_iso():
    """Current UTC time as ISO-8601 (matches dataset_artifacts convention)."""
    return datetime.now(timezone.utc).isoformat()


def default_events_path():
    return DEFAULT_AUDIT_DIR / DEFAULT_EVENTS_FILENAME


def record_event(event, path=None):
    """Append one normalized audit event to the JSONL log (durable).

    ``event`` must be a dict carrying ``event_type`` and ``observed_at``
    (required).  The schema version tag, a unique ``event_id`` and
    ``recorded_at`` are filled in when absent, and the serialized record is
    written with a single line per event followed by ``flush`` + ``fsync``.

    Returns the record actually persisted (including the generated fields).
    """
    if not isinstance(event, dict):
        raise TypeError("audit event must be a JSON object")
    for field in ("event_type", "observed_at"):
        if field not in event:
            raise ValueError(f"audit event missing required field: {field}")
    record = dict(event)
    record.setdefault("audit_schema_version", AUDIT_EVENTS_SCHEMA_VERSION)
    record.setdefault("event_id", str(uuid.uuid4()))
    record.setdefault("recorded_at", utcnow_iso())
    dest = Path(path) if path is not None else default_events_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return record


def read_events(path=None):
    """Return every audit event from the log, in append order.

    Raises ValueError on any corrupt (non-JSON) line so a truncated audit log
    can never silently pass validation.
    """
    dest = Path(path) if path is not None else default_events_path()
    if not dest.exists():
        return []
    events = []
    for number, line in enumerate(dest.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"corrupt audit event (line {number}): {exc}")
        if not isinstance(record, dict):
            raise ValueError(
                f"corrupt audit event (line {number}): not a JSON object"
            )
        events.append(record)
    return events