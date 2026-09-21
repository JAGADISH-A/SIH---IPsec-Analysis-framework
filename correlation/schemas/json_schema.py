"""JSON Schema (draft 2020-12) documentation for the correlation contract.

These schemas are DOCUMENTATION of the canonical serialized form. They mirror
the dataclass constraints (which remain the actual enforcement point);
runtime validation is performed by the models, not by a JSON-Schema engine.
The authoritative 59-feature schema is intentionally NOT expanded (referenced
via ``description`` only) to avoid drift.
"""

from ..models import SPI_DIRECTIONS
from ..version import CORRELATION_SCHEMA_VERSION

JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_VERSION = "2020-12"


def _definitions():
    return {
        "identity": {
            "type": "object",
            "title": "CorrelationIdentity",
            "description": "Identity spine: dataset_run_id -> sequence -> "
            "experiment_id -> attempt_number -> window.",
            "properties": {
                "dataset_run_id": {"type": "string", "minLength": 1},
                "sequence": {"type": "integer", "minimum": 1},
                "experiment_id": {"type": "string", "minLength": 1},
                "attempt_number": {"type": "integer", "minimum": 1},
                "window_index": {"type": ["integer", "null"], "minimum": 0},
                "window_start_ns": {"type": ["integer", "null"], "minimum": 0},
                "window_end_ns": {"type": ["integer", "null"], "minimum": 0},
            },
            "required": [
                "dataset_run_id",
                "sequence",
                "experiment_id",
                "attempt_number",
            ],
        },
        "ike": {
            "type": "object",
            "description": "ike.version/encryption/integrity/dh_group "
            "(not directly observable; AUDIT_ONLY).",
            "properties": {
                "version": {"type": ["integer", "null"], "enum": [1, 2, None]},
                "encryption": {"type": "string"},
                "integrity": {"type": "string"},
                "dh_group": {"type": "string"},
            },
            "required": ["version", "encryption", "integrity", "dh_group"],
        },
        "esp": {
            "type": "object",
            "description": "esp.encryption/integrity/dh_group/pfs.",
            "properties": {
                "encryption": {"type": "string"},
                "integrity": {"type": ["string", "null"]},
                "dh_group": {"type": "string"},
                "pfs": {"type": "boolean"},
            },
            "required": ["encryption", "integrity", "dh_group", "pfs"],
        },
        "traffic": {
            "type": "object",
            "description": "traffic.profile/duration/port.",
            "properties": {
                "profile": {"type": "string"},
                "duration": {"type": "integer"},
                "port": {"type": "integer"},
            },
            "required": ["profile", "duration", "port"],
        },
        "expected": {
            "type": "object",
            "description": "Expected testbed state. configuration_id and "
            "security_posture are DERIVED metadata.",
            "properties": {
                "mode": {"type": "string", "enum": ["tunnel", "transport"]},
                "address_family": {"type": "string", "enum": ["ipv4", "ipv6"]},
                "ike": {"$ref": "#/$defs/ike"},
                "esp": {"$ref": "#/$defs/esp"},
                "traffic": {"$ref": "#/$defs/traffic"},
                "capture_filter": {"type": "string", "minLength": 1},
                "configuration_id": {"type": ["string", "null"]},
                "security_posture": {"type": ["string", "null"]},
            },
            "required": [
                "mode",
                "address_family",
                "ike",
                "esp",
                "traffic",
                "capture_filter",
            ],
        },
        "spi": {
            "type": "object",
            "description": "Per-SPI state-builder observation. No crypto fields.",
            "properties": {
                "spi": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                "direction": {"type": ["string", "null"], "enum": list(SPI_DIRECTIONS) + [None]},
                "active": {"type": "boolean"},
                "first_seen_ns": {"type": "integer", "minimum": 0},
                "last_seen_ns": {"type": "integer", "minimum": 0},
                "packet_count": {"type": "integer", "minimum": 0},
                "first_sequence": {"type": ["integer", "null"]},
                "last_sequence": {"type": ["integer", "null"]},
                "highest_sequence": {"type": ["integer", "null"]},
                "sequence_delta": {"type": ["integer", "null"]},
            },
            "required": ["spi"],
        },
        "transition": {
            "type": "object",
            "description": "State-engine transition.",
            "properties": {
                "name": {"type": "string"},
                "timestamp_ns": {"type": "integer", "minimum": 0},
                "details": {"type": "object"},
            },
            "required": ["name", "timestamp_ns"],
        },
        "observed": {
            "type": "object",
            "description": "Observed IPsec state (IPsecStateBuilder.snapshot "
            "contract). Crypto is NOT inferred/represented.",
            "properties": {
                "timestamp_ns": {"type": "integer", "minimum": 0},
                "endpoints": {"type": "object"},
                "tunnel_seen": {"type": "boolean"},
                "active": {"type": "boolean"},
                "packets_seen": {"type": "integer", "minimum": 0},
                "bytes_seen": {"type": "integer", "minimum": 0},
                "packets_a_to_b": {"type": "integer", "minimum": 0},
                "packets_b_to_a": {"type": "integer", "minimum": 0},
                "bytes_a_to_b": {"type": "integer", "minimum": 0},
                "bytes_b_to_a": {"type": "integer", "minimum": 0},
                "ike_seen": {"type": "boolean"},
                "ike_nat_t_seen": {"type": "boolean"},
                "esp_seen": {"type": "boolean"},
                "ah_seen": {"type": "boolean"},
                "observed_ike_activity": {"type": "boolean"},
                "last_ike_timestamp_ns": {"type": ["integer", "null"], "minimum": 0},
                "last_ike_nat_t_timestamp_ns": {"type": ["integer", "null"], "minimum": 0},
                "last_esp_timestamp_ns": {"type": ["integer", "null"], "minimum": 0},
                "last_ah_timestamp_ns": {"type": ["integer", "null"], "minimum": 0},
                "spis": {"type": "array", "items": {"$ref": "#/$defs/spi"}},
                "transitions": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/transition"},
                },
            },
            "required": ["timestamp_ns"],
        },
        "live_features": {
            "type": "object",
            "description": "Live v2 feature window. The 59-feature schema is "
            "NOT enumerated here; authority: sihipsec controller/dataset_artifacts.py.",
            "properties": {
                "feature_schema_version": {"type": "string", "const": "v2"},
                "window_start_ns": {"type": "integer", "minimum": 0},
                "window_end_ns": {"type": "integer", "minimum": 0},
                "features": {"type": "object"},
            },
            "required": [
                "feature_schema_version",
                "window_start_ns",
                "window_end_ns",
                "features",
            ],
        },
        "ml_result": {
            "type": "object",
            "description": "ML result CONTRACT ONLY. Fields extensible via "
            "'extras'; ML is NOT implemented in this phase.",
            "properties": {
                "model_version": {"type": ["string", "null"]},
                "traffic_class": {"type": ["string", "null"]},
                "classification_confidence": {
                    "type": ["number", "null"],
                    "minimum": 0.0,
                    "maximum": 1.0,
                },
                "anomaly": {"type": ["boolean", "null"]},
                "anomaly_score": {"type": ["number", "null"], "minimum": 0.0},
                "extras": {"type": "object"},
            },
        },
        "evidence": {
            "type": "object",
            "description": "Evidence reference. Does not require file existence.",
            "properties": {
                "pcap_path": {"type": ["string", "null"]},
                "capture_sequence": {"type": ["integer", "null"], "minimum": 1},
                "audit_event_reference": {"type": ["string", "null"]},
                "source": {"type": ["string", "null"]},
                "timestamp": {"type": ["string", "null"]},
            },
        },
        "correlation_result": {
            "type": "object",
            "description": "Expected-vs-observed comparison result (Phase 4). "
            "status is one of MATCH / MISMATCH / UNKNOWN / NOT_APPLICABLE / "
            "PARTIAL / NOT_EVALUATED; comparison rules in correlation/comparison/.",
            "properties": {
                "correlation_schema_version": {
                    "type": "string",
                    "const": CORRELATION_SCHEMA_VERSION,
                },
                "identity": {"$ref": "#/$defs/identity"},
                "status": {
                    "type": "string",
                    "enum": [
                        "NOT_EVALUATED",
                        "MATCH",
                        "MISMATCH",
                        "UNKNOWN",
                        "PARTIAL",
                        "NOT_APPLICABLE",
                    ],
                },
                "matches": {"type": "array"},
                "mismatches": {"type": "array"},
                "unknowns": {"type": "array"},
                "not_applicable": {"type": "array"},
                "metadata": {"type": "object"},
            },
            "required": [
                "correlation_schema_version",
                "identity",
                "status",
                "matches",
                "mismatches",
                "unknowns",
                "not_applicable",
            ],
        },
    }


def _with_schema_version(defs, root_title):
    return {
        "$schema": JSON_SCHEMA_DIALECT,
        "$id": f"sihipsec-correlation-{CORRELATION_SCHEMA_VERSION}",
        "title": root_title,
        "description": f"correlation_schema_version = {CORRELATION_SCHEMA_VERSION}",
        "type": "object",
        "properties": {
            "correlation_schema_version": {
                "type": "string",
                "const": CORRELATION_SCHEMA_VERSION,
            },
            "identity": {"$ref": "#/$defs/identity"},
            "expected": {"$ref": "#/$defs/expected"},
            "observed": {"oneOf": [{"$ref": "#/$defs/observed"}, {"type": "null"}]},
            "live_features": {
                "oneOf": [{"$ref": "#/$defs/live_features"}, {"type": "null"}],
            },
            "ml_result": {"oneOf": [{"$ref": "#/$defs/ml_result"}, {"type": "null"}]},
            "evidence": {"type": "array", "items": {"$ref": "#/$defs/evidence"}},
        },
        "required": [
            "correlation_schema_version",
            "identity",
            "expected",
        ],
        "$defs": defs,
    }


def build_correlation_input_json_schema() -> dict:
    """JSON Schema for the canonical ``CorrelationInput`` serialization."""
    defs = _definitions()
    return _with_schema_version(defs, "CorrelationInput")


def build_correlation_result_json_schema() -> dict:
    """JSON Schema for the ``CorrelationResult`` skeleton."""
    return _definitions()["correlation_result"]


def json_schemas() -> dict:
    return {
        "correlation_input": build_correlation_input_json_schema(),
        "correlation_result": build_correlation_result_json_schema(),
        "definitions": _definitions(),
    }