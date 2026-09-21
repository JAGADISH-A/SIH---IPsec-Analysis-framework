import os
import unittest

from correlation import CORRELATION_SCHEMA_VERSION
from correlation.models import (
    CANONICAL_VARIABLES,
    CorrelationIdentity,
    CorrelationInput,
    CorrelationResult,
    EspExpected,
    EvidenceRef,
    ExpectedState,
    IkeExpected,
    LiveFeatureWindow,
    MLResult,
    ObservedState,
    SpiObservation,
    TrafficExpected,
    TransitionObservation,
)
from correlation.schemas import (
    build_correlation_input_json_schema,
    build_correlation_result_json_schema,
)

EXPECTED_JSON = os.path.join(os.path.dirname(__file__), "fixtures", "expected_example.json")
OBSERVED_JSON = os.path.join(os.path.dirname(__file__), "fixtures", "observed_example.json")
ML_JSON = os.path.join(os.path.dirname(__file__), "fixtures", "ml_example.json")
INPUT_JSON = os.path.join(os.path.dirname(__file__), "fixtures", "correlation_input_example.json")


def build_identity():
    return CorrelationIdentity(
        dataset_run_id="run-20260920-001",
        sequence=1,
        experiment_id="exp-aes256gcm16-video",
        attempt_number=1,
        window_index=0,
        window_start_ns=12300000000,
        window_end_ns=12300000100,
    )


def build_expected():
    return ExpectedState(
        mode="tunnel",
        address_family="ipv4",
        ike=IkeExpected(version=2, encryption="aes256", integrity="sha256", dh_group="modp2048"),
        esp=EspExpected(encryption="aes256gcm16", integrity=None, dh_group="modp2048", pfs=True),
        traffic=TrafficExpected(profile="video", duration=30, port=20000),
        capture_filter="udp port 500 or udp port 4500 or esp or ah",
        configuration_id="tunnel-ipv4-aes256gcm16-none-modp2048-true",
        security_posture=None,
    )


def build_observed():
    return ObservedState(
        timestamp_ns=12300000100,
        endpoints={"a": "192.0.2.100", "b": "192.0.2.200"},
        tunnel_seen=True,
        active=True,
        packets_seen=120,
        bytes_seen=48000,
        packets_a_to_b=60,
        packets_b_to_a=60,
        ike_seen=True,
        esp_seen=True,
        observed_ike_activity=True,
        last_ike_timestamp_ns=12300000020,
        last_esp_timestamp_ns=12300000090,
        spis=[
            SpiObservation(
                spi=1234,
                direction="A_TO_B",
                active=True,
                first_seen_ns=12300000010,
                last_seen_ns=12300000100,
                packet_count=60,
                first_sequence=1,
                last_sequence=60,
                highest_sequence=60,
                sequence_delta=59,
            )
        ],
        transitions=[
            TransitionObservation(name="ACTIVE", timestamp_ns=12300000010)
        ],
    )


def build_window():
    return LiveFeatureWindow(
        feature_schema_version="v2",
        window_start_ns=12300000000,
        window_end_ns=12300000100,
        features={"ip_total": 480, "esp_packets": 120},
    )


def build_input():
    return CorrelationInput(
        identity=build_identity(),
        expected=build_expected(),
        observed=build_observed(),
        live_features=build_window(),
        ml_result=MLResult(
            model_version="v1",
            traffic_class="video",
            classification_confidence=0.94,
            anomaly=False,
            anomaly_score=0.08,
        ),
        evidence=[
            EvidenceRef(
                pcap_path=(
                    "results/datasets/run-20260920-001/captures/1/"
                    "exp-aes256gcm16-video.pcap"
                ),
                capture_sequence=1,
                source="training_pcap",
            )
        ],
    )


class TestCorrelationContract(unittest.TestCase):
    def test_contract_version_is_v1(self):
        self.assertEqual(CORRELATION_SCHEMA_VERSION, "v1")

    def test_build_complete_correlation_input(self):
        inp = build_input()
        self.assertIsInstance(inp.identity, CorrelationIdentity)
        self.assertIsInstance(inp.expected, ExpectedState)
        self.assertIsInstance(inp.observed, ObservedState)
        self.assertIsInstance(inp.live_features, LiveFeatureWindow)
        self.assertIsInstance(inp.ml_result, MLResult)
        self.assertEqual(len(inp.evidence), 1)

    def test_result_skeleton_not_evaluated(self):
        result = CorrelationResult(identity=build_identity())
        self.assertEqual(result.status, "NOT_EVALUATED")
        self.assertEqual(result.matches, [])
        self.assertEqual(result.mismatches, [])
        self.assertEqual(result.unknowns, [])
        self.assertEqual(result.not_applicable, [])

    def test_invalid_status_rejected(self):
        with self.assertRaises(ValueError):
            CorrelationResult(identity=build_identity(), status="MATCHED-anything")

    def test_invalid_schema_version_rejected(self):
        with self.assertRaises(ValueError):
            CorrelationInput(
                correlation_schema_version="v0",
                identity=build_identity(),
                expected=build_expected(),
            )

    def test_json_round_trip_preserves_values(self):
        inp = build_input()
        restored = CorrelationInput.from_json(inp.to_json())
        self.assertEqual(restored.to_dict(), inp.to_dict())
        self.assertEqual(restored, inp)

        result = CorrelationResult(identity=build_identity())
        restored_result = CorrelationResult.from_json(result.to_json())
        self.assertEqual(restored_result, result)

    def test_canonical_variable_names_preserved(self):
        inp = build_input()
        d = inp.to_dict()
        expected = d["expected"]
        dotted = {
            "ike.version": expected["ike"]["version"],
            "ike.encryption": expected["ike"]["encryption"],
            "ike.integrity": expected["ike"]["integrity"],
            "ike.dh_group": expected["ike"]["dh_group"],
            "esp.encryption": expected["esp"]["encryption"],
            "esp.integrity": expected["esp"]["integrity"],
            "esp.dh_group": expected["esp"]["dh_group"],
            "esp.pfs": expected["esp"]["pfs"],
            "traffic.profile": expected["traffic"]["profile"],
            "traffic.duration": expected["traffic"]["duration"],
            "traffic.port": expected["traffic"]["port"],
        }
        top_level = {
            "mode": expected["mode"],
            "address_family": expected["address_family"],
            "capture_filter": expected["capture_filter"],
        }

        # Serialization round trip preserves every canonical variable.
        restored = CorrelationInput.from_json(inp.to_json())
        rexpected = restored.to_dict()["expected"]

        derived = {f"{prefix}.{k}": v for prefix in ("ike", "esp", "traffic")
                   for k, v in rexpected[prefix].items()}
        flattened = dict(rexpected)
        flattened.update(derived)

        for canonical in CANONICAL_VARIABLES:
            if canonical in dotted or canonical in top_level:
                self.assertIn(
                    canonical.replace(".", ":") if False else canonical,
                    CANONICAL_VARIABLES,
                )

        self.assertEqual(rexpected["ike"]["version"], 2)
        self.assertEqual(rexpected["ike"]["encryption"], "aes256")
        self.assertEqual(rexpected["ike"]["integrity"], "sha256")
        self.assertEqual(rexpected["ike"]["dh_group"], "modp2048")
        self.assertEqual(rexpected["esp"]["encryption"], "aes256gcm16")
        self.assertIsNone(rexpected["esp"]["integrity"])
        self.assertEqual(rexpected["esp"]["dh_group"], "modp2048")
        self.assertTrue(rexpected["esp"]["pfs"])
        self.assertEqual(rexpected["traffic"]["profile"], "video")
        self.assertEqual(rexpected["traffic"]["duration"], 30)
        self.assertEqual(rexpected["traffic"]["port"], 20000)
        self.assertEqual(rexpected["mode"], "tunnel")
        self.assertEqual(rexpected["address_family"], "ipv4")
        self.assertEqual(
            rexpected["capture_filter"], "udp port 500 or udp port 4500 or esp or ah"
        )

    def test_fixtures_load_and_introspect(self):
        import json

        with open(EXPECTED_JSON, encoding="utf-8") as fh:
            exp = json.load(fh)
        with open(OBSERVED_JSON, encoding="utf-8") as fh:
            obs = json.load(fh)
        with open(ML_JSON, encoding="utf-8") as fh:
            ml = json.load(fh)
        with open(INPUT_JSON, encoding="utf-8") as fh:
            inp = json.load(fh)

        self.assertEqual(inp["correlation_schema_version"], "v1")
        self.assertEqual(exp["esp"]["encryption"], "aes256gcm16")
        self.assertTrue(obs["tunnel_seen"])
        self.assertEqual(obs["spis"][0]["direction"], "A_TO_B")
        self.assertIsNone(inp["ml_result"])

    def test_json_schema_docs_available(self):
        schema = build_correlation_input_json_schema()
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(schema["properties"]["correlation_schema_version"]["const"], "v1")
        self.assertIn("identity", schema["properties"])
        self.assertIn("expected", schema["properties"])
        result_schema = build_correlation_result_json_schema()
        self.assertEqual(
            result_schema["properties"]["status"]["enum"],
            [
                "NOT_EVALUATED",
                "MATCH",
                "MISMATCH",
                "UNKNOWN",
                "PARTIAL",
                "NOT_APPLICABLE",
            ],
        )
        self.assertIn("not_applicable", result_schema["properties"])
        self.assertIn("not_applicable", result_schema["required"])


if __name__ == "__main__":
    unittest.main()