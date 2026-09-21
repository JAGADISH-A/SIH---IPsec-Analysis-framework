"""Phase 8 — API adapter unit tests: mapping correctness + NO MUTATION proof."""

import copy
import json
import unittest

from tests.fixtures.risk.risk_fixtures import (
    build_identity,
    expected_from_plan_sample,
    plan_samples,
)

from correlation.api.adapters import (
    assessment_bundle,
    assessment_id_for,
    correlation_to_view,
    expected_to_view,
    identity_to_view,
    ml_to_view,
    observed_to_view,
    parse_assessment_id,
    risk_to_view,
    xai_to_view,
)
from correlation.models import MLResult
from correlation.risk import RiskEngine, RiskPolicy
from correlation.xai import ExplainabilityEngine


def sample_by_posture(posture):
    for sample in plan_samples():
        if sample["security_posture"] == posture:
            return sample
    raise AssertionError(f"no {posture} sample in plan")


class IdentityMappingTest(unittest.TestCase):
    def test_identity_fields_preserved(self):
        identity = build_identity(dataset_run_id="run-1", sequence=3,
                                  experiment_id="exp-3", attempt_number=2,
                                  window_index=1, window_start_ns=10, window_end_ns=20)
        view = identity_to_view(identity)
        self.assertEqual(view["dataset_run_id"], "run-1")
        self.assertEqual(view["sequence"], 3)
        self.assertEqual(view["experiment_id"], "exp-3")
        self.assertEqual(view["attempt_number"], 2)
        self.assertEqual(view["window_start_ns"], 10)
        self.assertEqual(view["window_end_ns"], 20)

    def test_window_none_preserved_as_none(self):
        identity = build_identity(window_index=None, window_start_ns=None, window_end_ns=None)
        view = identity_to_view(identity)
        self.assertIsNone(view["window_index"])
        self.assertIsNone(view["window_end_ns"])

    def test_assessment_id_round_trip(self):
        aid = assessment_id_for("run-1", 5, "worst-ml")
        self.assertEqual(aid, "run-1:5:worst-ml")
        parsed = parse_assessment_id(aid)
        self.assertEqual(parsed, ("run-1", 5, "worst-ml"))

    def test_parse_rejects_bad_ids(self):
        for bad in (None, "", "nope", "a:0:x", "a:x:y", "a:1", "a:1:2:3"):
            self.assertIsNone(parse_assessment_id(bad))


class ExpectedViewTest(unittest.TestCase):
    def test_configuration_card_shape(self):
        expected = expected_from_plan_sample(sample_by_posture("WEAK"))
        snap = copy.deepcopy(expected.to_dict())
        view = expected_to_view(expected)
        self.assertEqual(view["mode"], expected.mode)
        self.assertEqual(view["address_family"], expected.address_family)
        self.assertEqual(view["ike"]["version"], expected.ike.version)
        self.assertEqual(view["esp"]["encryption"], expected.esp.encryption)
        self.assertEqual(view["esp"]["integrity"], expected.esp.integrity)
        self.assertEqual(view["esp"]["pfs"], expected.esp.pfs)
        self.assertEqual(view["traffic"]["profile"], expected.traffic.profile)
        self.assertEqual(view["configuration_id"], expected.configuration_id)
        self.assertEqual(view["security_posture"], "WEAK")
        # no mutation
        self.assertEqual(expected.to_dict(), snap)

    def test_esp_integrity_none_preserved(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        self.assertEqual(expected.esp.integrity, None)
        self.assertIsNone(expected_to_view(expected)["esp"]["integrity"])


class ObservedViewTest(unittest.TestCase):
    def test_absent_observed(self):
        view = observed_to_view(None)
        self.assertFalse(view["present"])
        self.assertIn("no observed-state snapshot", view["reason"])

    def test_spi_values_preserved(self):
        from tests.fixtures.risk.risk_fixtures import build_observed
        observed = build_observed(spis=[])
        view = observed_to_view(observed)
        self.assertTrue(view["present"])
        self.assertEqual(view["spis"], [])
        self.assertEqual(view["endpoints"], {"a": "192.0.2.1", "b": "192.0.2.2"})
        self.assertEqual(view.get("last_ah_timestamp_ns"), None)

    def test_no_crypto_inferred(self):
        from tests.fixtures.risk.risk_fixtures import build_observed
        view = observed_to_view(build_observed())
        self.assertNotIn("encryption", view)
        self.assertNotIn("integrity", view)
        self.assertNotIn("ike_version", view)


class CorrelationViewTest(unittest.TestCase):
    def test_rows_preserve_statuses(self):
        from tests.fixtures.risk.risk_fixtures import run_comparison
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        correlation = run_comparison(expected)
        view = correlation_to_view(correlation)
        statuses = {row["status"] for row in view["rows"]}
        self.assertTrue(statuses <= {"MATCH", "MISMATCH", "UNKNOWN", "NOT_APPLICABLE"})
        self.assertEqual(view["status"], correlation.status)
        self.assertEqual(sum(view["status_counts"].values()), len(view["rows"]))
        self.assertEqual(view["rows"][0]["variable"], min(
            row["variable"] for row in view["rows"]))

    def test_unknown_row_preserved(self):
        from tests.fixtures.risk.risk_fixtures import run_comparison
        expected = expected_from_plan_sample(sample_by_posture("GOOD"))
        correlation = run_comparison(expected, observed_values=None)
        view = correlation_to_view(correlation)
        unknown = [row for row in view["rows"] if row["status"] == "UNKNOWN"]
        self.assertTrue(unknown)
        self.assertEqual(
            view["status_counts"]["UNKNOWN"], correlation_to_view(correlation)["status_counts"]["UNKNOWN"])
        unknown = [row for row in view["rows"] if row["status"] == "UNKNOWN"]
        self.assertTrue(unknown)


class MLViewTest(unittest.TestCase):
    def test_not_present(self):
        view = ml_to_view(None)
        self.assertFalse(view["present"])
        self.assertEqual(view["anomaly"], None)
        self.assertIsNone(view["model_version"])

    def test_fields_preserved(self):
        ml = MLResult(model_version="m1", traffic_class="video",
                      classification_confidence=0.91, anomaly=True, anomaly_score=0.9)
        view = ml_to_view(ml)
        self.assertTrue(view["present"])
        self.assertEqual(view["model_version"], "m1")
        self.assertEqual(view["traffic_class"], "video")
        self.assertEqual(view["classification_confidence"], 0.91)
        self.assertIs(view["anomaly"], True)
        self.assertEqual(view["anomaly_score"], 0.9)

    def test_anomaly_none_when_missing(self):
        view = ml_to_view(MLResult(model_version="m"))
        self.assertIsNone(view["anomaly"])


class RiskViewTest(unittest.TestCase):
    def _assessment(self):
        from tests.fixtures.risk.risk_fixtures import run_comparison
        expected = expected_from_plan_sample(sample_by_posture("WORST"))
        from tests.fixtures.risk.risk_fixtures import build_observed
        correlation = run_comparison(expected, observed=build_observed(),
                                     observed_values=None)
        return expected, correlation, RiskEngine(RiskPolicy.default()).assess(
            expected=expected, correlation=correlation)

    def test_score_severity_verbatim(self):
        expected, correlation, assessment = self._assessment()
        snap = copy.deepcopy(assessment.to_dict())
        view = risk_to_view(assessment)
        self.assertEqual(view["overall_score"], assessment.overall_score)
        self.assertEqual(view["severity"], assessment.severity)
        self.assertEqual(view["risk_policy_version"], assessment.risk_policy_version)
        self.assertEqual(view["findings"], [f.to_dict() for f in assessment.findings])
        self.assertEqual(assessment.to_dict(), snap)

    def test_finding_structured_fields(self):
        expected, correlation, assessment = self._assessment()
        view = risk_to_view(assessment)
        self.assertTrue(view["findings"])
        finding = view["findings"][0]
        for key in ("finding_id", "rule_id", "severity", "category", "title",
                    "reason", "condition", "source", "evidence_type"):
            self.assertIn(key, finding)
            self.assertIsInstance(finding[key], str)
        self.assertIn("related_variable", finding)
        self.assertIn("evidence_refs", finding)


class XAIViewTest(unittest.TestCase):
    def test_verbatim_passthrough(self):
        from tests.fixtures.risk.risk_fixtures import run_comparison
        expected = expected_from_plan_sample(sample_by_posture("WORST"))
        correlation = run_comparison(expected)
        assessment = RiskEngine(RiskPolicy.default()).assess(expected=expected, correlation=correlation)
        xai = ExplainabilityEngine().explain(assessment, correlation=correlation)
        view = xai_to_view(xai)
        self.assertEqual(view["score_explanation"]["score"], assessment.overall_score)
        self.assertEqual(view["metadata"], xai.metadata)
        self.assertEqual(len(view["finding_explanations"]), len(assessment.findings))


class NoMutationTests(unittest.TestCase):
    """The adapter must never change backend domain objects (data honesty)."""

    def test_bundle_inputs_untouched(self):
        from tests.fixtures.risk.risk_fixtures import run_comparison
        expected = expected_from_plan_sample(sample_by_posture("WORST"))
        correlation = run_comparison(expected)
        ml = MLResult(model_version="m", anomaly=True, anomaly_score=0.9)
        assessment = RiskEngine(RiskPolicy.default()).assess(
            expected=expected, correlation=correlation, ml_result=ml)
        xai = ExplainabilityEngine().explain(assessment, correlation=correlation, ml_result=ml)

        before = {
            "expected": json.dumps(expected.to_dict(), sort_keys=True),
            "correlation": json.dumps(correlation.to_dict(), sort_keys=True),
            "assessment": json.dumps(assessment.to_dict(), sort_keys=True),
            "xai": json.dumps(xai.to_dict(), sort_keys=True),
        }
        assessment_bundle(
            "run:1:worst-ml",
            identity=assessment.identity,
            expected=expected,
            observed=None,
            correlation=correlation,
            ml=ml,
            assessment=assessment,
            xai=xai,
            slot="worst-ml",
            scenario="demo",
            evidence=[],
        )
        after = {
            "expected": json.dumps(expected.to_dict(), sort_keys=True),
            "correlation": json.dumps(correlation.to_dict(), sort_keys=True),
            "assessment": json.dumps(assessment.to_dict(), sort_keys=True),
            "xai": json.dumps(xai.to_dict(), sort_keys=True),
        }
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()