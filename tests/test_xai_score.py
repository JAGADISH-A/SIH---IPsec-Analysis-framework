"""Phase 7 XAI score-explanation tests: consumed, never recomputed."""

import unittest

from correlation.models import CorrelationIdentity
from correlation.risk import (
    CATEGORY_CONFIGURATION_MISMATCH,
    CATEGORY_ML_TRAFFIC_ANOMALY,
    RiskAssessment,
    RiskFinding,
    RISK_SOURCES,
    SEVERITY_CRITICAL,
)
from correlation.risk.models import RISK_ENGINE_VERSION, RISK_SCHEMA_VERSION
from correlation.xai import build_score_explanation

POLICY = "risk-policy-v1"


def make_finding(**overrides):
    base = dict(
        finding_id="RISK-MODE-MISMATCH",
        rule_id="correlation.mismatch.mode",
        category=CATEGORY_CONFIGURATION_MISMATCH,
        severity="HIGH",
        title="t",
        description="d",
        reason="reason",
        condition="cond",
        source="CORRELATION",
        evidence_type="observation",
        related_variable="mode",
        expected_value="tunnel",
        observed_value="transport",
    )
    base.update(overrides)
    return RiskFinding(**base)


def make_identity():
    return CorrelationIdentity(
        dataset_run_id="dataset-20260916-231246",
        sequence=5,
        experiment_id="exp-score",
        attempt_number=1,
        window_index=0,
        window_start_ns=1_000_000_000,
        window_end_ns=60_000_000_000,
    )


def make_assessment(score, severity, findings, metadata=None):
    return RiskAssessment(
        schema_version=RISK_SCHEMA_VERSION,
        risk_engine_version=RISK_ENGINE_VERSION,
        risk_policy_version=POLICY,
        identity=make_identity(),
        overall_score=score,
        severity=severity,
        findings=tuple(findings),
        metadata=metadata or {},
    )


SCORE_DETAIL = {
    "score": 55,
    "severity": "CRITICAL",
    "severity_band": ["CRITICAL", 40, 100],
    "raw_sum": 55,
    "contributions": [
        {"finding_id": "RISK-MODE-MISMATCH", "rule_id": "correlation.mismatch.mode",
         "category": "CONFIGURATION_MISMATCH", "severity": "HIGH", "weight": 25, "added": 25},
        {"finding_id": "RISK-ML-ANOMALY", "rule_id": "ml.anomaly",
         "category": "ML_TRAFFIC_ANOMALY", "severity": "LOW", "weight": 6, "added": 6},
    ],
    "per_category_totals": [["CONFIGURATION_MISMATCH", 25], ["ML_TRAFFIC_ANOMALY", 6]],
}


class TestScoreExplanation(unittest.TestCase):
    def test_consumes_score_severity_policy(self):
        findings = (
            make_finding(),
            make_finding(
                finding_id="RISK-ML-ANOMALY",
                rule_id="ml.anomaly",
                category=CATEGORY_ML_TRAFFIC_ANOMALY,
                severity="LOW",
                source="ML",
                evidence_type="ml",
                related_variable="ML_ANOMALY",
                observed_value=True,
            ),
        )
        assessment = make_assessment(
            55, "CRITICAL", findings,
            metadata={"score_detail": dict(SCORE_DETAIL), "ml": {"ml_present": True}},
        )
        exp = build_score_explanation(assessment)
        self.assertEqual(exp.score, 55)
        self.assertEqual(exp.severity, SEVERITY_CRITICAL)
        self.assertEqual(exp.risk_policy_version, POLICY)
        self.assertTrue(exp.score_unchanged)
        self.assertTrue(exp.severity_unchanged)
        self.assertEqual(exp.provenance, "RISK_ASSESSMENT")

    def test_contributions_preserved(self):
        assessment = make_assessment(
            55, "CRITICAL", (make_finding(),),
            metadata={"score_detail": dict(SCORE_DETAIL)},
        )
        exp = build_score_explanation(assessment)
        self.assertEqual(len(exp.contributions), 2)
        self.assertEqual(exp.contributions[0]["finding_id"], "RISK-MODE-MISMATCH")
        self.assertEqual(exp.contributions[0]["added"], 25)
        self.assertEqual(exp.contributions[1]["rule_id"], "ml.anomaly")

    def test_band_and_raw_sum(self):
        assessment = make_assessment(
            55, "CRITICAL", (make_finding(),),
            metadata={"score_detail": dict(SCORE_DETAIL)},
        )
        exp = build_score_explanation(assessment)
        self.assertEqual(exp.severity_band, ("CRITICAL", 40, 100))
        self.assertEqual(exp.raw_sum, 55)
        self.assertIn(("CONFIGURATION_MISMATCH", 25), exp.per_category_totals)

    def test_single_high_finding(self):
        assessment = make_assessment(
            25, "HIGH", (make_finding(),),
            metadata={"score_detail": {
                "score": 25, "severity": "HIGH", "severity_band": ["HIGH", 20, 39],
                "raw_sum": 25,
                "contributions": [
                    {"finding_id": "RISK-MODE-MISMATCH", "rule_id": "correlation.mismatch.mode",
                     "category": "CONFIGURATION_MISMATCH", "severity": "HIGH",
                     "weight": 25, "added": 25}],
                "per_category_totals": [["CONFIGURATION_MISMATCH", 25]],
            }},
        )
        exp = build_score_explanation(assessment)
        self.assertEqual(exp.score, 25)
        self.assertEqual(exp.severity, "HIGH")
        self.assertEqual(exp.severity_band, ("HIGH", 20, 39))
        self.assertEqual(exp.contributions, (
            {"finding_id": "RISK-MODE-MISMATCH", "rule_id": "correlation.mismatch.mode",
             "category": "CONFIGURATION_MISMATCH", "severity": "HIGH",
             "weight": 25, "added": 25},
        ))

    def test_no_score_detail(self):
        assessment = make_assessment(12, "MEDIUM", (make_finding(),), metadata={})
        exp = build_score_explanation(assessment)
        self.assertEqual(exp.score, 12)
        self.assertEqual(exp.severity, "MEDIUM")
        self.assertIsNone(exp.severity_band)
        self.assertEqual(exp.contributions, ())
        self.assertIsNone(exp.raw_sum)
        self.assertIn("does not recompute or modify", exp.explanation)

    def test_score_unchanged_flag_even_for_critical(self):
        assessment = make_assessment(
            55, "CRITICAL", (make_finding(),),
            metadata={"score_detail": dict(SCORE_DETAIL)},
        )
        exp = build_score_explanation(assessment)
        self.assertTrue(exp.score_unchanged)
        self.assertTrue(exp.severity_unchanged)

    def test_ml_note_present(self):
        assessment = make_assessment(
            55, "CRITICAL", (make_finding(),),
            metadata={"score_detail": dict(SCORE_DETAIL), "ml": {"ml_present": True}},
        )
        exp = build_score_explanation(assessment)
        self.assertIn("model-derived evidence", exp.explanation)

    def test_does_not_recompute_low(self):
        assessment = make_assessment(0, "INFO", (), metadata={})
        exp = build_score_explanation(assessment)
        self.assertEqual(exp.score, 0)
        self.assertEqual(exp.severity, "INFO")

    def test_round_trip(self):
        assessment = make_assessment(
            55, "CRITICAL", (make_finding(),),
            metadata={"score_detail": dict(SCORE_DETAIL)},
        )
        exp = build_score_explanation(assessment)
        restored = exp.__class__.from_dict(exp.to_dict())
        self.assertEqual(exp.to_dict(), restored.to_dict())


if __name__ == "__main__":
    unittest.main()