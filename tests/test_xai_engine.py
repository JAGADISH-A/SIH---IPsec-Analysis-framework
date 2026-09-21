"""Phase 7 XAI engine end-to-end tests: real-fixture validation, determinism,
no-mutation, identity preservation, UNKNOWN/NOT_APPLICABLE, no fabrication."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fixtures", "risk"))

from risk_fixtures import (  # noqa: E402
    build_identity,
    expected_from_plan_sample,
    make_correlation,
    observed_values_for,
    plan_samples,
    run_comparison,
)

from correlation.models import (  # noqa: E402
    CORRELATION_STATUS_MATCH,
    CORRELATION_STATUS_MISMATCH,
    CORRELATION_STATUS_UNKNOWN,
    CorrelationIdentity,
    EvidenceRef,
    MLResult,
)
from correlation.risk import RiskAssessment, RiskEngine, RiskPolicy  # noqa: E402
from correlation.xai import (  # noqa: E402
    EXPLANATION_IDS,
    RULE_TO_XAI_IDS,
    XAI_TRACEABILITY,
    ExplainabilityEngine,
)

SAMPLES = plan_samples()
P6_RUN = "dataset-20260916-231246"
POLICY = "risk-policy-v1"

REF = EvidenceRef(
    pcap_path="results/datasets/dataset-20260916-231246/captures/1/x.pcap",
    capture_sequence=1,
    audit_event_reference="audit://tap-events.jsonl#100",
    source="training_pcap",
    timestamp="2026-09-16T23:12:46Z",
)


def sample_by_posture(posture):
    return next(s for s in SAMPLES if s["security_posture"] == posture)


def assess_and_explain(expected, *, correlation=None, ml_result=None, evidence_refs=()):
    if correlation is None:
        correlation = run_comparison(expected)
    engine = RiskEngine()
    assessment = engine.assess(
        expected=expected,
        correlation=correlation,
        ml_result=ml_result,
        evidence_refs=evidence_refs,
    )
    xai = ExplainabilityEngine().explain(
        assessment,
        correlation=correlation,
        ml_result=ml_result,
        evidence_refs=evidence_refs,
    )
    return assessment, xai


class TestScenarios(unittest.TestCase):
    def test_01_strong_no_findings(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        assessment, xai = assess_and_explain(expected)
        self.assertEqual(assessment.overall_score, 0)
        self.assertEqual(assessment.severity, "INFO")
        self.assertEqual(xai.score_explanation.score, assessment.overall_score)
        self.assertEqual(xai.score_explanation.severity, assessment.severity)
        self.assertEqual(len(xai.finding_explanations), 0)
        self.assertEqual(xai.summary.finding_explanations, 0)

    def test_02_weak_pfs_disabled(self):
        expected = expected_from_plan_sample(sample_by_posture("WEAK"))
        assessment, xai = assess_and_explain(expected)
        self.assertEqual(len(assessment.findings), 1)
        finding = assessment.findings[0]
        explanation = xai.finding_explanations[0]
        self.assertEqual(finding.finding_id, "RISK-PFS-DISABLED")
        self.assertEqual(explanation.finding_id, "RISK-PFS-DISABLED")
        self.assertIs(explanation.expected, finding.expected_value)
        self.assertEqual(explanation.reason, finding.reason)
        self.assertEqual(explanation.condition, finding.condition)
        self.assertIn("PFS", explanation.why_it_was_flagged)
        self.assertEqual(xai.score_explanation.score, 12)
        self.assertEqual(xai.score_explanation.severity, "MEDIUM")

    def test_03_confirmed_mode_mismatch(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        other = "transport" if expected.mode == "tunnel" else "tunnel"
        correlation = run_comparison(
            expected, observed_values=observed_values_for(expected, mode=other)
        )
        assessment, xai = assess_and_explain(expected, correlation=correlation)
        self.assertEqual(assessment.overall_score, 25)
        self.assertEqual(assessment.severity, "HIGH")
        explanation = xai.finding_explanations[0]
        self.assertEqual(explanation.finding_id, "RISK-MODE-MISMATCH")
        self.assertEqual(explanation.expected, "tunnel")
        self.assertEqual(explanation.observed, other)
        self.assertEqual(explanation.reason, correlation.mismatches[0]["reason"])
        self.assertEqual(xai.score_explanation.score, 25)
        self.assertEqual(xai.score_explanation.severity, "HIGH")

    def test_04_unknown_observation(self):
        expected = expected_from_plan_sample(sample_by_posture("GOOD"))
        correlation = run_comparison(expected, observed_values=None)
        assessment, xai = assess_and_explain(expected, correlation=correlation)
        self.assertEqual(assessment.overall_score, 0)
        self.assertEqual(len(assessment.findings), 0)
        self.assertEqual(correlation.status, CORRELATION_STATUS_UNKNOWN)
        self.assertGreaterEqual(len(xai.unknown_explanations), 1)
        for gap in xai.unknown_explanations:
            self.assertEqual(gap.status, "UNKNOWN")
            self.assertIn("unavailable", gap.explanation)
            self.assertIn("not treated as a vulnerability", gap.explanation)
        self.assertEqual(xai.metadata["input_summary"]["correlation_status"], "UNKNOWN")

    def test_05_ml_anomaly(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        ml = MLResult(model_version="traffic-rf-v1", anomaly=True, anomaly_score=0.9)
        assessment, xai = assess_and_explain(expected, ml_result=ml)
        self.assertEqual(len(assessment.findings), 1)
        self.assertEqual(assessment.findings[0].finding_id, "RISK-ML-ANOMALY")
        self.assertEqual(len(xai.ml_explanations), 1)
        ml_exp = xai.ml_explanations[0]
        self.assertEqual(ml_exp.explanation_kind, "anomaly")
        self.assertEqual(ml_exp.model_version, "traffic-rf-v1")
        self.assertIn("does not by itself establish", ml_exp.explanation)
        self.assertEqual(xai.score_explanation.severity, "LOW")
        self.assertEqual(xai.score_explanation.score, 6)

    def test_06_combined(self):
        expected = expected_from_plan_sample(sample_by_posture("WORST"))
        other = "transport" if expected.mode == "tunnel" else "tunnel"
        correlation = run_comparison(
            expected, observed_values=observed_values_for(expected, mode=other)
        )
        ml = MLResult(model_version="traffic-rf-v1", anomaly=True, anomaly_score=0.9)
        assessment, xai = assess_and_explain(
            expected, correlation=correlation, ml_result=ml
        )
        self.assertEqual(assessment.overall_score, 55)
        self.assertEqual(assessment.severity, "CRITICAL")
        ids = [f.finding_id for f in assessment.findings]
        self.assertEqual(
            sorted(ids),
            ["RISK-ML-ANOMALY", "RISK-MODE-MISMATCH", "RISK-PFS-DISABLED", "RISK-WEAK-ESP-CRYPTO"],
        )
        by_id = {e.finding_id: e for e in xai.finding_explanations}
        self.assertEqual(set(by_id), set(ids))
        self.assertEqual(xai.score_explanation.score, 55)
        self.assertEqual(xai.score_explanation.severity, "CRITICAL")
        self.assertEqual(
            xai.score_explanation.risk_policy_version, assessment.risk_policy_version
        )
        self.assertEqual(len(xai.ml_explanations), 1)


class TestPreservationAndSafety(unittest.TestCase):
    def test_score_severity_never_changed_across_all_bands(self):
        for sample in SAMPLES:
            expected = expected_from_plan_sample(sample)
            assessment, xai = assess_and_explain(expected)
            self.assertEqual(xai.score_explanation.score, assessment.overall_score)
            self.assertEqual(xai.score_explanation.severity, assessment.severity)
            self.assertEqual(xai.summary.overall_score, assessment.overall_score)
            self.assertEqual(xai.summary.severity, assessment.severity)

    def test_does_not_mutate_assessment(self):
        expected = expected_from_plan_sample(sample_by_posture("WORST"))
        before = expected_from_plan_sample(sample_by_posture("WORST"))
        correlation = run_comparison(expected, observed_values=observed_values_for(expected))
        engine = RiskEngine()
        assessment = engine.assess(expected=expected, correlation=correlation)
        snapshot = assessment.to_json(sort_keys=True)
        xai = ExplainabilityEngine().explain(assessment, correlation=correlation)
        self.assertEqual(assessment.to_json(sort_keys=True), snapshot)
        self.assertEqual(xai.score_explanation.score, assessment.overall_score)
        self.assertEqual(xai.score_explanation.severity, assessment.severity)

    def test_identity_preserved(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        assessment, xai = assess_and_explain(expected)
        self.assertEqual(xai.identity, assessment.identity)
        self.assertEqual(
            xai.identity.dataset_run_id, P6_RUN
        )

    def test_empty_findings_summary(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        assessment, xai = assess_and_explain(expected)
        self.assertIn("produced no security findings", xai.summary.overall_explanation)

    def test_multiple_findings_order_matches_assessment(self):
        expected = expected_from_plan_sample(sample_by_posture("WORST"))
        assessment, xai = assess_and_explain(expected)
        self.assertEqual(
            [f.finding_id for f in xai.finding_explanations],
            [f.finding_id for f in assessment.findings],
        )

    def test_expected_observed_preserved_per_finding(self):
        expected = expected_from_plan_sample(sample_by_posture("WORST"))
        other = "transport" if expected.mode == "tunnel" else "tunnel"
        correlation = run_comparison(
            expected, observed_values=observed_values_for(expected, mode=other)
        )
        assessment, xai = assess_and_explain(expected, correlation=correlation)
        by_id = {e.finding_id: e for e in xai.finding_explanations}
        for find in assessment.findings:
            exp = by_id[find.finding_id]
            self.assertEqual(exp.expected, find.expected_value)
            self.assertEqual(exp.observed, find.observed_value)
            self.assertEqual(exp.reason, find.reason)
            self.assertEqual(exp.severity, find.severity)
            self.assertEqual(exp.rule_id, find.rule_id)

    def test_evidence_preserved_exactly(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        correlation = run_comparison(
            expected,
            observed_values=observed_values_for(expected),
            evidence_refs=(REF,),
        )
        assessment, xai = assess_and_explain(
            expected, correlation=correlation, evidence_refs=(REF,)
        )
        self.assertEqual(xai.evidence_summary.total_refs, 1)
        self.assertEqual(list(xai.evidence_summary.refs), [REF.to_dict()])
        self.assertEqual(
            list(xai.evidence_summary.refs)[0]["pcap_path"], REF.pcap_path
        )
        self.assertTrue(all(e.evidence_refs for e in xai.finding_explanations))

    def test_no_evidence_never_fabricated(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        assessment, xai = assess_and_explain(expected)
        self.assertEqual(xai.evidence_summary.total_refs, 0)
        self.assertEqual(xai.evidence_summary.refs, ())
        self.assertIsNotNone(xai.evidence_summary.limitation)
        self.assertFalse(xai.evidence_summary.fabricated)

    def test_not_applicable_explanation(self):
        identity = build_identity()
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        correlation = make_correlation(
            identity,
            not_applicable=[
                {
                    "variable": "capture_filter",
                    "status": "NOT_APPLICABLE",
                    "reason": "capture filter is not a semantic comparison target",
                }
            ],
        )
        assessment, xai = assess_and_explain(expected, correlation=correlation)
        self.assertGreaterEqual(len(xai.not_applicable_explanations), 1)
        gap = xai.not_applicable_explanations[0]
        self.assertEqual(gap.status, "NOT_APPLICABLE")
        self.assertEqual(gap.variable, "capture_filter")
        self.assertIn("not applicable", gap.explanation.lower())

    def test_unknown_never_becomes_mismatch(self):
        expected = expected_from_plan_sample(sample_by_posture("GOOD"))
        correlation = run_comparison(expected, observed_values=None)
        assessment, xai = assess_and_explain(expected, correlation=correlation)
        self.assertEqual(correlation.status, CORRELATION_STATUS_UNKNOWN)
        for gap in xai.unknown_explanations:
            self.assertNotEqual(gap.status, "MISMATCH")
            # the text only explains that a match/mismatch could NOT be
            # established; it never claims a mismatch was recorded
            self.assertIn("could not establish a match or mismatch", gap.explanation)

    def test_match_status_preserved(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        correlation = run_comparison(
            expected,
            observed_values=observed_values_for(expected),
            live_features=None,
        )
        assessment, xai = assess_and_explain(expected, correlation=correlation)
        self.assertEqual(
            xai.metadata["input_summary"]["correlation_status"],
            CORRELATION_STATUS_MATCH,
        )


class TestDeterminism(unittest.TestCase):
    def test_two_runs_identical(self):
        expected = expected_from_plan_sample(sample_by_posture("WORST"))
        other = "transport" if expected.mode == "tunnel" else "tunnel"
        correlation = run_comparison(
            expected, observed_values=observed_values_for(expected, mode=other)
        )
        ml = MLResult(model_version="m", anomaly=True, anomaly_score=0.9)
        assessment, xai = assess_and_explain(
            expected, correlation=correlation, ml_result=ml
        )
        second = ExplainabilityEngine().explain(
            assessment, correlation=correlation, ml_result=ml
        )
        self.assertEqual(
            xai.to_json(sort_keys=True),
            second.to_json(sort_keys=True),
        )

    def test_deterministic_serialization(self):
        expected = expected_from_plan_sample(sample_by_posture("WORST"))
        assessment, xai = assess_and_explain(expected)
        first = json.dumps(xai.to_dict(), sort_keys=True)
        second = json.dumps(xai.to_dict(), sort_keys=True)
        self.assertEqual(first, second)


class TestTraceability(unittest.TestCase):
    def test_registry_keys_present(self):
        required = {
            "explanation_id",
            "source_field",
            "input_model",
            "output_field",
            "logic",
            "limitations",
        }
        for explanation_id, meta in XAI_TRACEABILITY.items():
            self.assertEqual(meta["explanation_id"], explanation_id)
            self.assertTrue(required.issubset(set(meta.keys())), meta)
            self.assertEqual(meta["explanation_id"], explanation_id)

    def test_ids_sorted(self):
        self.assertEqual(EXPLANATION_IDS, tuple(sorted(XAI_TRACEABILITY.keys())))

    def test_rules_mapped_to_xai(self):
        # every Phase-6 rule that can produce a finding maps to an explanation
        for rule in ("esp.pfs.disabled", "esp.encryption.cbc", "esp.dh_group.weak",
                     "correlation.mismatch", "ml.anomaly",
                     "ml.classification.disagreement", "evidence.insufficient"):
            self.assertIn(rule, RULE_TO_XAI_IDS, rule)
            self.assertGreaterEqual(len(RULE_TO_XAI_IDS[rule]), 1)


class TestEngineValidation(unittest.TestCase):
    def test_rejects_non_assessment(self):
        with self.assertRaises(TypeError):
            ExplainabilityEngine().explain(assessment="not an assessment")

    def test_rejects_non_correlation(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        assessment = RiskEngine().assess(expected=expected, correlation=run_comparison(expected))
        with self.assertRaises(TypeError):
            ExplainabilityEngine().explain(assessment, correlation="nope")


if __name__ == "__main__":
    unittest.main()