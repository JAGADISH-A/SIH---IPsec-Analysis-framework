"""Phase 7 XAI model tests: vocabularies, validation, JSON round-trips."""

import unittest

from correlation.models import CorrelationIdentity, EvidenceRef
from correlation.risk import (
    CATEGORY_CONFIGURATION_WEAKNESS,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SOURCE_EXPECTED_CONFIGURATION,
    RiskAssessment,
    RiskFinding,
)
from correlation.xai import (
    XAI_SCHEMA_VERSION,
    EXPLANATION_CATEGORY_CONFIGURATION,
    EXPLANATION_CATEGORY_LIMITATION,
    EXPLANATION_CATEGORY_ML,
    EXPLANATION_CATEGORY_SCORE,
    EvidenceSummary,
    ExplainabilityResult,
    ExplainabilitySummary,
    FindingExplanation,
    GapExplanation,
    MLExplanation,
    ScoreExplanation,
)


def make_finding(**overrides):
    base = dict(
        finding_id="RISK-PFS-DISABLED",
        rule_id="esp.pfs.disabled",
        category=CATEGORY_CONFIGURATION_WEAKNESS,
        severity=SEVERITY_HIGH,
        title="t",
        description="d",
        reason="reason",
        condition="cond",
        source=SOURCE_EXPECTED_CONFIGURATION,
        evidence_type="configuration",
        related_variable="esp.pfs",
    )
    base.update(overrides)
    return RiskFinding(**base)


def make_identity():
    return CorrelationIdentity(
        dataset_run_id="dataset-20260916-231246",
        sequence=3,
        experiment_id="exp-xai",
        attempt_number=1,
        window_index=0,
        window_start_ns=1_000_000_000,
        window_end_ns=60_000_000_000,
    )


class TestExplanationCategories(unittest.TestCase):
    def test_vocabulary_exists(self):
        from correlation.xai import EXPLANATION_CATEGORIES

        for expected in (
            "CONFIGURATION_EXPLANATION",
            "OBSERVATION_EXPLANATION",
            "CORRELATION_EXPLANATION",
            "ML_EXPLANATION",
            "EVIDENCE_EXPLANATION",
            "SCORE_EXPLANATION",
            "LIMITATION",
        ):
            self.assertIn(expected, EXPLANATION_CATEGORIES)

    def test_schema_version(self):
        self.assertEqual(XAI_SCHEMA_VERSION, "v1")

    def test_invalid_category_rejected(self):
        with self.assertRaises(ValueError):
            FindingExplanation(
                provenance="RISK_FINDING",
                finding_id="F",
                rule_id="r",
                title="t",
                severity="HIGH",
                category="CONFIGURATION_WEAKNESS",
                why_it_was_flagged="why",
                source="EXPECTED_CONFIGURATION",
                evidence_type="configuration",
                explanation_categories=("NOT_A_CATEGORY",),
            )


class TestFindingExplanationRoundTrip(unittest.TestCase):
    def build(self):
        return FindingExplanation(
            finding_id="RISK-PFS-DISABLED",
            rule_id="esp.pfs.disabled",
            title="PFS disabled",
            severity="MEDIUM",
            category="CONFIGURATION_WEAKNESS",
            related_variable="esp.pfs",
            why_it_was_flagged="why",
            expected=False,
            observed=None,
            condition="esp.pfs == False",
            reason="r",
            source="EXPECTED_CONFIGURATION",
            evidence_type="configuration",
            confidence=None,
            model_version=None,
            contributing_factors=("expected configuration deficiency",),
            explanation_categories=(
                EXPLANATION_CATEGORY_CONFIGURATION,
                EXPLANATION_CATEGORY_LIMITATION,
            ),
            limitations=("The conclusion is based on configuration evidence only.",),
        )

    def test_round_trip(self):
        exp = self.build()
        data = exp.to_dict()
        restored = FindingExplanation.from_dict(data)
        self.assertEqual(exp.to_dict(), restored.to_dict())

    def test_expected_observed_none_preserved(self):
        exp = self.build()
        data = exp.to_dict()
        self.assertIsNone(data["observed"])
        self.assertIs(exp.observed, None)


class TestMLExplanationRoundTrip(unittest.TestCase):
    def test_round_trip(self):
        exp = MLExplanation(
            explanation_kind="classification",
            model_version="model-v1",
            traffic_class="video",
            classification_confidence=0.91,
            explanation="The ML model classified the observed traffic as video.",
            explanation_categories=(EXPLANATION_CATEGORY_ML,),
            limitations=("Model-derived evidence only.",),
        )
        data = exp.to_dict()
        self.assertEqual(data["classification_confidence"], 0.91)
        restored = MLExplanation.from_dict(data)
        self.assertEqual(exp.to_dict(), restored.to_dict())

    def test_anomaly_fields(self):
        exp = MLExplanation(
            explanation_kind="anomaly",
            model_version="m",
            anomaly=True,
            anomaly_score=0.9,
            explanation="x",
            explanation_categories=(EXPLANATION_CATEGORY_ML,),
        )
        data = exp.to_dict()
        self.assertIs(data["anomaly"], True)
        self.assertEqual(data["anomaly_score"], 0.9)


class TestGapExplanation(unittest.TestCase):
    def test_unknown_allowed(self):
        GapExplanation(status="UNKNOWN", variable="esp.encryption", explanation="e")

    def test_not_applicable_allowed(self):
        GapExplanation(
            status="NOT_APPLICABLE", variable="capture_filter", explanation="e"
        )

    def test_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            GapExplanation(status="MISMATCH", variable="mode", explanation="e")


class TestEvidenceSummary(unittest.TestCase):
    def test_round_trip(self):
        ref = EvidenceRef(
            pcap_path="results/datasets/dataset-20260916-231246/captures/1/x.pcap",
            capture_sequence=1,
            audit_event_reference="audit://tap-events.jsonl#100",
            source="training_pcap",
            timestamp="2026-09-16T23:12:46Z",
        )
        summary = EvidenceSummary(
            total_refs=1,
            refs=(ref.to_dict(),),
            sources=("training_pcap",),
            source_counts=(("training_pcap", 1),),
            limitation=None,
            fabricated=False,
        )
        data = summary.to_dict()
        self.assertEqual(data["total_refs"], 1)
        restored = EvidenceSummary.from_dict(data)
        self.assertEqual(summary.to_dict(), restored.to_dict())
        self.assertIs(restored.fabricated, False)

    def test_cannot_fabricate(self):
        with self.assertRaises(ValueError):
            EvidenceSummary(
                total_refs=0,
                refs=(),
                limitation=None,
                fabricated=True,
            )


class TestScoreExplanation(unittest.TestCase):
    def test_round_trip(self):
        exp = ScoreExplanation(
            score=55,
            severity="CRITICAL",
            severity_band=("CRITICAL", 40, 100),
            risk_policy_version="risk-policy-v1",
            raw_sum=55,
            contributions=(
                {"finding_id": "RISK-MODE-MISMATCH", "weight": 25, "added": 25},
            ),
            per_category_totals=(("CONFIGURATION_MISMATCH", 25),),
            explanation="The Phase-6 risk assessment produced a score of 55.",
            score_unchanged=True,
            severity_unchanged=True,
        )
        data = exp.to_dict()
        self.assertEqual(data["severity_band"], ["CRITICAL", 40, 100])
        restored = ScoreExplanation.from_dict(data)
        self.assertEqual(exp.to_dict(), restored.to_dict())

    def test_cannot_mutate(self):
        with self.assertRaises(ValueError):
            ScoreExplanation(
                score=55,
                severity="CRITICAL",
                risk_policy_version="risk-policy-v1",
                explanation="x",
                score_unchanged=False,
            )


class TestSummaryAndResult(unittest.TestCase):
    def test_summary_round_trip(self):
        exp = ExplainabilitySummary(
            overall_score=12,
            severity="MEDIUM",
            risk_policy_version="risk-policy-v1",
            finding_explanations=1,
            ml_explanations=0,
            unknown_explanations=2,
            not_applicable_explanations=1,
            evidence_refs=0,
            overall_explanation="overall",
        )
        data = exp.to_dict()
        restored = ExplainabilitySummary.from_dict(data)
        self.assertEqual(exp.to_dict(), restored.to_dict())

    def test_result_round_trip(self):
        finding = FindingExplanation(
            finding_id="RISK-PFS-DISABLED",
            rule_id="esp.pfs.disabled",
            title="PFS disabled",
            severity="MEDIUM",
            category="CONFIGURATION_WEAKNESS",
            why_it_was_flagged="why",
            source="EXPECTED_CONFIGURATION",
            evidence_type="configuration",
            explanation_categories=(EXPLANATION_CATEGORY_CONFIGURATION,),
        )
        score = ScoreExplanation(
            score=12,
            severity="MEDIUM",
            risk_policy_version="risk-policy-v1",
            explanation="x",
        )
        result = ExplainabilityResult(
            schema_version=XAI_SCHEMA_VERSION,
            identity=make_identity(),
            summary=ExplainabilitySummary(
                overall_score=12,
                severity="MEDIUM",
                risk_policy_version="risk-policy-v1",
                finding_explanations=1,
                overall_explanation="o",
            ),
            finding_explanations=(finding,),
            evidence_summary=EvidenceSummary(total_refs=0, refs=()),
            score_explanation=score,
            metadata={"deterministic": True},
        )
        data = result.to_dict()
        self.assertEqual(data["schema_version"], "v1")
        self.assertEqual(data["identity"]["dataset_run_id"], "dataset-20260916-231246")
        restored = ExplainabilityResult.from_dict(data)
        self.assertEqual(result.to_dict(), restored.to_dict())

    def test_result_identity_preserved(self):
        identity = make_identity()
        result = ExplainabilityResult(
            schema_version=XAI_SCHEMA_VERSION,
            identity=identity,
            summary=None,
        )
        self.assertEqual(result.identity, identity)

    def test_result_rejects_bad_nested(self):
        with self.assertRaises(ValueError):
            ExplainabilityResult(
                schema_version=XAI_SCHEMA_VERSION,
                finding_explanations=(make_finding(),),  # not a FindingExplanation
            )


class TestScoreExplanationCrossCheck(unittest.TestCase):
    def test_contribution_field_shape(self):
        exp = ScoreExplanation(
            score=25,
            severity="HIGH",
            risk_policy_version="risk-policy-v1",
            explanation="x",
        )
        self.assertEqual(exp.contributions, ())


if __name__ == "__main__":
    unittest.main()