"""Phase 7 XAI explainer tests: finding + ML explanation builders."""

import unittest

from correlation.models import EvidenceRef, MLResult
from correlation.risk import (
    CATEGORY_CONFIGURATION_MISMATCH,
    CATEGORY_CONFIGURATION_WEAKNESS,
    CATEGORY_INSUFFICIENT_EVIDENCE,
    CATEGORY_ML_CLASSIFICATION_DISAGREEMENT,
    CATEGORY_ML_TRAFFIC_ANOMALY,
    CATEGORY_OBSERVED_MISMATCH,
    CATEGORY_PROTOCOL_ANOMALY,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SOURCE_CORRELATION,
    SOURCE_EXPECTED_CONFIGURATION,
    SOURCE_ML,
    RiskFinding,
)
from correlation.xai import (
    EXPLANATION_CATEGORY_CONFIGURATION,
    EXPLANATION_CATEGORY_CORRELATION,
    EXPLANATION_CATEGORY_LIMITATION,
    EXPLANATION_CATEGORY_ML,
    PROVENANCE_ML_RESULT,
    PROVENANCE_RISK_FINDING,
    explain_finding,
    explain_ml_anomaly,
    explain_ml_classification,
    explain_ml_result,
)

REF = EvidenceRef(
    pcap_path="results/datasets/dataset-20260916-231246/captures/1/x.pcap",
    capture_sequence=1,
    audit_event_reference="audit://tap-events.jsonl#100",
    source="training_pcap",
    timestamp="2026-09-16T23:12:46Z",
)


def finding(**overrides):
    base = dict(
        finding_id="F",
        rule_id="r",
        category=CATEGORY_CONFIGURATION_WEAKNESS,
        severity=SEVERITY_LOW,
        title="t",
        description="d",
        reason="reason",
        condition="cond",
        source=SOURCE_EXPECTED_CONFIGURATION,
        evidence_type="configuration",
    )
    base.update(overrides)
    return RiskFinding(**base)


class TestFindingExplanations(unittest.TestCase):
    def test_pfs_disabled(self):
        f = finding(
            finding_id="RISK-PFS-DISABLED",
            rule_id="esp.pfs.disabled",
            category=CATEGORY_CONFIGURATION_WEAKNESS,
            severity="MEDIUM",
            related_variable="esp.pfs",
            expected_value=False,
            observed_value=None,
        )
        exp = explain_finding(f)
        self.assertEqual(exp.provenance, PROVENANCE_RISK_FINDING)
        self.assertEqual(exp.finding_id, "RISK-PFS-DISABLED")
        self.assertEqual(exp.expected, False)
        self.assertIsNone(exp.observed)
        self.assertIn("PFS", exp.why_it_was_flagged)
        self.assertIn("disabled", exp.why_it_was_flagged.lower())
        self.assertIn("esp.pfs.disabled", exp.why_it_was_flagged)
        self.assertIn("expected configuration deficiency", exp.contributing_factors)
        self.assertIn(
            "The conclusion is based on configuration evidence only.",
            exp.limitations,
        )
        self.assertIn(EXPLANATION_CATEGORY_CONFIGURATION, exp.explanation_categories)
        self.assertIn(EXPLANATION_CATEGORY_LIMITATION, exp.explanation_categories)

    def test_cbc(self):
        f = finding(
            finding_id="RISK-WEAK-ESP-CRYPTO",
            rule_id="esp.encryption.cbc",
            category=CATEGORY_CONFIGURATION_WEAKNESS,
            severity="MEDIUM",
            related_variable="esp.encryption",
            expected_value="aes256cbc",
            observed_value=None,
        )
        exp = explain_finding(f)
        self.assertIn("CBC", exp.why_it_was_flagged)
        self.assertIn("aes256cbc", exp.why_it_was_flagged)

    def test_dh_group_weak(self):
        f = finding(
            finding_id="RISK-WEAK-DH-GROUP",
            rule_id="esp.dh_group.weak",
            category=CATEGORY_CONFIGURATION_WEAKNESS,
            severity=SEVERITY_LOW,
            related_variable="esp.dh_group",
            expected_value="modp2048",
        )
        exp = explain_finding(f)
        self.assertIn("modp2048", exp.why_it_was_flagged)

    def test_mode_mismatch(self):
        f = finding(
            finding_id="RISK-MODE-MISMATCH",
            rule_id="correlation.mismatch.mode",
            category=CATEGORY_CONFIGURATION_MISMATCH,
            severity=SEVERITY_HIGH,
            related_variable="mode",
            expected_value="tunnel",
            observed_value="transport",
            source=SOURCE_CORRELATION,
            evidence_type="observation",
            reason="authoritative observed mode contradicts expected",
        )
        exp = explain_finding(f)
        self.assertEqual(exp.severity, SEVERITY_HIGH)
        self.assertEqual(exp.expected, "tunnel")
        self.assertEqual(exp.observed, "transport")
        self.assertEqual(exp.reason, "authoritative observed mode contradicts expected")
        self.assertIn("mode", exp.why_it_was_flagged)
        self.assertIn("tunnel", exp.why_it_was_flagged)
        self.assertIn("transport", exp.why_it_was_flagged)
        self.assertIn("authoritative comparison outcome", exp.contributing_factors)
        self.assertIn(EXPLANATION_CATEGORY_CORRELATION, exp.explanation_categories)

    def test_esp_presence_absent_is_high(self):
        f = finding(
            finding_id="RISK-ESP-MISMATCH",
            rule_id="correlation.mismatch.esp.presence",
            category=CATEGORY_OBSERVED_MISMATCH,
            severity=SEVERITY_HIGH,
            related_variable="esp.presence",
            expected_value=True,
            observed_value=False,
            source=SOURCE_CORRELATION,
        )
        exp = explain_finding(f)
        self.assertEqual(exp.severity, SEVERITY_HIGH)
        self.assertIn("was not observed", exp.why_it_was_flagged)

    def test_esp_presence_unexpected_is_low(self):
        f = finding(
            finding_id="RISK-ESP-MISMATCH",
            rule_id="correlation.mismatch.esp.presence",
            category=CATEGORY_OBSERVED_MISMATCH,
            severity=SEVERITY_LOW,
            related_variable="esp.presence",
            expected_value=False,
            observed_value=True,
            source=SOURCE_CORRELATION,
        )
        exp = explain_finding(f)
        self.assertEqual(exp.severity, SEVERITY_LOW)
        self.assertIn("was not expected", exp.why_it_was_flagged)

    def test_ah_anomaly(self):
        f = finding(
            finding_id="RISK-AH-UNEXPECTED",
            rule_id="correlation.mismatch.ah.presence",
            category=CATEGORY_PROTOCOL_ANOMALY,
            severity="MEDIUM",
            related_variable="ah.presence",
            expected_value=False,
            observed_value=True,
            source=SOURCE_CORRELATION,
        )
        exp = explain_finding(f)
        self.assertIn("AH", exp.why_it_was_flagged)
        self.assertIn(EXPLANATION_CATEGORY_CORRELATION, exp.explanation_categories)

    def test_ml_anomaly_finding(self):
        f = finding(
            finding_id="RISK-ML-ANOMALY",
            rule_id="ml.anomaly",
            category=CATEGORY_ML_TRAFFIC_ANOMALY,
            severity=SEVERITY_LOW,
            related_variable="ML_ANOMALY",
            expected_value=None,
            observed_value=True,
            source=SOURCE_ML,
            evidence_type="ml",
            model_version="traffic-rf-v1",
            reason="ML anomaly flag=True with score=0.9 from model_version='traffic-rf-v1'.",
            evidence_refs=(REF,),
        )
        exp = explain_finding(f)
        self.assertEqual(exp.model_version, "traffic-rf-v1")
        self.assertEqual(exp.evidence_refs, (REF.to_dict(),))
        self.assertIn("does not by itself establish", exp.why_it_was_flagged)
        self.assertIn("anomal", exp.why_it_was_flagged)
        self.assertIn("model-derived evidence only", " ".join(e.lower() for e in exp.limitations))
        self.assertIn(EXPLANATION_CATEGORY_ML, exp.explanation_categories)
        self.assertIn(EXPLANATION_CATEGORY_LIMITATION, exp.explanation_categories)

    def test_ml_classification_disagreement_finding(self):
        f = finding(
            finding_id="RISK-ML-CLASSIFICATION",
            rule_id="ml.classification.disagreement",
            category=CATEGORY_ML_CLASSIFICATION_DISAGREEMENT,
            severity=SEVERITY_LOW,
            related_variable="ML_TRAFFIC_CLASSIFICATION",
            expected_value="messaging",
            observed_value="video",
            confidence=0.91,
            source=SOURCE_ML,
            evidence_type="ml",
            model_version="model-v1",
        )
        exp = explain_finding(f)
        self.assertEqual(exp.confidence, 0.91)
        self.assertEqual(exp.model_version, "model-v1")
        self.assertEqual(exp.expected, "messaging")
        self.assertEqual(exp.observed, "video")
        self.assertIn("0.91", exp.why_it_was_flagged)
        self.assertIn("model classification confidence 0.91", " ".join(exp.contributing_factors))
        self.assertIn(EXPLANATION_CATEGORY_ML, exp.explanation_categories)

    def test_insufficient_evidence(self):
        f = finding(
            finding_id="RISK-INSUFFICIENT-EVIDENCE-mode",
            rule_id="evidence.insufficient",
            category=CATEGORY_INSUFFICIENT_EVIDENCE,
            severity=SEVERITY_INFO,
            related_variable="mode",
            expected_value="tunnel",
            observed_value=None,
            source=SOURCE_CORRELATION,
            evidence_type="correlation",
        )
        exp = explain_finding(f)
        self.assertIn("NOT a vulnerability", exp.why_it_was_flagged)
        self.assertEqual(exp.severity, SEVERITY_INFO)

    def test_generic_fallback_for_unknown_rule(self):
        f = finding(
            finding_id="F",
            rule_id="future.rule.not.yet.templated",
            category=CATEGORY_OBSERVED_MISMATCH,
            severity=SEVERITY_LOW,
            related_variable="some.field",
            expected_value="a",
            observed_value="b",
            source=SOURCE_CORRELATION,
            evidence_type="observation",
        )
        exp = explain_finding(f)
        self.assertIn("some.field", exp.why_it_was_flagged)
        self.assertIn("a", exp.why_it_was_flagged)
        self.assertIn("b", exp.why_it_was_flagged)


class TestMlExplainers(unittest.TestCase):
    def test_classification_returns_none_without_class(self):
        ml = MLResult(model_version="m", anomaly=True)
        self.assertIsNone(explain_ml_classification(ml))

    def test_classification_text(self):
        ml = MLResult(
            model_version="model-v1",
            traffic_class="video",
            classification_confidence=0.91,
        )
        exp = explain_ml_classification(ml)
        self.assertIsNotNone(exp)
        self.assertEqual(exp.provenance, PROVENANCE_ML_RESULT)
        self.assertEqual(exp.traffic_class, "video")
        self.assertEqual(exp.classification_confidence, 0.91)
        self.assertEqual(exp.model_version, "model-v1")
        self.assertIn("video", exp.explanation)
        self.assertIn("0.91", exp.explanation)
        self.assertIn("model_version=model-v1", exp.explanation)
        self.assertIn(EXPLANATION_CATEGORY_ML, exp.explanation_categories)
        self.assertNotIn("malicious", exp.explanation.lower())

    def test_anomaly_true(self):
        ml = MLResult(model_version="m", anomaly=True, anomaly_score=0.9)
        exp = explain_ml_anomaly(ml)
        self.assertIs(exp.anomaly, True)
        self.assertEqual(exp.anomaly_score, 0.9)
        self.assertIn("does not by itself establish", exp.explanation)
        self.assertIn("0.9", exp.explanation)
        self.assertIn(EXPLANATION_CATEGORY_LIMITATION, exp.explanation_categories)

    def test_anomaly_false(self):
        ml = MLResult(model_version="m", anomaly=False, anomaly_score=0.01)
        exp = explain_ml_anomaly(ml)
        self.assertIs(exp.anomaly, False)
        self.assertIn("did not mark", exp.explanation)

    def test_anomaly_none(self):
        ml = MLResult(model_version="m")
        self.assertIsNone(explain_ml_anomaly(ml))

    def test_ml_result_ordering(self):
        ml = MLResult(
            model_version="m",
            traffic_class="video",
            classification_confidence=0.9,
            anomaly=True,
            anomaly_score=0.8,
        )
        classification = explain_ml_classification(ml)
        anomaly = explain_ml_anomaly(ml)
        items = explain_ml_result(ml)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].explanation_kind, "classification")
        self.assertEqual(items[1].explanation_kind, "anomaly")
        self.assertEqual(items[0].to_dict(), classification.to_dict())
        self.assertEqual(items[1].to_dict(), anomaly.to_dict())

    def test_ml_result_empty(self):
        self.assertEqual(explain_ml_result(MLResult(model_version="m")), ())


if __name__ == "__main__":
    unittest.main()