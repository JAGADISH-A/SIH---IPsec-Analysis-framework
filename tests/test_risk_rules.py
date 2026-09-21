"""Phase 6 rule-level tests: configuration, correlation, ML, evidence rules.

Covers the Phase 6 brief section 4 discipline (not every MISMATCH is HIGH),
sections 11-16 (authoritative crypto semantics, posture context, ML evidence,
UNKNOWN discipline), and the finding/source/evidence contracts.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fixtures", "risk"))

from risk_fixtures import (  # noqa: E402
    build_identity,
    build_observed,
    complete_window,
    expected_from_plan_sample,
    make_correlation,
    observed_values_for,
    plan_samples,
    run_comparison,
)

from correlation.risk import (  # noqa: E402
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
    SEVERITY_MEDIUM,
    SOURCE_CORRELATION,
    SOURCE_EXPECTED_CONFIGURATION,
    SOURCE_ML,
    RiskEngine,
    RiskFinding,
    RiskPolicy,
)

from correlation.models import MLResult  # noqa: E402


def findings_for(
    expected,
    *,
    observed=None,
    correlation=None,
    ml_result=None,
    evidence_refs=(),
    policy=None,
):
    engine = RiskEngine(policy=policy or RiskPolicy.default())
    if correlation is None:
        correlation = run_comparison(expected, observed=observed)
    assessment = engine.assess(
        expected=expected,
        observed=observed,
        correlation=correlation,
        ml_result=ml_result,
        evidence_refs=evidence_refs,
    )
    return assessment


def by_id(assessment, finding_id):
    for finding in assessment.findings:
        if finding.finding_id == finding_id:
            return finding
    return None


SAMPLES = plan_samples()
STRONG_SAMPLE = next(s for s in SAMPLES if s["security_posture"] == "STRONG")
WEAK_SAMPLE = next(s for s in SAMPLES if s["security_posture"] == "WEAK")  # pfs false
WORST_SAMPLE = next(s for s in SAMPLES if s["security_posture"] == "WORST")  # cbc


class TestConfigurationRules(unittest.TestCase):
    def test_01_strong_configuration_produces_no_weakness_finding(self):
        expected = expected_from_plan_sample(STRONG_SAMPLE)
        assessment = findings_for(expected)
        config = [
            f for f in assessment.findings
            if f.source == SOURCE_EXPECTED_CONFIGURATION
        ]
        self.assertEqual(config, [])

    def test_02_pfs_disabled_produces_documented_finding(self):
        expected = expected_from_plan_sample(WEAK_SAMPLE)  # esp.pfs False
        self.assertFalse(expected.esp.pfs)
        finding = by_id(findings_for(expected), "RISK-PFS-DISABLED")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.rule_id, "esp.pfs.disabled")
        self.assertEqual(finding.category, CATEGORY_CONFIGURATION_WEAKNESS)
        self.assertEqual(finding.severity, SEVERITY_MEDIUM)
        self.assertEqual(finding.source, SOURCE_EXPECTED_CONFIGURATION)
        self.assertEqual(finding.evidence_type, "configuration")
        self.assertEqual(finding.related_variable, "esp.pfs")
        self.assertIsNotNone(finding.rule_id)

    def test_03_weak_crypto_finding_only_when_authoritative_policy_says_so(self):
        worst = expected_from_plan_sample(WORST_SAMPLE)  # aes128cbc
        self.assertIn(worst.esp.encryption, ("aes128cbc", "aes256cbc"))
        cbc = by_id(findings_for(worst), "RISK-WEAK-ESP-CRYPTO")
        self.assertIsNotNone(cbc)
        self.assertEqual(cbc.severity, SEVERITY_MEDIUM)
        self.assertEqual(cbc.related_variable, "esp.encryption")
        # aes128 key length is NOT a weakness in the authoritative model.
        strong_aes128 = by_id(findings_for(expected_from_plan_sample(STRONG_SAMPLE)), "RISK-WEAK-ESP-CRYPTO")
        self.assertIsNone(strong_aes128)

    def test_04_dh_group_weak_only_when_pfs_enabled(self):
        pfs_on_modp2048 = expected_from_plan_sample(
            {
                "traffic_profile": "voip",
                "security_posture": "MEDIUM",
                "configuration_id": "tunnel-ipv4-aes128gcm16-none-modp2048-true",
                "ipsec_configuration": {
                    "mode": "tunnel",
                    "address_family": "ipv4",
                    "ike": {"version": 2, "encryption": "aes256",
                            "integrity": "sha256", "dh_group": "modp2048"},
                    "esp": {"encryption": "aes128gcm16", "integrity": None,
                            "dh_group": "modp2048", "pfs": True},
                },
            }
        )
        finding = by_id(findings_for(pfs_on_modp2048), "RISK-WEAK-DH-GROUP")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, SEVERITY_LOW)
        # PFS off -> the rekey DH exchange does not occur; no DH finding.
        w = expected_from_plan_sample(WEAK_SAMPLE)
        self.assertFalse(w.esp.pfs)
        self.assertIsNone(by_id(findings_for(w), "RISK-WEAK-DH-GROUP"))


class TestCorrelationRules(unittest.TestCase):
    def test_05_mode_mismatch_is_high_configuration_mismatch(self):
        expected = expected_from_plan_sample(STRONG_SAMPLE)
        expected_mode_other = "transport" if expected.mode == "tunnel" else "tunnel"
        correlation = run_comparison(
            expected,
            observed_values=observed_values_for(expected, mode=expected_mode_other),
        )
        finding = by_id(findings_for(expected, correlation=correlation), "RISK-MODE-MISMATCH")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.category, CATEGORY_CONFIGURATION_MISMATCH)
        self.assertEqual(finding.severity, SEVERITY_HIGH)
        self.assertEqual(finding.source, SOURCE_CORRELATION)

    def test_06_esp_presence_absent_with_complete_window_is_high(self):
        expected = expected_from_plan_sample(STRONG_SAMPLE)
        correlation = run_comparison(
            expected,
            observed=build_observed(esp_seen=False),
            live_features=complete_window(),
        )
        esp_outcome = [
            o for o in correlation.mismatches if o["variable"] == "esp.presence"
        ]
        self.assertTrue(esp_outcome, "expected esp.presence MISMATCH from complete absence")
        finding = by_id(findings_for(expected, correlation=correlation), "RISK-ESP-MISMATCH")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, SEVERITY_HIGH)
        self.assertEqual(finding.expected_value, True)
        self.assertEqual(finding.observed_value, False)

    def test_07_unexpected_ah_presence_is_protocol_anomaly(self):
        expected = expected_from_plan_sample(STRONG_SAMPLE)
        correlation = run_comparison(
            expected,
            observed=build_observed(ah_seen=True),
            observed_values=observed_values_for(expected),
        )
        finding = by_id(findings_for(expected, correlation=correlation), "RISK-AH-UNEXPECTED")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.category, CATEGORY_PROTOCOL_ANOMALY)
        self.assertEqual(finding.severity, SEVERITY_MEDIUM)

    def test_08_non_security_mismatch_is_not_high(self):
        expected = expected_from_plan_sample(STRONG_SAMPLE)
        identity = build_identity(
            window_start_ns=1_000_000_000,
            window_end_ns=2_000_000_000,
        )
        correlation = make_correlation(
            identity,
            mismatches=[
                {
                    "variable": "window.containment",
                    "status": "MISMATCH",
                    "expected_value": [1_000_000_000, 2_000_000_000],
                    "observed_value": 5_000_000_000,
                }
            ],
        )
        assessment = findings_for(expected, correlation=correlation)
        finding = by_id(assessment, "RISK-WINDOW-OUTSIDE")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, SEVERITY_LOW)
        self.assertLessEqual(assessment.overall_score, 9)

    def test_09_unregistered_mismatch_produces_no_finding(self):
        expected = expected_from_plan_sample(STRONG_SAMPLE)
        identity = build_identity()
        correlation = make_correlation(
            identity,
            mismatches=[
                {
                    "variable": "traffic.port",
                    "status": "MISMATCH",
                    "expected_value": 20000,
                    "observed_value": 10,
                }
            ],
        )
        assessment = findings_for(expected, correlation=correlation)
        self.assertEqual(assessment.findings, ())
        self.assertEqual(assessment.overall_score, 0)

    def test_10_unknown_never_becomes_vulnerability(self):
        expected = expected_from_plan_sample(STRONG_SAMPLE)
        correlation = run_comparison(
            expected,
            observed=build_observed(),
            live_features=None,
        )
        self.assertTrue(correlation.unknowns)
        assessment = findings_for(expected, correlation=correlation)
        self.assertEqual(assessment.findings, ())
        self.assertEqual(assessment.overall_score, 0)
        self.assertEqual(assessment.severity, SEVERITY_INFO)

    def test_10b_not_applicable_never_becomes_vulnerability(self):
        expected = expected_from_plan_sample(STRONG_SAMPLE)
        correlation = run_comparison(
            expected,
            observed=build_observed(),
            observed_values=observed_values_for(expected),
        )
        self.assertTrue(correlation.not_applicable)
        assessment = findings_for(expected, correlation=correlation)
        self.assertEqual(assessment.findings, ())
        self.assertEqual(assessment.overall_score, 0)


class TestMLRules(unittest.TestCase):
    ANOMALOUS = MLResult(
        model_version="traffic-rf-v1",
        traffic_class="voip",
        anomaly=True,
        anomaly_score=0.9,
        extras={"source": "ml"},
    )

    def test_11_ml_anomaly_is_ml_derived_and_preserves_model_version(self):
        expected = expected_from_plan_sample(STRONG_SAMPLE)
        assessment = findings_for(expected, ml_result=self.ANOMALOUS)
        finding = by_id(assessment, "RISK-ML-ANOMALY")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.source, SOURCE_ML)
        self.assertEqual(finding.category, CATEGORY_ML_TRAFFIC_ANOMALY)
        self.assertEqual(finding.model_version, "traffic-rf-v1")
        self.assertEqual(finding.evidence_type, "ml")

    def test_12_ml_anomaly_never_critical(self):
        expected = expected_from_plan_sample(STRONG_SAMPLE)
        assessment = findings_for(expected, ml_result=self.ANOMALOUS)
        self.assertEqual(by_id(assessment, "RISK-ML-ANOMALY").severity, SEVERITY_LOW)
        self.assertLessEqual(assessment.overall_score, 9)

    def test_13_ml_classification_disagreement_is_low_only(self):
        expected = expected_from_plan_sample(STRONG_SAMPLE)  # profile voip
        other = "web" if expected.traffic.profile != "web" else "email"
        ml = MLResult(
            model_version="traffic-rf-v1",
            traffic_class=other,
            classification_confidence=0.9,
        )
        assessment = findings_for(expected, ml_result=ml)
        finding = by_id(assessment, "RISK-ML-CLASSIFICATION")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.category, CATEGORY_ML_CLASSIFICATION_DISAGREEMENT)
        self.assertEqual(finding.severity, SEVERITY_LOW)
        self.assertEqual(finding.confidence, 0.9)
        self.assertEqual(finding.model_version, "traffic-rf-v1")
        self.assertLessEqual(assessment.overall_score, 9)

    def test_14_missing_ml_result_does_not_increase_risk(self):
        expected = expected_from_plan_sample(STRONG_SAMPLE)
        none_assessment = findings_for(expected, ml_result=None)
        with_ml = findings_for(
            expected,
            ml_result=MLResult(model_version="traffic-rf-v1", traffic_class=None),
        )
        self.assertEqual(none_assessment.overall_score, 0)
        self.assertEqual(with_ml.overall_score, 0)
        self.assertEqual(none_assessment.findings, ())


class TestEvidenceRules(unittest.TestCase):
    def test_16_findings_preserve_evidence_references(self):
        expected = expected_from_plan_sample(STRONG_SAMPLE)
        from correlation.models import EvidenceRef

        refs = (EvidenceRef(capture_sequence=1, source="swanctl"),)
        other = "transport" if expected.mode == "tunnel" else "tunnel"
        correlation = run_comparison(
            expected,
            observed_values=observed_values_for(expected, mode=other),
            evidence_refs=refs,
        )
        assessment = findings_for(expected, correlation=correlation, evidence_refs=refs)
        finding = by_id(assessment, "RISK-MODE-MISMATCH")
        self.assertEqual(len(finding.evidence_refs), 1)
        self.assertEqual(finding.evidence_refs[0].capture_sequence, 1)
        self.assertEqual(finding.evidence_refs[0].source, "swanctl")

    def test_17_no_fake_evidence_references_generated(self):
        expected = expected_from_plan_sample(WEAK_SAMPLE)
        assessment = findings_for(expected, evidence_refs=())
        finding = by_id(assessment, "RISK-PFS-DISABLED")
        self.assertEqual(finding.evidence_refs, ())
        for item in assessment.evidence_refs:
            self.assertIsNone(item.pcap_path)
        self.assertFalse(assessment.metadata["evidence_policy"]["fabricates_references"])

    def test_18_configuration_only_findings_identify_configuration_source(self):
        expected = expected_from_plan_sample(WEAK_SAMPLE)
        finding = by_id(findings_for(expected), "RISK-PFS-DISABLED")
        self.assertEqual(finding.source, SOURCE_EXPECTED_CONFIGURATION)
        self.assertEqual(finding.evidence_type, "configuration")


class TestInsufficientEvidence(unittest.TestCase):
    def test_15_insufficient_evidence_opt_in_only(self):
        expected = expected_from_plan_sample(STRONG_SAMPLE)
        correlation = run_comparison(expected, observed=build_observed())
        self.assertTrue(correlation.unknowns)
        default = findings_for(expected, correlation=correlation)
        self.assertEqual(default.findings, ())
        enabled = RiskPolicy.default().with_unknown_handling(
            enable_insufficient_evidence=True
        )
        assessment = findings_for(
            expected, correlation=correlation, policy=enabled
        )
        ev = [
            f for f in assessment.findings
            if f.category == CATEGORY_INSUFFICIENT_EVIDENCE
        ]
        self.assertTrue(ev)
        for finding in ev:
            self.assertEqual(finding.severity, SEVERITY_INFO)
            self.assertTrue(finding.finding_id.startswith("RISK-INSUFFICIENT-EVIDENCE-"))
        # INFO findings never inflate the score.
        self.assertEqual(assessment.overall_score, 0)


if __name__ == "__main__":
    unittest.main()