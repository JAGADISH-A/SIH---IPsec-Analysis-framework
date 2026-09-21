"""Phase 6 risk-engine end-to-end tests (the 28 brief scenarios + real-fixture
validation + serialization + identity safety)."""

import json
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

from correlation.adapters import MaterializedExpectedState  # noqa: E402
from correlation.comparison import IdentityMismatchError  # noqa: E402
from correlation.models import (  # noqa: E402
    CORRELATION_STATUS_MATCH,
    EvidenceRef,
    MLResult,
)
from correlation.risk import (  # noqa: E402
    CATEGORY_CONFIGURATION_MISMATCH,
    CATEGORY_CONFIGURATION_WEAKNESS,
    CATEGORY_ML_TRAFFIC_ANOMALY,
    DEFAULT_RISK_POLICY_VERSION,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SOURCE_ML,
    RiskAssessment,
    RiskEngine,
    RiskPolicy,
)

SAMPLES = plan_samples()
P6_RUN = "dataset-20260916-231246"


def sample_by_posture(posture):
    return next(s for s in SAMPLES if s["security_posture"] == posture)


def engine_for(policy=None):
    return RiskEngine(policy=policy or RiskPolicy.default())


def base_identity(expected, sequence):
    return build_identity(
        dataset_run_id=P6_RUN,
        sequence=sequence,
        experiment_id=f"exp-{sequence}",
    )


def assess_scenario(expected, *, correlation=None, observed=None, ml_result=None,
                    evidence_refs=(), expected_wrapper=None, policy=None):
    engine = engine_for(policy)
    correlation = correlation or run_comparison(expected, observed=observed)
    kw = dict(expected=expected_wrapper or expected, observed=observed,
              correlation=correlation, ml_result=ml_result,
              evidence_refs=evidence_refs)
    return engine.assess(**kw)


def by_id(assessment, finding_id):
    for f in assessment.findings:
        if f.finding_id == finding_id:
            return f
    return None


class TestConfiguration(unittest.TestCase):
    def test_01_strong_configuration_no_weakness(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        assessment = assess_scenario(expected)
        config = [f for f in assessment.findings if f.source == "EXPECTED_CONFIGURATION"]
        self.assertEqual(config, [])
        self.assertEqual(assessment.overall_score, 0)
        self.assertEqual(assessment.severity, SEVERITY_INFO)

    def test_02_pfs_disabled_documented_finding(self):
        expected = expected_from_plan_sample(sample_by_posture("WEAK"))
        self.assertFalse(expected.esp.pfs)
        assessment = assess_scenario(expected)
        finding = by_id(assessment, "RISK-PFS-DISABLED")
        self.assertIsNotNone(finding)
        self.assertEqual(findings_score(assessment), 12)
        self.assertEqual(assessment.severity, SEVERITY_MEDIUM)

    def test_03_weak_crypto_only_when_authoritative(self):
        worst = expected_from_plan_sample(sample_by_posture("WORST"))  # CBC
        self.assertIsNotNone(by_id(assess_scenario(worst), "RISK-WEAK-ESP-CRYPTO"))
        strong = expected_from_plan_sample(sample_by_posture("STRONG"))  # GCM family
        self.assertIsNone(by_id(assess_scenario(strong), "RISK-WEAK-ESP-CRYPTO"))

    def test_04_posture_consumed_not_recomputed(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        assessment = assess_scenario(expected)
        posture = assessment.metadata["posture_context"]
        self.assertEqual(posture["authoritative_posture"], "STRONG")
        self.assertTrue(posture["posture_not_recomputed"])
        self.assertTrue(posture["posture_is_context_only"])
        # posture is never transmuted into a finding
        self.assertFalse(any(f.related_variable == "security_posture"
                             for f in assessment.findings))

    def test_05_posture_does_not_double_count_existing_finding(self):
        expected = expected_from_plan_sample(sample_by_posture("WEAK"))  # PFS off
        assessment = assess_scenario(expected)
        pfs_findings = [f for f in assessment.findings
                        if f.finding_id == "RISK-PFS-DISABLED"]
        self.assertEqual(len(pfs_findings), 1)
        self.assertEqual(assessment.overall_score, findings_score(assessment))
        # the same underlying issue is not re-created from the posture value
        # itself (no posture-based duplicate)
        self.assertLessEqual(assessment.overall_score, 20)


class TestCorrelation(unittest.TestCase):
    def test_06_authoritative_mismatch_appropriate_finding(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        other = "transport" if expected.mode == "tunnel" else "tunnel"
        correlation = run_comparison(
            expected, observed_values=observed_values_for(expected, mode=other),
        )
        assessment = assess_scenario(expected, correlation=correlation)
        finding = by_id(assessment, "RISK-MODE-MISMATCH")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.category, CATEGORY_CONFIGURATION_MISMATCH)
        self.assertEqual(finding.severity, SEVERITY_HIGH)
        self.assertEqual(assessment.overall_score, 25)

    def test_07_non_security_mismatch_not_high(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        identity = build_identity()
        correlation = make_correlation(
            identity,
            mismatches=[{
                "variable": "window.containment", "status": "MISMATCH",
                "expected_value": [1_000_000_000, 2_000_000_000],
                "observed_value": 5_000_000_000,
            }],
        )
        assessment = assess_scenario(expected, correlation=correlation)
        finding = by_id(assessment, "RISK-WINDOW-OUTSIDE")
        self.assertEqual(finding.severity, SEVERITY_LOW)
        self.assertLessEqual(assessment.overall_score, 9)

    def test_08_unknown_no_vulnerability(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        correlation = run_comparison(expected, observed=build_observed())
        self.assertTrue(correlation.unknowns)
        self.assertEqual(correlation.status != CORRELATION_STATUS_MATCH, True)
        assessment = assess_scenario(expected, correlation=correlation)
        self.assertEqual(assessment.findings, ())
        self.assertEqual(assessment.overall_score, 0)
        self.assertEqual(assessment.severity, SEVERITY_INFO)

    def test_09_not_applicable_no_vulnerability(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        correlation = run_comparison(
            expected, observed=build_observed(),
            observed_values=observed_values_for(expected),
        )
        self.assertTrue(correlation.not_applicable)
        assessment = assess_scenario(expected, correlation=correlation)
        self.assertEqual(assessment.findings, ())
        self.assertEqual(assessment.overall_score, 0)

    def test_10_partial_observation_no_false_absence(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        # PARTIAL window + ESP not seen -> esp.presence is UNKNOWN, NOT a
        # mismatch, therefore no absence-based finding.
        correlation = run_comparison(
            expected, observed=build_observed(esp_seen=False),
            live_features=None,
        )
        esp_presence = [
            o for o in correlation.unknowns if o["variable"] == "esp.presence"
        ]
        self.assertTrue(esp_presence)
        assessment = assess_scenario(expected, correlation=correlation)
        self.assertEqual(assessment.findings, ())
        self.assertEqual(assessment.overall_score, 0)


class TestML(unittest.TestCase):
    def test_11_ml_anomaly_preserved_as_ml(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        ml = MLResult(model_version="traffic-rf-v1", anomaly=True, anomaly_score=0.9)
        assessment = assess_scenario(expected, ml_result=ml)
        finding = by_id(assessment, "RISK-ML-ANOMALY")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.source, SOURCE_ML)
        self.assertEqual(finding.category, CATEGORY_ML_TRAFFIC_ANOMALY)
        self.assertEqual(finding.model_version, "traffic-rf-v1")
        self.assertEqual(assessment.metadata["ml"]["model_version"], "traffic-rf-v1")
        self.assertTrue(assessment.metadata["ml"]["ml_is_evidence_only"])

    def test_12_ml_anomaly_not_critical(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        ml = MLResult(model_version="traffic-rf-v1", anomaly=True, anomaly_score=0.99)
        assessment = assess_scenario(expected, ml_result=ml)
        self.assertLessEqual(assessment.overall_score, 9)
        self.assertEqual(assessment.severity, SEVERITY_LOW)

    def test_13_ml_classification_disagreement_not_vulnerability(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        other = "web" if expected.traffic.profile != "web" else "email"
        ml = MLResult(model_version="traffic-rf-v1", traffic_class=other,
                      classification_confidence=0.9)
        assessment = assess_scenario(expected, ml_result=ml)
        finding = by_id(assessment, "RISK-ML-CLASSIFICATION")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, SEVERITY_LOW)
        self.assertLessEqual(assessment.overall_score, 9)

    def test_14_missing_ml_does_not_increase_risk(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        self.assertEqual(assess_scenario(expected).overall_score,
                         assess_scenario(
                             expected, ml_result=MLResult(model_version="m")).overall_score)

    def test_15_model_version_preserved(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        ml = MLResult(model_version="traffic-rf-v1", anomaly=True)
        finding = by_id(assess_scenario(expected, ml_result=ml), "RISK-ML-ANOMALY")
        self.assertEqual(finding.model_version, "traffic-rf-v1")

    def test_ml_from_correlation_metadata_is_consumed(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        ml = MLResult(model_version="from-metadata", anomaly=False, anomaly_score=0.1)
        from correlation.comparison import ComparisonEngine, ComparisonEngineOptions
        result = ComparisonEngine(ComparisonEngineOptions()).compare(
            expected, build_observed(),
            identity=build_identity(),
            observed_identity=build_identity(),
            ml_result=ml,
        )
        from correlation.ml.integration import attach_ml_metadata
        result = attach_ml_metadata(result, expected=expected, ml_result=ml)
        assessment = assess_scenario(expected, correlation=result, ml_result=None)
        self.assertEqual(assessment.metadata["ml"]["model_version"], "from-metadata")


class TestEvidence(unittest.TestCase):
    def test_16_findings_preserve_evidence_references(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        refs = (EvidenceRef(capture_sequence=2, source="swanctl"),)
        correlation = run_comparison(
            expected, evidence_refs=refs,
        )
        assessment = assess_scenario(expected, correlation=correlation,
                                     evidence_refs=refs)
        self.assertEqual(list(assessment.evidence_refs), list(refs))

    def test_17_no_fake_evidence(self):
        expected = expected_from_plan_sample(sample_by_posture("WEAK"))
        assessment = assess_scenario(expected)
        finding = by_id(assessment, "RISK-PFS-DISABLED")
        self.assertEqual(finding.evidence_refs, ())
        self.assertEqual(list(assessment.evidence_refs), [])
        self.assertFalse(assessment.metadata["evidence_policy"]["fabricates_references"])

    def test_18_config_only_findings_identify_config_source(self):
        expected = expected_from_plan_sample(sample_by_posture("WEAK"))
        finding = by_id(assess_scenario(expected), "RISK-PFS-DISABLED")
        self.assertEqual(finding.source, "EXPECTED_CONFIGURATION")
        self.assertEqual(finding.evidence_type, "configuration")


class TestScoringDeterminism(unittest.TestCase):
    def test_19_same_input_same_score(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        first = assess_scenario(expected, ml_result=MLResult(
            model_version="m", anomaly=True)).to_json(sort_keys=True)
        second = assess_scenario(expected, ml_result=MLResult(
            model_version="m", anomaly=True)).to_json(sort_keys=True)
        self.assertEqual(first, second)

    def test_20_score_always_0_100(self):
        for posture in ("STRONG", "GOOD", "MEDIUM", "WEAK", "WORST"):
            expected = expected_from_plan_sample(sample_by_posture(posture))
            for scenario in (
                lambda: assess_scenario(expected),
                lambda: assess_scenario(expected, observed=build_observed()),
            ):
                assessment = scenario()
                self.assertGreaterEqual(assessment.overall_score, 0)
                self.assertLessEqual(assessment.overall_score, 100)

    def test_21_score_maps_to_exactly_one_severity(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        assessment = assess_scenario(expected, ml_result=MLResult(
            model_version="m", anomaly=True))
        _, low, high = RiskPolicy.default().band_for(assessment.overall_score)
        self.assertTrue(low <= assessment.overall_score <= high)
        self.assertEqual(assessment.severity, RiskPolicy.default()
                         .band_for(assessment.overall_score)[0])

    def test_22_duplicate_findings_deduplicated(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        identity = build_identity()
        correlation = make_correlation(
            identity,
            mismatches=[
                {
                    "variable": "address_family", "status": "MISMATCH",
                    "expected_value": "ipv4", "observed_value": "ipv6",
                },
                {
                    "variable": "address_family", "status": "MISMATCH",
                    "expected_value": "ipv4", "observed_value": "ipv6",
                },
            ],
        )
        assessment = assess_scenario(expected, correlation=correlation)
        self.assertEqual(len([f for f in assessment.findings
                              if f.related_variable == "address_family"]), 1)
        self.assertEqual(assessment.overall_score, 12)  # MEDIUM once

    def test_23_policy_version_preserved(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        self.assertEqual(assess_scenario(expected).risk_policy_version,
                         DEFAULT_RISK_POLICY_VERSION)

    def test_custom_policy_version_carried(self):
        policy = RiskPolicy(policy_version="government-policy-2026",
                            weights=RiskPolicy.default().weights,
                            severity_bands=RiskPolicy.default().severity_bands)
        expected = expected_from_plan_sample(sample_by_posture("WEAK"))
        self.assertEqual(assess_scenario(expected, policy=policy).risk_policy_version,
                         "government-policy-2026")


class TestIdentity(unittest.TestCase):
    def test_24_mismatched_identities_rejected(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        correlation = run_comparison(expected)
        materialized = MaterializedExpectedState(
            expected=expected,
            identity=build_identity(sequence=99),  # different experiment
            provenance={},
        )
        with self.assertRaises(IdentityMismatchError):
            engine_for().assess(
                expected=materialized, correlation=correlation,
            )

    def test_25_findings_preserve_correlation_identity(self):
        expected = expected_from_plan_sample(sample_by_posture("WEAK"))
        identity = build_identity(sequence=3)
        correlation = run_comparison(expected, identity=identity,
                                     observed_identity=identity)
        assessment = assess_scenario(expected, correlation=correlation)
        self.assertEqual(assessment.identity, identity)
        self.assertEqual(assessment.identity.dataset_run_id, P6_RUN)


class TestSerialization(unittest.TestCase):
    def test_26_json_round_trip(self):
        expected = expected_from_plan_sample(sample_by_posture("WORST"))
        assessment = assess_scenario(expected, ml_result=MLResult(
            model_version="m", anomaly=True))
        payload = assessment.to_dict()
        restored = RiskAssessment.from_dict(json.loads(json.dumps(payload)))
        self.assertEqual(restored.to_dict(), payload)
        self.assertEqual(RiskAssessment.from_json(assessment.to_json()).to_dict(),
                         payload)

    def test_27_deterministic_serialization(self):
        expected = expected_from_plan_sample(sample_by_posture("WORST"))
        a = assess_scenario(expected, ml_result=MLResult(model_version="m", anomaly=True))
        b = assess_scenario(expected, ml_result=MLResult(model_version="m", anomaly=True))
        self.assertEqual(a.to_json(sort_keys=True), b.to_json(sort_keys=True))

    def test_every_finding_has_rule_id(self):
        for posture in ("STRONG", "GOOD", "MEDIUM", "WEAK", "WORST"):
            expected = expected_from_plan_sample(sample_by_posture(posture))
            assessment = assess_scenario(expected, ml_result=MLResult(
                model_version="m", anomaly=True))
            for finding in assessment.findings:
                self.assertTrue(finding.rule_id)


class TestRealArtifactValidation(unittest.TestCase):
    """Section 29: demonstrate six scenarios on the REAL Phase-3 plan."""

    def test_real_strong_expected_config(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        assessment = assess_scenario(
            expected,
            correlation=run_comparison(
                expected, observed=build_observed(),
                observed_values=observed_values_for(expected),
                live_features=complete_window(),
            ),
        )
        self.assertEqual(assessment.findings, ())
        self.assertEqual(assessment.overall_score, 0)
        self.assertEqual(assessment.severity, SEVERITY_INFO)

    def test_real_weak_expected_config(self):
        expected = expected_from_plan_sample(sample_by_posture("WEAK"))
        assessment = assess_scenario(expected)
        self.assertIsNotNone(by_id(assessment, "RISK-PFS-DISABLED"))
        self.assertEqual(assessment.overall_score, 12)

    def test_real_confirmed_observed_mismatch(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        other = "transport" if expected.mode == "tunnel" else "tunnel"
        correlation = run_comparison(
            expected, observed_values=observed_values_for(expected, mode=other),
        )
        assessment = assess_scenario(expected, correlation=correlation)
        self.assertIsNotNone(by_id(assessment, "RISK-MODE-MISMATCH"))
        self.assertEqual(assessment.overall_score, 25)
        self.assertEqual(assessment.severity, SEVERITY_HIGH)

    def test_real_unknown_observation(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        correlation = run_comparison(expected, observed=build_observed())
        assessment = assess_scenario(expected, correlation=correlation)
        self.assertEqual(assessment.findings, ())
        self.assertEqual(assessment.overall_score, 0)

    def test_real_ml_anomaly(self):
        expected = expected_from_plan_sample(sample_by_posture("STRONG"))
        assessment = assess_scenario(expected, ml_result=MLResult(
            model_version="traffic-rf-v1", anomaly=True, anomaly_score=0.9))
        self.assertIsNotNone(by_id(assessment, "RISK-ML-ANOMALY"))
        self.assertLessEqual(assessment.overall_score, 9)

    def test_real_combined_config_correlation_ml(self):
        sample = sample_by_posture("WORST")  # CBC + PFS off
        expected = expected_from_plan_sample(sample)
        other = "transport" if expected.mode == "tunnel" else "tunnel"
        correlation = run_comparison(
            expected, observed_values=observed_values_for(expected, mode=other),
        )
        assessment = assess_scenario(
            expected,
            correlation=correlation,
            ml_result=MLResult(model_version="traffic-rf-v1", anomaly=True,
                               anomaly_score=0.9),
        )
        ids = {f.finding_id for f in assessment.findings}
        self.assertIn("RISK-WEAK-ESP-CRYPTO", ids)
        self.assertIn("RISK-PFS-DISABLED", ids)
        self.assertIn("RISK-MODE-MISMATCH", ids)
        self.assertIn("RISK-ML-ANOMALY", ids)
        self.assertGreaterEqual(assessment.overall_score, 12 + 12 + 25 + 6)
        self.assertEqual(len(assessment.findings), 4)
        # ML never appears in protocol lists and never overrides the verdict.
        for f in assessment.findings:
            self.assertNotEqual(f.source, "OBSERVED_PROTOCOL")


def findings_score(assessment):
    return sum(RiskPolicy.default().weight_of(f.severity) for f in assessment.findings)


if __name__ == "__main__":
    unittest.main()