"""Phase 4 tests: deterministic Expected-vs-Observed Comparison Engine.

Covers the 37 required scenarios from the Phase 4 brief:

  identity safety                        tests 01-05
  direct comparisons                     tests 06-09
  IKE crypto unavailable                 tests 10-13
  ESP crypto unavailable                 tests 14-16
  GCM null integrity preserved           test  17
  traffic unavailable                    tests 18-20
  capture filter NOT_APPLICABLE          test  21
  configuration_id not guessed           test  22
  security_posture not recomputed        test  23
  mismatch carries evidence refs         test  24
  UNKNOWN always names the gap           test  25
  COMPLETE-observation absence rules     tests 26-27
  clock-domain handling                  tests 28-30
  determinism                            test  31
  overall status aggregation             tests 32-35
  contract/regression survival           tests 36-37
  extra: ML output never evaluated       test  38 (required coverage extension)
"""

import unittest

from correlation.comparison import (
    CLOCK_DOMAIN_LIVE_MONOTONIC_NS,
    CLOCK_DOMAIN_UTC_EPOCH_NS,
    ComparisonEngine,
    ComparisonEngineOptions,
    IdentityMismatchError,
    aggregate_status,
)
from correlation.comparison.clock import ClockAlignment
from correlation.models import (
    CORRELATION_STATUS_MATCH,
    CORRELATION_STATUS_MISMATCH,
    CORRELATION_STATUS_NOT_APPLICABLE,
    CORRELATION_STATUS_NOT_EVALUATED,
    CORRELATION_STATUS_UNKNOWN,
    CorrelationIdentity,
    CorrelationResult,
    EspExpected,
    EvidenceRef,
    ExpectedState,
    IkeExpected,
    LiveFeatureWindow,
    ObservedState,
    TrafficExpected,
)

MONOTONIC = CLOCK_DOMAIN_LIVE_MONOTONIC_NS
UTC = CLOCK_DOMAIN_UTC_EPOCH_NS

RUN_ID = "run-20260920-p4"
SEQ = 1
EXP_ID = "exp-p4-engine"
ATTEMPT = 1


def build_identity(**overrides):
    base = dict(
        dataset_run_id=RUN_ID,
        sequence=SEQ,
        experiment_id=EXP_ID,
        attempt_number=ATTEMPT,
        window_index=0,
        window_start_ns=1_000_000_000,
        window_end_ns=2_000_000_000,
    )
    base.update(overrides)
    return CorrelationIdentity(**base)


def build_expected(**overrides):
    kwargs = dict(
        mode="tunnel",
        address_family="ipv4",
        ike=IkeExpected(version=2, encryption="aes256", integrity="sha256",
                        dh_group="modp2048"),
        esp=EspExpected(encryption="aes256gcm16", integrity=None,
                        dh_group="modp2048", pfs=True),
        traffic=TrafficExpected(profile="video", duration=30, port=20000),
        capture_filter="udp port 500 or udp port 4500 or esp or ah",
        configuration_id="tunnel-ipv4-aes256gcm16-none-modp2048-true",
        security_posture=None,
    )
    kwargs.update(overrides)
    return ExpectedState(**kwargs)


def build_observed(**overrides):
    kwargs = dict(
        timestamp_ns=1_500_000_000,
        endpoints={"a": "192.0.2.1", "b": "192.0.2.2"},
        tunnel_seen=True,
        active=True,
        packets_seen=120,
        bytes_seen=48000,
        ike_seen=True,
        ike_nat_t_seen=False,
        esp_seen=True,
        ah_seen=False,
        spis=[],
    )
    kwargs.update(overrides)
    return ObservedState(**kwargs)


def complete_window() -> LiveFeatureWindow:
    """A live window that spans >= the expected 30s duration (COMPLETE)."""
    return LiveFeatureWindow(
        feature_schema_version="v2",
        window_start_ns=1_000_000_000,
        window_end_ns=40_000_000_000,
        features={"ip_total": 1, "esp_packets": 1},
    )


def short_window() -> LiveFeatureWindow:
    return LiveFeatureWindow(
        feature_schema_version="v2",
        window_start_ns=1_000_000_000,
        window_end_ns=2_000_000_000,  # 1s << expected.duration=30s -> PARTIAL
        features={"ip_total": 1},
    )


def find_outcome(result, variable):
    for bucket in (result.matches, result.mismatches,
                   result.unknowns, result.not_applicable):
        for outcome in bucket:
            if outcome["variable"] == variable:
                return outcome
    return None


def status_of(result, variable):
    outcome = find_outcome(result, variable)
    return outcome["status"] if outcome else None


def run_comparison(expected=None, observed=None, *, identity=None,
                   observed_identity=None, observed_values=None,
                   evidence_refs=(), live_features=None, clock_alignment=None,
                   options=None):
    engine = ComparisonEngine(options or ComparisonEngineOptions())
    return engine.compare(
        expected if expected is not None else build_expected(),
        observed if observed is not None else build_observed(),
        identity=identity if identity is not None else build_identity(),
        observed_identity=observed_identity
        if observed_identity is not None else build_identity(),
        observed_values=observed_values,
        evidence_refs=evidence_refs,
        live_features=live_features,
        clock_alignment=clock_alignment,
    )


GOOD_OBSERVED_VALUES = {
    "mode": "tunnel",
    "address_family": "ipv4",
    "ike.version": 2,
    "ike.encryption": "aes256",
    "ike.integrity": "sha256",
    "ike.dh_group": "modp2048",
    "esp.encryption": "aes256gcm16",
    "esp.integrity": None,
    "esp.dh_group": "modp2048",
    "esp.pfs": True,
    "traffic.profile": "video",
    "traffic.duration": 30,
    "traffic.port": 20000,
}


class TestIdentitySafety(unittest.TestCase):
    def test_01_identity_match_accepted(self):
        identity = build_identity()
        result = run_comparison(
            identity=identity, observed_identity=identity,
            observed_values=GOOD_OBSERVED_VALUES,
        )
        self.assertEqual(result.status, CORRELATION_STATUS_MATCH)

    def test_02_dataset_run_id_mismatch_rejected(self):
        with self.assertRaises(IdentityMismatchError):
            run_comparison(
                identity=build_identity(),
                observed_identity=build_identity(dataset_run_id="run-OTHER"),
            )

    def test_03_sequence_mismatch_rejected(self):
        with self.assertRaises(IdentityMismatchError):
            run_comparison(
                identity=build_identity(),
                observed_identity=build_identity(sequence=2),
            )

    def test_04_experiment_id_mismatch_rejected(self):
        with self.assertRaises(IdentityMismatchError):
            run_comparison(
                identity=build_identity(),
                observed_identity=build_identity(experiment_id="exp-OTHER"),
            )

    def test_05_attempt_number_mismatch_rejected(self):
        with self.assertRaises(IdentityMismatchError):
            run_comparison(
                identity=build_identity(),
                observed_identity=build_identity(attempt_number=2),
            )


class TestDirectComparison(unittest.TestCase):
    def test_06_mode_match(self):
        result = run_comparison(observed_values={"mode": "tunnel"})
        self.assertEqual(status_of(result, "mode"), CORRELATION_STATUS_MATCH)

    def test_07_mode_mismatch(self):
        result = run_comparison(
            observed_values={**GOOD_OBSERVED_VALUES, "mode": "transport"}
        )
        self.assertEqual(status_of(result, "mode"), CORRELATION_STATUS_MISMATCH)
        self.assertEqual(result.status, CORRELATION_STATUS_MISMATCH)

    def test_08_address_family_derived_from_endpoints(self):
        result = run_comparison(
            observed=build_observed(
                endpoints={"a": "192.0.2.1", "b": "192.0.2.2"}
            ),
            observed_values={k: v for k, v in GOOD_OBSERVED_VALUES.items()
                             if k != "address_family"},
        )
        self.assertEqual(status_of(result, "address_family"),
                         CORRELATION_STATUS_MATCH)

    def test_09_address_family_unavailable(self):
        result = run_comparison(
            observed=build_observed(endpoints={}),
            observed_values={k: v for k, v in GOOD_OBSERVED_VALUES.items()
                             if k != "address_family"},
        )
        self.assertEqual(status_of(result, "address_family"), CORRELATION_STATUS_UNKNOWN)


class TestIkeCryptoUnavailable(unittest.TestCase):
    def _assert_unavailable(self, variable):
        result = run_comparison()
        self.assertEqual(status_of(result, variable), CORRELATION_STATUS_UNKNOWN)

    def test_10_ike_version_unavailable(self):
        self._assert_unavailable("ike.version")

    def test_11_ike_encryption_unavailable(self):
        self._assert_unavailable("ike.encryption")

    def test_12_ike_integrity_unavailable(self):
        self._assert_unavailable("ike.integrity")

    def test_13_ike_dh_group_unavailable(self):
        self._assert_unavailable("ike.dh_group")


class TestEspCryptoUnavailable(unittest.TestCase):
    def test_14_esp_encryption_unavailable(self):
        result = run_comparison()
        self.assertEqual(status_of(result, "esp.encryption"), CORRELATION_STATUS_UNKNOWN)

    def test_15_esp_dh_group_unavailable(self):
        result = run_comparison()
        self.assertEqual(status_of(result, "esp.dh_group"), CORRELATION_STATUS_UNKNOWN)

    def test_16_esp_pfs_unavailable(self):
        result = run_comparison()
        self.assertEqual(status_of(result, "esp.pfs"), CORRELATION_STATUS_UNKNOWN)

    def test_17_gcm_null_integrity_preserved(self):
        # Expected esp.integrity is None (AES-GCM): it stays the null value and
        # is never coerced to the string "none".
        unobserved = run_comparison()
        outcome = find_outcome(unobserved, "esp.integrity")
        self.assertEqual(outcome["status"], CORRELATION_STATUS_UNKNOWN)
        self.assertTrue(outcome["expected_value"] is None)
        self.assertFalse(isinstance(outcome["expected_value"], str))
        # An authoritative observed null integrity -> exact MATCH (None == None),
        # and again the value is preserved as null, not the string "none".
        observed = run_comparison(observed_values={"esp.integrity": None})
        outcome = find_outcome(observed, "esp.integrity")
        self.assertEqual(outcome["status"], CORRELATION_STATUS_MATCH)
        self.assertTrue(outcome["expected_value"] is None)
        self.assertTrue(outcome["observed_value"] is None)
        self.assertFalse(isinstance(outcome["observed_value"], str))


class TestTrafficUnavailable(unittest.TestCase):
    def test_18_traffic_profile_unavailable(self):
        result = run_comparison()
        self.assertEqual(status_of(result, "traffic.profile"), CORRELATION_STATUS_UNKNOWN)

    def test_19_traffic_duration_unavailable(self):
        result = run_comparison()
        self.assertEqual(status_of(result, "traffic.duration"), CORRELATION_STATUS_UNKNOWN)

    def test_20_traffic_port_unavailable(self):
        result = run_comparison()
        self.assertEqual(status_of(result, "traffic.port"), CORRELATION_STATUS_UNKNOWN)


class TestPlanningMetadataNeverInferred(unittest.TestCase):
    def test_21_capture_filter_not_applicable(self):
        result = run_comparison()
        self.assertEqual(status_of(result, "capture_filter"),
                         CORRELATION_STATUS_NOT_APPLICABLE)

    def test_22_configuration_id_not_guessed(self):
        result = run_comparison()
        outcome = find_outcome(result, "configuration_id")
        self.assertEqual(outcome["status"], CORRELATION_STATUS_NOT_APPLICABLE)
        self.assertIsNone(outcome["observed_value"])

    def test_23_security_posture_not_recomputed(self):
        result = run_comparison()
        outcome = find_outcome(result, "security_posture")
        self.assertEqual(outcome["status"], CORRELATION_STATUS_NOT_APPLICABLE)
        # Posture is never upgraded to MATCH/MISMATCH even with full evidence.
        full = run_comparison(observed_values=GOOD_OBSERVED_VALUES)
        self.assertEqual(status_of(full, "security_posture"),
                         CORRELATION_STATUS_NOT_APPLICABLE)


class TestOutcomeQuality(unittest.TestCase):
    def test_24_mismatch_carries_evidence_refs(self):
        ev = EvidenceRef(pcap_path="results/datasets/x/captures/1/e.pcap",
                         capture_sequence=1, source="training_pcap")
        result = run_comparison(
            observed_values={**GOOD_OBSERVED_VALUES, "mode": "transport"},
            evidence_refs=[ev],
        )
        mismatch = find_outcome(result, "mode")
        self.assertEqual(mismatch["status"], CORRELATION_STATUS_MISMATCH)
        self.assertEqual(mismatch["evidence_refs"], [ev.to_dict()])
        self.assertIn("contradicts", mismatch["reason"])

    def test_25_unknown_always_names_the_gap(self):
        result = run_comparison()
        for outcome in result.unknowns:
            self.assertGreater(len(outcome["reason"] or ""), 0)
            self.assertTrue(outcome["reason"].endswith("."))


class TestObservationCompleteness(unittest.TestCase):
    def test_26_complete_observation_absence_is_mismatch(self):
        # Full-coverage live window => COMPLETE; expected traffic present but
        # the observed set has zero traffic => MISMATCH.
        result = run_comparison(
            observed=build_observed(packets_seen=0, esp_seen=False),
            live_features=complete_window(),
        )
        self.assertEqual(result.metadata["observation_completeness"], "COMPLETE")
        self.assertEqual(status_of(result, "traffic.activity"),
                         CORRELATION_STATUS_MISMATCH)
        self.assertEqual(status_of(result, "esp.presence"),
                         CORRELATION_STATUS_MISMATCH)

    def test_27_partial_observation_absence_is_unknown(self):
        # No live window => PARTIAL => absence is NOT authoritative.
        result = run_comparison(
            observed=build_observed(packets_seen=0, esp_seen=False),
            live_features=None,
        )
        self.assertEqual(result.metadata["observation_completeness"], "PARTIAL")
        self.assertEqual(status_of(result, "traffic.activity"),
                         CORRELATION_STATUS_UNKNOWN)
        short = run_comparison(
            observed=build_observed(packets_seen=0),
            live_features=short_window(),
        )
        self.assertEqual(short.metadata["observation_completeness"], "PARTIAL")
        self.assertEqual(status_of(short, "traffic.activity"),
                         CORRELATION_STATUS_UNKNOWN)


class TestClockDomainHandling(unittest.TestCase):
    def test_28_same_domain_comparable(self):
        result = run_comparison()  # both LIVE_MONOTONIC_NS by default
        self.assertEqual(status_of(result, "window.containment"),
                         CORRELATION_STATUS_MATCH)

    def test_29_cross_domain_without_alignment_unknown(self):
        options = ComparisonEngineOptions(
            observed_clock_domain=MONOTONIC, window_clock_domain=UTC
        )
        result = run_comparison(options=options)
        self.assertEqual(status_of(result, "window.containment"),
                         CORRELATION_STATUS_UNKNOWN)

    def test_30_cross_domain_with_alignment_comparables(self):
        alignment = ClockAlignment(
            from_domain=UTC, to_domain=MONOTONIC, offset_ns=100,
            description="test calibration",
        )
        options = ComparisonEngineOptions(
            observed_clock_domain=MONOTONIC, window_clock_domain=UTC
        )
        result = run_comparison(options=options, clock_alignment=alignment)
        self.assertEqual(status_of(result, "window.containment"),
                         CORRELATION_STATUS_MATCH)


class TestDeterminism(unittest.TestCase):
    def test_31_identical_inputs_identical_results(self):
        first = run_comparison(observed_values=GOOD_OBSERVED_VALUES)
        second = run_comparison(observed_values=GOOD_OBSERVED_VALUES)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.metadata["rules_executed"],
                         second.metadata["rules_executed"])
        self.assertGreater(len(first.metadata["rules_executed"]), 20)


class TestAggregation(unittest.TestCase):
    def test_32_all_matches_is_match(self):
        result = run_comparison(observed_values=GOOD_OBSERVED_VALUES)
        self.assertEqual(result.status, CORRELATION_STATUS_MATCH)
        self.assertEqual(result.mismatches, [])
        self.assertEqual(result.unknowns, [])

    def test_33_mismatch_dominates_even_with_unknowns(self):
        # Only the mode observation is supplied -> the mode MISMATCH coexists
        # with UNKNOWN crypto variables; MISMATCH must still dominate.
        result = run_comparison(observed_values={"mode": "transport"})
        self.assertEqual(result.status, CORRELATION_STATUS_MISMATCH)
        self.assertGreater(len(result.unknowns), 0)
        self.assertGreater(len(result.mismatches), 0)

    def test_34_no_mismatch_but_unknowns_is_unknown(self):
        result = run_comparison()  # presence matches, crypto unobserved
        self.assertEqual(result.status, CORRELATION_STATUS_UNKNOWN)
        self.assertGreater(len(result.unknowns), 0)
        self.assertEqual(result.mismatches, [])

    def test_35_only_not_applicable_is_not_applicable(self):
        status = aggregate_status([], [], [], [{"a": 1}, {"b": 2}])
        self.assertEqual(status, CORRELATION_STATUS_NOT_APPLICABLE)
        self.assertEqual(
            aggregate_status([], [], [], []), CORRELATION_STATUS_NOT_EVALUATED
        )


class TestRegressionSurvival(unittest.TestCase):
    def test_36_result_container_round_trips_with_not_applicable(self):
        result = CorrelationResult(
            identity=build_identity(),
            status=CORRELATION_STATUS_MATCH,
            matches=[{"variable": "mode"}],
            not_applicable=[{"variable": "spi"}],
        )
        restored = CorrelationResult.from_json(result.to_json())
        self.assertEqual(restored, result)
        self.assertEqual(restored.not_applicable, [{"variable": "spi"}])
        with self.assertRaises(ValueError):
            CorrelationResult(
                identity=build_identity(), status="NOPE", not_applicable=[1.0]
            )

    def test_37_canonical_variables_still_covered(self):
        from correlation.comparison.rules import (
            ACCOUNTED_VARIABLES,
            RULE_CLASSIFICATIONS,
            accounting_driven_rule_order,
        )
        from correlation.models import CANONICAL_VARIABLES

        for variable in CANONICAL_VARIABLES:
            self.assertIn(variable, RULE_CLASSIFICATIONS)
            self.assertIn(variable, ACCOUNTED_VARIABLES)
        for variable in ACCOUNTED_VARIABLES:
            self.assertIn(variable, accounting_driven_rule_order())
        self.assertEqual(len(RULE_CLASSIFICATIONS), len(ACCOUNTED_VARIABLES))

    def test_38_ml_never_evaluated(self):
        from correlation.models import MLResult

        engine = ComparisonEngine(ComparisonEngineOptions())
        identity = build_identity()
        result = engine.compare(
            build_expected(), build_observed(), identity=identity,
            observed_identity=identity,
            ml_result=MLResult(model_version="v1", traffic_class="voip",
                               classification_confidence=0.5, anomaly=False,
                               anomaly_score=0.0),
            observed_values=GOOD_OBSERVED_VALUES,
        )
        self.assertEqual(result.metadata["ml_evaluated"], True)
        # ML output never influences item statuses: esp.pfs remains UNKNOWN
        # even with a full MLResult present.
        result_bare = engine.compare(
            build_expected(), build_observed(), identity=identity,
            observed_identity=identity,
            ml_result=MLResult(model_version="v1", traffic_class="voip",
                               classification_confidence=0.5, anomaly=False,
                               anomaly_score=0.0),
        )
        self.assertEqual(status_of(result_bare, "esp.pfs"),
                         CORRELATION_STATUS_UNKNOWN)


if __name__ == "__main__":
    unittest.main()