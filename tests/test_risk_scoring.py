"""Phase 6 scoring tests: contributions, bands, caps, determinism.

Covers the Phase 6 brief sections 8 (bounded 0-100 score), 21 (documented
aggregation), 22 (score -> exactly one severity), 9 (determinism) and 20
(deduplication before scoring).
"""

import unittest

from correlation.risk import (
    CATEGORY_CONFIGURATION_WEAKNESS,
    CATEGORY_OBSERVED_MISMATCH,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    RiskFinding,
    RiskPolicy,
    ScoreResult,
    deduplicate_findings,
    score_findings,
    validate_severity_bands,
)


def finding(severity, *, finding_id=None, category=None, related_variable=None,
            source="CORRELATION"):
    return RiskFinding(
        finding_id=finding_id or f"RISK-{severity}",
        rule_id="test.rule",
        category=category or CATEGORY_OBSERVED_MISMATCH,
        severity=severity,
        title="t",
        description="d",
        reason="r",
        condition="cond",
        source=source,
        evidence_type="correlation",
        related_variable=related_variable,
    )


POLICY = RiskPolicy.default()


class TestScoreBands(unittest.TestCase):
    def test_21_every_score_maps_to_exactly_one_severity(self):
        expected_bands = {
            0: SEVERITY_INFO,
            1: SEVERITY_LOW, 9: SEVERITY_LOW,
            10: SEVERITY_MEDIUM, 19: SEVERITY_MEDIUM,
            20: SEVERITY_HIGH, 39: SEVERITY_HIGH,
            40: SEVERITY_CRITICAL, 100: SEVERITY_CRITICAL,
        }
        for score in range(101):
            severity, low, high = POLICY.band_for(score)
            self.assertIn(severity, expected_bands.values())
            self.assertGreaterEqual(score, low)
            self.assertLessEqual(score, high)
            if score in expected_bands:
                self.assertEqual(severity, expected_bands[score])

    def test_band_ranges_are_disjoint_and_exhaustive(self):
        bands = validate_severity_bands(POLICY.severity_bands)
        covered = set()
        for _severity, low, high in bands:
            for value in range(low, high + 1):
                self.assertNotIn(value, covered, "bands overlap")
                covered.add(value)
        self.assertEqual(covered, set(range(101)))


class TestScoreCalculation(unittest.TestCase):
    def test_19_score_with_no_findings_is_zero_info(self):
        result = score_findings([], POLICY)
        self.assertEqual(result.score, 0)
        self.assertEqual(result.severity, SEVERITY_INFO)

    def test_low_finding_contributes_6(self):
        result = score_findings([finding(SEVERITY_LOW)], POLICY)
        self.assertEqual(result.score, 6)
        self.assertEqual(result.severity, SEVERITY_LOW)

    def test_medium_contributes_12(self):
        result = score_findings([finding(SEVERITY_MEDIUM)], POLICY)
        self.assertEqual(result.score, 12)
        self.assertEqual(result.severity, SEVERITY_MEDIUM)

    def test_high_contributes_25(self):
        result = score_findings([finding(SEVERITY_HIGH)], POLICY)
        self.assertEqual(result.score, 25)
        self.assertEqual(result.severity, SEVERITY_HIGH)

    def test_category_cap_bounds_one_theme(self):
        # Two HIGH findings in the SAME category cap at the category cap (30)
        # instead of stacking to 50 -> stays HIGH, never CRITICAL.
        a = finding(SEVERITY_HIGH, related_variable="esp.presence")
        b = finding(SEVERITY_HIGH, related_variable="tunnel.activity")
        result = score_findings([a, b], POLICY)
        self.assertEqual(result.score, POLICY.category_cap)
        self.assertEqual(result.severity, SEVERITY_HIGH)
        details = dict(result.to_dict())
        totals = dict(result.per_category_totals)
        self.assertEqual(totals[CATEGORY_OBSERVED_MISMATCH], POLICY.category_cap)
        self.assertEqual(result.contributions[-1]["added"], 5)  # capped remainder

    def test_cross_category_stacking_can_reach_critical(self):
        a = finding(SEVERITY_HIGH, related_variable="mode",
                    category=CATEGORY_CONFIGURATION_WEAKNESS)
        b = finding(SEVERITY_HIGH, related_variable="esp.presence",
                    category=CATEGORY_OBSERVED_MISMATCH)
        result = score_findings([a, b], POLICY)
        self.assertEqual(result.score, 50)
        self.assertEqual(result.severity, SEVERITY_CRITICAL)

    def test_20_score_always_within_zero_to_hundred(self):
        severities = (SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM,
                      SEVERITY_HIGH, SEVERITY_CRITICAL)
        categories = (
            "CONFIGURATION_WEAKNESS", "OBSERVED_MISMATCH",
            "PROTOCOL_ANOMALY", "CONFIGURATION_MISMATCH",
        )
        worst = 0
        for a in severities:
            for b in severities:
                for c in severities:
                    result = score_findings(
                        [
                            finding(a, category=categories[0]),
                            finding(b, category=categories[1]),
                            finding(c, category=categories[2]),
                            finding(c, category=categories[3]),
                        ],
                        POLICY,
                    )
                    self.assertGreaterEqual(result.score, 0)
                    self.assertLessEqual(result.score, 100)
                    worst = max(worst, result.score)
        self.assertEqual(worst, 100)  # CRITICAL findings saturate at the cap

    def test_score_cap_saturates(self):
        # The score cap is reachable only by stacking CRITICAL-weight findings
        # across MULTIPLE categories (a single theme is bounded by the category
        # cap, so no one category can reach CRITICAL by itself).
        categories = (
            "CONFIGURATION_WEAKNESS", "OBSERVED_MISMATCH",
            "PROTOCOL_ANOMALY", "CONFIGURATION_MISMATCH",
        )
        findings_row = [
            finding(SEVERITY_CRITICAL, category=cat, related_variable=f"v{i}")
            for i, cat in enumerate(categories)
        ]
        result = score_findings(findings_row, POLICY)
        self.assertEqual(result.score, POLICY.score_cap)
        self.assertEqual(result.severity, SEVERITY_CRITICAL)

    def test_9_deterministic_same_inputs_same_score(self):
        findings_row = [
            finding(SEVERITY_HIGH, related_variable="mode"),
            finding(SEVERITY_MEDIUM, related_variable="esp.pfs"),
            finding(SEVERITY_LOW, related_variable="esp.dh_group"),
        ]
        first = score_findings(findings_row, POLICY)
        second = score_findings(findings_row, POLICY)
        self.assertEqual(first.to_dict(), second.to_dict())
        repeated = score_findings(list(findings_row), POLICY)
        self.assertEqual(repeated.score, first.score)
        self.assertEqual(repeated.severity, first.severity)


class TestDeduplicationBeforeScoring(unittest.TestCase):
    def test_22_duplicate_findings_are_deduplicated_before_scoring(self):
        a = finding(SEVERITY_MEDIUM, finding_id="RISK-PFS-DISABLED",
                    related_variable="esp.pfs",
                    source="EXPECTED_CONFIGURATION",
                    category=CATEGORY_CONFIGURATION_WEAKNESS)
        b = finding(SEVERITY_MEDIUM, finding_id="RISK-PFS-AGAIN",
                    related_variable="esp.pfs",
                    source="EXPECTED_CONFIGURATION",
                    category=CATEGORY_CONFIGURATION_WEAKNESS)
        deduped = deduplicate_findings([a, b], POLICY)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0].finding_id, "RISK-PFS-DISABLED")
        result = score_findings([a, b], POLICY)
        dedup_result = score_findings(deduped, POLICY)
        # duplicates contribute once, not twice
        self.assertEqual(dedup_result.score, 12)
        self.assertLess(dedup_result.score, result.raw_sum or 24)

    def test_dedup_respects_policy_keys(self):
        a = finding(SEVERITY_LOW, finding_id="A", related_variable="ML_ANOMALY",
                    source="ML")
        b = finding(SEVERITY_LOW, finding_id="B", related_variable="ML_ANOMALY",
                    source="ML")
        c = finding(SEVERITY_LOW, finding_id="C", related_variable="esp.dh_group",
                    source="EXPECTED_CONFIGURATION")
        deduped = deduplicate_findings([a, b, c], POLICY)
        self.assertEqual(len(deduped), 2)


class TestDeterministicIdSuffix(unittest.TestCase):
    def test_repeated_id_gets_deterministic_suffix(self):
        a = finding(SEVERITY_LOW, finding_id="RISK-X",
                    related_variable="traffic.activity")
        b = finding(SEVERITY_LOW, finding_id="RISK-X",
                    related_variable="tunnel.activity")
        result = deduplicate_findings([a, b], POLICY)
        ids = [f.finding_id for f in result]
        self.assertIn("RISK-X", ids)
        self.assertIn("RISK-X-2", ids)


if __name__ == "__main__":
    unittest.main()