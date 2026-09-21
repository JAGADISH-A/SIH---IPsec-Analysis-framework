"""Phase 4 REAL-FIXTURE validation.

Uses the actual plan fixture (``tests/fixtures/datasets/.../plan.json``,
materialized by the Phase 3 ``ExpectedStateAdapter``) and, when available, the
real campaign artifact (``D:\\sihipsec\\campaign-quality.json``) for an
identity-safety cross-source check. No crypto is ever invented: the
"matching" scenario feeds the engine ONLY the plan's own canonical values as
authoritative observed evidence, and the "insufficient" scenario proves the
engine refuses to conclude anything from raw packet/presence observations.
"""

import os
import unittest

from correlation.adapters import ExpectedStateAdapter
from correlation.comparison import ComparisonEngine, ComparisonEngineOptions
from correlation.comparison import IdentityMismatchError
from correlation.models import (
    CORRELATION_STATUS_MATCH,
    CORRELATION_STATUS_MISMATCH,
    CORRELATION_STATUS_UNKNOWN,
    ObservedState,
)

PLAN_JSON = os.path.join(
    os.path.dirname(__file__),
    "fixtures",
    "datasets",
    "dataset-20260916-231246",
    "staging",
    "plan.json",
)
CAMPAIGN_JSON = r"D:\sihipsec\campaign-quality.json"


def materialize_sequence(sequence=1):
    return ExpectedStateAdapter(
        materialized_at="2026-09-20T00:00:00+00:00"
    ).from_plan(PLAN_JSON, sequence=sequence)


def observed_values_from(expected):
    """Authoritative audit-style observed values copied from the plan itself.

    This simulates the swanctl/audit channel that CAN observe crypto — the only
    channel the engine is allowed to match those variables against.
    """
    return {
        "mode": expected.mode,
        "address_family": expected.address_family,
        "ike.version": expected.ike.version,
        "ike.encryption": expected.ike.encryption,
        "ike.integrity": expected.ike.integrity,
        "ike.dh_group": expected.ike.dh_group,
        "esp.encryption": expected.esp.encryption,
        "esp.integrity": expected.esp.integrity,
        "esp.dh_group": expected.esp.dh_group,
        "esp.pfs": expected.esp.pfs,
        "traffic.profile": expected.traffic.profile,
        "traffic.duration": expected.traffic.duration,
        "traffic.port": expected.traffic.port,
    }


def build_observed():
    return ObservedState(
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
    )


def find_outcome(result, variable):
    for bucket in (result.matches, result.mismatches,
                   result.unknowns, result.not_applicable):
        for outcome in bucket:
            if outcome["variable"] == variable:
                return outcome
    return None


class TestRealFixtureComparison(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = ExpectedStateAdapter(materialized_at="2026-09-20T00:00:00+00:00")
        cls.engine = ComparisonEngine(ComparisonEngineOptions())

    def test_matching_evidence_is_match(self):
        materialized = self.adapter.from_plan(PLAN_JSON, sequence=1)
        result = self.engine.compare(
            materialized,
            build_observed(),
            observed_identity=materialized.identity,
            observed_values=observed_values_from(materialized.expected),
        )
        self.assertEqual(result.status, CORRELATION_STATUS_MATCH, result.to_json())
        self.assertEqual(result.mismatches, [])
        self.assertEqual(result.unknowns, [])
        self.assertEqual([o["variable"] for o in result.not_applicable],
                         ["capture_filter", "configuration_id",
                          "security_posture", "window.containment", "spi"])

    def test_contradictory_mode_is_mismatch_even_with_full_evidence(self):
        materialized = self.adapter.from_plan(PLAN_JSON, sequence=1)
        values = observed_values_from(materialized.expected)
        values["mode"] = "transport"  # authoritative contradiction of tunnel
        result = self.engine.compare(
            materialized,
            build_observed(),
            observed_identity=materialized.identity,
            observed_values=values,
        )
        self.assertEqual(result.status, CORRELATION_STATUS_MISMATCH)
        self.assertEqual(find_outcome(result, "mode")["status"],
                         CORRELATION_STATUS_MISMATCH)

    def test_insufficient_observation_is_unknown_not_guess(self):
        materialized = self.adapter.from_plan(PLAN_JSON, sequence=1)
        result = self.engine.compare(
            materialized,
            build_observed(),
            observed_identity=materialized.identity,
        )
        self.assertEqual(result.status, CORRELATION_STATUS_UNKNOWN)
        # crypto is NEVER inferred from raw observed presence/counters
        for variable in ("ike.encryption", "esp.encryption", "traffic.profile"):
            self.assertEqual(find_outcome(result, variable)["status"],
                             CORRELATION_STATUS_UNKNOWN)

    def test_cross_source_identity_safety(self):
        if not os.path.isfile(CAMPAIGN_JSON):
            self.skipTest("campaign-quality.json not available")
        plan_state = self.adapter.from_plan(PLAN_JSON, sequence=1)
        campaign_state = self.adapter.from_campaign(CAMPAIGN_JSON, sequence=1)
        self.assertNotEqual(plan_state.identity.dataset_run_id,
                            campaign_state.identity.dataset_run_id)
        with self.assertRaises(IdentityMismatchError):
            self.engine.compare(
                plan_state,
                build_observed(),
                observed_identity=campaign_state.identity,
            )

    def test_real_fixture_determinism(self):
        materialized = self.adapter.from_plan(PLAN_JSON, sequence=3)
        kwargs = dict(
            observed=build_observed(),
            observed_identity=materialized.identity,
            observed_values=observed_values_from(materialized.expected),
        )
        first = self.engine.compare(materialized, **kwargs)
        second = self.engine.compare(materialized, **kwargs)
        self.assertEqual(first.to_dict(), second.to_dict())


if __name__ == "__main__":
    unittest.main()