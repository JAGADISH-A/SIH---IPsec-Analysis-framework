"""Phase 3 tests: expected-state materialization from SIH artifacts.

Requirement: the authoritative SIH repository (D:\\sihipsec) is READ-ONLY.
All fixtures under tests/fixtures are committed as real artifacts and are
never modified by any test.
"""

import json
import os
import unittest
from pathlib import Path

from correlation.adapters import (
    ExpectedStateAdapter,
    ExpectedStateMaterializationError,
    MissingExpectedVariableError,
)
from correlation.models.expected import (
    CANONICAL_VARIABLES,
    ExpectedState,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REAL_PLAN = FIXTURES / "datasets" / "dataset-20260916-231246" / "staging" / "plan.json"
PLAN_WITH_TRAFFIC = FIXTURES / "plan_with_traffic.json"
MISSING_VARIABLE_PLAN = FIXTURES / "missing_variable_plan.json"
SIH_CAMPAIGN = Path(r"D:\sihipsec\campaign-quality.json")

RUN_ID = "dataset-20260916-231246"


class ExpectedStateMaterializationTest(unittest.TestCase):

    def setUp(self):
        self.adapter = ExpectedStateAdapter(materialized_at="2026-09-20T00:00:00+00:00")

    # -- Test 1: real plan extraction ------------------------------------
    def test_01_real_plan_extracts_expected_state(self):
        state = self.adapter.from_plan(REAL_PLAN, 1)
        self.assertIsInstance(state.expected, ExpectedState)
        self.assertEqual(state.identity.dataset_run_id, RUN_ID)
        self.assertEqual(state.identity.sequence, 1)
        self.assertEqual(
            state.identity.experiment_id,
            f"{RUN_ID}-exp-0001-attempt-01",
        )
        self.assertEqual(state.expected.mode, "tunnel")
        self.assertEqual(state.expected.address_family, "ipv4")
        self.assertEqual(state.expected.ike.version, 2)
        self.assertEqual(state.expected.traffic.profile, "voip")
        self.assertEqual(
            state.expected.configuration_id,
            "tunnel-ipv4-aes128gcm16-none-modp4096-true",
        )
        self.assertEqual(state.expected.security_posture, "STRONG")

    # -- Test 2: all 14 canonical variables populated ---------------------
    def test_02_all_fourteen_canonical_variables_present(self):
        state = self.adapter.from_plan(REAL_PLAN, 2)
        missing = self.adapter.check_all_canonical_variables(state.expected)
        self.assertEqual(missing, ())

    # -- Test 3: canonical names preserved (no renames) -------------------
    def test_03_canonical_variable_names_preserved(self):
        self.assertListEqual(list(CANONICAL_VARIABLES), [
            "mode",
            "address_family",
            "ike.version",
            "ike.encryption",
            "ike.integrity",
            "ike.dh_group",
            "esp.encryption",
            "esp.integrity",
            "esp.dh_group",
            "esp.pfs",
            "traffic.profile",
            "traffic.duration",
            "traffic.port",
            "capture_filter",
        ])

    # -- Test 4: GCM null-integrity preserved (never coerced) -------------
    def test_04_gcm_integrity_null_preserved(self):
        state = self.adapter.from_plan(REAL_PLAN, 1)
        self.assertEqual(state.expected.esp.encryption, "aes128gcm16")
        self.assertIsNone(state.expected.esp.integrity)
        payload = state.expected.to_dict()
        self.assertEqual(payload["esp"]["encryption"], "aes128gcm16")
        self.assertIsNone(payload["esp"]["integrity"])

    # -- Test 5: distinct samples distinguish different configurations ----
    def test_05_different_samples_yield_different_states(self):
        s1 = self.adapter.from_plan(REAL_PLAN, 1)
        s6 = self.adapter.from_plan(REAL_PLAN, 6)
        self.assertNotEqual(s1.expected, s6.expected)
        self.assertEqual(s1.expected.esp.dh_group, "modp4096")
        self.assertEqual(s6.expected.esp.dh_group, "modp3072")
        self.assertNotEqual(
            s1.expected.configuration_id,
            s6.expected.configuration_id,
        )

    # -- Test 6: physical attempt isolation ------------------------------
    def test_06_attempt_isolation(self):
        a1 = self.adapter.from_plan_record(
            json.loads(REAL_PLAN.read_text(encoding="utf-8")),
            run_id=RUN_ID,
            sequence=3,
            attempt_number=1,
        )
        a2 = self.adapter.from_plan_record(
            json.loads(REAL_PLAN.read_text(encoding="utf-8")),
            run_id=RUN_ID,
            sequence=3,
            attempt_number=2,
        )
        self.assertNotEqual(a1.identity.experiment_id, a2.identity.experiment_id)
        self.assertEqual(
            a1.identity.experiment_id, f"{RUN_ID}-exp-0003-attempt-01"
        )
        self.assertEqual(
            a2.identity.experiment_id, f"{RUN_ID}-exp-0003-attempt-02"
        )
        self.assertEqual(a1.identity.attempt_number, 1)
        self.assertEqual(a2.identity.attempt_number, 2)
        self.assertEqual(a1.expected, a2.expected)

    # -- Test 7: missing variable fails fast ------------------------------
    def test_07_missing_expected_variable_fails_fast(self):
        with self.assertRaises(MissingExpectedVariableError) as ctx:
            self.adapter.from_plan(MISSING_VARIABLE_PLAN, 1, run_id=RUN_ID)
        exc = ctx.exception
        self.assertEqual(exc.missing_variable, "esp.encryption")
        self.assertEqual(exc.run_id, RUN_ID)
        self.assertEqual(exc.sequence, 1)
        self.assertIn(RUN_ID, exc.experiment_id)
        self.assertIn("missing_variable_plan.json", exc.source_file)
        self.assertIn("esp.encryption", exc.describe())

    # -- Test 8: provenance present and per-variable ----------------------
    def test_08_provenance_traceability(self):
        state = self.adapter.from_plan(REAL_PLAN, 2)
        prov = state.provenance
        self.assertEqual(prov.source_type, "plan")
        self.assertEqual(prov.source_record, "sequence=2")
        self.assertEqual(prov.materialized_at, "2026-09-20T00:00:00+00:00")
        sources = prov.variable_sources
        # all 14 canonical variables must be traceable (map also carries the
        # two derived keys configuration_id and security_posture)
        self.assertTrue(set(CANONICAL_VARIABLES) <= set(sources.keys()))
        for variable in CANONICAL_VARIABLES:
            status, source_key = sources[variable]
            self.assertIn(status, ("MAPPED", "MAPPED_WITH_NORMALIZATION", "UNAVAILABLE"))
            self.assertTrue(source_key, f"{variable} must carry a source key")
        self.assertIn("MAPPED", sources["esp.encryption"][0])
        self.assertIn("MAPPED", sources["configuration_id"][0])

    # -- Test 9: deterministic output (fixed materialized_at) -------------
    def test_09_deterministic_output(self):
        a = self.adapter.from_plan(REAL_PLAN, 4).to_json()
        b = self.adapter.from_plan(REAL_PLAN, 4).to_json()
        self.assertEqual(a, b)

    # -- Test 10: batch materialization count == sample count -------------
    def test_10_batch_materializes_all_samples(self):
        states = self.adapter.materialize_all_plan_samples(REAL_PLAN)
        self.assertEqual(len(states), 6)
        sequences = sorted(s.identity.sequence for s in states)
        self.assertEqual(sequences, [1, 2, 3, 4, 5, 6])
        self.assertEqual(len({s.identity.experiment_id for s in states}), 6)


class ExpectedStateTrafficOverrideTest(unittest.TestCase):
    """Explicit per-sample traffic values are preserved verbatim."""

    def setUp(self):
        self.adapter = ExpectedStateAdapter(materialized_at="2026-09-20T00:00:00+00:00")

    def test_per_sample_traffic_overrides_preserved(self):
        state = self.adapter.from_plan(PLAN_WITH_TRAFFIC, 1, run_id=RUN_ID)
        self.assertEqual(state.expected.traffic.duration, 25)
        self.assertEqual(state.expected.traffic.port, 21000)
        self.assertEqual(state.expected.capture_filter, "esp")
        self.assertEqual(
            state.provenance.variable_sources["capture_filter"][1],
            "plan.samples[1].traffic.capture_filter",
        )
        self.assertEqual(
            state.provenance.variable_sources["capture_filter"][0],
            "MAPPED",
        )


class ExpectedStateCampaignTest(unittest.TestCase):
    """Extraction directly from authoritative campaign JSONs."""

    @unittest.skipUnless(SIH_CAMPAIGN.exists(), "D:\\sihipsec not present")
    def setUp(self):
        self.adapter = ExpectedStateAdapter(materialized_at="2026-09-20T00:00:00+00:00")
        campaign = json.loads(SIH_CAMPAIGN.read_text(encoding="utf-8"))
        self.experiments = campaign["experiments"]

    def test_campaign_experiments_map_to_expected_states(self):
        for i, expected in enumerate(self.experiments, start=1):
            state = self.adapter.from_campaign(SIH_CAMPAIGN, i)
            self.assertEqual(state.identity.dataset_run_id, "quality-01")
            self.assertEqual(
                state.identity.experiment_id, f"quality-01-exp-{i:04d}"
            )
            # payload agrees with the authoritative record
            self.assertEqual(state.expected.mode, expected["mode"])
            self.assertEqual(
                state.expected.capture_filter,
                expected["traffic"]["capture_filter"],
            )
            self.assertEqual(
                state.provenance.variable_sources["capture_filter"][0],
                "MAPPED",
            )

    def test_campaign_preserves_gcm_null_integrity_and_filter(self):
        state = self.adapter.from_campaign(SIH_CAMPAIGN, 3)
        self.assertEqual(state.expected.esp.encryption, "aes256gcm16")
        self.assertIsNone(state.expected.esp.integrity)
        self.assertEqual(state.expected.capture_filter, "esp")

    def test_campaign_posture_unavailable_not_computed(self):
        state = self.adapter.from_campaign(SIH_CAMPAIGN, 1)
        self.assertIsNone(state.expected.security_posture)
        self.assertEqual(
            state.provenance.variable_sources["security_posture"][0],
            "UNAVAILABLE",
        )


if __name__ == "__main__":
    unittest.main()