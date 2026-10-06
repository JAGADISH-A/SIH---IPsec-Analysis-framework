"""Mission context: explicit, operator-supplied asset context.

The premise under test is narrow and specific: an evidence-derived *technical*
risk stays exactly as the risk engine computed it, and a *separately declared*
asset context produces an additional, separately labelled contextualized number.
Nothing in this suite asserts that mission criticality can be discovered from a
capture, because it cannot and must not be.

Test classes map onto the milestone's acceptance list:

* ``TestProfileLoadsAsConfiguration``      -- 1, 2, 6, 17
* ``TestWeightingModel``                   -- 3, 4, 13, 14, 15
* ``TestNoProfileBehaviour``               -- 5, 6
* ``TestSameFindingDifferentAssets``       -- 7, 8, 9, 10, 11, 12
* ``TestProvenanceBoundary``               -- 2, 16
* ``TestCustodyIntegration``               -- 16, 18
* ``TestApiAndOpenApi``                    -- 19
* ``TestBoundaryIsEnforcedNotJustIntended`` -- the milestone's own constraints,
  asserted against the source rather than assumed: no control-plane import, no
  observed or modelled state, one read-only file open, and no new route.
"""

import ast
import copy
import json
import os
import pathlib
import re
import types
import unittest

from correlation.api.custody_routes import (
    handle_assessment_finding_explanation,
    handle_finding_explanation,
)
from correlation.api.openapi import openapi_document
from correlation.api.store import build_store
from correlation.custody.builder import _mission_integrity
from correlation.custody.models import (
    AUTHORITATIVE_CATEGORIES,
    CATEGORY_AUTHORITY,
    CHECK_FAIL,
    CHECK_PASS,
    FACT_CONFIGURED,
    FACT_OBSERVED,
    ChainOfCustody,
)
from correlation.mission import (
    CONTEXT_SOURCE,
    CRITICALITIES,
    MISSION_CONTEXT_MODEL_VERSION,
    MISSION_IMPACTS,
    MISSION_PROFILES_RELATIVE_PATH,
    ROLES,
    STATUS_CONFIGURED,
    STATUS_NOT_CONFIGURED,
    AssetMissionProfile,
    context_multiplier_bp,
    contextualize,
    load_mission_profiles,
    mission_context,
    weight_of,
)
from correlation.artifacts import REPO_ROOT
from correlation.mission.contextualize import ContextualizedRisk
from correlation.mission.profiles import AssetMissionProfile as ProfileFromDict
from correlation.risk.policy import RiskPolicy

#: A real assessment with a real MEDIUM finding, reused by the demonstration.
DEMO_ASSESSMENT = "dataset-20260924-003710:4:pfs-weak"
DEMO_FINDING = "RISK-PFS-DISABLED"
#: A real assessment whose technical risk crosses a severity band once the
#: declared context is high.
BAND_ASSESSMENT = "dataset-20260924-003710:75:ml-mismatch"
BAND_FINDING = "RISK-ML-CLASSIFICATION"

#: The two declared assets shipped in the profile file: a low-criticality
#: development gateway and a high-criticality operational gateway.
LOW_ASSET = "gw-a"
HIGH_ASSET = "gw-b"

#: The custody integrity set that predates mission context.
LEGACY_CHECK_IDS = [
    "finding.record_digest",
    "evidence.artifact_digests",
    "observation.authoritative_value_present",
    "observation.expected_observed_coherent",
    "provenance.artifact_digests",
    "audit.chain_linked",
    "xai.non_authoritative",
]


def profile(asset_id="a", role="test", criticality="low", mission_impact="low"):
    return AssetMissionProfile(
        asset_id=asset_id,
        role=role,
        criticality=criticality,
        mission_impact=mission_impact,
    )


def chain_for(asset_id=None, profiles="default"):
    """One real chain, built the way the API builds it."""
    book = load_mission_profiles() if profiles == "default" else profiles
    return build_store(asset_id=asset_id, mission_profiles=book).chain_of_custody(
        DEMO_ASSESSMENT, DEMO_FINDING
    )


class TestProfileLoadsAsConfiguration(unittest.TestCase):
    """1, 2, 6, 17: a valid profile loads, and loads as *input*."""

    @classmethod
    def setUpClass(cls):
        cls.book = load_mission_profiles()

    def test_a_valid_profile_file_loads(self):
        self.assertEqual(self.book.asset_ids(), (LOW_ASSET, HIGH_ASSET))
        self.assertEqual(len(self.book), 2)
        gw_a = self.book.get(LOW_ASSET)
        self.assertEqual(
            (gw_a.role, gw_a.criticality, gw_a.mission_impact),
            ("development", "low", "low"),
        )
        gw_b = self.book.get(HIGH_ASSET)
        self.assertEqual(
            (gw_b.role, gw_b.criticality, gw_b.mission_impact),
            ("operational-communications", "high", "high"),
        )

    def test_categories_are_bounded(self):
        for asset_id in self.book.asset_ids():
            declared = self.book.get(asset_id)
            with self.subTest(asset_id=asset_id):
                self.assertIn(declared.role, ROLES)
                self.assertIn(declared.criticality, CRITICALITIES)
                self.assertIn(declared.mission_impact, MISSION_IMPACTS)

    def test_an_out_of_range_category_is_refused(self):
        for kwargs in (
            {"criticality": "catastrophic"},
            {"mission_impact": "very-high"},
            {"role": "totally-made-up"},
        ):
            with self.subTest(**kwargs):
                with self.assertRaises(ValueError):
                    profile(**kwargs)

    def test_a_malformed_profile_is_refused_rather_than_half_loaded(self):
        """A silently-ignored profile would be a silently-absent context."""
        for bad in (
            {"asset_id": "x"},                                      # missing
            {"asset_id": "x", "role": "test", "criticality": "low",
             "mission_impact": "low", "criticity": "high"},        # typo
            "not-an-object",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    ProfileFromDict.from_dict(bad)

    def test_an_unknown_asset_has_no_profile(self):
        for absent in ("gw-does-not-exist", None, "", 7):
            with self.subTest(asset_id=absent):
                self.assertIsNone(self.book.get(absent))

    def test_the_source_is_a_relative_path_with_a_digest(self):
        self.assertEqual(self.book.source, MISSION_PROFILES_RELATIVE_PATH)
        self.assertEqual(len(self.book.source_sha256), 64)
        self.assertFalse(os.path.isabs(self.book.source))

    def test_no_absolute_host_path_reaches_a_profile(self):
        """17: the profile provenance discloses nothing about the host."""
        text = json.dumps(self.book.to_dict())
        self.assertNotIn(REPO_ROOT, text)
        self.assertNotIn(os.path.expanduser("~"), text)
        self.assertNotIn(os.path.abspath(os.sep), text.replace(MISSION_PROFILES_RELATIVE_PATH, ""))

    def test_the_profile_cannot_smuggle_a_path_as_an_asset_id(self):
        for bad in ("../escape", "/etc/passwd", "a/b", "..", "gw-a/"):
            with self.subTest(asset_id=bad):
                with self.assertRaises(ValueError):
                    profile(asset_id=bad)


class TestWeightingModel(unittest.TestCase):
    """3, 4, 13, 14, 15: the model itself."""

    def test_the_existing_technical_scale_is_retained(self):
        """The contextualized number lives on the existing 0-100 scale."""
        for technical in (0, 1, 12, 30, 99, 100):
            with self.subTest(technical=technical):
                risk = contextualize(
                    technical, "MEDIUM", profile(criticality="high", mission_impact="high")
                )
                self.assertEqual(risk.score_cap, 100)
                self.assertGreaterEqual(risk.contextualized_risk, 0)
                self.assertLessEqual(risk.contextualized_risk, risk.score_cap)

    def test_a_low_context_does_not_inflate_anything(self):
        """A 'low' asset is never made to look worse than the evidence says."""
        policy = RiskPolicy.default()
        for technical in (0, 6, 12, 30, 67):
            with self.subTest(technical=technical):
                severity = policy.band_for(technical)[0]
                risk = contextualize(technical, severity, profile())
                self.assertEqual(risk.multiplier_bp, 10000)
                self.assertEqual(risk.contextualized_risk, technical)
                self.assertEqual(risk.contextualized_severity, risk.technical_severity)

    def test_the_contextualized_risk_never_falls_below_technical(self):
        for criticality in CRITICALITIES:
            for impact in MISSION_IMPACTS:
                with self.subTest(criticality=criticality, impact=impact):
                    risk = contextualize(
                        24, "HIGH", profile(criticality=criticality, mission_impact=impact)
                    )
                    self.assertGreaterEqual(risk.contextualized_risk, risk.technical_risk)

    def test_the_uplift_is_capped_at_fifty_percent(self):
        _, best = context_multiplier_bp("high", "high")
        self.assertEqual(best, 15000)
        self.assertEqual(
            contextualize(
                100, "CRITICAL", profile(criticality="high", mission_impact="high")
            ).contextualized_risk,
            100,
        )

    def test_more_declared_context_never_means_less_risk(self):
        """Monotonic in each argument: raising either never lowers the risk."""
        for held, varying in (("mission_impact", "criticality"),
                              ("criticality", "mission_impact")):
            for fixed in CRITICALITIES:
                previous = -1
                for level in CRITICALITIES:
                    with self.subTest(held=held, fixed=fixed, level=level):
                        kwargs = {held: fixed, varying: level}
                        risk = contextualize(12, "MEDIUM", profile(**kwargs))
                        self.assertGreaterEqual(
                            risk.contextualized_risk, previous,
                            f"{kwargs} lost risk against the previous level",
                        )
                        previous = risk.contextualized_risk

    def test_the_context_index_is_a_symmetric_average(self):
        for criticality in CRITICALITIES:
            for impact in MISSION_IMPACTS:
                with self.subTest(criticality=criticality, impact=impact):
                    swapped = contextualize(
                        12, "MEDIUM", profile(criticality=impact, mission_impact=criticality)
                    )
                    self.assertEqual(
                        swapped.multiplier_bp,
                        contextualize(
                            12, "MEDIUM",
                            profile(criticality=criticality, mission_impact=impact),
                        ).multiplier_bp,
                    )

    def test_the_multiplier_is_reported_and_reproducible(self):
        """A consumer can redo the arithmetic from the emitted numbers."""
        risk = contextualize(
            12, "MEDIUM", profile(criticality="medium", mission_impact="high")
        )
        self.assertEqual(
            risk.contextualized_risk, min(100, (12 * risk.multiplier_bp) // 10000)
        )
        self.assertEqual(
            risk.context_index,
            (risk.criticality_weight + risk.mission_impact_weight) // 2,
        )
        self.assertEqual(risk.criticality_weight, weight_of("medium"))
        self.assertEqual(risk.mission_impact_weight, weight_of("high"))
        self.assertGreater(risk.multiplier_bp, 10000)

    def test_the_calculation_is_deterministic(self):
        """14: same inputs, same number, every time."""
        declared = profile(criticality="high", mission_impact="medium")
        self.assertEqual(
            len({contextualize(12, "MEDIUM", declared).contextualized_risk
                 for _ in range(50)}),
            1,
        )

    def test_the_model_version_is_explicit(self):
        """15: a consumer can tell two model versions apart."""
        risk = contextualize(12, "MEDIUM", profile(criticality="high", mission_impact="high"))
        self.assertEqual(risk.model_version, "mission-context-v1")
        self.assertEqual(risk.model_version, MISSION_CONTEXT_MODEL_VERSION)
        self.assertIn("contextualized", risk.formula)

    def test_the_role_never_enters_the_calculation(self):
        """A role rename must not be able to move a risk number."""
        development = contextualize(
            12, "MEDIUM", profile(role="development", criticality="high", mission_impact="high")
        )
        operational = contextualize(
            12, "MEDIUM",
            profile(role="operational-communications", criticality="high", mission_impact="high"),
        )
        self.assertEqual(development.contextualized_risk, operational.contextualized_risk)
        self.assertEqual(development.multiplier_bp, operational.multiplier_bp)

    def test_contextualized_severity_uses_the_existing_bands(self):
        policy = RiskPolicy.default()
        for criticality in CRITICALITIES:
            for impact in MISSION_IMPACTS:
                with self.subTest(criticality=criticality, impact=impact):
                    risk = contextualize(
                        30, "HIGH", profile(criticality=criticality, mission_impact=impact)
                    )
                    self.assertEqual(
                        risk.contextualized_severity,
                        policy.band_for(risk.contextualized_risk)[0],
                    )

    def test_an_out_of_range_technical_risk_is_refused(self):
        for bad in (-1, 101, 12.5, "12", True, None):
            with self.subTest(technical=bad):
                with self.assertRaises(ValueError):
                    contextualize(
                        bad, "MEDIUM", profile(criticality="high", mission_impact="high")
                    )

    def test_the_result_serialises_with_its_own_audit_trail(self):
        payload = contextualize(
            12, "MEDIUM", profile(criticality="high", mission_impact="high")
        ).to_dict()
        self.assertEqual(payload["technical_risk"], 12)
        self.assertEqual(payload["contextualized_risk"], 18)
        self.assertEqual(payload["technical_severity"], "MEDIUM")
        self.assertFalse(payload["inferred_from_traffic"])
        json.dumps(payload)


class TestNoProfileBehaviour(unittest.TestCase):
    """5, 6: the hard requirement -- no profile, no invented context."""

    def test_a_missing_profile_reports_not_configured(self):
        for context in (
            mission_context(12, "MEDIUM", None, load_mission_profiles()),
            mission_context(12, "MEDIUM", "gw-zzz", load_mission_profiles()),
            mission_context(12, "MEDIUM", "gw-a", None),
            mission_context(12, "MEDIUM", "", load_mission_profiles()),
        ):
            with self.subTest(asset_id=context.asset_id):
                self.assertEqual(context.status, STATUS_NOT_CONFIGURED)
                self.assertFalse(context.configured)
                self.assertIsNone(context.profile)
                self.assertIsNone(context.risk)
                self.assertIn("unchanged", context.reason)

    def test_no_default_criticality_is_assumed(self):
        """6: absent context must not read as a quiet 'low' or 'medium'."""
        payload = mission_context(
            12, "MEDIUM", "gw-unmapped", load_mission_profiles()
        ).to_dict()
        self.assertIsNone(payload["profile"])
        self.assertIsNone(payload["risk"])
        for key in ("criticality", "mission_impact", "role"):
            with self.subTest(key=key):
                self.assertNotIn(
                    key, payload,
                    f"{key} must be absent, never defaulted to a plausible value",
                )
        for key in ("context_source", "context_source_path", "context_source_sha256"):
            with self.subTest(key=key):
                self.assertIsNone(payload[key], f"{key} must be null, not a default")
        self.assertFalse(payload["derived_from_observation"])

    def test_an_unknown_asset_never_falls_back_to_a_known_one(self):
        context = mission_context(12, "MEDIUM", "gw-aa", load_mission_profiles())
        self.assertIsNone(context.profile)
        self.assertIsNone(context.risk)
        self.assertIn("gw-aa", context.reason)

    def test_the_store_without_an_asset_reports_not_configured(self):
        chain = build_store().chain_of_custody(DEMO_ASSESSMENT, DEMO_FINDING)
        self.assertEqual(chain.mission_context["status"], STATUS_NOT_CONFIGURED)
        self.assertIsNone(chain.mission_context["risk"])
        self.assertEqual(chain.risk_score, 12)
        self.assertEqual(chain.severity, "MEDIUM")

    def test_an_unmapped_asset_id_leaves_technical_risk_untouched(self):
        chain = chain_for(asset_id="gw-not-in-the-file")
        self.assertEqual(chain.mission_context["status"], STATUS_NOT_CONFIGURED)
        self.assertEqual(chain.risk_score, 12)
        self.assertEqual(chain.severity, "MEDIUM")

    def test_a_store_with_no_profile_file_reports_not_configured(self):
        chain = chain_for(asset_id=HIGH_ASSET, profiles=None)
        self.assertEqual(chain.mission_context["status"], STATUS_NOT_CONFIGURED)
        self.assertIsNone(chain.mission_context["risk"])


class TestSameFindingDifferentAssets(unittest.TestCase):
    """7-12: the primary acceptance demonstration."""

    @classmethod
    def setUpClass(cls):
        book = load_mission_profiles()
        # Two runs of the SAME plan and the SAME artifacts, differing only in the
        # asset the operator declared.
        cls.low = build_store(asset_id=LOW_ASSET, mission_profiles=book)
        cls.high = build_store(asset_id=HIGH_ASSET, mission_profiles=book)
        cls.chain_low = cls.low.chain_of_custody(DEMO_ASSESSMENT, DEMO_FINDING)
        cls.chain_high = cls.high.chain_of_custody(DEMO_ASSESSMENT, DEMO_FINDING)

    def test_same_finding_is_explained_under_both_assets(self):
        for chain in (self.chain_low, self.chain_high):
            with self.subTest(asset=chain.mission_context["asset_id"]):
                self.assertEqual(chain.assessment_id, DEMO_ASSESSMENT)
                self.assertEqual(chain.finding_id, DEMO_FINDING)

    def test_the_contextualized_result_differs_by_declared_context(self):
        low = self.chain_low.mission_context["risk"]
        high = self.chain_high.mission_context["risk"]
        self.assertEqual((low["technical_risk"], high["technical_risk"]), (12, 12))
        self.assertEqual(low["contextualized_risk"], 12)
        self.assertEqual(high["contextualized_risk"], 18)
        self.assertEqual(low["multiplier_bp"], 10000)
        self.assertEqual(high["multiplier_bp"], 15000)

    def test_the_observed_state_is_identical_between_the_runs(self):
        """9: nothing about the capture changed."""
        self.assertEqual(
            self.low.custody_inputs[DEMO_ASSESSMENT].observed.to_dict(),
            self.high.custody_inputs[DEMO_ASSESSMENT].observed.to_dict(),
        )

    def test_the_evidence_references_are_identical_between_the_runs(self):
        """10: same evidence ids, same digests, same verification."""
        self.assertEqual(
            [(e.evidence_id, e.artifact_sha256, e.verification_status)
             for e in self.chain_low.evidence],
            [(e.evidence_id, e.artifact_sha256, e.verification_status)
             for e in self.chain_high.evidence],
        )
        self.assertTrue(self.chain_low.evidence, "a chain must cite evidence")

    def test_the_technical_risk_is_identical_between_the_runs(self):
        """11, and 3: the technical assessment is untouched by context."""
        self.assertEqual(self.chain_low.risk_score, self.chain_high.risk_score)
        self.assertEqual(self.chain_low.severity, self.chain_high.severity)
        self.assertEqual(self.chain_low.finding_digest, self.chain_high.finding_digest)
        for chain in (self.chain_low, self.chain_high):
            with self.subTest(asset=chain.mission_context["asset_id"]):
                self.assertEqual(
                    chain.mission_context["risk"]["technical_risk"], chain.risk_score
                )
                self.assertEqual(
                    chain.mission_context["risk"]["technical_severity"], chain.severity
                )

    def test_only_the_mission_parts_of_the_two_chains_differ(self):
        """12: every other part of the two chains is identical."""
        left = self.chain_low.to_dict()
        right = self.chain_high.to_dict()
        self.assertEqual(set(left), set(right))
        self.assertEqual(
            {key for key in left if left[key] != right[key]},
            {"mission_context", "facts", "limitations", "integrity"},
        )
        for key in ("risk_score", "severity", "summary", "evidence", "sources",
                    "rule", "steps", "recommendation", "determinism", "identity",
                    "assessment_id", "finding_id", "finding_digest"):
            with self.subTest(key=key):
                self.assertEqual(left[key], right[key])

    def test_the_observed_facts_are_untouched_by_context(self):
        observed_low = [f for f in self.chain_low.facts if f.category == FACT_OBSERVED]
        observed_high = [f for f in self.chain_high.facts if f.category == FACT_OBSERVED]
        self.assertEqual(observed_low, observed_high)
        self.assertTrue(observed_low, "the finding must cite an observation")

    def test_the_differing_facts_are_exactly_the_mission_ones(self):
        low = {f.fact_id: f for f in self.chain_low.facts}
        high = {f.fact_id: f for f in self.chain_high.facts}
        self.assertEqual(set(low), set(high))
        differing = sorted(
            key for key in low
            if low[key].value != high[key].value
            or low[key].category != high[key].category
        )
        self.assertTrue(
            all(key.startswith(("asset.", "configured.", "derived.")) for key in differing),
            f"non-mission facts changed: {differing}",
        )

    def test_only_the_configured_category_carries_mission_values(self):
        for chain in (self.chain_low, self.chain_high):
            configured = [f for f in chain.facts if f.category == FACT_CONFIGURED]
            with self.subTest(asset=chain.mission_context["asset_id"]):
                self.assertTrue(configured)
                self.assertEqual(
                    {f.authority for f in configured},
                    {CATEGORY_AUTHORITY[FACT_CONFIGURED]},
                )
        self.assertNotIn(FACT_CONFIGURED, AUTHORITATIVE_CATEGORIES)

    def test_a_band_can_be_crossed_without_touching_the_technical_band(self):
        """The reason this feature exists, on real recorded data."""
        low = self.low.chain_of_custody(BAND_ASSESSMENT, BAND_FINDING)
        high = self.high.chain_of_custody(BAND_ASSESSMENT, BAND_FINDING)
        self.assertEqual(low.risk_score, high.risk_score)
        self.assertEqual(low.risk_severity, high.risk_severity)
        self.assertEqual(low.risk_score, 30)
        self.assertEqual(low.risk_severity, "HIGH")
        # A low-criticality asset sees the risk exactly as the engine scored it.
        self.assertEqual(low.mission_context["risk"]["contextualized_risk"], 30)
        self.assertEqual(
            low.mission_context["risk"]["contextualized_severity"], "HIGH"
        )
        # The same risk, on a declared high-criticality asset, crosses a band.
        self.assertEqual(high.mission_context["risk"]["contextualized_risk"], 45)
        self.assertEqual(
            high.mission_context["risk"]["contextualized_severity"], "CRITICAL"
        )

    def test_the_contextualized_view_covers_the_risk_not_the_finding(self):
        """The technical pair is the assessment's; the finding's own severity is not
        what is contextualized, and it is never altered."""
        chain = self.high.chain_of_custody(BAND_ASSESSMENT, BAND_FINDING)
        risk = chain.mission_context["risk"]
        self.assertEqual(risk["technical_risk"], chain.risk_score)
        self.assertEqual(risk["technical_severity"], chain.risk_severity)
        self.assertEqual(chain.severity, "LOW")
        self.assertNotEqual(chain.severity, chain.risk_severity)
        self.assertEqual(
            chain.severity,
            self.low.chain_of_custody(BAND_ASSESSMENT, BAND_FINDING).severity,
        )


class TestProvenanceBoundary(unittest.TestCase):
    """2, 16: configured context is never dressed up as an observation."""

    @classmethod
    def setUpClass(cls):
        cls.chain = chain_for(asset_id=HIGH_ASSET)

    def test_configured_is_not_an_authoritative_category(self):
        self.assertNotIn(FACT_CONFIGURED, AUTHORITATIVE_CATEGORIES)
        self.assertEqual(
            CATEGORY_AUTHORITY[FACT_CONFIGURED], "configured_assessment_context"
        )

    def test_every_mission_fact_says_where_it_came_from(self):
        mission_facts = [
            f for f in self.chain.facts
            if f.category == FACT_CONFIGURED or f.fact_id == "derived.contextualized_risk"
        ]
        self.assertTrue(mission_facts)
        for fact in mission_facts:
            with self.subTest(fact_id=fact.fact_id):
                self.assertIn(MISSION_PROFILES_RELATIVE_PATH, fact.source)
                # Every mission fact must disclaim observation in its own words.
                self.assertTrue(
                    "not an observation" in fact.detail
                    or "not inferred from traffic" in fact.detail,
                    f"{fact.fact_id} does not disclaim observation: {fact.detail!r}",
                )
        declared = [f for f in mission_facts if f.fact_id.startswith("asset.")]
        self.assertTrue(declared)
        for fact in declared:
            with self.subTest(fact_id=fact.fact_id):
                self.assertIn("assessment input", fact.detail)

    def test_no_mission_value_is_filed_as_an_observation(self):
        observed = {
            fact.fact_id: fact.value
            for fact in self.chain.facts
            if fact.category == FACT_OBSERVED
        }
        self.assertTrue(observed)
        for value in (
            self.chain.mission_context["asset_id"],
            self.chain.mission_context["profile"]["role"],
            self.chain.mission_context["profile"]["criticality"],
            self.chain.mission_context["profile"]["mission_impact"],
        ):
            with self.subTest(value=value):
                self.assertNotIn(value, observed.values())

    def test_the_declared_values_are_reported_verbatim(self):
        profile_payload = self.chain.mission_context["profile"]
        self.assertEqual(
            profile_payload,
            {
                "asset_id": HIGH_ASSET,
                "role": "operational-communications",
                "criticality": "high",
                "mission_impact": "high",
            },
        )
        filed = {f.fact_id: f.value for f in self.chain.facts if f.fact_id.startswith("asset.")}
        self.assertEqual(filed["asset.asset_id"], HIGH_ASSET)
        self.assertEqual(filed["asset.criticality"], "high")
        self.assertEqual(filed["asset.mission_impact"], "high")
        self.assertEqual(filed["asset.role"], "operational-communications")

    def test_the_context_declares_that_it_was_not_derived_from_observation(self):
        self.assertFalse(self.chain.mission_context["derived_from_observation"])
        self.assertFalse(self.chain.mission_context["risk"]["inferred_from_traffic"])
        self.assertEqual(self.chain.mission_context["context_source"], CONTEXT_SOURCE)
        self.assertEqual(
            self.chain.mission_context["context_source_path"], MISSION_PROFILES_RELATIVE_PATH
        )
        self.assertEqual(len(self.chain.mission_context["context_source_sha256"]), 64)

    def test_a_limitation_states_the_provenance_boundary(self):
        joined = " ".join(self.chain.limitations).lower()
        self.assertIn("operator-declared", joined)
        self.assertIn("not observations", joined)
        self.assertIn("technical risk and severity are unchanged", joined)

    def test_the_context_check_states_the_source_digest(self):
        check = self.chain.integrity_check("mission.context_declared")
        self.assertIsNotNone(check)
        self.assertEqual(check.status, CHECK_PASS)
        self.assertIn(MISSION_PROFILES_RELATIVE_PATH, check.detail)
        self.assertIn("no mission value was derived from observed traffic", check.detail)

    def test_the_model_marks_itself_derived_and_versioned(self):
        risk = self.chain.mission_context["risk"]
        self.assertEqual(risk["model_version"], MISSION_CONTEXT_MODEL_VERSION)
        self.assertEqual(risk["technical_risk"], self.chain.risk_score)
        self.assertEqual(risk["score_cap"], 100)
        self.assertEqual(self.chain.mission_context["model_version"],
                         MISSION_CONTEXT_MODEL_VERSION)


class TestCustodyIntegration(unittest.TestCase):
    """16, 18: the previous milestone keeps working, unchanged."""

    def test_a_chain_without_context_keeps_the_legacy_integrity_set(self):
        """18: no mission check is invented for a chain that has no context."""
        plain = build_store().chain_of_custody(DEMO_ASSESSMENT, DEMO_FINDING)
        self.assertEqual([check.check_id for check in plain.integrity], LEGACY_CHECK_IDS)
        self.assertEqual(len(plain.facts), 10)
        self.assertFalse(
            [f for f in plain.facts if f.category == FACT_CONFIGURED]
        )

    def test_configured_context_adds_exactly_its_own_checks(self):
        chain = chain_for(asset_id=HIGH_ASSET)
        ids = [check.check_id for check in chain.integrity]
        self.assertEqual(ids, LEGACY_CHECK_IDS + [
            "mission.context_declared",
            "mission.risk_preserves_technical",
        ])

    def test_the_preservation_check_would_notice_a_broken_model(self):
        """The check is load-bearing, not decorative."""
        broken = ContextualizedRisk(
            technical_risk=12,
            technical_severity="MEDIUM",
            contextualized_risk=3,        # below the technical risk: impossible
            contextualized_severity="LOW",
            context_index=33,
            multiplier_bp=10000,
            criticality_weight=33,
            mission_impact_weight=33,
        )
        context = types.SimpleNamespace(
            configured=True,
            profile=profile(asset_id=HIGH_ASSET, criticality="high", mission_impact="high"),
            risk=broken,
            context_source=CONTEXT_SOURCE,
            context_source_path=MISSION_PROFILES_RELATIVE_PATH,
            context_source_sha256="0" * 64,
        )
        checks = _mission_integrity(context, technical_risk=12)
        self.assertEqual(checks[0].status, CHECK_PASS)
        self.assertEqual(checks[-1].check_id, "mission.risk_preserves_technical")
        self.assertEqual(checks[-1].status, CHECK_FAIL)

    def test_a_real_context_passes_the_same_checks(self):
        context = mission_context(12, "MEDIUM", HIGH_ASSET, load_mission_profiles())
        checks = _mission_integrity(context, technical_risk=12)
        self.assertEqual(
            [c.status for c in checks], [CHECK_PASS, CHECK_PASS]
        )
        self.assertEqual(
            [c.check_id for c in checks],
            ["mission.context_declared", "mission.risk_preserves_technical"],
        )

    def test_no_context_adds_no_mission_checks(self):
        for context in (
            mission_context(12, "MEDIUM", None, load_mission_profiles()),
            mission_context(12, "MEDIUM", "gw-zzz", load_mission_profiles()),
        ):
            with self.subTest(status=context.status):
                self.assertEqual(_mission_integrity(context, technical_risk=12), [])

    def test_the_chain_round_trips_with_mission_context(self):
        chain = chain_for(asset_id=LOW_ASSET)
        again = ChainOfCustody.from_dict(chain.to_dict())
        self.assertEqual(again.to_dict(), chain.to_dict())
        self.assertEqual(again.mission_context, chain.mission_context)

    def test_mission_context_does_not_mutate_the_pipeline_objects(self):
        store = build_store(asset_id=HIGH_ASSET, mission_profiles=load_mission_profiles())
        held = store.custody_inputs[DEMO_ASSESSMENT]
        before = (
            copy.deepcopy(held.assessment.to_dict()),
            copy.deepcopy(held.observed.to_dict()),
            copy.deepcopy(held.response_plan.to_dict()),
        )
        for _ in range(3):
            store.chain_of_custody(DEMO_ASSESSMENT, DEMO_FINDING)
        after = (
            held.assessment.to_dict(),
            held.observed.to_dict(),
            held.response_plan.to_dict(),
        )
        self.assertEqual(before, after)

    def test_contextualized_risk_is_reproducible_across_store_builds(self):
        first = chain_for(asset_id=HIGH_ASSET)
        second = chain_for(asset_id=HIGH_ASSET)
        self.assertEqual(first.mission_context["risk"], second.mission_context["risk"])
        self.assertEqual(
            first.mission_context["context_source_sha256"],
            second.mission_context["context_source_sha256"],
        )


class TestApiAndOpenApi(unittest.TestCase):
    """19: the existing explanation route carries the new fields."""

    @classmethod
    def setUpClass(cls):
        cls.store = build_store(
            asset_id=HIGH_ASSET, mission_profiles=load_mission_profiles()
        )

    def test_the_existing_route_exposes_mission_context(self):
        payload = handle_assessment_finding_explanation(
            self.store, DEMO_ASSESSMENT, DEMO_FINDING
        )
        context = payload["mission_context"]
        self.assertEqual(context["status"], STATUS_CONFIGURED)
        self.assertEqual(context["asset_id"], HIGH_ASSET)
        self.assertEqual(context["risk"]["technical_risk"], payload["risk_score"])
        self.assertEqual(payload["risk_score"], 12)
        self.assertEqual(context["risk"]["contextualized_risk"], 18)
        json.dumps(payload)

    def test_the_flat_route_exposes_it_too(self):
        payload = handle_finding_explanation(
            self.store, DEMO_FINDING, {"assessment_id": DEMO_ASSESSMENT}
        )
        self.assertEqual(payload["mission_context"]["status"], STATUS_CONFIGURED)
        self.assertEqual(payload["mission_context"]["profile"]["criticality"], "high")

    def test_a_store_without_context_reports_not_configured_over_the_api(self):
        payload = handle_assessment_finding_explanation(
            build_store(), DEMO_ASSESSMENT, DEMO_FINDING
        )
        self.assertEqual(payload["mission_context"]["status"], STATUS_NOT_CONFIGURED)
        self.assertIsNone(payload["mission_context"]["risk"])
        self.assertEqual(payload["risk_score"], 12)

    def test_no_absolute_path_is_served(self):
        payload = handle_assessment_finding_explanation(
            self.store, DEMO_ASSESSMENT, DEMO_FINDING
        )
        self.assertNotIn(REPO_ROOT, json.dumps(payload))
        self.assertEqual(
            payload["mission_context"]["context_source_path"],
            MISSION_PROFILES_RELATIVE_PATH,
        )

    def test_the_document_declares_the_new_field_and_categories(self):
        schema = openapi_document()["components"]["schemas"]["ChainOfCustody"]
        self.assertIn("mission_context", schema["properties"])
        facts = schema["properties"]["facts"]["items"]["properties"]
        self.assertIn(FACT_CONFIGURED, facts["category"]["enum"])
        self.assertIn("configured_assessment_context", facts["authority"]["enum"])
        self.assertIn("CONFIGURED", schema["properties"]["facts"]["description"])
        json.dumps(openapi_document())

    @staticmethod
    def _mission_context_schema(document=None):
        """The mission-context schema, resolved through whatever it is reached by.

        It was declared inline on ``ChainOfCustody`` until the asset selector
        needed the same document at ``/api/v1/assets/{asset_id}/context``. It is now
        a named component referenced from both, so resolving the reference here
        keeps these assertions about the shape rather than about where the shape
        happens to be spelled out.
        """
        document = document or openapi_document()
        schemas = document["components"]["schemas"]
        property_schema = schemas["ChainOfCustody"]["properties"]["mission_context"]
        if "properties" in property_schema:
            return property_schema
        (reference,) = property_schema["allOf"]
        self_ref = reference["$ref"].rsplit("/", 1)[-1]
        return schemas[self_ref]

    def test_the_contextualized_severity_is_declared_beside_the_technical_one(self):
        mission_context = self._mission_context_schema()
        risk = mission_context["properties"]["risk"]
        self.assertIn("technical_risk", risk["required"])
        self.assertIn("technical_severity", risk["required"])
        self.assertIn("contextualized_risk", risk["required"])
        self.assertIn("contextualized_severity", risk["required"])
        self.assertIn("model_version", risk["required"])
        status = mission_context["properties"]["status"]
        self.assertEqual(status["enum"], ["configured", "not_configured"])

    def test_no_new_route_was_introduced(self):
        """The feature rides the existing response; no asset-management API.

        The route count is pinned so a new surface cannot appear unnoticed, so
        the later drift milestone's three read-only routes are named here
        explicitly, as is the XDP capture feed. What this test really protects
        is the *shape* of the API: still no asset-management surface, and every
        route still a GET.

        The two asset routes were added later, and deliberately: they are the
        query side of this same model, not a management surface. They are named
        here for the same reason the others are -- an unnamed route must not be
        able to appear -- and they are additionally pinned to being reads below.
        """
        document = openapi_document()
        drift_routes = {
            "/api/v1/drift",
            "/api/v1/drift/baselines",
            "/api/v1/assessments/{id}/drift",
        }
        # The live XDP capture feed: the read-only tail of the shared live
        # journal that carries real observed packets into the API. It is part of
        # the observation path, not a new management surface, so it is named
        # here rather than allowed to push the pinned base count.
        capture_routes = {"/api/v1/capture/events"}
        # Read-only asset queries. `GET /api/v1/assets` is what a client reads to
        # learn which assets an operator declared, and `.../{asset_id}/context`
        # is this same model addressed by a chosen asset instead of the one the
        # store was started with. Neither creates, configures or removes an
        # asset, which is what the "no asset-management API" boundary means.
        asset_routes = {
            "/api/v1/assets",
            "/api/v1/assets/{asset_id}/context",
        }
        named = drift_routes | capture_routes | asset_routes
        # The security-analysis products (brief areas 1-9) are sub-resources of
        # the assessment that produced them: same id, same read-only verb, same
        # envelope. Naming them here is what keeps the pinned base count honest
        # while asserting that the answer surface grew *inside* an existing
        # family rather than as a new API.
        analysis_product_routes = {
            "/api/assessments/{id}/expected",
            "/api/assessments/{id}/observed",
            "/api/assessments/{id}/sa",
            "/api/assessments/{id}/crypto-evidence",
            "/api/assessments/{id}/replay",
            "/api/assessments/{id}/metadata-exposure",
            "/api/assessments/{id}/threat-matrix",
            "/api/assessments/{id}/report",
            "/api/assessments/{id}/executive-report",
        }
        named |= analysis_product_routes
        self.assertLessEqual(named, set(document["paths"]))
        self.assertEqual(len(set(document["paths"]) - named), 33)
        self.assertEqual(len(document["paths"]), 33 + len(named))
        # An assessment sub-resource that is not one of these is a new surface
        # (or a typo), not a query.
        self.assertEqual(
            {path for path in document["paths"]
             if path.startswith("/api/assessments/{id}/")},
            {
                "/api/assessments/{id}/correlation",
                "/api/assessments/{id}/risk",
                "/api/assessments/{id}/xai",
                "/api/assessments/{id}/ml",
                "/api/assessments/{id}/evidence",
                "/api/assessments/{id}/ipsec-state",
            } | analysis_product_routes,
        )
        # The asset surface is exactly the two sanctioned reads: an asset path
        # that is not one of these is a new surface, not a query.
        self.assertEqual(
            {path for path in document["paths"] if "asset" in path.lower()},
            asset_routes,
        )
        for path, operations in document["paths"].items():
            self.assertEqual(
                sorted(operations), ["get"], f"{path} must stay read-only"
            )

    def test_the_documented_shape_matches_the_served_one(self):
        payload = handle_assessment_finding_explanation(
            self.store, DEMO_ASSESSMENT, DEMO_FINDING
        )
        mission_context = self._mission_context_schema()
        declared = set(mission_context["properties"])
        self.assertEqual(declared, set(payload["mission_context"]))
        risk = mission_context["properties"]["risk"]
        self.assertEqual(set(risk["properties"]), set(payload["mission_context"]["risk"]))
        self.assertLessEqual(set(risk["required"]), set(risk["properties"]))

    def test_the_asset_selector_route_documents_the_same_document(self):
        """One schema, referenced from both places it is served.

        The custody chain and the per-selected-asset route publish the identical
        document. It was inline on ``ChainOfCustody`` until the second consumer
        existed; leaving two copies would let them drift, which is the failure
        mode this test existed to catch for the original inline copy.
        """
        document = openapi_document()
        schemas = document["components"]["schemas"]

        def target(schema):
            """The named schema a property or response schema resolves to."""
            reference = schema.get("$ref")
            if reference is None:
                return None
            return schemas[reference.rsplit("/", 1)[-1]]

        from_custody = self._mission_context_schema(document)
        response = document["paths"]["/api/v1/assets/{asset_id}/context"]["get"][
            "responses"
        ]["200"]["content"]["application/json"]["schema"]
        asset_context = target(response)
        self.assertIsNotNone(asset_context)
        self.assertIn("mission_context", asset_context["properties"])
        from_assets = target(asset_context["properties"]["mission_context"])
        self.assertIs(from_assets, from_custody)
        self.assertIn("status", from_assets["properties"])
        self.assertIn("risk", from_assets["properties"])


class TestBoundaryIsEnforcedNotJustIntended(unittest.TestCase):
    """The constraints of the milestone, asserted rather than assumed."""

    @staticmethod
    def _modules():
        package = pathlib.Path(__file__).resolve().parents[1] / "correlation" / "mission"
        return sorted(package.glob("*.py"))

    @staticmethod
    def _imports(source):
        imported = set()
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        return imported

    def test_the_mission_package_does_not_import_the_control_plane(self):
        """Coupling mission context to the controller would be a real defect."""
        for source in self._modules():
            for name in sorted(self._imports(source)):
                with self.subTest(source=source.name, module=name):
                    self.assertNotEqual(
                        name.split(".")[0], "controller",
                        f"{source.name} now depends on the control plane: {name}",
                    )

    def test_the_mission_package_reads_no_observation_or_model_state(self):
        """Only the risk policy and the repo root are reachable from the package.

        An allowlist, not a blocklist: a new import of anything that carries
        captured or modelled state fails here, which is the point.
        """
        permitted = {"risk.policy", "artifacts", "models", "profiles",
                     "contextualize", "typing", "dataclasses", "json",
                     "os", "hashlib"}
        for source in self._modules():
            for name in sorted(self._imports(source)):
                relative = name[2:] if name.startswith("..") else name
                relative = relative.lstrip(".")
                with self.subTest(source=source.name, module=name):
                    self.assertNotIn(
                        relative.split(".")[0],
                        {"ml", "correlation", "custody", "api", "shap",
                         "sklearn", "numpy", "pandas"},
                        f"{source.name} imports {name}, which can carry "
                        f"observed or modelled state",
                    )
                    self.assertIn(relative, permitted, f"unexpected import {name}")

    def test_the_mission_layer_opens_exactly_one_file_read_only(self):
        """It reads the profile file and creates nothing, anywhere."""
        opened = 0
        for source in self._modules():
            for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
                if not (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == "open"):
                    continue
                opened += 1
                mode = node.args[1].value if len(node.args) > 1 else "r"
                with self.subTest(source=source.name, mode=mode):
                    self.assertEqual(mode, "rb", f"{source.name} must read only")
        self.assertEqual(opened, 1, "only the profile file may be opened")

    def test_the_only_file_the_package_knows_is_the_profile_file(self):
        for source in self._modules():
            for constant in re.findall(r'^"([^"]*\.json)"', source.read_text("utf-8"),
                                       re.MULTILINE):
                with self.subTest(source=source.name, constant=constant):
                    self.assertEqual(constant, MISSION_PROFILES_RELATIVE_PATH)

    def test_the_custody_and_api_layers_do_not_import_the_controller(self):
        for relative in ("correlation/custody/builder.py",
                         "correlation/custody/models.py",
                         "correlation/api/store.py"):
            source = pathlib.Path(__file__).resolve().parents[1] / relative
            for name in sorted(self._imports(source)):
                with self.subTest(source=relative, module=name):
                    self.assertNotEqual(name.split(".")[0], "controller")


if __name__ == "__main__":
    unittest.main()
