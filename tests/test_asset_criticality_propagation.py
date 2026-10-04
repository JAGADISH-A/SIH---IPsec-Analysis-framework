"""Asset criticality: the value an analyst is shown is the one that was calculated.

``tests/test_mission_context.py`` proves the *model* is bounded, deterministic and
provenance-aware. This suite proves something different and complementary: that the
declared criticality survives the whole path an analyst actually walks --

    configs/mission/asset_mission_profiles.json
        -> AssetMissionProfile / MissionProfileBook
        -> mission_context() / contextualize()
        -> AssessmentStore.chain_of_custody()
        -> GET /api/v1/assessments/{id}/findings/{id}/explanation
        -> AssetPriorityPanel

-- and that a break anywhere along that chain makes a test fail.

The gap this suite was written for: the calculation existed and was correct, but
the production entry point never supplied an ``asset_id`` or a profile book, and
the frontend panel read ``priority``/``asset_priority``/top-level ``criticality``,
none of which the API has ever published. The result was a correct, tested
calculation that no user could see and no deployment could configure. A test that
only asserts the arithmetic passes in exactly that world, which is why the
propagation assertions below exist.

The contract under test is the project's own, unchanged:

* input attributes: ``role``, ``criticality``, ``mission_impact`` per asset
* categories: ``low`` / ``medium`` / ``high`` for criticality and mission impact
* rules: weights 33/66/100, ``context_index`` the integer average, uplift measured
  from the 33 floor, at most 50%, integer floor division, capped at the existing 100
* unknown or unconfigured assets: ``not_configured`` with no assumed criticality
"""

import copy
import json
import os
import pathlib
import unittest

from correlation.api.custody_routes import (
    handle_assessment_finding_explanation,
    handle_finding_explanation,
)
from correlation.api.store import build_store
from correlation.mission import (
    CONTEXT_SOURCE,
    CRITICALITIES,
    MISSION_IMPACTS,
    MISSION_PROFILES_RELATIVE_PATH,
    STATUS_CONFIGURED,
    STATUS_NOT_CONFIGURED,
    AssetMissionProfile,
    context_multiplier_bp,
    load_mission_profiles,
    mission_context,
    weight_of,
)
from correlation.mission.contextualize import (
    MAX_UPLIFT_BP,
    NEUTRAL_BP,
    TECHNICAL_SCORE_CAP,
    WEIGHT_FLOOR,
)
from correlation.artifacts import REPO_ROOT
from correlation.risk.policy import RiskPolicy

REPO = pathlib.Path(REPO_ROOT)
PANEL = REPO / "sentinel-frontend/src/components/traffic/panels.tsx"
PROFILE_FILE = REPO / MISSION_PROFILES_RELATIVE_PATH

#: The two declared testbed assets: low-criticality development, high-criticality
#: operational communications.
LOW_ASSET = "gw-a"
HIGH_ASSET = "gw-b"

#: A real assessment/finding pair reused from the existing mission-context suite.
ASSESSMENT = "dataset-20260924-003710:4:pfs-weak"
FINDING = "RISK-PFS-DISABLED"


def profile(asset_id="a", role="test", criticality="low", mission_impact="low"):
    return AssetMissionProfile(
        asset_id=asset_id,
        role=role,
        criticality=criticality,
        mission_impact=mission_impact,
    )


def book_from(profiles):
    """A profile book built in memory, so a test can declare an asset the
    shipped two-asset file does not contain without editing the shipped file."""
    from correlation.mission.profiles import MissionProfileBook

    payload = {p.asset_id: p for p in profiles}
    return MissionProfileBook(payload, source="in-test", source_sha256="0" * 64)


def chain_for(asset_id, profiles=None, assessment=ASSESSMENT, finding=FINDING):
    book = load_mission_profiles() if profiles is None else profiles
    return build_store(asset_id=asset_id, mission_profiles=book).chain_of_custody(
        assessment, finding
    )


def served_chain(store, assessment=ASSESSMENT, finding=FINDING):
    """The payload the API actually returns, not an internal object."""
    return handle_assessment_finding_explanation(store, assessment, finding)


def context_of(payload):
    return payload["mission_context"]


class TestTheDeclaredInventoryIsRealConfiguration(unittest.TestCase):
    """The asset inventory exists as declared input, and is closed."""

    def test_the_shipped_profile_file_declares_the_two_testbed_assets(self):
        payload = json.loads(PROFILE_FILE.read_text("utf-8"))
        self.assertEqual(
            sorted(payload["assets"]), [LOW_ASSET, HIGH_ASSET],
            "the shipped inventory is the two declared testbed gateways",
        )
        self.assertEqual(payload["assets"][LOW_ASSET]["criticality"], "low")
        self.assertEqual(payload["assets"][HIGH_ASSET]["criticality"], "high")

    def test_criticality_and_impact_use_only_the_bounded_categories(self):
        self.assertEqual(CRITICALITIES, ("low", "medium", "high"))
        self.assertEqual(MISSION_IMPACTS, ("low", "medium", "high"))
        payload = json.loads(PROFILE_FILE.read_text("utf-8"))
        for asset_id, declared in payload["assets"].items():
            with self.subTest(asset=asset_id):
                self.assertIn(declared["criticality"], CRITICALITIES)
                self.assertIn(declared["mission_impact"], MISSION_IMPACTS)

    def test_the_asset_id_is_the_only_link_between_asset_and_profile(self):
        """Criticality is looked up by declared id, never derived from evidence."""
        book = load_mission_profiles()
        self.assertEqual(book.get(LOW_ASSET).criticality, "low")
        self.assertEqual(book.get(HIGH_ASSET).criticality, "high")
        # An id that appears in no profile resolves to nothing at all.
        self.assertIsNone(book.get("host-c"))


class TestALowCriticalityAssetIsNotInflated(unittest.TestCase):
    """Case 1: the clearly low-criticality asset."""

    @classmethod
    def setUpClass(cls):
        cls.book = load_mission_profiles()
        cls.context = mission_context(40, "HIGH", LOW_ASSET, cls.book)
        cls.payload = served_chain(build_store(
            asset_id=LOW_ASSET, mission_profiles=cls.book
        ))

    def test_the_low_asset_is_configured_from_its_own_declaration(self):
        self.assertEqual(self.context.status, STATUS_CONFIGURED)
        self.assertTrue(self.context.configured)
        self.assertEqual(self.context.profile.criticality, "low")

    def test_a_low_low_profile_multiplies_by_exactly_one(self):
        index, multiplier = context_multiplier_bp("low", "low")
        self.assertEqual(index, WEIGHT_FLOOR)
        self.assertEqual(
            multiplier, NEUTRAL_BP,
            "the uplift is measured from the lowest declared value, so a low "
            "asset is never made to look worse",
        )
        self.assertEqual(
            self.context.risk.contextualized_risk, self.context.risk.technical_risk
        )

    def test_the_served_payload_carries_the_low_criticality(self):
        context = context_of(self.payload)
        self.assertTrue(context["configured"])
        self.assertEqual(context["profile"]["criticality"], "low")
        self.assertEqual(context["profile"]["mission_impact"], "low")

    def test_a_low_asset_is_never_labelled_with_another_assets_criticality(self):
        served = context_of(self.payload)["profile"]["criticality"]
        self.assertNotEqual(served, "high")
        self.assertNotIn("high", served)


class TestAHighCriticalityAssetIsUplifted(unittest.TestCase):
    """Case 2: the clearly high-criticality asset."""

    @classmethod
    def setUpClass(cls):
        cls.book = load_mission_profiles()
        cls.context = mission_context(30, "HIGH", HIGH_ASSET, cls.book)
        cls.payload = served_chain(build_store(
            asset_id=HIGH_ASSET, mission_profiles=cls.book
        ))

    def test_the_high_asset_reaches_the_ceiling_multiplier(self):
        index, multiplier = context_multiplier_bp("high", "high")
        self.assertEqual(index, 100)
        self.assertEqual(multiplier, NEUTRAL_BP + MAX_UPLIFT_BP)
        self.assertEqual(self.context.risk.multiplier_bp, NEUTRAL_BP + MAX_UPLIFT_BP)

    def test_the_high_asset_is_uplifted_and_never_lowered(self):
        risk = self.context.risk
        self.assertGreater(risk.contextualized_risk, risk.technical_risk)
        self.assertGreaterEqual(
            risk.contextualized_risk, risk.technical_risk,
            "context may add context but never subtract risk",
        )

    def test_the_same_technical_score_yields_a_higher_number_for_high(self):
        low = mission_context(30, "HIGH", LOW_ASSET, self.book).risk
        high = self.context.risk
        self.assertEqual(low.technical_risk, high.technical_risk)
        self.assertLess(low.contextualized_risk, high.contextualized_risk)

    def test_the_served_payload_carries_the_high_criticality(self):
        context = context_of(self.payload)
        self.assertEqual(context["profile"]["criticality"], "high")
        self.assertEqual(context["risk"]["multiplier_bp"], NEUTRAL_BP + MAX_UPLIFT_BP)
        self.assertGreater(
            context["risk"]["contextualized_risk"], context["risk"]["technical_risk"]
        )


class TestAnIntermediateAssetIsSupported(unittest.TestCase):
    """Case 3: the middle category the contract explicitly supports."""

    def setUp(self):
        self.book = book_from([
            profile("mid", "mission-support", "medium", "medium"),
        ])

    def test_medium_medium_sits_strictly_between_low_and_high(self):
        low, _ = context_multiplier_bp("low", "low")
        mid, mid_bp = context_multiplier_bp("medium", "medium")
        high, high_bp = context_multiplier_bp("high", "high")
        self.assertTrue(low < mid < high)
        self.assertTrue(NEUTRAL_BP < mid_bp < NEUTRAL_BP + MAX_UPLIFT_BP)

    def test_a_medium_asset_lands_between_the_two_declared_assets(self):
        low = mission_context(30, "HIGH", LOW_ASSET, load_mission_profiles()).risk
        mid = mission_context(30, "HIGH", "mid", self.book).risk
        high = mission_context(30, "HIGH", HIGH_ASSET, load_mission_profiles()).risk
        self.assertLess(low.contextualized_risk, mid.contextualized_risk)
        self.assertLess(mid.contextualized_risk, high.contextualized_risk)

    def test_mixed_declarations_average_rather_than_max(self):
        """criticality high / impact low is not the same as high/high."""
        both_high, high_bp = context_multiplier_bp("high", "high")
        mixed, mixed_bp = context_multiplier_bp("high", "low")
        self.assertGreater(mixed_bp, NEUTRAL_BP)
        self.assertLess(mixed_bp, high_bp)

    def test_the_medium_asset_is_served_as_configured(self):
        payload = served_chain(build_store(asset_id="mid", mission_profiles=self.book))
        context = context_of(payload)
        self.assertEqual(context["profile"]["criticality"], "medium")
        self.assertEqual(context["risk"]["criticality_weight"], weight_of("medium"))


class TestMissingOrPartialInformationIsNeverCompleted(unittest.TestCase):
    """Case 4: missing or partial asset information."""

    def test_a_profile_missing_a_field_is_refused_rather_than_defaulted(self):
        for missing in ("asset_id", "role", "criticality", "mission_impact"):
            payload = profile().to_dict()
            del payload[missing]
            with self.subTest(missing=missing):
                with self.assertRaises(ValueError):
                    AssetMissionProfile.from_dict(payload)

    def test_a_malformed_profile_file_raises_instead_of_half_loading(self):
        import tempfile

        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False
        ) as handle:
            json.dump({"schema_version": "v1", "assets": {LOW_ASSET: {
                "asset_id": LOW_ASSET, "role": "development",
            }}}, handle)
            path = handle.name
        try:
            with self.assertRaises(ValueError):
                load_mission_profiles(path)
        finally:
            os.unlink(path)

    def test_a_misspelled_criticality_cannot_silently_disable_context(self):
        with self.assertRaises(ValueError):
            profile(criticality="criticalty")

    def test_no_profile_file_means_not_configured_not_low(self):
        context = mission_context(50, "HIGH", HIGH_ASSET, None)
        self.assertEqual(context.status, STATUS_NOT_CONFIGURED)
        self.assertIsNone(context.profile)
        self.assertIsNone(context.risk)

    def test_the_served_payload_for_an_unconfigured_store_assumes_nothing(self):
        payload = served_chain(build_store())
        context = context_of(payload)
        self.assertEqual(context["status"], STATUS_NOT_CONFIGURED)
        self.assertFalse(context["configured"])
        self.assertIsNone(context["profile"])
        self.assertIsNone(context["risk"])


class TestAnUnknownAssetGetsNoCriticality(unittest.TestCase):
    """Case 5: unknown or unregistered assets."""

    def setUp(self):
        self.book = load_mission_profiles()

    def test_an_unregistered_asset_is_not_configured(self):
        context = mission_context(50, "CRITICAL", "gw-typo", self.book)
        self.assertEqual(context.status, STATUS_NOT_CONFIGURED)
        self.assertIsNone(context.profile)

    def test_an_unknown_asset_never_borrows_a_declared_one(self):
        unknown = mission_context(50, "CRITICAL", "gw-typo", self.book)
        high = mission_context(50, "CRITICAL", HIGH_ASSET, self.book)
        self.assertNotEqual(unknown.risk, high.risk)
        self.assertIsNone(unknown.risk)

    def test_a_missing_asset_id_is_not_configured(self):
        for asset_id in (None, "", 0):
            with self.subTest(asset_id=asset_id):
                context = mission_context(50, "CRITICAL", asset_id, self.book)
                self.assertEqual(context.status, STATUS_NOT_CONFIGURED)

    def test_the_served_payload_names_the_asset_it_could_not_resolve(self):
        payload = served_chain(build_store(
            asset_id="gw-typo", mission_profiles=self.book
        ))
        context = context_of(payload)
        self.assertFalse(context["configured"])
        self.assertEqual(context["asset_id"], "gw-typo")
        self.assertIsNone(context["profile"])


class TestBoundaryValuesAroundTheThresholds(unittest.TestCase):
    """Case 6: the boundaries of the existing categories and score range."""

    def test_the_weight_floor_and_ceiling_are_the_documented_ones(self):
        self.assertEqual(weight_of("low"), 33)
        self.assertEqual(weight_of("medium"), 66)
        self.assertEqual(weight_of("high"), 100)

    def test_the_neutral_and_maximum_multipliers_are_exact(self):
        self.assertEqual(context_multiplier_bp("low", "low"), (33, NEUTRAL_BP))
        self.assertEqual(
            context_multiplier_bp("high", "high"), (100, NEUTRAL_BP + MAX_UPLIFT_BP)
        )

    def test_a_zero_technical_score_stays_zero(self):
        book = load_mission_profiles()
        for asset_id in (LOW_ASSET, HIGH_ASSET):
            with self.subTest(asset=asset_id):
                risk = mission_context(0, "INFO", asset_id, book).risk
                self.assertEqual(risk.contextualized_risk, 0)

    def test_the_uplift_is_capped_at_the_existing_technical_ceiling(self):
        book = load_mission_profiles()
        risk = mission_context(
            TECHNICAL_SCORE_CAP, "CRITICAL", HIGH_ASSET, book
        ).risk
        self.assertLessEqual(risk.contextualized_risk, TECHNICAL_SCORE_CAP)
        self.assertEqual(risk.contextualized_risk, TECHNICAL_SCORE_CAP)

    def test_an_out_of_range_technical_risk_is_refused(self):
        for bad in (-1, 101, 1000):
            with self.subTest(score=bad):
                with self.assertRaises(ValueError):
                    mission_context(bad, "HIGH", HIGH_ASSET, load_mission_profiles())

    def test_a_non_integer_technical_risk_is_refused(self):
        for bad in (True, "40", 40.0, None):
            with self.subTest(score=bad):
                with self.assertRaises(ValueError):
                    mission_context(bad, "HIGH", HIGH_ASSET, load_mission_profiles())

    def test_the_contextualized_severity_uses_the_existing_bands(self):
        book = load_mission_profiles()
        for asset_id in (LOW_ASSET, HIGH_ASSET):
            risk = mission_context(45, "HIGH", asset_id, book).risk
            with self.subTest(asset=asset_id):
                self.assertEqual(
                    risk.contextualized_severity,
                    RiskPolicy.default().band_for(risk.contextualized_risk)[0],
                )


class TestRepeatedEvaluationIsDeterministic(unittest.TestCase):
    """Case 7: identical input yields identical output."""

    def test_the_calculation_is_reproducible_in_process(self):
        book = load_mission_profiles()
        first = mission_context(37, "HIGH", HIGH_ASSET, book).to_dict()
        for _ in range(5):
            self.assertEqual(mission_context(37, "HIGH", HIGH_ASSET, book).to_dict(), first)

    def test_the_served_payload_is_reproducible_across_store_builds(self):
        book = load_mission_profiles()
        first = served_chain(build_store(asset_id=HIGH_ASSET, mission_profiles=book))
        for _ in range(3):
            self.assertEqual(
                served_chain(build_store(asset_id=HIGH_ASSET, mission_profiles=book)),
                first,
            )

    def test_the_profile_book_is_immutable_and_snapshotted(self):
        book = load_mission_profiles()
        snapshot = book.to_dict()
        served_chain(build_store(asset_id=HIGH_ASSET, mission_profiles=book))
        self.assertEqual(book.to_dict(), snapshot)


class TestAssetsDoNotContaminateEachOther(unittest.TestCase):
    """Case 8: one asset's criticality never reaches another's result."""

    def test_identical_evidence_under_both_assets_differs_only_by_declaration(self):
        book = load_mission_profiles()
        low = chain_for(LOW_ASSET, book).to_dict()
        high = chain_for(HIGH_ASSET, book).to_dict()

        self.assertEqual(low["assessment_id"], high["assessment_id"],
                         "both chains describe the same assessment")

        observed = {
            f["fact_id"]: f["value"] for f in low["facts"]
            if f["category"] not in ("CONFIGURED", "DERIVED")
        }
        observed_high = {
            f["fact_id"]: f["value"] for f in high["facts"]
            if f["category"] not in ("CONFIGURED", "DERIVED")
        }
        self.assertEqual(observed, observed_high,
                         "every fact that is not declared context or derived "
                         "from it is identical across the two assets")

        self.assertEqual(low["mission_context"]["profile"]["criticality"], "low")
        self.assertEqual(high["mission_context"]["profile"]["criticality"], "high")

    def test_the_technical_risk_is_identical_across_assets(self):
        book = load_mission_profiles()
        low = context_of(served_chain(
            build_store(asset_id=LOW_ASSET, mission_profiles=book)))["risk"]
        high = context_of(served_chain(
            build_store(asset_id=HIGH_ASSET, mission_profiles=book)))["risk"]
        self.assertEqual(low["technical_risk"], high["technical_risk"])
        self.assertEqual(low["technical_severity"], high["technical_severity"])

    def test_the_asset_id_reported_is_the_one_requested(self):
        book = load_mission_profiles()
        for asset_id in (LOW_ASSET, HIGH_ASSET):
            payload = served_chain(build_store(asset_id=asset_id, mission_profiles=book))
            with self.subTest(asset=asset_id):
                self.assertEqual(context_of(payload)["asset_id"], asset_id)
                self.assertEqual(
                    context_of(payload)["profile"]["asset_id"], asset_id
                )

    def test_only_declared_mission_facts_differ_between_two_assets(self):
        book = load_mission_profiles()
        low = chain_for(LOW_ASSET, book)
        high = chain_for(HIGH_ASSET, book)

        low_by_id = {f.fact_id: f for f in low.facts}
        high_by_id = {f.fact_id: f for f in high.facts}
        self.assertEqual(sorted(low_by_id), sorted(high_by_id),
                         "the same fact ids exist for both assets")

        differing = [fact_id for fact_id in sorted(low_by_id)
                     if low_by_id[fact_id].value != high_by_id[fact_id].value]
        self.assertTrue(differing, "the two assets must not be identical")
        for fact_id in differing:
            with self.subTest(fact=fact_id):
                # Only declared context and the risk derived from it may differ.
                self.assertIn(
                    low_by_id[fact_id].category, ("CONFIGURED", "DERIVED")
                )


class TestTheValueTheUserSeesIsTheCalculatedOne(unittest.TestCase):
    """The propagation assertions: the analyst-facing number is the real one."""

    @classmethod
    def setUpClass(cls):
        cls.book = load_mission_profiles()

    def _context(self, asset_id):
        return context_of(served_chain(
            build_store(asset_id=asset_id, mission_profiles=self.book)
        ))

    def test_the_custody_chain_publishes_the_configured_criticality(self):
        for asset_id in (LOW_ASSET, HIGH_ASSET):
            chain = chain_for(asset_id, self.book).to_dict()
            with self.subTest(asset=asset_id):
                self.assertEqual(chain["mission_context"]["status"],
                                 STATUS_CONFIGURED)
                self.assertEqual(chain["mission_context"]["profile"]["criticality"],
                                 self.book.get(asset_id).criticality)

    def test_the_flat_route_publishes_the_same_context(self):
        store = build_store(asset_id=HIGH_ASSET, mission_profiles=self.book)
        nested = handle_assessment_finding_explanation(
            store, ASSESSMENT, FINDING
        )
        flat = handle_finding_explanation(
            store, FINDING, {"assessment_id": ASSESSMENT}
        )
        self.assertEqual(nested["mission_context"], flat["mission_context"])
        self.assertEqual(flat["mission_context"]["profile"]["criticality"], "high")

    def test_the_contextualized_score_is_recomputable_from_the_served_fields(self):
        """The published numbers must reproduce the published multiplier."""
        for asset_id in (LOW_ASSET, HIGH_ASSET):
            context = self._context(asset_id)
            risk = context["risk"]
            expected = min(
                risk["score_cap"],
                (risk["technical_risk"] * risk["multiplier_bp"]) // NEUTRAL_BP,
            )
            with self.subTest(asset=asset_id):
                self.assertEqual(risk["contextualized_risk"], expected)
                self.assertEqual(
                    risk["criticality_weight"],
                    weight_of(context["profile"]["criticality"]),
                )

    def test_no_absolute_host_path_is_ever_served(self):
        context = self._context(HIGH_ASSET)
        self.assertNotIn(str(REPO), context["context_source_path"])
        self.assertFalse(os.path.isabs(context["context_source_path"]))

    def test_the_context_declares_it_is_not_derived_from_observation(self):
        for asset_id in (LOW_ASSET, HIGH_ASSET):
            context = self._context(asset_id)
            with self.subTest(asset=asset_id):
                self.assertFalse(context["derived_from_observation"])
                self.assertFalse(context["risk"]["inferred_from_traffic"])

    def test_an_unconfigured_store_publishes_no_criticality_at_all(self):
        context = context_of(served_chain(build_store()))
        self.assertIsNone(context["asset_id"])
        self.assertIsNone(context["profile"])
        self.assertIsNone(context["risk"])


class TestTheProductionEntryPointCanBeConfigured(unittest.TestCase):
    """The calculation must be reachable from the process that actually serves.

    ``build_store`` accepts an ``asset_id`` and a profile book, but the analytics
    server never supplied either, so every real deployment answered
    ``not_configured``. This pins that the entry point can now be told which asset
    it is describing -- an additive capability, not a change in default behaviour.
    """

    @classmethod
    def setUpClass(cls):
        cls.source = (REPO / "correlation/api/app.py").read_text("utf-8")

    def test_the_server_accepts_an_asset_id_and_a_profile_file(self):
        # A substring check for "--asset-id" would still pass if the flag were
        # renamed to "--asset-id-disabled", so the option is pinned as an
        # argparse declaration and the value is pinned as reaching build_store.
        self.assertIn('"--asset-id", default=None', self.source)
        self.assertIn('"--mission-profiles", default=None', self.source)
        self.assertIn("asset_id=args.asset_id", self.source)
        self.assertIn("mission_profiles=mission_profiles", self.source)

    def test_the_server_refuses_an_asset_it_has_no_profile_for(self):
        """A typo must fail at startup, not serve a silently-defaulted context."""
        self.assertIn("no mission profile is declared for asset", self.source)

    def test_the_declared_asset_reaches_the_built_store(self):
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument("--asset-id", default=None)
        parser.add_argument("--mission-profiles", default=None)
        args = parser.parse_args(["--asset-id", HIGH_ASSET,
                                  "--mission-profiles",
                                  str(PROFILE_FILE)])
        store = build_store(asset_id=args.asset_id,
                            mission_profiles=load_mission_profiles(
                                args.mission_profiles))
        self.assertEqual(
            context_of(served_chain(store))["profile"]["criticality"], "high"
        )

    def test_the_default_invocation_stays_unconfigured(self):
        """An operator who declares nothing must still get ``not_configured``."""
        self.assertIsNone(context_of(served_chain(build_store()))["profile"])


class TestTheDeclaredAssetsAreRealTestbedNodes(unittest.TestCase):
    """Real-lab evidence, and its exact limit.

    The asset *identities* are real: ``gw-a`` and ``gw-b`` are actual containerlab
    nodes in ``topology/tunnel/ipsec.clab.yml``, each with its own swanctl
    configuration. What is **not** observable from the network is the criticality
    itself -- ``low`` and ``high`` are operator declarations in a JSON file, and
    nothing in a capture could confirm or contradict them. This class pins the
    identity correspondence without ever letting a declared value masquerade as
    a measurement.
    """

    @classmethod
    def setUpClass(cls):
        cls.topology = (REPO / "topology/tunnel/ipsec.clab.yml").read_text("utf-8")
        cls.book = load_mission_profiles()

    def test_every_declared_asset_id_is_a_real_testbed_node(self):
        for asset_id in self.book.asset_ids():
            with self.subTest(asset=asset_id):
                self.assertIn(f"{asset_id}:", self.topology)

    def test_the_declared_assets_are_distinct_nodes(self):
        self.assertEqual(len(self.book.asset_ids()), 2)
        self.assertNotEqual(LOW_ASSET, HIGH_ASSET)

    def test_a_testbed_node_with_no_profile_gets_no_criticality(self):
        """The topology declares nodes the inventory does not."""
        undeclared = [
            node for node in ("host-a", "host-b", "sensor", "br-wan")
            if f"{node}:" in self.topology
        ]
        self.assertTrue(undeclared, "the topology declares nodes beyond the gateways")
        for node in undeclared:
            with self.subTest(node=node):
                self.assertIsNone(self.book.get(node))
                context = mission_context(50, "CRITICAL", node, self.book)
                self.assertEqual(context.status, STATUS_NOT_CONFIGURED)

    def test_the_criticality_values_are_declared_not_measured(self):
        """The boundary, asserted: no declared value may claim observation."""
        for asset_id in self.book.asset_ids():
            context = mission_context(50, "HIGH", asset_id, self.book).to_dict()
            with self.subTest(asset=asset_id):
                self.assertFalse(context["derived_from_observation"])
                self.assertFalse(context["risk"]["inferred_from_traffic"])
                self.assertEqual(context["context_source"], CONTEXT_SOURCE)

    def test_the_profile_file_is_the_only_asset_inventory(self):
        """Criticality is read from one declared file, reported relatively."""
        self.assertEqual(self.book.source, MISSION_PROFILES_RELATIVE_PATH)
        self.assertEqual(len(self.book.source_sha256), 64)


class TestTheFrontendReadsTheFieldsTheApiPublishes(unittest.TestCase):
    """The analyst-facing panel must render the backend's own context.

    ``AssetPriorityPanel`` read ``priority``/``asset_priority`` at the top level
    and ``criticality`` at the top level. The API publishes none of those: it
    publishes ``profile.criticality``, ``profile.mission_impact`` and a ``risk``
    block whose ``context_index`` is the declared priority. Every row was
    therefore dropped and the panel was permanently empty.
    """

    @classmethod
    def setUpClass(cls):
        cls.source = PANEL.read_text("utf-8")

    def test_the_panel_never_renders_a_row_from_our_service(self):
        payload = served_chain(
            build_store(asset_id=HIGH_ASSET, mission_profiles=load_mission_profiles())
        )
        context = payload["mission_context"]
        self.assertTrue(context["configured"])
        self.assertNotIn("priority", context)
        self.assertNotIn("asset_priority", context)
        self.assertNotIn("criticality", context)
        self.assertEqual(context["profile"]["criticality"], "high")

    def test_the_panel_reads_the_profile_and_risk_blocks_the_api_serves(self):
        # The rendered-output proof lives in
        # sentinel-frontend/smoke/asset-criticality-smoke.ts, which renders this
        # panel with the exact served payload. These assertions only pin the
        # field paths so a rename fails here too.
        self.assertIn("record.profile", self.source)
        self.assertIn("record.risk", self.source)
        self.assertIn("profile.criticality", self.source)
        self.assertIn("risk.context_index", self.source)
        self.assertIn("profile.mission_impact", self.source)

    def test_the_panel_does_not_read_fields_that_do_not_exist(self):
        for phantom in ("asset_priority", "record.priority",
                        "record.criticality"):
            with self.subTest(field=phantom):
                self.assertNotIn(phantom, self.source)

    def test_a_rendered_panel_smoke_exists_and_is_wired_into_the_suite(self):
        smoke = REPO / "sentinel-frontend/smoke/asset-criticality-smoke.ts"
        self.assertTrue(smoke.exists(), "the panel must have a rendered-output check")
        source = smoke.read_text("utf-8")
        self.assertIn("AssetPriorityPanel", source)
        self.assertIn("profile", source)
        package = (REPO / "sentinel-frontend/package.json").read_text("utf-8")
        self.assertIn("smoke:asset-criticality", package)

    def test_an_unconfigured_context_still_yields_no_row(self):
        context = served_chain(build_store())["mission_context"]
        self.assertFalse(context["configured"])
        self.assertIsNone(context["profile"])