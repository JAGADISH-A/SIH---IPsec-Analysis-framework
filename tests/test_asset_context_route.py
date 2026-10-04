"""The asset selector must reach a real backend, and the backend must be the answer.

``tests/test_asset_criticality_propagation.py`` proves the value an analyst is
shown survives the path *the store was started with*: ``--asset-id`` ->
``chain_of_custody`` -> the custody explanation. That path is closed to a
selector, because ``AssessmentStore.asset_id`` is fixed when the store is built
and every request therefore answers about the same asset.

So a UI offering ``gw-a`` / ``gw-b`` had no route to ask about the asset the
operator did *not* start the store with. This suite covers the thin route that
was added to expose the existing capability
(``GET /api/v1/assets/{asset_id}/context``) and, just as importantly, proves what
that route is *not*:

* it delegates. If it ever computes a contextualised score itself, the delegation
  test fails;
* it is read-only. Selecting an asset does not rebind the store, so the custody
  explanation keeps reporting the startup asset;
* it invents nothing. An undeclared asset is ``not_configured`` with no profile
  and no criticality, exactly as ``mission_context`` already behaved;
* it is reachable from the router and documented, so the frontend's client and
  the OpenAPI contract cannot drift apart.

The tests here deliberately assert on values fetched from the shipped profile
file rather than on literals, so they keep meaning something if the declared
inventory ever changes.
"""

import os
import pathlib
import unittest

from correlation.api.asset_routes import (
    ASSET_CONTEXT_SUFFIX,
    ASSETS_PATH,
    handle_asset_context,
    handle_assets,
)
from correlation.api.app import handle_combined
from correlation.api.live import Phase10Context
from correlation.api.openapi import openapi_document
from correlation.api.routes import ApiError
from correlation.api.store import build_store
from correlation.mission import (
    MISSION_PROFILES_RELATIVE_PATH,
    STATUS_CONFIGURED,
    STATUS_NOT_CONFIGURED,
    context_multiplier_bp,
    load_mission_profiles,
    mission_context,
    weight_of,
)
from correlation.mission.profiles import MissionProfileBook
from correlation.mission.models import CRITICALITIES

from correlation.artifacts import REPO_ROOT

REPO = pathlib.Path(REPO_ROOT)
PANEL = REPO / "sentinel-frontend/src/components/traffic/panels.tsx"
ANALYTICS = REPO / "sentinel-frontend/src/api/analytics.ts"
CONTEXT_PANEL = REPO / "sentinel-frontend/src/components/traffic/panels.tsx"
PROFILE_FILE = REPO / MISSION_PROFILES_RELATIVE_PATH

#: A real assessment id from the shipped plan, reused from the existing suites.
ASSESSMENT = "dataset-20260924-003710:4:pfs-weak"


def book_from(profiles):
    """A profile book built in memory, so a test can declare an asset the
    shipped two-asset file does not contain without editing the shipped file."""
    payload = {p.asset_id: p for p in profiles}
    return MissionProfileBook(payload, source="in-test", source_sha256="0" * 64)


def lowest_and_highest(book):
    """The declared low- and high-criticality assets, read from the file.

    Nothing in this suite hardcodes which asset is which: the point of the test
    is that the backend's declared criticality reaches the client, so choosing
    the assets from the file is what makes the assertion meaningful.
    """
    declared = [book.get(asset_id) for asset_id in book.asset_ids()]
    low = min((p for p in declared if p.criticality == "low"),
              key=lambda p: p.asset_id)
    high = max((p for p in declared if p.criticality == "high"),
               key=lambda p: p.asset_id)
    return low.asset_id, high.asset_id


class TestTheAssetListIsTheSelectorsOnlySource(unittest.TestCase):
    """A selector has to learn which assets exist from the backend."""

    @classmethod
    def setUpClass(cls):
        cls.book = load_mission_profiles()
        cls.store = build_store(asset_id=cls.book.asset_ids()[0],
                                mission_profiles=cls.book)

    def test_the_list_is_the_profiles_the_operator_declared(self):
        payload = handle_assets(self.store)
        self.assertTrue(payload["configured"])
        self.assertIsNone(payload["reason"])
        self.assertEqual(tuple(payload["assets"]), self.book.asset_ids())

    def test_the_list_carries_the_files_provenance(self):
        payload = handle_assets(self.store)
        self.assertEqual(payload["source"], self.book.source)
        self.assertEqual(payload["source_sha256"], self.book.source_sha256)
        self.assertFalse(os.path.isabs(payload["source"]))
        self.assertNotIn(str(REPO), payload["source"])

    def test_the_list_says_which_asset_the_custody_route_reports(self):
        payload = handle_assets(self.store)
        self.assertEqual(payload["store_asset_id"], self.store.asset_id)

    def test_an_unconfigured_store_declares_nothing_rather_than_guessing(self):
        payload = handle_assets(build_store())
        self.assertFalse(payload["configured"])
        self.assertEqual(payload["assets"], [])
        self.assertIsNotNone(payload["reason"])
        self.assertIsNone(payload["store_asset_id"])

    def test_a_missing_store_is_unavailable_not_empty(self):
        """An empty list means "the operator declared nothing"; it must never be
        used to report a store that was not attached."""
        with self.assertRaises(ApiError) as caught:
            handle_assets(None)
        self.assertEqual(caught.exception.status, 503)


class TestTheSelectedAssetReachesTheExistingCalculation(unittest.TestCase):
    """The route must delegate to ``mission_context``, not reimplement it."""

    @classmethod
    def setUpClass(cls):
        cls.book = load_mission_profiles()
        cls.low, cls.high = lowest_and_highest(cls.book)
        cls.store = build_store(asset_id=cls.low, mission_profiles=cls.book)

    def _context(self, asset_id, params=None):
        payload = handle_asset_context(self.store, asset_id, params or {})
        self.assertEqual(payload["asset_id"], asset_id)
        self.assertTrue(payload["read_only"])
        return payload

    def test_the_low_criticality_asset_reports_low_and_is_not_inflated(self):
        context = self._context(self.low)["mission_context"]
        self.assertEqual(context["status"], STATUS_CONFIGURED)
        self.assertEqual(context["asset_id"], self.low)
        self.assertEqual(context["profile"]["criticality"], "low")
        # A low-criticality asset must not be pushed above its technical score.
        risk = context["risk"]
        self.assertEqual(risk["contextualized_risk"], risk["technical_risk"])
        self.assertEqual(
            risk["multiplier_bp"], context_multiplier_bp("low", "low")[1]
        )

    def test_the_high_criticality_asset_reports_high_and_is_uplifted(self):
        context = self._context(self.high)["mission_context"]
        self.assertEqual(context["status"], STATUS_CONFIGURED)
        self.assertEqual(context["asset_id"], self.high)
        self.assertEqual(context["profile"]["criticality"], "high")
        risk = context["risk"]
        self.assertGreater(risk["contextualized_risk"], risk["technical_risk"])
        self.assertEqual(
            risk["multiplier_bp"], context_multiplier_bp("high", "high")[1]
        )

    def test_the_two_assets_do_not_contaminate_each_other(self):
        """The whole point of the route: one store, two answers, each correct.

        Checked on the weights rather than on substrings, because the weights are
        the value that actually drives the score -- a mixed answer would show up
        as the high asset carrying the low asset's weight, and only that can be
        asserted exactly.
        """
        low = self._context(self.low)["mission_context"]["risk"]
        high = self._context(self.high)["mission_context"]["risk"]
        self.assertEqual(low["criticality_weight"], weight_of("low"))
        self.assertEqual(high["criticality_weight"], weight_of("high"))
        self.assertNotEqual(low["criticality_weight"],
                            high["criticality_weight"])
        # Same technical risk on both sides: only the declared profile differs,
        # so any difference in the result is attributable to the profile alone.
        self.assertEqual(low["technical_risk"], high["technical_risk"])
        self.assertLess(low["contextualized_risk"], high["contextualized_risk"])

    def test_the_answer_is_exactly_what_mission_context_returns(self):
        """The delegation test.

        The route must be a projection: it takes a technical risk from the store
        and hands it to the existing function. If it ever grew arithmetic of its
        own -- its own weighting, banding or cap -- this comparison would drift,
        because ``mission_context`` would no longer be the source of the answer.
        """
        for asset_id in (self.low, self.high):
            payload = self._context(asset_id)
            with self.subTest(asset=asset_id):
                expected = mission_context(
                    technical_risk=payload["technical_risk"],
                    technical_severity=payload["technical_severity"],
                    asset_id=asset_id,
                    profiles=self.book,
                ).to_dict()
                self.assertEqual(payload["mission_context"], expected)

    def test_the_declared_criticality_is_never_assigned_by_the_route(self):
        """Every published criticality must be one the profile file declares."""
        for asset_id in self.book.asset_ids():
            profile = self.book.get(asset_id)
            context = self._context(asset_id)["mission_context"]
            with self.subTest(asset=asset_id):
                self.assertEqual(context["profile"]["criticality"],
                                 profile.criticality)
                self.assertIn(context["profile"]["criticality"], CRITICALITIES)

    def test_an_undeclared_asset_gets_no_criticality_at_all(self):
        payload = self._context("gw-does-not-exist")
        context = payload["mission_context"]
        self.assertEqual(context["status"], STATUS_NOT_CONFIGURED)
        self.assertIsNone(context["profile"])
        self.assertIsNone(context["risk"])
        self.assertIn("gw-does-not-exist", context["reason"])

    def test_a_store_without_profiles_declares_no_context(self):
        payload = handle_asset_context(build_store(), "gw-a", {})
        self.assertEqual(payload["mission_context"]["status"],
                         STATUS_NOT_CONFIGURED)
        self.assertIsNone(payload["mission_context"]["risk"])

    def test_an_empty_asset_id_is_not_a_question(self):
        with self.assertRaises(ApiError) as caught:
            handle_asset_context(self.store, "", {})
        self.assertEqual(caught.exception.status, 404)

    def test_a_nested_asset_id_is_rejected_rather_than_truncated(self):
        with self.assertRaises(ApiError) as caught:
            handle_asset_context(self.store, "gw-a/gw-b", {})
        self.assertEqual(caught.exception.status, 404)


class TestTheRouteStatesWhichRiskItContextualised(unittest.TestCase):
    """A contextualised score is meaningless without the score it came from."""

    @classmethod
    def setUpClass(cls):
        cls.book = load_mission_profiles()
        cls.store = build_store(asset_id=cls.book.asset_ids()[0],
                                mission_profiles=cls.book)
        cls.asset_id = cls.book.asset_ids()[-1]

    def test_the_default_is_the_store_highest_risk_and_says_so(self):
        payload = handle_asset_context(self.store, self.asset_id, {})
        overview = self.store.overview
        self.assertIsNone(payload["assessment_id"])
        self.assertEqual(payload["technical_risk_source"], "store_highest_risk")
        self.assertEqual(payload["technical_risk"], overview["highest_risk"])
        self.assertEqual(payload["technical_severity"],
                         overview["highest_severity"])

    def test_a_named_assessment_is_used_and_echoed(self):
        header = next(h for h in self.store.headers
                      if h["assessment_id"] == ASSESSMENT)
        payload = handle_asset_context(
            self.store, self.asset_id, {"assessment_id": ASSESSMENT}
        )
        self.assertEqual(payload["assessment_id"], ASSESSMENT)
        self.assertEqual(payload["technical_risk_source"], "assessment_header")
        self.assertEqual(payload["technical_risk"], header["risk_score"])
        self.assertEqual(payload["technical_severity"], header["severity"])

    def test_an_unknown_assessment_is_a_404_not_a_silent_fallback(self):
        with self.assertRaises(ApiError) as caught:
            handle_asset_context(
                self.store, self.asset_id, {"assessment_id": "nope"}
            )
        self.assertEqual(caught.exception.status, 404)

    def test_the_same_asset_reads_differently_against_different_assessments(self):
        """Stating the source is not decoration: it changes the answer."""
        lowest = min(self.store.headers,
                     key=lambda h: (h["risk_score"], h["assessment_id"]))
        highest = min(self.store.headers,
                      key=lambda h: (-h["risk_score"], h["assessment_id"]))
        if lowest["risk_score"] == highest["risk_score"]:
            self.skipTest("every assessment in this store has the same risk")
        for header in (lowest, highest):
            payload = handle_asset_context(
                self.store, self.asset_id,
                {"assessment_id": header["assessment_id"]},
            )
            with self.subTest(assessment=header["assessment_id"]):
                self.assertEqual(payload["technical_risk"],
                                 header["risk_score"])


class TestTheRouteChangesNothing(unittest.TestCase):
    """Selecting an asset is a question. It must not be a reconfiguration."""

    @classmethod
    def setUpClass(cls):
        cls.book = load_mission_profiles()
        cls.low, cls.high = lowest_and_highest(cls.book)
        cls.store = build_store(asset_id=cls.low, mission_profiles=cls.book)

    def test_the_store_asset_binding_is_untouched_by_a_selection(self):
        handle_asset_context(self.store, self.high, {})
        self.assertEqual(self.store.asset_id, self.low)

    def test_the_custody_explanation_still_reports_the_bound_asset(self):
        from correlation.api.custody_routes import (
            handle_assessment_finding_explanation,
        )

        before = handle_assessment_finding_explanation(
            self.store, ASSESSMENT, "RISK-PFS-DISABLED"
        )["mission_context"]
        handle_asset_context(self.store, self.high, {})
        after = handle_assessment_finding_explanation(
            self.store, ASSESSMENT, "RISK-PFS-DISABLED"
        )["mission_context"]
        self.assertEqual(before, after)
        self.assertEqual(after["asset_id"], self.low)

    def test_a_selected_asset_adds_nothing_to_the_declared_inventory(self):
        payload = handle_assets(self.store)
        self.assertNotIn(self.high, [a for a in payload["assets"]
                                     if a not in self.book.asset_ids()])
        self.assertEqual(len(payload["assets"]), len(self.book.asset_ids()))


class TestTheRouteIsReachableAndDocumented(unittest.TestCase):
    """The frontend client and the OpenAPI contract must agree with the router."""

    def setUp(self):
        self.book = load_mission_profiles()
        self.low, self.high = lowest_and_highest(self.book)
        self.store = build_store(asset_id=self.low, mission_profiles=self.book)

    def test_the_dispatcher_answers_both_asset_routes(self):
        context = Phase10Context()
        listed, content = handle_combined(self.store, context, ASSETS_PATH, {})
        self.assertEqual(content, "application/json")
        self.assertEqual(listed["assets"], list(self.book.asset_ids()))

        path = ASSETS_PATH + "/" + self.high + ASSET_CONTEXT_SUFFIX
        payload, _ = handle_combined(self.store, context, path, {})
        self.assertEqual(payload["asset_id"], self.high)
        self.assertEqual(payload["mission_context"]["profile"]["criticality"],
                         "high")

    def test_the_dispatcher_answers_a_selected_asset_by_name(self):
        path = ASSETS_PATH + "/" + self.low + ASSET_CONTEXT_SUFFIX
        payload, _ = handle_combined(self.store, Phase10Context(), path, {})
        self.assertEqual(payload["mission_context"]["profile"]["criticality"],
                         "low")

    def test_a_bare_asset_path_is_not_a_route(self):
        """``/api/v1/assets/{id}`` must 404, not answer with something partial."""
        with self.assertRaises(ApiError) as caught:
            handle_combined(self.store, Phase10Context(),
                            ASSETS_PATH + "/" + self.high, {})
        self.assertEqual(caught.exception.status, 404)

    def test_an_over_long_asset_path_is_not_a_route(self):
        with self.assertRaises(ApiError) as caught:
            handle_combined(self.store, Phase10Context(),
                            ASSETS_PATH + "/a/b/c", {})
        self.assertEqual(caught.exception.status, 404)

    def test_both_routes_are_in_the_openapi_contract(self):
        paths = openapi_document()["paths"]
        self.assertIn(ASSETS_PATH, paths)
        self.assertIn(ASSETS_PATH + "/{asset_id}" + ASSET_CONTEXT_SUFFIX, paths)

    def test_the_contract_documents_the_read_only_boundary(self):
        schema = openapi_document()["components"]["schemas"]["AssetContext"]
        self.assertTrue(schema["properties"]["read_only"]["const"])
        self.assertEqual(
            schema["properties"]["technical_risk_source"]["enum"],
            ["assessment_header", "store_highest_risk"],
        )


class TestTheClientCannotBypassTheBackend(unittest.TestCase):
    """Source-level guards on the wiring that has to exist for the demo.

    These are cheap string assertions, and that is the point: the two failures
    this guards against -- a frontend that keeps its own asset-to-criticality
    table, or a client function that drops the selected asset id -- are invisible
    to every other test here, because the backend would still be correct.
    """

    @classmethod
    def setUpClass(cls):
        cls.analytics = ANALYTICS.read_text("utf-8")
        cls.panels = CONTEXT_PANEL.read_text("utf-8")

    def test_the_client_sends_the_selected_asset_id_in_the_path(self):
        self.assertIn("getAssetContext", self.analytics)
        self.assertIn("/api/v1/assets/${encodeURIComponent(assetId)}/context",
                      self.analytics)

    def test_the_client_reads_the_declared_asset_list(self):
        self.assertIn("getAssets", self.analytics)

    def test_the_panel_has_a_selector_and_an_apply_action(self):
        self.assertIn("AssetContextPanel", self.panels)
        self.assertIn("Assess asset", self.panels)

    def test_the_frontend_holds_no_asset_to_criticality_table(self):
        """A hardcoded mapping would make the demo pass without the backend."""
        for asset in ("gw-a", "gw-b"):
            self.assertNotIn(
                asset, self.analytics,
                f"{asset} is named in the API client; the asset list must come "
                "from the backend",
            )
        panel_source = self.panels
        for line in panel_source.splitlines():
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            with self.subTest(line=stripped[:60]):
                self.assertNotIn("gw-a", stripped)
                self.assertNotIn("gw-b", stripped)


def json_text(payload):
    """Compact JSON, for substring absence assertions."""
    import json

    return json.dumps(payload, sort_keys=True)


if __name__ == "__main__":
    unittest.main()