"""Drift detection: production-path propagation and non-vacuity.

``tests/test_drift_detection.py`` already establishes the algorithm contract: the
canonical scope, the four declared outcomes, baseline integrity, and the
anti-false-positive property over four real recorded captures. This file covers
what that suite does not:

* **propagation** -- the verdict has to survive the real journey from a recorded
  observation through the store, the HTTP surface and the frontend renderer. A
  detector can be perfect in isolation and still publish a claim the UI
  misreads, which is exactly what happened to ``indeterminate``.
* **non-vacuity** -- each required behaviour is pinned so that a broken detector
  fails. The point is stated explicitly in
  :meth:`TestTheVerdictTracksTheActualInput`: the reported field must be the one
  that actually moved, and swapping the baseline or the current observation must
  change the verdict. A test that only asserted ``status == drift`` would pass
  against a constant.

Every input here is either a real recorded capture or the repository's existing
declared derived fixture. Nothing about the drift implementation is rewritten;
this file only observes and constrains it.
"""

import dataclasses
import json
import pathlib
import unittest

from correlation.api.drift_routes import handle_assessment_drift
from correlation.api.store import AssessmentStore
from correlation.artifacts import load_observed_state
from correlation.drift import (
    BaselineIntegrityError,
    BaselineRegistry,
    COMPARABLE_VARIABLES,
    DRIFT_STATUS_DRIFT,
    DRIFT_STATUS_INDETERMINATE,
    DRIFT_STATUS_NO_DRIFT,
    DRIFT_STATUS_NOT_CONFIGURED,
    assess_drift,
    canonical_security_state,
    validate_baseline,
)
from correlation.drift.canonical import observation_is_informative
from correlation.models.observed import ObservedState

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
FRONTEND_BLOCK = (
    REPO_ROOT / "sentinel-frontend" / "src" / "components" / "packet"
    / "AssessmentDriftBlock.tsx"
)
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "drift" / "ah_substitution_state.jsonl"

REAL_TUNNEL_V4 = "results/e2e-verification/parser/tunnel_v4/state.jsonl"
REAL_LIVE_FULL = "results/observed-state/live_state_from_events_full.jsonl"
REAL_LIVE_PRE_REKEY = "results/observed-state/live_state_from_events_pre_rekey.jsonl"
REAL_LAB_VERIFY = "results/observed-state/lab-verify-20260919-143813/state_events.jsonl"

VALIDATED_AT = "2026-09-20T09:00:00Z"
VALIDATED_BY = "sec-ops"


def real_state(path):
    return load_observed_state(REPO_ROOT / path)[0]


def shifted_state():
    """The repository's declared derived fixture: ESP replaced by AH."""
    return ObservedState.from_dict(json.loads(FIXTURE.read_text("utf-8").strip()))


def idle_state(observed):
    """A copy of ``observed`` that carried no traffic at all."""
    return dataclasses.replace(
        observed,
        tunnel_seen=False,
        active=False,
        packets_seen=0,
        bytes_seen=0,
        packets_a_to_b=0,
        packets_b_to_a=0,
        bytes_a_to_b=0,
        bytes_b_to_a=0,
        esp_seen=False,
        ah_seen=False,
        ike_seen=False,
        ike_nat_t_seen=False,
        spis=(),
    )


def baseline_from(observed, baseline_id="baseline-nonvacuity"):
    return validate_baseline(
        observed,
        baseline_id=baseline_id,
        validated_at=VALIDATED_AT,
        validated_by=VALIDATED_BY,
    )


def drifting_store():
    """A store whose current state is the declared derived fixture.

    This is the only way to reach a drifting verdict, because no two real
    recorded captures in this repository differ in a comparable field (see
    ``TestRealLabDriftEvidenceIsNotAvailable``).
    """
    from correlation.api.store import DriftCurrentObservation

    current, record = load_observed_state(FIXTURE)
    registry = BaselineRegistry()
    registry.register(baseline_from(real_state(REAL_TUNNEL_V4)))
    return AssessmentStore(
        asset_id="gw-a",
        baselines=registry,
        baseline_id="baseline-nonvacuity",
        drift_observations=[
            DriftCurrentObservation(
                slot="band-medium",
                observed=current,
                state_record=record,
                declared_provenance={"kind": "disclosed_derived_observation"},
            )
        ],
    )


def real_store():
    """A store built the way production builds one, with a real baseline."""
    registry = BaselineRegistry()
    registry.register(baseline_from(real_state(REAL_TUNNEL_V4)))
    return AssessmentStore(
        asset_id="gw-a", baselines=registry, baseline_id="baseline-nonvacuity"
    )


# ---------------------------------------------------------------------------
# 1. The four required behaviours
# ---------------------------------------------------------------------------


class TestStableDataReportsNoDrift(unittest.TestCase):
    """Baseline and current observations that remain consistent."""

    def test_four_real_captures_of_one_state_report_no_drift(self):
        baseline = baseline_from(real_state(REAL_TUNNEL_V4))
        for path in (REAL_TUNNEL_V4, REAL_LIVE_FULL, REAL_LAB_VERIFY):
            with self.subTest(capture=path):
                result = assess_drift(baseline, real_state(path))
                self.assertEqual(result.status, DRIFT_STATUS_NO_DRIFT)
                self.assertFalse(result.drift_detected)
                self.assertEqual(result.changed_fields, ())
                self.assertIsNone(result.risk)

    def test_no_drift_names_every_compared_variable_as_unchanged(self):
        baseline = baseline_from(real_state(REAL_TUNNEL_V4))
        result = assess_drift(baseline, real_state(REAL_LIVE_FULL))
        self.assertEqual(
            sorted(result.unchanged_variables), sorted(COMPARABLE_VARIABLES)
        )


class TestShiftedDataReportsDrift(unittest.TestCase):
    """Current observations that differ materially from the baseline."""

    def test_a_protection_change_is_reported_as_drift(self):
        result = assess_drift(baseline_from(real_state(REAL_TUNNEL_V4)),
                              shifted_state())
        self.assertEqual(result.status, DRIFT_STATUS_DRIFT)
        self.assertTrue(result.drift_detected)
        self.assertTrue(result.changed_fields)

    def test_drift_raises_a_real_risk_finding(self):
        result = assess_drift(baseline_from(real_state(REAL_TUNNEL_V4)),
                              shifted_state())
        self.assertIsNotNone(result.risk)
        self.assertTrue(result.risk.findings)
        self.assertIn(
            "RISK-DRIFT-ESP-PRESENCE", {f.finding_id for f in result.risk.findings}
        )


class TestNoiseLevelVariationReportsNoDrift(unittest.TestCase):
    """Natural variation must not manufacture drift.

    This detector's noise tolerance is structural rather than statistical: the
    noise-prone fields are excluded from the canonical state by declaration, so
    a rekey, a different capture length or a different packet volume cannot move
    the verdict. These tests confirm the exclusions still hold on real captures.
    """

    def test_a_rekey_of_the_same_state_reports_no_drift(self):
        # pre_rekey and full are two real captures either side of a rekey: the
        # SPI sets differ completely and the packet counts differ, yet the
        # security state is the same.
        baseline = baseline_from(real_state(REAL_TUNNEL_V4))
        rekeyed = real_state(REAL_LIVE_PRE_REKEY)
        after = real_state(REAL_LIVE_FULL)
        self.assertNotEqual(
            frozenset(s.spi for s in rekeyed.spis),
            frozenset(s.spi for s in after.spis),
        )
        self.assertNotEqual(rekeyed.packets_seen, after.packets_seen)
        for observed in (rekeyed, after):
            with self.subTest(spi_count=len(observed.spis)):
                self.assertEqual(
                    assess_drift(baseline, observed).status, DRIFT_STATUS_NO_DRIFT
                )

    def test_capture_length_alone_cannot_move_the_verdict(self):
        baseline = baseline_from(real_state(REAL_TUNNEL_V4))
        observed = real_state(REAL_LAB_VERIFY)
        volumes = {observed.packets_seen}
        for scale in (0, 1, 7, 1000):
            scaled = dataclasses.replace(
                observed,
                packets_seen=observed.packets_seen * scale,
                bytes_seen=observed.bytes_seen * scale,
            )
            volumes.add(scaled.packets_seen)
            with self.subTest(packets=scaled.packets_seen):
                self.assertEqual(
                    assess_drift(baseline, scaled).status, DRIFT_STATUS_NO_DRIFT
                )
        self.assertGreater(len(volumes), 1, "volume must actually have varied")


class TestInvalidOrInsufficientDataIsNeverSilentNoDrift(unittest.TestCase):
    """Missing evidence must be reported, never downgraded to agreement."""

    def test_no_baseline_is_not_configured_rather_than_no_drift(self):
        result = assess_drift(None, real_state(REAL_LIVE_FULL))
        self.assertEqual(result.status, DRIFT_STATUS_NOT_CONFIGURED)
        self.assertFalse(result.drift_detected)
        self.assertIn("no validated baseline", result.reason)

    def test_a_trafficless_observation_is_indeterminate_not_no_drift(self):
        result = assess_drift(baseline_from(real_state(REAL_TUNNEL_V4)),
                              idle_state(real_state(REAL_TUNNEL_V4)))
        self.assertEqual(result.status, DRIFT_STATUS_INDETERMINATE)
        self.assertFalse(result.drift_detected)
        self.assertEqual(result.changed_fields, ())
        self.assertIn("no traffic", result.reason)

    def test_a_trafficless_baseline_cannot_be_validated(self):
        with self.assertRaises(ValueError):
            validate_baseline(
                idle_state(real_state(REAL_TUNNEL_V4)),
                baseline_id="b",
                validated_at=VALIDATED_AT,
                validated_by=VALIDATED_BY,
            )

    def test_a_tampered_baseline_never_reaches_a_comparison(self):
        baseline = baseline_from(real_state(REAL_TUNNEL_V4))
        tampered = dataclasses.replace(
            baseline,
            canonical_state={"address_family": "ipv4", "esp.presence": False,
                             "ah.presence": False},
        )
        with self.assertRaises(BaselineIntegrityError):
            assess_drift(tampered, real_state(REAL_LIVE_FULL))

    def test_malformed_input_is_refused(self):
        with self.assertRaises(TypeError):
            validate_baseline(
                {"esp_seen": True},
                baseline_id="b",
                validated_at=VALIDATED_AT,
                validated_by=VALIDATED_BY,
            )

    def test_an_observation_with_nothing_comparable_is_not_agreeing(self):
        """No traffic means not-informative, so nothing may be called equal."""
        idle = idle_state(real_state(REAL_TUNNEL_V4))
        self.assertFalse(observation_is_informative(idle))
        result = assess_drift(baseline_from(real_state(REAL_TUNNEL_V4)), idle)
        self.assertNotEqual(result.status, DRIFT_STATUS_NO_DRIFT)


# ---------------------------------------------------------------------------
# 2. Feature-level evidence: the reported field is the field that moved
# ---------------------------------------------------------------------------


class TestTheVerdictTracksTheActualInput(unittest.TestCase):
    """The detector must respond to the data, not to a constant.

    Each test here pins a value that only a working detector can produce. A
    detector hard-wired to one answer fails all of them; a detector that ignores
    its current input fails ``test_swapping_the_current_observation_...``; one
    that ignores the baseline fails ``test_swapping_the_baseline_...``.
    """

    def test_the_reported_variable_is_exactly_the_one_that_moved(self):
        baseline = baseline_from(real_state(REAL_TUNNEL_V4))
        result = assess_drift(baseline, shifted_state())
        changed = {change.variable for change in result.changed_fields}
        # The fixture moved esp.presence (and ah.presence) only; the address
        # family is untouched and must NOT be reported.
        self.assertEqual(changed, {"esp.presence", "ah.presence"})
        self.assertNotIn("address_family", changed)
        self.assertIn("address_family", result.unchanged_variables)

    def test_each_change_reports_baseline_and_current_values_apart(self):
        result = assess_drift(baseline_from(real_state(REAL_TUNNEL_V4)),
                              shifted_state())
        esp = result.changed_variable("esp.presence")
        self.assertIsNotNone(esp)
        self.assertIs(esp.baseline_value, True)
        self.assertIs(esp.current_value, False)
        self.assertNotEqual(esp.baseline_value, esp.current_value)

    def test_swapping_the_current_observation_changes_the_verdict(self):
        baseline = baseline_from(real_state(REAL_TUNNEL_V4))
        clean = assess_drift(baseline, real_state(REAL_LIVE_FULL))
        drifted = assess_drift(baseline, shifted_state())
        self.assertEqual(clean.status, DRIFT_STATUS_NO_DRIFT)
        self.assertEqual(drifted.status, DRIFT_STATUS_DRIFT)

    def test_swapping_the_baseline_changes_the_verdict(self):
        current = shifted_state()
        matching = assess_drift(baseline_from(shifted_state(),
                                             baseline_id="b-matching"), current)
        mismatched = assess_drift(baseline_from(real_state(REAL_TUNNEL_V4),
                                                baseline_id="b-real"), current)
        self.assertEqual(matching.status, DRIFT_STATUS_NO_DRIFT)
        self.assertEqual(mismatched.status, DRIFT_STATUS_DRIFT)

    def test_a_different_drifting_field_yields_a_different_verdict(self):
        """Field attribution, not just the drift bit, has to be correct."""
        baseline = baseline_from(real_state(REAL_TUNNEL_V4))
        esp_loss = assess_drift(baseline, shifted_state())
        address_family = assess_drift(
            baseline,
            dataclasses.replace(real_state(REAL_TUNNEL_V4), endpoints={}),
        )
        self.assertEqual(esp_loss.status, DRIFT_STATUS_DRIFT)
        # An unestablishable address family is unknown, never drift.
        self.assertNotEqual(address_family.status, DRIFT_STATUS_DRIFT)
        self.assertIn("address_family", address_family.unknown_variables)


# ---------------------------------------------------------------------------
# 3. Production path: recorded observation -> store -> HTTP -> frontend
# ---------------------------------------------------------------------------


class TestTheProductionPathCarriesTheVerdict(unittest.TestCase):
    def test_a_configured_store_reports_per_status_counts(self):
        summary = real_store().drift_summary()
        self.assertTrue(summary["configured"])
        self.assertGreater(sum(summary["status_counts"].values()), 0)

    def test_an_unconfigured_store_never_reads_as_no_drift(self):
        summary = AssessmentStore().drift_summary()
        self.assertFalse(summary["configured"])
        self.assertIn("no validated baseline registry", summary["reason"])

    def test_the_per_assessment_bundle_carries_the_verdict(self):
        """The served assessment payload publishes its own drift section.

        ``drift`` is a documented property of the assessment schema (see the
        ``drift`` property in ``correlation/api/openapi.py``), so a store that
        computed the comparison but published ``null`` would be serving a lie
        that the per-assessment HTTP route would never expose.
        """
        store = real_store()
        self.assertTrue(store.drift_inputs)
        for assessment_id, drift in store.drift_inputs.items():
            with self.subTest(assessment=assessment_id):
                bundle = store.bundles[assessment_id]
                self.assertIsNotNone(bundle.get("drift"))
                self.assertEqual(bundle["drift"]["status"], drift.status)
                self.assertEqual(
                    bundle["drift"]["drift_detected"], drift.drift_detected
                )

    def test_the_store_overview_carries_the_drift_summary(self):
        store = real_store()
        self.assertEqual(store.overview["drift"], store.drift_summary())
        self.assertTrue(store.overview["drift"]["configured"])

    def test_a_store_built_chain_of_custody_carries_the_drift_claim(self):
        """The custody chain the store builds must state the drift.

        ``AssessmentStore.chain_of_custody`` is the only place the store hands
        its comparison to the custody builder. The existing custody tests call
        ``build_chain_of_custody`` directly, so this wiring was unpinned: a
        store that computed the comparison correctly and then published a chain
        claiming no drift at all would have passed every other test.
        """
        store = drifting_store()
        drift_assessment_id = next(
            aid for aid, drift in store.drift_inputs.items()
            if drift.status == DRIFT_STATUS_DRIFT
        )
        finding_id = store.custody_inputs[
            drift_assessment_id
        ].assessment.findings[0].finding_id

        chain = store.chain_of_custody(
            drift_assessment_id, finding_id, verify_evidence=False
        ).to_dict()

        self.assertIn("drift", chain)
        self.assertEqual(chain["drift"]["status"], DRIFT_STATUS_DRIFT)
        self.assertTrue(chain["drift"]["drift_detected"])
        self.assertEqual(
            chain["drift"]["baseline"]["baseline_id"], "baseline-nonvacuity"
        )

    def test_the_declared_current_observation_is_published_as_declared(self):
        """A declared current state must never be readable as a live capture."""
        store = drifting_store()
        drift = next(
            d for d in store.drift_inputs.values() if d.status == DRIFT_STATUS_DRIFT
        )
        self.assertFalse(drift.current_source.is_capture)
        served = drift.to_dict()["current"]["source"]
        self.assertFalse(served["is_capture"])

    def test_an_unconfigured_store_publishes_no_invented_verdict(self):
        """No baseline means no drift section at all, on the store or a bundle.

        Absence is the honest representation here: the configured-store path
        publishes the summary, so an unconfigured store that published one would
        be asserting a comparison it never made.
        """
        store = AssessmentStore()
        self.assertNotIn("drift", store.overview)
        self.assertNotIn("drift", store.store)
        for header in store.headers:
            self.assertNotIn("drift", store.bundles[header["assessment_id"]])

    def test_the_indeterminate_verdict_reaches_the_http_surface(self):
        store = real_store()
        indeterminate = [
            aid for aid, drift in store.drift_inputs.items()
            if drift.status == DRIFT_STATUS_INDETERMINATE
        ]
        self.assertTrue(indeterminate, "expected real indeterminate comparisons")
        for assessment_id in indeterminate:
            with self.subTest(assessment=assessment_id):
                served = handle_assessment_drift(store, assessment_id)
                self.assertEqual(served["status"], DRIFT_STATUS_INDETERMINATE)
                self.assertIs(served["drift_detected"], False)
                self.assertTrue(served["reason"])

    def test_the_frontend_never_renders_indeterminate_as_no_drift(self):
        """Regression guard for the fixed renderer.

        The API serves ``indeterminate`` with ``drift_detected: false`` while
        claiming neither drift nor agreement. The component used to treat any
        non-drift status as "No drift detected", which inverted the drift
        layer's explicit promise that absence of evidence is never agreement.
        """
        source = FRONTEND_BLOCK.read_text("utf-8")
        self.assertIn("'no_drift'", source,
                      "the clean verdict must be matched explicitly")
        self.assertIn(DRIFT_STATUS_INDETERMINATE, source,
                      "indeterminate must be handled as its own state")

        branch = source.index("'no_drift'")
        phrase = source.index("No drift detected")
        self.assertEqual(source.count("No drift detected"), 1)
        self.assertGreater(
            phrase, branch,
            "'No drift detected' must only be reachable from the no_drift branch",
        )
        # Nothing after the clean branch -- i.e. the indeterminate/other-status
        # fallback -- may say "no drift".
        self.assertNotIn(
            "No drift detected", source[phrase + 1:],
            "no status other than no_drift may be rendered as 'No drift detected'",
        )


if __name__ == "__main__":
    unittest.main()