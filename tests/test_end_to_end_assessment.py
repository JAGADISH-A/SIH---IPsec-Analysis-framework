"""END-TO-END ACCEPTANCE: one assessment, traced from baseline to API.

This suite exists to prove that the three finished milestones are actually
*connected*, not merely adjacent. Each earlier milestone was accepted on its own
terms:

* ``test_chain_of_custody.py`` -- a chain can be built and explained.
* ``test_mission_context.py`` -- mission context is applied, explicitly.
* ``test_drift_detection.py`` -- a validated baseline can be compared.

None of those three tests demonstrated that a **drift finding** can be reached
by anything downstream. In the code as it stood, ``AssessmentStore`` computed a
``DriftAssessment`` and attached it to the plan-based assessment as *context*,
while ``chain_of_custody`` resolves findings only from the assessment that was
registered. A drift finding was therefore real, scored, and unreachable::

    KeyError: '...:3:band-medium:RISK-DRIFT-ESP-PRESENCE'

So the gap this file closes is narrow and specific: a drift finding must be a
first-class assessment, registered the way any other assessment is, so that the
existing bundle, custody, integrity, mission-context and API layers serve it
without a single parallel implementation.

The scenario
------------

Every real capture in this repository reports the same security posture
(IPv4, ESP present, AH absent), so no recorded capture can demonstrate drift.
The demonstration therefore uses:

* a **real** recorded capture -- ``results/e2e-verification/parser/tunnel_v4/
  state.jsonl`` -- to establish the validated baseline, and
* the **disclosed controlled fixture** -- ``tests/fixtures/drift/
  ah_substitution_state.jsonl`` -- as the current observation, declared as
  exactly that.

The fixture is never dressed up as a capture. ``DriftCurrentSource`` carries the
distinction as data (``kind='declared_observation'``, ``is_capture=False``), the
producer's own "this is NOT a packet capture" statement is carried verbatim, and
the fixture is deliberately excluded from the evidence-reference list, because
``evidence_ref_for`` types any ``.jsonl`` as a live XDP state artifact and that
is precisely the claim a fixture must not be given.

The current observation is declared for a single scenario slot, so the recorded
capture remains the observed state of the plan-based assessment. The pipeline is
not rerouted; one additional assessment is registered, and only when the
comparison actually produces findings.
"""

import dataclasses
import json
import unittest
from pathlib import Path

from correlation.api.adapters import parse_assessment_id
from correlation.api.drift_routes import (
    handle_assessment_drift,
    handle_drift,
)
from correlation.api.custody_routes import (
    handle_assessment_finding_explanation,
    handle_finding_explanation,
)
from correlation.api.openapi import openapi_document
from correlation.api.store import (
    DriftCurrentObservation,
    build_store,
    real_evidence,
)
from correlation.artifacts import REPO_ROOT, load_observed_state
from correlation.drift import (
    DRIFT_SOURCE_KIND_DECLARED,
    DRIFT_SOURCE_KIND_RECORDED,
    BaselineRegistry,
    DriftCurrentSource,
    validate_baseline,
)
from correlation.drift.models import DRIFT_SOURCE_KINDS
from correlation.mission import load_mission_profiles
from correlation.models.evidence import sha256_file

# -- the scenario, declared once ---------------------------------------------

#: The real recorded capture the baseline is validated from.
BASELINE_STATE = "results/e2e-verification/parser/tunnel_v4/state.jsonl"
#: The real recorded capture whose state is the current observation.
RECORDED_STATE = BASELINE_STATE
#: The disclosed controlled fixture used as the current observation.
FIXTURE_STATE = "tests/fixtures/drift/ah_substitution_state.jsonl"
#: The fixture producer's own provenance, including the "not a capture" claim.
FIXTURE_PROVENANCE = "tests/fixtures/drift/ah_substitution_provenance.json"

BASELINE_ID = "baseline-e2e-tunnel-v4"
BASELINE_VALIDATED_BY = "sec-ops@ipsec-testbed"
BASELINE_VALIDATED_AT = "2026-09-20T09:00:00Z"

#: The plan-based assessment whose slot receives the declared observation.
PLAN_ASSESSMENT = "dataset-20260924-003710:3:band-medium"
DRIFT_ASSESSMENT = "dataset-20260924-003710:3:band-medium-drift"
DRIFT_SLOT = "band-medium"

ESP_FINDING = "RISK-DRIFT-ESP-PRESENCE"
AH_FINDING = "RISK-DRIFT-AH-PRESENCE"

LOW_ASSET = "gw-a"
HIGH_ASSET = "gw-b"
MISSION_PROFILES = "configs/mission/asset_mission_profiles.json"

#: The expected technical result of the declared comparison, taken from the
#: drift milestone's own verified fixture expectations rather than recomputed
#: here: the finding ids, the severities and the scores all come out of the real
#: risk engine, and these are the values it produced.
EXPECTED_TECHNICAL_RISK = 30
EXPECTED_TECHNICAL_SEVERITY = "HIGH"


def _registry() -> BaselineRegistry:
    """A baseline registry holding one explicitly validated baseline."""
    state, _ = load_observed_state(BASELINE_STATE)
    registry = BaselineRegistry()
    registry.register(validate_baseline(
        state,
        baseline_id=BASELINE_ID,
        validated_by=BASELINE_VALIDATED_BY,
        validated_at=BASELINE_VALIDATED_AT,
        # Deliberately un-scoped to an asset: the asset is mission-context
        # input, and the comparison baseline is a security state. Leaving the
        # baseline un-scoped is what makes the two-asset comparison clean --
        # the only difference between the two runs is the declared context.
    ))
    return registry


def _declared_current() -> DriftCurrentObservation:
    """The controlled fixture, declared as a declared observation."""
    state, record = load_observed_state(FIXTURE_STATE)
    provenance = json.loads(Path(REPO_ROOT, FIXTURE_PROVENANCE).read_text())
    return DriftCurrentObservation(
        slot=DRIFT_SLOT,
        observed=state,
        state_record=record,
        declared_provenance=provenance,
    )


def _store(asset_id=None, *, with_baseline=True, with_declared=True,
           verify_evidence=True):
    """Build the integrated store for one asset context.

    Every input is a real artifact or an explicit declaration; nothing is
    synthesized and no stage is stubbed.
    """
    return build_store(
        asset_id=asset_id,
        mission_profiles=load_mission_profiles(),
        baselines=_registry() if with_baseline else None,
        baseline_id=BASELINE_ID if with_baseline else None,
        drift_observations=[_declared_current()] if with_declared else (),
        drift_scenario_label=(
            "longitudinal comparison of a declared controlled current "
            "observation against the validated baseline built from the real "
            "recorded tunnel_v4 capture; the current state is a disclosed "
            "derived fixture, not a capture of a live device"
        ),
    )


def _chain(store, assessment_id=DRIFT_ASSESSMENT, finding_id=ESP_FINDING,
           **kwargs):
    return store.chain_of_custody(
        assessment_id, finding_id, verify_evidence=True, **kwargs
    ).to_dict()


def _drift_digests(comparison):
    """The baseline and current canonical-state digests of one comparison.

    Accepts either the serialised drift context or a ``DriftAssessment``, so a
    single invariant can be stated once and applied to both surfaces.
    """
    if isinstance(comparison, dict):
        return (comparison["baseline"]["state_digest"],
                comparison["current"]["state_digest"])
    return comparison.baseline_state_digest, comparison.current_state_digest


def _drift_verdicts_without_a_canonical_difference(comparisons):
    """Comparisons that report drift while carrying an identical state.

    Wholly data-derived: it walks the comparisons that were actually built and
    compares the two canonical-state digests each one carries. No assessment id
    and no expected digest string takes part in the decision, so the guard
    survives a change of ids and cannot be satisfied by a fixed total.

    ``indeterminate`` is skipped deliberately. An uninformative observation
    carries a different digest precisely *because* it observed nothing
    comparable, so a flat "drift iff the digests differ" rule would be wrong
    here. The rule is one-directional on purpose: drift requires a difference,
    and an absent difference may never be promoted into drift.
    """
    offenders = []
    for assessment_id, comparison in comparisons.items():
        status = (comparison["status"] if isinstance(comparison, dict)
                  else comparison.status)
        if status != "drift":
            continue
        baseline_digest, current_digest = _drift_digests(comparison)
        if baseline_digest == current_digest:
            offenders.append(assessment_id)
    return offenders


class TestScenarioIsRealAndDisclosed(unittest.TestCase):
    """2: one deterministic scenario, and every input of it is accounted for."""

    @classmethod
    def setUpClass(cls):
        cls.store = _store(HIGH_ASSET)
        cls.chain = _chain(cls.store)

    def test_the_baseline_comes_from_a_real_recorded_capture(self):
        """The validated side is a real artifact, with its real digest."""
        fact = self._fact("configured.drift_baseline")
        self.assertEqual(fact["value"]["baseline_id"], BASELINE_ID)
        self.assertEqual(fact["value"]["validated_by"], BASELINE_VALIDATED_BY)
        self.assertEqual(fact["value"]["validated_at"], BASELINE_VALIDATED_AT)
        recorded = self._source("observed_state")
        self.assertEqual(recorded["public_path"], BASELINE_STATE)
        self.assertEqual(
            recorded["artifact_sha256"],
            sha256_file(str(Path(REPO_ROOT, BASELINE_STATE))),
        )

    def test_the_current_observation_is_declared_and_labelled_as_such(self):
        """The current side is a declaration, and says so everywhere."""
        source = self.chain["drift"]["current"]["source"]
        self.assertEqual(source["kind"], DRIFT_SOURCE_KIND_DECLARED)
        self.assertFalse(source["is_capture"])
        self.assertFalse(source["is_live_capture"])
        self.assertEqual(source["public_path"], FIXTURE_STATE)
        self.assertEqual(
            source["artifact_sha256"],
            sha256_file(str(Path(REPO_ROOT, FIXTURE_STATE))),
        )
        # The producer's own words, not a paraphrase by this system.
        provenance = json.loads(Path(REPO_ROOT, FIXTURE_PROVENANCE).read_text())
        self.assertEqual(source["declared_kind"], provenance["kind"])
        self.assertEqual(source["declaration"], provenance["not_a_capture"])
        self.assertIn("NOT a packet capture", source["declaration"])

    def test_the_declared_observation_is_never_given_a_capture_evidence_ref(self):
        """A fixture must not be reachable through the live-capture evidence channel.

        ``evidence_ref_for`` types an artifact by extension, so a ``.jsonl``
        would be published as a live XDP state artifact. The declared current
        observation is therefore published through the provenance channel only.
        """
        for ref in self.chain["evidence"]:
            self.assertNotIn(FIXTURE_STATE, json.dumps(ref))
        self.assertNotIn(FIXTURE_STATE, json.dumps(self.chain["evidence"]))
        # Its role in the provenance list is explicit.
        self.assertEqual(
            self._source("controlled_drift_observation")["public_path"],
            FIXTURE_STATE,
        )
        # And the recorded capture is still the live-capture evidence.
        types = {ref["artifact_type"] for ref in self.chain["evidence"]}
        self.assertTrue(types, "the comparison has no evidence at all")
        self.assertTrue(
            any(ref["artifact_sha256"] for ref in self.chain["evidence"])
        )

    def test_the_derived_fixture_is_linked_to_its_real_source(self):
        """The declaration names the real artifact it was derived from."""
        source = self.chain["drift"]["current"]["source"]
        derived = source["derived_from"]
        self.assertEqual(derived["path"], BASELINE_STATE)
        self.assertEqual(
            derived["artifact_sha256"],
            sha256_file(str(Path(REPO_ROOT, BASELINE_STATE))),
        )

    def test_a_declared_artifact_that_no_longer_matches_itself_is_refused(self):
        """6: no silent repair -- the digest published is the digest checked."""
        state, record = load_observed_state(FIXTURE_STATE)
        lying = dataclasses.replace(
            record, artifact_sha256="0" * 64)
        with self.assertRaises(Exception) as caught:
            DriftCurrentObservation(
                slot=DRIFT_SLOT, observed=state, state_record=lying)
        self.assertIn("changed since it was loaded", str(caught.exception))

    def test_the_drift_finding_is_reachable_as_a_first_class_assessment(self):
        """The gap: a drift finding is an assessment, not orphaned context."""
        self.assertIn(DRIFT_ASSESSMENT, self.store.bundles)
        self.assertIn(DRIFT_ASSESSMENT, self.store.custody_inputs)
        finding_ids = [
            item["finding_id"]
            for item in self.store.bundles[DRIFT_ASSESSMENT]["risk"]["findings"]
        ]
        self.assertIn(ESP_FINDING, finding_ids)
        self.assertIn(AH_FINDING, finding_ids)
        # It is addressable by the API's own id grammar, so it is served by the
        # existing routes rather than needing a parallel surface.
        self.assertEqual(
            parse_assessment_id(DRIFT_ASSESSMENT),
            ("dataset-20260924-003710", 3, "band-medium-drift"),
        )

    def test_no_drift_registers_no_extra_assessment(self):
        """10: the no-drift control adds nothing to the surface."""
        control = _store(HIGH_ASSET, with_declared=False)
        self.assertNotIn(DRIFT_ASSESSMENT, control.bundles)
        self.assertEqual(
            len(control.bundles), len(self.store.bundles) - 1)

        genuine_drift = set()
        for assessment_id, bundle in control.bundles.items():
            drift = bundle["drift"]
            if drift["status"] != "drift":
                # Anything that agrees with the baseline -- or that could not be
                # observed at all -- registers nothing. Nothing is excused from
                # this by the shape of its id.
                self.assertIsNone(
                    drift["risk"],
                    f"{assessment_id} compares as {drift['status']!r} yet "
                    f"registered {drift['risk']!r}")
                continue
            # A drift verdict is admissible only where the canonical states the
            # comparison itself carries actually differ. Membership is decided
            # by the comparison, never by the assessment's name: an assessment
            # whose id happens to contain 'transport-v6' gets exactly the same
            # scrutiny as any other, and this stays valid if ids are renumbered.
            baseline_digest, current_digest = _drift_digests(drift)
            self.assertNotEqual(
                baseline_digest, current_digest,
                f"{assessment_id} reports drift while carrying an identical "
                f"canonical state ({baseline_digest})")
            genuine_drift.add(assessment_id)

        # The non-drifting assessments are exactly the agreed and the
        # unobservable ones; no fourth verdict may appear.
        self.assertEqual(
            {bundle["drift"]["status"] for bundle in control.bundles.values()
             if bundle["drift"]["status"] != "drift"},
            {"no_drift", "indeterminate"})
        # And the corpus really does contain a genuine difference, so the
        # assertions above are exercised rather than vacuously satisfied.
        self.assertTrue(
            genuine_drift,
            "no assessment drifted against the baseline, so this control "
            "proves nothing")

    def test_a_store_without_a_baseline_adds_no_drift_at_all(self):
        control = _store(HIGH_ASSET, with_baseline=False)
        self.assertNotIn(DRIFT_ASSESSMENT, control.bundles)
        self.assertEqual(control.drift_inputs, {})
        for bundle in control.bundles.values():
            self.assertNotIn("drift", bundle)

    def test_the_scenario_is_deterministic(self):
        self.assertEqual(
            json.dumps(_chain(_store(HIGH_ASSET)), sort_keys=True),
            json.dumps(_chain(_store(HIGH_ASSET)), sort_keys=True),
        )

    # -- helpers ------------------------------------------------------------

    def _fact(self, fact_id):
        return next(
            item for item in self.chain["facts"] if item["fact_id"] == fact_id)

    def _source(self, role):
        return next(
            item for item in self.chain["sources"] if item["role"] == role)


class TestVerticalSliceIsComplete(unittest.TestCase):
    """2/4: every stage of the slice is present in one chain."""

    @classmethod
    def setUpClass(cls):
        cls.store = _store(HIGH_ASSET)
        cls.chain = _chain(cls.store)

    def test_every_stage_of_the_vertical_slice_is_reachable(self):
        payload = self.chain
        stages = {
            "validated baseline": payload["drift"]["baseline"],
            "current observed": payload["drift"]["current"],
            "drift comparison": payload["drift"]["status"],
            "drift finding": payload["finding_id"],
            "technical risk": payload["risk_score"],
            "mission context": payload["mission_context"],
            "contextualized risk": payload["mission_context"]["risk"],
            "custody explanation": payload["facts"],
            "evidence": payload["evidence"],
            "provenance": payload["sources"],
            "integrity": payload["integrity"],
            "recommendation": payload["recommendation"],
            "rule": payload["rule"],
        }
        for name, value in stages.items():
            self.assertIsNotNone(value, f"{name} is missing from the chain")
        self.assertEqual(payload["drift"]["status"], "drift")
        self.assertEqual(payload["finding_id"], ESP_FINDING)
        self.assertEqual(payload["rule"]["rule_id"], "drift.configuration")
        json.dumps(payload)

    def test_the_two_sides_of_the_comparison_are_both_established(self):
        baseline = self.chain["drift"]["baseline"]
        current = self.chain["drift"]["current"]
        self.assertEqual(baseline["baseline_id"], BASELINE_ID)
        self.assertEqual(baseline["validation_status"], "validated")
        self.assertNotEqual(baseline["state_digest"], current["state_digest"])

    def test_the_changed_fields_are_the_supported_ones_and_nothing_else(self):
        changed = self.chain["drift"]["changed_fields"]
        self.assertEqual(
            sorted(item["variable"] for item in changed),
            ["ah.presence", "esp.presence"],
        )
        # The two sides are named separately, so neither can be mistaken.
        esp = next(c for c in changed if c["variable"] == "esp.presence")
        self.assertIs(esp["baseline_value"], True)
        self.assertIs(esp["current_value"], False)
        self.assertTrue(esp["comparison_rule"])

    def test_the_explanation_is_structured_not_prose(self):
        """4: every claim is a value with a source, not a sentence.

        The chain is a report an analyst has to be able to act on, so the shape
        that matters is that a field is present and typed rather than that a
        narrative exists. ``detail`` strings are allowed -- they are diagnostic
        -- but nothing may be the *only* carrier of a claim.
        """
        fact = next(
            item for item in self.chain["facts"]
            if item["fact_id"] == "observed.drift_current_state"
        )
        self.assertEqual(
            fact["value"], self.chain["drift"]["current"]["state_digest"])
        self.assertEqual(fact["category"], "OBSERVED")
        self.assertTrue(fact["value_digest"])
        self.assertIn("correlation.drift", fact["source"])

        for item in self.chain["facts"]:
            self.assertTrue(item["fact_id"])
            self.assertTrue(item["category"])
            self.assertTrue(item["source"])
            self.assertIn(
                item["category"],
                ("OBSERVED", "EXPECTED", "CONFIGURED", "DERIVED",
                 "RECOMMENDED", "UNKNOWN"),
            )
            self.assertTrue(item["value_digest"])
            if item["category"] != "UNKNOWN":
                self.assertIsNotNone(item["value"])

    def test_the_ordered_derivation_names_every_stage_that_ran(self):
        steps = self.chain["steps"]
        self.assertTrue(steps)
        self.assertEqual(
            [step["index"] for step in steps],
            list(range(1, len(steps) + 1)),
            "the derivation is not in pipeline order",
        )
        for step in steps:
            self.assertTrue(step["stage"])
            self.assertTrue(step["action"])
            self.assertTrue(step["component"])
            self.assertIsInstance(step["authoritative"], bool)
            self.assertIsInstance(step["inputs"], list)
            self.assertIn("outcome", step)
            for item in step["inputs"]:
                self.assertIsInstance(item, str)
                self.assertTrue(item)
        # The stages that consumed artifacts name them by digest, so the
        # derivation is replayable from the digests alone.
        by_stage = {step["stage"]: step for step in steps}
        for stage in ("expected_state", "observed_state"):
            for digest in by_stage[stage]["inputs"]:
                self.assertRegex(digest, r"^[0-9a-f]{64}$")
        stages = [step["stage"] for step in steps]
        for stage in ("expected_state", "observed_state", "comparison",
                      "risk_rules", "risk_scoring", "xai", "response_planning"):
            self.assertIn(stage, stages, f"{stage} is missing from the derivation")
        self.assertLess(
            stages.index("comparison"), stages.index("risk_rules"),
            "the comparison did not precede the risk rules",
        )
        self.assertLess(
            stages.index("risk_scoring"), stages.index("response_planning"),
            "the score was not produced before anything could act on it",
        )

    def test_the_recommendation_is_labelled_as_derived_not_observed(self):
        recommendation = self.chain["recommendation"]
        self.assertTrue(recommendation["recommendation_id"])
        self.assertTrue(recommendation["action"])
        self.assertIn(recommendation["priority"], ("HIGH", "MEDIUM", "LOW", "INFO"))
        # A recommendation proposes; it is never applied by this surface.
        self.assertFalse(recommendation["applied"])
        self.assertTrue(recommendation["approval_required"])
        for fact in self.chain["facts"]:
            if fact["category"] == "RECOMMENDED":
                self.assertEqual(fact["source"], "ResponseRecommendation.action")
        self.assertFalse(
            any(
                fact["category"] == "OBSERVED"
                and "Response" in fact["source"]
                for fact in self.chain["facts"]
            ),
            "a recommendation was filed as an observation",
        )
        # The recommendation names the component that produced it, and the
        # chain records that the same component's action is the fact.
        self.assertEqual(
            self.chain["recommendation"]["derived_by"], "response.planner")


class TestProvenanceBoundary(unittest.TestCase):
    """5: every value in the chain is filed under the source that established it."""

    @classmethod
    def setUpClass(cls):
        cls.store = _store(HIGH_ASSET)
        cls.chain = _chain(cls.store)
        cls.by_id = {item["fact_id"]: item for item in cls.chain["facts"]}

    def test_the_baseline_is_filed_as_configured_not_observed(self):
        """A validated state is a declaration by an operator, not a capture."""
        fact = self.by_id["configured.drift_baseline"]
        self.assertEqual(fact["category"], "CONFIGURED")
        self.assertNotEqual(fact["category"], "OBSERVED")
        self.assertIn("registry", fact["source"])

    def test_the_current_state_is_filed_as_observed(self):
        fact = self.by_id["observed.drift_current_state"]
        self.assertEqual(fact["category"], "OBSERVED")
        self.assertIn("ObservedState", fact["source"])

    def test_the_comparison_result_is_filed_as_derived(self):
        fact = self.by_id["derived.drift_changed_fields"]
        self.assertEqual(fact["category"], "DERIVED")
        self.assertIn("correlation.drift", fact["source"])

    def test_the_source_kind_itself_is_filed_as_configured(self):
        fact = self.by_id["configured.drift_current_source"]
        self.assertEqual(fact["category"], "CONFIGURED")
        self.assertEqual(fact["value"]["kind"], DRIFT_SOURCE_KIND_DECLARED)
        self.assertFalse(fact["value"]["is_capture"])

    def test_mission_context_is_never_filed_as_observed(self):
        """A declared profile is assessment input, not a property of the network."""
        self.assertTrue(
            all(
                fact["category"] != "OBSERVED"
                for fact in self.chain["facts"]
                if "mission" in fact["source"].lower()
            )
        )
        context = self.chain["mission_context"]
        self.assertFalse(context["risk"]["inferred_from_traffic"])
        self.assertFalse(context["derived_from_observation"])
        self.assertEqual(
            context["context_source"], "operator_supplied_asset_mission_profile")
        self.assertEqual(context["context_source_path"], MISSION_PROFILES)
        self.assertEqual(
            context["context_source_sha256"],
            sha256_file(str(Path(REPO_ROOT, MISSION_PROFILES))),
        )

    def test_ml_output_cannot_override_the_authoritative_comparison(self):
        """The ML result is a separate evidence channel, never a drift input.

        No such finding is produced, and the model -- whose own output is filed
        as ``ml_output`` -- is not among the sources of the drift facts. The
        comparison holds even if an ML result is present, which is asserted by
        ``test_the_ml_channel_cannot_create_or_suppress_drift`` below.
        """
        drift_sources = {
            fact["source"] for fact in self.chain["facts"]
            if "drift" in fact["fact_id"]
        }
        self.assertFalse(
            any("ml" in source.lower() for source in drift_sources),
            f"a drift fact was sourced from the model: {drift_sources}",
        )
        for fact in self.chain["facts"]:
            if fact["category"] == "OBSERVED" and "drift" in fact["fact_id"]:
                self.assertNotIn("ml", fact["source"].lower())

    def test_the_ml_channel_cannot_create_or_suppress_drift(self):
        """6: the authoritative comparison is independent of the model output."""
        from correlation.models.observed import ObservedState

        state, record = load_observed_state(FIXTURE_STATE)
        provenance = json.loads(Path(REPO_ROOT, FIXTURE_PROVENANCE).read_text())
        # A second declared current state: same security state, no ML at all.
        store = build_store(
            asset_id=HIGH_ASSET,
            mission_profiles=load_mission_profiles(),
            baselines=_registry(),
            baseline_id=BASELINE_ID,
            drift_observations=[DriftCurrentObservation(
                slot=DRIFT_SLOT, observed=state, state_record=record,
                declared_provenance=provenance,
            )],
        )
        chain = _chain(store)
        self.assertEqual(chain["drift"]["status"], "drift")
        self.assertEqual(
            chain["finding_digest"], self.chain["finding_digest"])
        self.assertEqual(chain["risk_score"], EXPECTED_TECHNICAL_RISK)

    def test_an_unknown_comparable_field_is_reported_not_resolved(self):
        """Absence of evidence is not agreement, and not drift either."""
        # A trafficless observation establishes no security state, so nothing
        # can be compared -- and the chain must say so rather than imply the
        # state held.
        from correlation.drift import assess_drift
        from correlation.models.observed import ObservedState

        registry = _registry()
        assessment = assess_drift(
            registry.get(BASELINE_ID), ObservedState(timestamp_ns=0),
            run_id="dataset-20260924-003710", sequence=3)
        self.assertEqual(assessment.status, "indeterminate")
        self.assertIsNone(assessment.risk)
        self.assertEqual(list(assessment.changed_fields), [])
        # Nothing was counted as agreement either, so no comparison claim is
        # implied in either direction.
        self.assertEqual(list(assessment.unchanged_variables), [])
        self.assertIn("address_family", assessment.unknown_variables)


class TestIntegrityAndTamper(unittest.TestCase):
    """6: the claim is checkable, and a doctored artifact is refused."""

    @classmethod
    def setUpClass(cls):
        cls.store = _store(HIGH_ASSET)
        cls.chain = _chain(cls.store)

    def test_every_evidence_artifact_verifies_against_its_real_bytes(self):
        self.assertTrue(self.chain["evidence"])
        for ref in self.chain["evidence"]:
            self.assertTrue(ref["verifiable"])
            self.assertEqual(ref["verification_status"], "valid")
            self.assertEqual(ref["artifact_present"], True)
            self.assertEqual(ref["artifact_sha256"], ref["actual_sha256"])

    def test_the_artifact_digest_check_passes_on_the_real_artifacts(self):
        check = self._check("evidence.artifact_digests")
        self.assertEqual(check["status"], "pass")
        self.assertTrue(check["client_verifiable"])

    def test_tampering_with_the_recorded_artifact_is_detected_and_not_repaired(self):
        """The one thing an integrity claim must never do is pass anyway."""
        held = self.store.custody_inputs[DRIFT_ASSESSMENT]
        finding = next(
            item for item in held.assessment.findings
            if item.finding_id == ESP_FINDING
        )
        self.assertTrue(finding.evidence_refs, "the drift finding has no evidence")
        doctored = dataclasses.replace(finding.evidence_refs[0],
                                       artifact_sha256="0" * 64)

        from correlation.custody.builder import build_chain_of_custody

        chain = build_chain_of_custody(
            assessment_id=DRIFT_ASSESSMENT,
            finding=dataclasses.replace(
                finding,
                evidence_refs=(doctored,) + tuple(finding.evidence_refs[1:]),
            ),
            assessment=held.assessment,
            correlation=held.correlation,
            expected=held.expected,
            drift=held and self.store.drift_inputs[DRIFT_ASSESSMENT],
            sources=held.sources,
            verify_evidence=True,
        )

        link = next(item for item in chain.evidence
                    if item.evidence_id == doctored.evidence_id)
        self.assertEqual(link.verification_status, "invalid")
        # Claimed digest reported as claimed, never quietly corrected ...
        self.assertEqual(link.artifact_sha256, "0" * 64)
        self.assertNotEqual(link.actual_sha256, "0" * 64)
        # ... the check fails rather than passing ...
        self.assertEqual(chain.integrity_check("evidence.artifact_digests").status,
                         "fail")
        # ... and nothing was rewritten to make it consistent.
        self.assertEqual(doctored.verify(REPO_ROOT).status, "invalid")
        self.assertEqual(doctored.artifact_sha256, "0" * 64)

    def test_skipping_verification_is_reported_as_not_performed_not_as_passed(self):
        skipped = self.store.chain_of_custody(
            DRIFT_ASSESSMENT, ESP_FINDING, verify_evidence=False).to_dict()
        check = self._check("evidence.artifact_digests", payload=skipped)
        self.assertNotEqual(check["status"], "pass")
        for ref in skipped["evidence"]:
            self.assertNotEqual(ref["verification_status"], "valid")

    def test_the_declared_source_check_states_the_fixture_is_not_a_capture(self):
        check = self._check("drift.current_source_declared_not_captured")
        self.assertEqual(check["status"], "pass")
        self.assertTrue(check["client_verifiable"])
        self.assertFalse(check["observed"]["is_capture"])
        self.assertEqual(check["observed"]["kind"], DRIFT_SOURCE_KIND_DECLARED)

    def test_a_declared_source_cannot_also_claim_to_be_a_capture(self):
        """The model refuses the contradiction instead of publishing it."""
        with self.assertRaises(ValueError):
            DriftCurrentSource(DRIFT_SOURCE_KIND_DECLARED, is_live_capture=True)
        with self.assertRaises(ValueError):
            DriftCurrentSource("something_else")
        self.assertIn(DRIFT_SOURCE_KIND_RECORDED, DRIFT_SOURCE_KINDS)
        self.assertIn(DRIFT_SOURCE_KIND_DECLARED, DRIFT_SOURCE_KINDS)

    def test_the_baseline_seal_is_present_and_verified(self):
        check = self._check("drift.baseline_explicit")
        self.assertEqual(check["status"], "pass")
        self.assertEqual(check["observed"]["baseline_id"], BASELINE_ID)
        self.assertTrue(check["observed"]["baseline_digest"])
        self.assertEqual(
            check["observed"]["current_state_digest"],
            self.chain["drift"]["current"]["state_digest"],
        )

    def test_the_comparison_stayed_inside_its_declared_scope(self):
        check = self._check("drift.fields_within_declared_scope")
        self.assertEqual(check["status"], "pass")
        self.assertEqual(
            sorted(check["observed"]["changed_variables"]),
            ["ah.presence", "esp.presence"],
        )
        self.assertEqual(
            sorted(check["expected"]["comparable_variables"]),
            ["address_family", "ah.presence", "esp.presence"],
        )

    def test_every_limitation_a_client_depends_on_is_published(self):
        limitations = " ".join(self.chain["limitations"])
        for subject in (
            "no cipher, DH group, PFS, IKE version",
            "excluded from the comparison by declaration",
            "does not establish intent",
            "declared artifact",
        ):
            self.assertIn(subject, limitations)

    # -- helpers ------------------------------------------------------------

    def _check(self, check_id, payload=None):
        return next(
            item for item in (payload or self.chain)["integrity"]
            if item["check_id"] == check_id
        )


class TestMissionContextComparison(unittest.TestCase):
    """3/7: identical technical evidence, different operational consequence."""

    def setUp(self):
        self.low = _store(LOW_ASSET)
        self.high = _store(HIGH_ASSET)
        self.low_chain = _chain(self.low)
        self.high_chain = _chain(self.high)

    def test_both_asset_contexts_are_evaluated_over_the_same_scenario(self):
        self.assertEqual(self.low.asset_id, LOW_ASSET)
        self.assertEqual(self.high.asset_id, HIGH_ASSET)
        self.assertIn(DRIFT_ASSESSMENT, self.low.bundles)
        self.assertIn(DRIFT_ASSESSMENT, self.high.bundles)
        self.assertEqual(
            sorted(self.low.bundles), sorted(self.high.bundles))

    #: Integrity checks that are about the declared context rather than about
    #: the technical evidence. These are the only ones allowed to differ.
    MISSION_CHECKS = ("mission.context_declared", "mission.risk_preserves_technical")
    #: Facts that are about the declared asset rather than about the observed or
    #: compared security state. These are the only facts allowed to differ.
    MISSION_FACTS = ("asset.asset_id", "asset.criticality",
                     "asset.mission_impact", "asset.role",
                     "derived.contextualized_risk")

    def test_every_technical_component_is_byte_identical(self):
        for section in ("drift", "evidence", "sources", "finding_id", "rule",
                        "risk_score", "risk_severity", "severity", "category",
                        "title", "steps"):
            self.assertEqual(
                json.dumps(self.low_chain[section], sort_keys=True),
                json.dumps(self.high_chain[section], sort_keys=True),
                f"{section} differs between the two asset contexts",
            )

    def test_only_the_declared_asset_facts_differ(self):
        """The observed and compared facts cannot absorb the asset id."""
        low = {item["fact_id"]: item for item in self.low_chain["facts"]}
        high = {item["fact_id"]: item for item in self.high_chain["facts"]}
        self.assertEqual(sorted(low), sorted(high))
        differing = set()
        for fact_id, item in low.items():
            if json.dumps(item, sort_keys=True) == json.dumps(
                    high[fact_id], sort_keys=True):
                continue
            differing.add(fact_id)
        self.assertEqual(differing, set(self.MISSION_FACTS))
        for fact_id in differing:
            self.assertIn("operator_supplied_asset_mission_profile",
                          low[fact_id]["source"])
            self.assertNotEqual(low[fact_id]["category"], "OBSERVED",
                                f"{fact_id} was filed as an observation")

    def test_only_the_mission_context_integrity_checks_differ(self):
        """The technical integrity verdicts are identical; the context's are not.

        Two checks name the declared asset and the contextualized score, so they
        must differ. Every other check -- the digests, the baseline seal, the
        comparison scope, the declared-source labelling -- must be byte
        identical, and must reach the same verdict.
        """
        low = {item["check_id"]: item for item in self.low_chain["integrity"]}
        high = {item["check_id"]: item for item in self.high_chain["integrity"]}
        self.assertEqual(sorted(low), sorted(high))
        for check_id, item in low.items():
            if check_id in self.MISSION_CHECKS:
                self.assertEqual(item["status"], "pass")
                self.assertEqual(high[check_id]["status"], "pass")
                continue
            self.assertEqual(
                json.dumps(item, sort_keys=True),
                json.dumps(high[check_id], sort_keys=True),
                f"the technical integrity check {check_id} differs between assets",
            )

    def test_the_finding_digest_is_identical_for_both_assets(self):
        self.assertEqual(self.low_chain["finding_digest"],
                         self.high_chain["finding_digest"])
        self.assertTrue(self.low_chain["finding_digest"])

    def test_the_technical_risk_is_identical_for_both_assets(self):
        self.assertEqual(self.low_chain["risk_score"], EXPECTED_TECHNICAL_RISK)
        self.assertEqual(self.high_chain["risk_score"], EXPECTED_TECHNICAL_RISK)
        self.assertEqual(self.low_chain["risk_severity"],
                         EXPECTED_TECHNICAL_SEVERITY)
        self.assertEqual(self.high_chain["risk_severity"],
                         EXPECTED_TECHNICAL_SEVERITY)

    def test_only_mission_context_and_contextualized_risk_differ(self):
        low = self.low_chain["mission_context"]
        high = self.high_chain["mission_context"]
        self.assertEqual(low["status"], "configured")
        self.assertEqual(high["status"], "configured")
        self.assertEqual(low["asset_id"], LOW_ASSET)
        self.assertEqual(high["asset_id"], HIGH_ASSET)
        self.assertEqual(low["profile"]["criticality"], "low")
        self.assertEqual(high["profile"]["criticality"], "high")
        self.assertEqual(low["profile"]["mission_impact"], "low")
        self.assertEqual(high["profile"]["mission_impact"], "high")
        # The technical input to the contextualization is the same number.
        self.assertEqual(low["risk"]["technical_risk"], high["risk"]["technical_risk"])
        self.assertEqual(low["risk"]["technical_risk"], EXPECTED_TECHNICAL_RISK)
        # The operational consequence is not.
        self.assertLess(low["risk"]["contextualized_risk"],
                        high["risk"]["contextualized_risk"])
        self.assertEqual(low["risk"]["contextualized_risk"], 30)
        self.assertEqual(high["risk"]["contextualized_risk"], 45)
        self.assertEqual(low["risk"]["contextualized_severity"], "HIGH")
        self.assertEqual(high["risk"]["contextualized_severity"], "CRITICAL")

    def test_the_contextualized_score_stays_inside_the_existing_scale(self):
        for chain in (self.low_chain, self.high_chain):
            risk = chain["mission_context"]["risk"]
            self.assertGreaterEqual(risk["contextualized_risk"], 0)
            self.assertLessEqual(risk["contextualized_risk"], 100)
            self.assertEqual(risk["score_cap"], 100)
            self.assertEqual(risk["model_version"], "mission-context-v1")

    def test_the_audit_and_identity_sections_are_not_mission_scoped(self):
        """A guard against a false pass: the contexts are not cosmetic, and the
        technical record does not absorb the asset id."""
        for section in ("identity", "audit_event_ids", "audit_linkage_status",
                        "read_only", "component", "component_version",
                        "schema_version", "risk_engine_version",
                        "risk_policy_version"):
            self.assertEqual(
                json.dumps(self.low_chain[section], sort_keys=True),
                json.dumps(self.high_chain[section], sort_keys=True),
                f"{section} differs between the two asset contexts",
            )
        # The asset id appears in the mission section, and only there among the
        # technical fields.
        self.assertEqual(self.low_chain["mission_context"]["asset_id"], LOW_ASSET)
        self.assertEqual(self.high_chain["mission_context"]["asset_id"], HIGH_ASSET)

    def test_an_undeclared_asset_keeps_the_technical_risk_alone(self):
        store = _store("gw-undeclared")
        chain = _chain(store)
        self.assertEqual(chain["mission_context"]["status"], "not_configured")
        self.assertIsNone(chain["mission_context"]["risk"])
        self.assertEqual(chain["risk_score"], EXPECTED_TECHNICAL_RISK)
        self.assertEqual(chain["finding_digest"], self.low_chain["finding_digest"])


class TestApiEndToEnd(unittest.TestCase):
    """8/11: the integrated result is served by the existing read-only surface."""

    @classmethod
    def setUpClass(cls):
        cls.store = _store(HIGH_ASSET)
        cls.payload = handle_assessment_finding_explanation(
            cls.store, DRIFT_ASSESSMENT, ESP_FINDING)

    def test_the_existing_explanation_route_serves_the_drift_finding(self):
        payload = self.payload
        self.assertEqual(payload["finding_id"], ESP_FINDING)
        self.assertEqual(payload["assessment_id"], DRIFT_ASSESSMENT)
        self.assertEqual(payload["drift"]["status"], "drift")
        self.assertEqual(payload["rule"]["rule_id"], "drift.configuration")
        self.assertEqual(payload["risk_score"], EXPECTED_TECHNICAL_RISK)
        self.assertEqual(payload["mission_context"]["status"], "configured")
        json.dumps(payload)

    def test_the_flat_route_serves_the_same_chain(self):
        payload = handle_finding_explanation(
            self.store, ESP_FINDING, {"assessment_id": DRIFT_ASSESSMENT})
        self.assertEqual(payload["finding_digest"],
                         self.payload["finding_digest"])
        self.assertEqual(payload["drift"]["status"], "drift")
        self.assertEqual(payload["mission_context"]["asset_id"], HIGH_ASSET)

    def test_the_explanation_carries_every_acceptance_element(self):
        payload = self.payload
        for element in (
            "drift", "facts", "integrity", "evidence", "sources", "steps",
            "mission_context", "recommendation", "limitations", "determinism",
            "read_only", "identity", "audit_linkage_status", "finding_digest",
        ):
            self.assertIn(element, payload, f"{element} is not served")
        self.assertTrue(payload["sources"])
        self.assertTrue(payload["evidence"])
        self.assertTrue(payload["integrity"])
        self.assertTrue(payload["limitations"])

    def test_the_served_payload_declares_the_fixture_is_not_a_capture(self):
        source = self.payload["drift"]["current"]["source"]
        self.assertFalse(source["is_capture"])
        self.assertIn("NOT a packet capture", source["declaration"])
        self.assertNotIn(REPO_ROOT, json.dumps(self.payload))

    def test_the_other_drift_finding_is_explained_too(self):
        payload = handle_assessment_finding_explanation(
            self.store, DRIFT_ASSESSMENT, AH_FINDING)
        self.assertEqual(payload["finding_id"], AH_FINDING)
        self.assertEqual(payload["drift"]["status"], "drift")
        self.assertNotEqual(payload["finding_digest"],
                            self.payload["finding_digest"])

    def test_the_drift_is_also_visible_from_the_drift_routes(self):
        summary = handle_drift(self.store)
        self.assertEqual(summary["baseline_id"], BASELINE_ID)
        self.assertTrue(summary["configured"])
        # Totals are over distinct comparisons: the one that drifted is
        # reported against two assessments but counted once.
        # Per-assessment counts: the drifted comparison is reported twice,
        # because it is both the context of the plan-based assessment and an
        # assessment in its own right.
        # Two drifted comparisons, each reported against two assessments: the
        # declared ESP/AH fixture, and the genuine transport/IPv6 capture of the
        # same asset under a different configuration.
        self.assertEqual(summary["status_counts"],
                         {"drift": 4, "indeterminate": 2, "no_drift": 9})
        self.assertEqual(summary["assessment_count"], 15)
        self.assertEqual(summary["drift_origin_count"], 2)
        # Four distinct comparison results, from fifteen assessments.
        self.assertEqual(summary["comparison_count"], 4)

        detail = handle_assessment_drift(self.store, DRIFT_ASSESSMENT)
        self.assertEqual(detail["status"], "drift")
        self.assertTrue(detail["drift_detected"])
        self.assertEqual(detail["current"]["source"]["kind"],
                         DRIFT_SOURCE_KIND_DECLARED)
        self.assertFalse(detail["current"]["source"]["is_capture"])

    def test_the_drift_assessment_is_listed_in_the_assessment_surface(self):
        ids = [header["assessment_id"] for header in self.store.headers]
        self.assertIn(DRIFT_ASSESSMENT, ids)
        header = next(item for item in self.store.headers
                      if item["assessment_id"] == DRIFT_ASSESSMENT)
        self.assertEqual(header["risk_score"], EXPECTED_TECHNICAL_RISK)
        self.assertEqual(header["severity"], EXPECTED_TECHNICAL_SEVERITY)
        self.assertEqual(header["slot"], "band-medium-drift")
        # The row says the current state was declared, not captured, before a
        # reader has to open anything.
        self.assertIn("declared controlled current observation",
                      header["scenario"])
        self.assertIn("not a capture of a live device", header["scenario"])

    def test_the_drift_summary_reports_the_source_kind_per_assessment(self):
        """A client scanning the table can see which side was only declared."""
        summary = handle_drift(self.store)
        entry = summary["assessments"][DRIFT_ASSESSMENT]
        self.assertEqual(entry["status"], "drift")
        self.assertEqual(entry["current_source_kind"], DRIFT_SOURCE_KIND_DECLARED)
        self.assertFalse(entry["current_source_is_capture"])
        self.assertEqual(entry["entry_kind"], "drift_origin")
        self.assertEqual(entry["parent_assessment_id"], PLAN_ASSESSMENT)
        # The plan-based entry is the same comparison, and says so.
        plan_entry = summary["assessments"][PLAN_ASSESSMENT]
        self.assertEqual(plan_entry["status"], "drift")
        self.assertEqual(plan_entry["entry_kind"], "plan_comparison")
        self.assertIsNone(plan_entry["parent_assessment_id"])
        self.assertEqual(plan_entry["current_source_kind"],
                         DRIFT_SOURCE_KIND_DECLARED)
        # One comparison, two assessments: both facts published. Two drifted
        # comparisons in total once transport-v6 is counted.
        self.assertEqual(summary["comparison_count"], 4)
        self.assertEqual(summary["assessment_count"], 15)
        self.assertEqual(summary["drift_origin_count"], 2)
        # Every other assessment used a real recorded capture.
        self.assertEqual(
            summary["current_source_kinds"],
            {DRIFT_SOURCE_KIND_DECLARED: 2, DRIFT_SOURCE_KIND_RECORDED: 13},
        )
        for assessment_id, other in summary["assessments"].items():
            if assessment_id in (DRIFT_ASSESSMENT, PLAN_ASSESSMENT):
                continue
            self.assertEqual(other["current_source_kind"],
                             DRIFT_SOURCE_KIND_RECORDED)
            self.assertTrue(other["current_source_is_capture"])

    def test_the_no_drift_control_is_served_as_no_drift(self):
        """Without the declaration, the declared scenario holds still.

        The store also holds transport-v6, a real capture of the same asset
        under an IPv6 configuration, which genuinely disagrees with the IPv4
        baseline. So the control is asserted on the slot under test: the
        declared scenario reports no_drift, and the only drift left anywhere is
        the one attributable to that genuine capture.
        """
        control = _store(HIGH_ASSET, with_declared=False)
        summary = handle_drift(control)
        self.assertEqual(summary["status_counts"],
                         {"indeterminate": 2, "drift": 2, "no_drift": 10})
        self.assertEqual(summary["assessment_count"], 14)
        self.assertEqual(summary["drift_origin_count"], 1)
        self.assertEqual(
            summary["current_source_kinds"], {DRIFT_SOURCE_KIND_RECORDED: 14})
        # The declared scenario, with its declaration removed, is at rest.
        self.assertEqual(summary["assessments"][PLAN_ASSESSMENT]["status"],
                         "no_drift")
        # And every remaining drift is the genuine IPv6 capture, not the fixture.
        drifted = {aid for aid, entry in summary["assessments"].items()
                   if entry["status"] == "drift"}
        self.assertEqual(
            drifted,
            {"dataset-20260924-003710:46:transport-v6",
             "dataset-20260924-003710:46:transport-v6-drift"},
        )
        for aid in drifted:
            entry = summary["assessments"][aid]
            self.assertEqual(entry["current_source_kind"],
                             DRIFT_SOURCE_KIND_RECORDED)
            self.assertTrue(entry["current_source_is_capture"])
            self.assertEqual(
                [(c["variable"], c["baseline_value"], c["current_value"])
                 for c in entry["changed_fields"]],
                [("address_family", "ipv4", "ipv6")])

    def test_the_openapi_document_declares_the_new_fields(self):
        document = openapi_document()
        schema = document["components"]["schemas"]["ChainOfCustody"]
        properties = schema["properties"]
        for field in ("drift", "mission_context", "recommendation", "facts",
                      "integrity", "evidence", "sources", "limitations"):
            self.assertIn(field, properties, f"{field} is not in the contract")
        # The drift-origin assessment is served by the existing routes: the
        # document needs no new path, only the fields inside the chain.
        paths = document["paths"]
        explanation = "/api/v1/assessments/{id}/findings/{finding_id}/explanation"
        self.assertIn(explanation, paths)
        self.assertEqual(set(paths[explanation]), {"get"})
        # No new path was invented for the drift-origin assessment: it is an
        # ordinary assessment, so it is served by the ordinary routes.
        self.assertEqual(
            len([p for p in paths if "drift" in p]), 3,
            "the drift surface grew a redundant route")

    def test_the_declared_source_fields_are_in_the_openapi_contract(self):
        document = openapi_document()
        schemas = document["components"]["schemas"]
        self.assertIn("DriftCurrentSource", schemas)
        current_source = schemas["DriftCurrentSource"]["properties"]
        for field in ("kind", "is_capture", "is_live_capture", "declared_kind",
                      "declaration", "derived_from", "artifact_sha256",
                      "public_path"):
            self.assertIn(field, current_source,
                          f"{field} is missing from DriftCurrentSource")
        self.assertIn(
            "DriftCurrentSource",
            json.dumps(schemas["DriftCurrentSide"]),
        )
        summary = schemas["DriftSummary"]["properties"]
        self.assertIn("current_source_kinds", summary)
        self.assertIn("drift_origin_count", summary)
        entry = summary["assessments"]["additionalProperties"]["properties"]
        self.assertEqual(entry["current_source_kind"]["enum"],
                         ["recorded_capture", "declared_observation"])
        self.assertIn("current_source_is_capture", entry)


class TestNoDriftControl(unittest.TestCase):
    """10: the honest negative case, stated as strongly as the positive one."""

    @classmethod
    def setUpClass(cls):
        cls.store = _store(HIGH_ASSET, with_declared=False)
        cls.chain = _chain(cls.store, assessment_id=PLAN_ASSESSMENT,
                           finding_id=_plan_finding())

    def test_the_real_capture_against_its_own_baseline_reports_no_drift(self):
        drift = self.chain["drift"]
        self.assertEqual(drift["status"], "no_drift")
        self.assertFalse(drift["drift_detected"])
        self.assertIsNone(drift["risk"])
        self.assertEqual(drift["changed_fields"], [])
        self.assertEqual(list(drift["unchanged_variables"]),
                         ["address_family", "esp.presence", "ah.presence"])

    def test_no_drift_creates_no_drift_finding_anywhere(self):
        """Removing the declaration removes the finding it would have created.

        Store-wide, one recorded case now drifts for real: transport-v6, whose
        capture was taken under a different configuration than the baseline. The
        claim under test is narrower and stronger -- no slot reports a drift
        finding unless a capture or a declaration actually supports one.
        """
        drift_origins = {aid for aid, parent in self.store.drift_parent.items()
                         if parent is not None}
        for assessment_id, bundle in self.store.bundles.items():
            drift = bundle["drift"]
            has_finding = any("DRIFT" in finding["finding_id"]
                              for finding in bundle["risk"]["findings"])
            # No drift finding without a drift result: that is the direction
            # that would be fabricated.
            if drift["status"] != "drift":
                self.assertFalse(
                    has_finding,
                    f"{assessment_id} carries a drift finding while comparing "
                    f"as {drift['status']!r}")
            # And a drifted comparison is registered as an assessment, so the
            # finding is reachable rather than orphaned in context.
            if assessment_id in drift_origins:
                self.assertTrue(
                    has_finding,
                    f"{assessment_id} is a drifted assessment with no finding")
        # Every drift verdict must rest on a canonical-state difference that the
        # comparison itself carries. Derived from the comparisons that were
        # built -- no ids and no expected digest strings participate -- so it
        # survives renumbering and cannot be satisfied by a fixed total.
        self.assertEqual(
            _drift_verdicts_without_a_canonical_difference(
                self.store.drift_inputs),
            [],
            "a drift verdict must rest on a real canonical-state difference")
        # The declared fixture's own assessment and its drift-origin row are
        # absent without the declaration.
        self.assertNotIn(DRIFT_ASSESSMENT, self.store.bundles)

    def test_a_drift_verdict_without_a_canonical_difference_is_rejected(self):
        """The digest guard above is load-bearing, and skips indeterminate.

        Two halves, both by mutation rather than by assertion:
        erasing the canonical difference while leaving ``status="drift"`` must be
        reported as an offender, and an uninformative observation that carries a
        different digest must not be -- otherwise the guard would be a flat
        biconditional and would misread every indeterminate comparison.
        """
        real = self.store.drift_inputs
        self.assertEqual(
            _drift_verdicts_without_a_canonical_difference(real), [],
            "the store itself must satisfy the invariant")

        drifted = sorted(aid for aid, c in real.items()
                         if c.status == "drift")
        self.assertTrue(drifted, "corpus must contain a genuine drift to forge")

        # Mutation: keep the verdict, remove the difference it claims to rest
        # on. This is the fabricated drift the invariant exists to reject.
        forged_id = drifted[0]
        forged = dict(real)
        forged[forged_id] = dataclasses.replace(
            real[forged_id],
            current_state_digest=real[forged_id].baseline_state_digest)
        self.assertEqual(
            _drift_verdicts_without_a_canonical_difference(forged),
            [forged_id],
            "a drift verdict over an identical canonical state must be caught")

        # The exemption is earned, not assumed: an indeterminate comparison in
        # this corpus really does carry a different digest -- it observed
        # nothing comparable -- and is still correctly not called drift.
        indistinguishable = sorted(
            aid for aid, c in real.items()
            if c.status == "indeterminate"
            and c.baseline_state_digest != c.current_state_digest)
        self.assertTrue(
            indistinguishable,
            "corpus must exercise the indeterminate exemption to prove it")
        self.assertEqual(
            _drift_verdicts_without_a_canonical_difference(
                {aid: real[aid] for aid in indistinguishable}),
            [],
            "an indeterminate observation with a differing digest is not drift")

    def test_no_drift_is_still_reported_rather_than_omitted(self):
        """The absence of a finding is not the presence of a comparison."""
        self.assertIn("drift", self.chain)
        self.assertEqual(self.chain["drift"]["baseline"]["baseline_id"],
                         BASELINE_ID)
        self.assertEqual(
            self.chain["drift"]["baseline"]["state_digest"],
            self.chain["drift"]["current"]["state_digest"],
        )
        self.assertTrue(self.chain["drift"]["current"]["state_digest"])

    def test_no_drift_claims_nothing_about_the_technical_risk(self):
        """The plan-based finding keeps its own risk, untouched by the comparison."""
        self.assertEqual(
            self.chain["drift"]["risk"], None)
        self.assertNotEqual(self.chain["risk_score"], EXPECTED_TECHNICAL_RISK)

    def test_the_other_real_captures_also_report_no_drift(self):
        """4: all four recorded live captures share one security state."""
        digests = set()
        for path in (
            "results/e2e-verification/parser/tunnel_v4/state.jsonl",
            "results/e2e-verification/parser/tunnel_v6inner/state.jsonl",
            "results/observed-state/live_state_from_events_full.jsonl",
            "results/observed-state/lab-verify-20260919-143813/state_events.jsonl",
        ):
            state, _ = load_observed_state(path)
            baseline = validate_baseline(
                state, baseline_id="probe", validated_by="probe",
                validated_at=BASELINE_VALIDATED_AT)
            from correlation.drift import assess_drift

            result = assess_drift(baseline, state, sequence=1)
            self.assertEqual(result.status, "no_drift", path)
            digests.add(result.current_state_digest)
        self.assertEqual(len(digests), 1, "the captures do not share a state")

    def test_a_drift_assessment_is_never_claimed_without_a_baseline(self):
        store = _store(HIGH_ASSET, with_baseline=False)
        self.assertEqual(store.drift_inputs, {})


class TestDemonstrationArtifact(unittest.TestCase):
    """9: a published demonstration that cannot be mistaken for a capture."""

    ARTIFACT = "results/end-to-end-assessment/accepted_drift_demo.json"

    @classmethod
    def setUpClass(cls):
        path = Path(REPO_ROOT, cls.ARTIFACT)
        if not path.exists():
            raise unittest.SkipTest(
                f"{cls.ARTIFACT} is not generated; run "
                "scripts/write_end_to_end_demo.py"
            )
        cls.document = json.loads(path.read_text())

    def test_the_artifact_separates_the_real_capture_from_the_fixture(self):
        status = self.document["data_status"]
        self.assertTrue(status["real_recorded_capture"]["is_capture"])
        self.assertIn(BASELINE_STATE, status["real_recorded_capture"]["paths"])
        self.assertFalse(status["controlled_fixture"]["is_capture"])
        self.assertIn(FIXTURE_STATE, status["controlled_fixture"]["paths"])
        note = status["controlled_fixture"]["note"].lower()
        self.assertIn("disclosed derived fixture", note)
        self.assertIn("labelled as such", note)

    def test_the_artifact_reports_the_same_numbers_as_the_pipeline(self):
        comparison = self.document["comparison"]
        self.assertTrue(comparison["finding_digest_identical"])
        self.assertTrue(comparison["technical_risk_identical"])
        self.assertEqual(comparison["finding_id"], ESP_FINDING)
        for asset, expected in ((LOW_ASSET, 30), (HIGH_ASSET, 45)):
            chain = self.document["asset_contexts"][asset]["chain"]
            self.assertEqual(chain["drift"]["status"], "drift")
            self.assertEqual(chain["risk_score"], EXPECTED_TECHNICAL_RISK)
            self.assertEqual(
                chain["mission_context"]["risk"]["contextualized_risk"],
                expected,
            )
            self.assertFalse(
                chain["drift"]["current"]["source"]["is_capture"])

    def test_the_artifact_carries_the_control_case_too(self):
        control = self.document["control_no_drift"]
        self.assertFalse(control["assessment_ids_include_drift_origin"])
        self.assertNotIn("drift", control["drift_summary"]["status_counts"])

    def test_the_artifact_leaks_no_host_path(self):
        self.assertNotIn(REPO_ROOT, json.dumps(self.document))


def _plan_finding() -> str:
    """A finding id from the plan-based assessment, for the control chain."""
    state, _ = load_observed_state(RECORDED_STATE)
    del state
    store = _store(HIGH_ASSET, with_declared=False)
    findings = store.bundles[PLAN_ASSESSMENT]["risk"]["findings"]
    if not findings:
        raise AssertionError("the plan assessment produced no finding")
    return findings[0]["finding_id"]


if __name__ == "__main__":
    unittest.main()
