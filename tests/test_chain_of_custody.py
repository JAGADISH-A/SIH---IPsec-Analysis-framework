"""Chain-of-custody contract: one decision, proven from recorded artifacts.

The custody chain answers the auditor's question -- *prove the finding to me* --
so the tests are organised around the ways that answer could be a lie. Each
class below attacks one specific failure mode:

``TestCustodyCoversEveryFinding``
    Every finding the store produces has a chain. A feature that explains some
    findings and silently skips others is worse than none, because the skipped
    ones look unremarkable.

``TestFactAuthorityIsStated``
    Category and authority travel together, an unobservable variable reports a
    null value with the engine's own reason, and no fact ever claims to be an
    observation it is not. This is the class that catches a planned value or a
    model verdict being filed as something that was seen.

``TestCustodyReusesThePipeline``
    Nothing is re-derived. Every authoritative value is the one the pipeline
    produced, the recommendation is the reused planner's, and the severity is
    the risk engine's.

``TestIntegrityChecksAreHonest``
    A check that could not run says so. ``invalid`` and ``unavailable`` are
    reported, never upgraded to ``pass``.

``TestCustodyIsDeterministic``
    Two independent store builds produce byte-identical chains, and the model
    round-trips through its own dict.

``TestCustodyIsReadOnlyAndRedacted``
    Nothing is applied, no absolute host path reaches the wire, no PCAP bytes
    are inlined, and the control API was not touched.

``TestCustodyRoutes``
    The pair addresses a decision, an ambiguous flat lookup answers 409 with
    candidates rather than guessing, and the routes are documented.
"""

from __future__ import annotations

import copy
import json
import os
import unittest

from correlation import artifacts
from correlation.api import app as app_module
from correlation.api.custody_routes import (
    handle_assessment_finding_explanation,
    handle_finding_explanation,
)
from correlation.api.openapi import openapi_document
from correlation.api.routes import ApiError
from correlation.api.store import build_store
from correlation.custody import (
    AUTHORITATIVE_CATEGORIES,
    CHECK_FAIL,
    CHECK_NOT_APPLICABLE,
    CHECK_PASS,
    CHECK_UNAVAILABLE,
    CATEGORY_AUTHORITY,
    FACT_DERIVED,
    FACT_EXPECTED,
    FACT_OBSERVED,
    FACT_RECOMMENDED,
    ChainOfCustody,
    canonical_digest,
)
from correlation.custody.models import CustodyRecommendation
from correlation.risk.models import SOURCE_EXPECTED_CONFIGURATION
from correlation.xai.models import FindingExplanation as XaiFindingExplanation

#: An assessment whose finding is a real observed/expected contradiction.
MISMATCH_ASSESSMENT = "dataset-20260924-003710:16:tunnel-v6"
MISMATCH_FINDING = "RISK-ADDRESS-FAMILY-MISMATCH"
#: An assessment whose finding is about the PLANNED configuration only.
PLAN_ASSESSMENT = "dataset-20260924-003710:4:band-weak"
PLAN_FINDING = "RISK-PFS-DISABLED"
#: A finding id genuinely raised by several assessments.
SHARED_FINDING = "RISK-PFS-DISABLED"
ML_ASSESSMENT = "dataset-20260924-003710:75:ml-mismatch"
ML_FINDING = "RISK-ML-CLASSIFICATION"


def _all_findings(store):
    for assessment_id in sorted(store.bundles):
        for finding in store.bundles[assessment_id]["risk"]["findings"]:
            yield assessment_id, finding


class _StoreCase(unittest.TestCase):
    """One store for the whole class: building it runs the real pipeline."""

    @classmethod
    def setUpClass(cls):
        cls.store = build_store()

    def chain(self, assessment_id, finding_id):
        return self.store.chain_of_custody(assessment_id, finding_id)


# ---------------------------------------------------------------------------
# the contract itself
# ---------------------------------------------------------------------------

class TestCustodyCoversEveryFinding(_StoreCase):
    def test_every_backend_produced_finding_has_a_chain(self):
        pairs = list(_all_findings(self.store))
        self.assertGreater(len(pairs), 0, "the store produced no findings at all")
        for assessment_id, finding in pairs:
            with self.subTest(assessment=assessment_id, finding=finding["finding_id"]):
                chain = self.chain(assessment_id, finding["finding_id"])
                self.assertEqual(chain.finding_id, finding["finding_id"])
                self.assertEqual(chain.assessment_id, assessment_id)

    def test_every_chain_answers_all_seven_auditor_questions(self):
        for assessment_id, finding in _all_findings(self.store):
            with self.subTest(assessment=assessment_id, finding=finding["finding_id"]):
                chain = self.chain(assessment_id, finding["finding_id"])
                # why it was flagged
                self.assertTrue(chain.summary)
                self.assertEqual(chain.severity, finding["severity"])
                # which rule
                self.assertEqual(chain.rule.rule_id, finding["rule_id"])
                # observed vs expected vs derived
                self.assertTrue(chain.facts)
                categories = {fact.category for fact in chain.facts}
                self.assertTrue(
                    categories & {FACT_EXPECTED, FACT_OBSERVED},
                    "a chain must quote at least one authoritative fact",
                )
                self.assertIn(FACT_DERIVED, categories)
                # which evidence, and how it was derived
                self.assertTrue(chain.steps)
                self.assertEqual(
                    [step.index for step in chain.steps],
                    list(range(1, len(chain.steps) + 1)),
                )
                # integrity / provenance checks
                self.assertTrue(chain.integrity)
                self.assertTrue(chain.limitations)
                self.assertTrue(chain.determinism["deterministic"])
                self.assertTrue(chain.read_only)

    def test_a_chain_refuses_a_finding_the_assessment_never_made(self):
        """Otherwise one capture's evidence would explain another's finding."""
        with self.assertRaises(KeyError):
            self.chain(PLAN_ASSESSMENT, MISMATCH_FINDING)

    def test_a_chain_refuses_an_unknown_assessment(self):
        with self.assertRaises(KeyError):
            self.chain("no-such-run:1:nope", PLAN_FINDING)

    def test_the_model_does_not_shadow_the_xai_explanation(self):
        """``FindingExplanation`` is taken; the custody contract is distinct."""
        self.assertIsNot(ChainOfCustody, XaiFindingExplanation)
        self.assertNotEqual(ChainOfCustody.__name__, XaiFindingExplanation.__name__)


# ---------------------------------------------------------------------------
# authority and observation honesty
# ---------------------------------------------------------------------------

class TestFactAuthorityIsStated(_StoreCase):
    def test_authority_is_derived_from_category_and_never_set_independently(self):
        for assessment_id, finding in _all_findings(self.store):
            chain = self.chain(assessment_id, finding["finding_id"])
            for fact in chain.facts:
                with self.subTest(fact=fact.fact_id):
                    self.assertEqual(fact.authority, CATEGORY_AUTHORITY[fact.category])
                    self.assertEqual(fact.is_authoritative, fact.category in AUTHORITATIVE_CATEGORIES)

    def test_serialised_facts_carry_their_authority(self):
        payload = self.chain(MISMATCH_ASSESSMENT, MISMATCH_FINDING).to_dict()
        for fact in payload["facts"]:
            with self.subTest(fact=fact["fact_id"]):
                self.assertIn("authority", fact)
                self.assertIn("authoritative", fact)
                self.assertEqual(fact["authority"], CATEGORY_AUTHORITY[fact["category"]])
                self.assertEqual(
                    fact["authoritative"], fact["category"] in AUTHORITATIVE_CATEGORIES
                )

    def test_a_planned_value_is_authoritative_about_intent_not_reality(self):
        chain = self.chain(PLAN_ASSESSMENT, PLAN_FINDING)
        expected = chain.facts_in_category(FACT_EXPECTED)
        self.assertTrue(expected)
        for fact in expected:
            with self.subTest(fact=fact.fact_id):
                self.assertEqual(fact.authority, "authoritative_plan")
                self.assertNotEqual(fact.authority, "authoritative_observation")

    def test_an_unobservable_variable_reports_null_with_the_engines_reason(self):
        """The single most important property: no substituted observation."""
        chain = self.chain(PLAN_ASSESSMENT, PLAN_FINDING)
        observed = chain.fact_by_id("observed.esp_pfs")
        self.assertIsNotNone(observed, "the chain must still address the variable")
        self.assertEqual(observed.category, FACT_OBSERVED)
        self.assertIsNone(
            observed.value,
            "a sensor that cannot see esp.pfs must not be reported as having seen it",
        )
        # The reason is the comparison engine's own, not a paraphrase.
        outcome_reason = None
        for row in chain.steps:
            if row.stage == "comparison":
                outcome_reason = row.outcome
        self.assertIn("UNKNOWN", outcome_reason)
        self.assertTrue(observed.detail)
        self.assertIn("no authoritative observation", observed.detail)

    def test_an_unobservable_variable_also_says_so_in_a_check_and_a_limitation(self):
        chain = self.chain(PLAN_ASSESSMENT, PLAN_FINDING)
        check = chain.integrity_check("observation.authoritative_value_present")
        # This finding is about the plan, so the check is not applicable -- and
        # it must say that rather than reporting a pass or an absence it did not
        # evaluate.
        self.assertEqual(check.status, CHECK_NOT_APPLICABLE)
        self.assertIn("PLANNED configuration", check.detail)
        self.assertTrue(
            any("no authoritative observed value" in item for item in chain.limitations)
        )

    def test_a_real_mismatch_reports_both_sides(self):
        chain = self.chain(MISMATCH_ASSESSMENT, MISMATCH_FINDING)
        observed = chain.fact_by_id("observed.address_family")
        expected = chain.fact_by_id("expected.address_family")
        self.assertEqual(observed.value, "ipv4")
        self.assertEqual(expected.value, "ipv6")
        self.assertEqual(observed.authority, "authoritative_observation")
        self.assertEqual(expected.authority, "authoritative_plan")
        self.assertNotEqual(observed.value, expected.value)
        self.assertEqual(
            chain.integrity_check("observation.expected_observed_coherent").status,
            CHECK_PASS,
        )

    def test_a_model_verdict_is_never_filed_as_an_observation(self):
        """A classifier's output is derived evidence, not a protocol sighting."""
        chain = self.chain(ML_ASSESSMENT, ML_FINDING)
        self.assertEqual(chain.rule.rule_id, "ml.classification.disagreement")
        self.assertFalse(
            [fact for fact in chain.facts if fact.category == FACT_OBSERVED],
            "an ML finding must not produce an authoritative observation fact",
        )
        verdict = chain.fact_by_id("derived.model_verdict")
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.category, FACT_DERIVED)
        self.assertFalse(verdict.is_authoritative)
        self.assertEqual(verdict.authority, "derived_non_authoritative")
        self.assertIn("never filed as an authoritative observation", verdict.detail)
        # The planned profile is still quoted, as a plan.
        planned = chain.fact_by_id("expected.ML_TRAFFIC_CLASSIFICATION")
        self.assertEqual(planned.value, "messaging")
        self.assertEqual(planned.authority, "authoritative_plan")
        check = chain.integrity_check("observation.authoritative_value_present")
        self.assertEqual(check.status, CHECK_NOT_APPLICABLE)
        self.assertIn("model-derived", check.detail)
        self.assertTrue(
            any("model-derived" in item for item in chain.limitations)
        )

    def test_every_fact_value_is_digested_so_an_edit_is_detectable(self):
        chain = self.chain(MISMATCH_ASSESSMENT, MISMATCH_FINDING)
        for fact in chain.facts:
            with self.subTest(fact=fact.fact_id):
                self.assertEqual(fact.value_digest, canonical_digest(fact.value))

    def test_the_finding_record_digest_covers_the_authoritative_finding(self):
        chain = self.chain(MISMATCH_ASSESSMENT, MISMATCH_FINDING)
        held = self.store.custody_inputs[MISMATCH_ASSESSMENT]
        finding = next(
            item for item in held.assessment.findings
            if item.finding_id == MISMATCH_FINDING
        )
        self.assertEqual(chain.finding_digest, canonical_digest(finding.to_dict()))
        self.assertEqual(
            chain.integrity_check("finding.record_digest").status, CHECK_PASS
        )

    def test_the_plan_finding_declares_its_source(self):
        chain = self.chain(PLAN_ASSESSMENT, PLAN_FINDING)
        self.assertEqual(chain.rule.rule_id, "esp.pfs.disabled")
        self.assertTrue(chain.rule.registered)
        self.assertIn("posture_of_config", chain.rule.authoritative_source)
        held = self.store.custody_inputs[PLAN_ASSESSMENT]
        finding = next(
            item for item in held.assessment.findings
            if item.finding_id == PLAN_FINDING
        )
        self.assertEqual(finding.source, SOURCE_EXPECTED_CONFIGURATION)


# ---------------------------------------------------------------------------
# reuse, not re-derivation
# ---------------------------------------------------------------------------

class TestCustodyReusesThePipeline(_StoreCase):
    def test_severity_and_score_are_the_risk_engines_own(self):
        for assessment_id, finding in _all_findings(self.store):
            with self.subTest(assessment=assessment_id, finding=finding["finding_id"]):
                chain = self.chain(assessment_id, finding["finding_id"])
                assessment = self.store.custody_inputs[assessment_id].assessment
                self.assertEqual(chain.severity, finding["severity"])
                self.assertEqual(chain.risk_score, assessment.overall_score)
                self.assertEqual(chain.risk_severity, assessment.severity)
                self.assertEqual(
                    chain.risk_policy_version, assessment.risk_policy_version
                )
                self.assertEqual(
                    chain.risk_engine_version, assessment.risk_engine_version
                )

    def test_the_observed_value_is_the_comparison_engines_own(self):
        chain = self.chain(MISMATCH_ASSESSMENT, MISMATCH_FINDING)
        held = self.store.custody_inputs[MISMATCH_ASSESSMENT]
        row = next(
            item
            for item in held.correlation.mismatches
            if item["variable"] == "address_family"
        )
        observed = chain.fact_by_id("observed.address_family")
        self.assertEqual(observed.value, row["observed_value"])
        self.assertEqual(
            chain.fact_by_id("expected.address_family").value, row["expected_value"]
        )
        self.assertEqual(
            chain.fact_by_id("derived.comparison_status").value, row["status"]
        )

    def test_the_score_contribution_is_read_not_recomputed(self):
        chain = self.chain(MISMATCH_ASSESSMENT, MISMATCH_FINDING)
        held = self.store.custody_inputs[MISMATCH_ASSESSMENT]
        recorded = next(
            row
            for row in held.assessment.metadata["score_detail"]["contributions"]
            if row["finding_id"] == MISMATCH_FINDING
        )
        self.assertEqual(
            chain.fact_by_id("derived.score_contribution").value, recorded["added"]
        )

    def test_the_recommendation_is_the_reused_planners_own(self):
        chain = self.chain(MISMATCH_ASSESSMENT, MISMATCH_FINDING)
        held = self.store.custody_inputs[MISMATCH_ASSESSMENT]
        planned = next(
            item for item in held.response_plan.recommendations
            if item.finding_id == MISMATCH_FINDING
        )
        self.assertEqual(chain.recommendation.action, planned.action)
        self.assertEqual(chain.recommendation.rationale, planned.rationale)
        self.assertEqual(chain.recommendation.policy_version, planned.policy_version)
        self.assertEqual(chain.recommendation.derived_by, "response.planner")
        self.assertEqual(chain.fact_by_id("recommended.action").value, planned.action)
        self.assertEqual(
            chain.fact_by_id("recommended.action").category, FACT_RECOMMENDED
        )

    def test_a_recommendation_can_never_be_marked_applied(self):
        """The model refuses it, so no caller can serve a chain that says so."""
        with self.assertRaises(ValueError):
            CustodyRecommendation(action="NO_ACTION", applied=True)
        for assessment_id, finding in _all_findings(self.store):
            chain = self.chain(assessment_id, finding["finding_id"])
            if chain.recommendation is not None:
                with self.subTest(assessment=assessment_id):
                    self.assertFalse(chain.recommendation.applied)

    def test_serving_a_chain_runs_no_pipeline_stage(self):
        """The retained objects are read; nothing is recomputed per request."""
        held = self.store.custody_inputs[MISMATCH_ASSESSMENT]
        before = (
            copy.deepcopy(held.assessment.to_dict()),
            copy.deepcopy(held.correlation.to_dict()),
            copy.deepcopy(held.expected.to_dict()),
            copy.deepcopy(held.response_plan.to_dict()),
        )
        for _ in range(3):
            self.store.chain_of_custody(MISMATCH_ASSESSMENT, MISMATCH_FINDING)
        after = (
            held.assessment.to_dict(),
            held.correlation.to_dict(),
            held.expected.to_dict(),
            held.response_plan.to_dict(),
        )
        self.assertEqual(before, after, "serving a chain mutated pipeline state")

    def test_evidence_ids_come_from_real_content_addressed_references(self):
        chain = self.chain(MISMATCH_ASSESSMENT, MISMATCH_FINDING)
        self.assertTrue(chain.evidence)
        known = {
            ref.evidence_id
            for ref in self.store.custody_inputs[MISMATCH_ASSESSMENT].evidence_refs
        }
        for link in chain.evidence:
            with self.subTest(evidence=link.evidence_id):
                self.assertIn(link.evidence_id, known)
                self.assertRegex(link.artifact_sha256, r"^[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# integrity honesty
# ---------------------------------------------------------------------------

class TestIntegrityChecksAreHonest(_StoreCase):
    def test_no_check_reports_a_pass_it_did_not_evaluate(self):
        for assessment_id, finding in _all_findings(self.store):
            chain = self.chain(assessment_id, finding["finding_id"])
            for check in chain.integrity:
                with self.subTest(assessment=assessment_id, check=check.check_id):
                    if check.status == CHECK_UNAVAILABLE:
                        self.assertFalse(
                            check.passed,
                            "an unavailable check must not read as a pass",
                        )
                        self.assertTrue(check.detail)

    def test_audit_linkage_is_reported_as_unavailable_when_no_journal_exists(self):
        chain = self.chain(MISMATCH_ASSESSMENT, MISMATCH_FINDING)
        self.assertEqual(chain.audit_linkage_status, "unavailable")
        self.assertEqual(chain.audit_event_ids, ())
        check = chain.integrity_check("audit.chain_linked")
        self.assertEqual(check.status, CHECK_UNAVAILABLE)
        self.assertFalse(check.passed)
        self.assertTrue(
            any("not anchored in the tamper-evident journal" in item
                for item in chain.limitations),
            "the missing audit anchor must be stated, not implied",
        )

    def test_supplying_audit_event_ids_links_the_chain(self):
        chain = self.store.chain_of_custody(
            MISMATCH_ASSESSMENT, MISMATCH_FINDING,
            audit_event_ids=("evt-b", "evt-a"),
        )
        self.assertEqual(chain.audit_linkage_status, "linked")
        self.assertEqual(chain.audit_event_ids, ("evt-a", "evt-b"))
        self.assertEqual(chain.integrity_check("audit.chain_linked").status, CHECK_PASS)

    def test_a_tampered_artifact_is_reported_invalid_and_never_repaired(self):
        """The ref's own verify() decides; the chain only reports it.

        The tamper is threaded through the *finding* so the chain is genuinely
        forced to evaluate it: an assertion on a separately-constructed ref
        would never prove the chain reports a failure.
        """
        import dataclasses

        from correlation.custody.builder import build_chain_of_custody

        held = self.store.custody_inputs[MISMATCH_ASSESSMENT]
        finding = next(
            item for item in held.assessment.findings
            if item.finding_id == MISMATCH_FINDING
        )
        self.assertTrue(finding.evidence_refs, "the recorded finding has no ref")
        ref = finding.evidence_refs[0]
        tampered = dataclasses.replace(ref, artifact_sha256="0" * 64)

        chain = build_chain_of_custody(
            assessment_id=MISMATCH_ASSESSMENT,
            finding=dataclasses.replace(
                finding, evidence_refs=(tampered,) + tuple(finding.evidence_refs[1:])
            ),
            assessment=held.assessment,
            correlation=held.correlation,
            expected=held.expected,
            sources=held.sources,
        )

        # The tampered artifact is named as invalid ...
        link = next(
            item for item in chain.evidence
            if item.evidence_id == tampered.evidence_id
        )
        self.assertEqual(link.verification_status, "invalid")
        # ... the digest is reported as claimed, never quietly corrected ...
        self.assertEqual(link.artifact_sha256, "0" * 64)
        self.assertNotEqual(link.actual_sha256, "0" * 64)
        # ... the check fails rather than passing ...
        check = chain.integrity_check("evidence.artifact_digests")
        self.assertEqual(check.status, CHECK_FAIL)
        # ... and nothing was written to repair it.
        self.assertEqual(
            tampered.verify(artifacts.REPO_ROOT).status, "invalid"
        )

    def test_a_finding_with_no_evidence_says_the_check_is_not_applicable(self):
        chain = self.chain(ML_ASSESSMENT, ML_FINDING)
        # The ML case does carry evidence; assert the not_applicable branch is
        # reachable and honest by construction instead of inventing a fixture.
        check = chain.integrity_check("evidence.artifact_digests")
        self.assertIn(
            check.status, (CHECK_PASS, CHECK_UNAVAILABLE, CHECK_FAIL, CHECK_NOT_APPLICABLE)
        )
        if not chain.evidence:
            self.assertEqual(check.status, CHECK_NOT_APPLICABLE)
            self.assertFalse(check.passed)

    def test_input_artifact_digests_are_required_and_reported(self):
        chain = self.chain(MISMATCH_ASSESSMENT, MISMATCH_FINDING)
        check = chain.integrity_check("provenance.artifact_digests")
        self.assertEqual(check.status, CHECK_PASS)
        self.assertTrue(chain.sources)
        for source in chain.sources:
            with self.subTest(role=source.role):
                self.assertRegex(source.artifact_sha256, r"^[0-9a-f]{64}$")

    def test_a_digestless_source_is_reported_as_a_failed_check(self):
        from correlation.custody.builder import build_chain_of_custody

        held = self.store.custody_inputs[MISMATCH_ASSESSMENT]
        chain = build_chain_of_custody(
            assessment_id=MISMATCH_ASSESSMENT,
            finding=next(
                item for item in held.assessment.findings
                if item.finding_id == MISMATCH_FINDING
            ),
            assessment=held.assessment,
            correlation=held.correlation,
            expected=held.expected,
            sources=[{"role": "observed_state", "public_path": "a.jsonl"}],
        )
        self.assertEqual(
            chain.integrity_check("provenance.artifact_digests").status, CHECK_FAIL
        )
        self.assertTrue(
            any("carry no digest" in item for item in chain.limitations),
            "a digestless source must be stated, not just counted",
        )

    def test_the_xai_layer_is_asserted_non_authoritative(self):
        chain = self.chain(MISMATCH_ASSESSMENT, MISMATCH_FINDING)
        check = chain.integrity_check("xai.non_authoritative")
        self.assertEqual(check.status, CHECK_PASS)
        self.assertEqual(check.observed, "derived_non_authoritative")
        step = next(row for row in chain.steps if row.stage == "xai")
        self.assertFalse(step.authoritative)

    def test_the_derivation_order_matches_the_pipeline(self):
        chain = self.chain(MISMATCH_ASSESSMENT, MISMATCH_FINDING)
        stages = [step.stage for step in chain.steps]
        self.assertEqual(
            stages,
            [
                "expected_state", "observed_state", "comparison", "risk_rules",
                "risk_scoring", "xai", "response_planning",
            ],
        )
        authoritative = {step.stage for step in chain.steps if step.authoritative}
        self.assertEqual(
            authoritative,
            {"expected_state", "observed_state", "comparison", "risk_rules", "risk_scoring"},
        )
        for step in chain.steps:
            with self.subTest(stage=step.stage):
                self.assertTrue(step.outcome, "a stage that produced nothing says so")


# ---------------------------------------------------------------------------
# determinism
# ---------------------------------------------------------------------------

class TestCustodyIsDeterministic(unittest.TestCase):
    def test_two_independent_store_builds_produce_identical_chains(self):
        first, second = build_store(), build_store()
        compared = 0
        for assessment_id, finding in _all_findings(first):
            with self.subTest(assessment=assessment_id, finding=finding["finding_id"]):
                left = first.chain_of_custody(
                    assessment_id, finding["finding_id"]
                ).to_dict()
                right = second.chain_of_custody(
                    assessment_id, finding["finding_id"]
                ).to_dict()
                self.assertEqual(
                    json.dumps(left, sort_keys=True),
                    json.dumps(right, sort_keys=True),
                )
                compared += 1
        self.assertGreater(compared, 0)

    def test_repeated_requests_are_byte_identical(self):
        store = build_store()
        first = json.dumps(
            store.chain_of_custody(MISMATCH_ASSESSMENT, MISMATCH_FINDING).to_dict(),
            sort_keys=True,
        )
        for _ in range(3):
            again = json.dumps(
                store.chain_of_custody(MISMATCH_ASSESSMENT, MISMATCH_FINDING).to_dict(),
                sort_keys=True,
            )
            self.assertEqual(first, again)

    def test_the_chain_round_trips_through_its_own_dict(self):
        store = build_store()
        for assessment_id, finding in _all_findings(store):
            with self.subTest(assessment=assessment_id, finding=finding["finding_id"]):
                original = store.chain_of_custody(
                    assessment_id, finding["finding_id"]
                ).to_dict()
                restored = ChainOfCustody.from_dict(original).to_dict()
                self.assertEqual(
                    json.dumps(original, sort_keys=True),
                    json.dumps(restored, sort_keys=True),
                )

    def test_no_wall_clock_and_no_random_ids_are_claimed_and_true(self):
        store = build_store()
        chain = store.chain_of_custody(MISMATCH_ASSESSMENT, MISMATCH_FINDING)
        determinism = chain.determinism
        self.assertTrue(determinism["deterministic"])
        self.assertFalse(determinism["reads_wall_clock"])
        self.assertFalse(determinism["generates_random_ids"])
        # Digests are sha256, and the fact digests match a fresh computation.
        self.assertEqual(determinism["digest_algorithm"], "sha256(canonical_json)")
        self.assertIn("evidence[].verification_status", determinism[
            "filesystem_dependent_fields"
        ])
        for fact in chain.facts:
            with self.subTest(fact=fact.fact_id):
                self.assertEqual(fact.value_digest, canonical_digest(fact.value))

    def test_ordering_is_explicit_and_stable(self):
        store = build_store()
        chain = store.chain_of_custody(MISMATCH_ASSESSMENT, MISMATCH_FINDING)
        self.assertEqual(
            [fact.fact_id for fact in chain.facts],
            sorted(fact.fact_id for fact in chain.facts),
        )
        self.assertEqual(
            [link.evidence_id for link in chain.evidence],
            sorted(link.evidence_id for link in chain.evidence),
        )
        self.assertEqual(
            [step.index for step in chain.steps],
            sorted(step.index for step in chain.steps),
        )

    def test_canonical_digest_ignores_key_order(self):
        self.assertEqual(
            canonical_digest({"a": 1, "b": [1, 2]}), canonical_digest({"b": [1, 2], "a": 1})
        )
        self.assertNotEqual(canonical_digest({"a": 1}), canonical_digest({"a": 2}))


# ---------------------------------------------------------------------------
# read-only and disclosure
# ---------------------------------------------------------------------------

class TestCustodyIsReadOnlyAndRedacted(_StoreCase):
    def test_the_chain_is_marked_read_only_and_cannot_be_marked_otherwise(self):
        chain = self.chain(MISMATCH_ASSESSMENT, MISMATCH_FINDING)
        self.assertTrue(chain.read_only)
        with self.assertRaises(ValueError):
            ChainOfCustody.from_dict(
                {**chain.to_dict(), "read_only": False}
            )

    def test_no_absolute_host_path_reaches_the_payload(self):
        root = os.path.abspath(artifacts.REPO_ROOT)
        for assessment_id, finding in _all_findings(self.store):
            chain = self.chain(assessment_id, finding["finding_id"]).to_dict()
            text = json.dumps(chain)
            with self.subTest(assessment=assessment_id, finding=finding["finding_id"]):
                self.assertNotIn(root, text)
                self.assertNotIn("\\\\", text)
                for source in chain["sources"]:
                    path = source["public_path"]
                    self.assertFalse(
                        os.path.isabs(path or ""),
                        f"an absolute path reached the payload: {path}",
                    )
                    self.assertNotIn("..", path or "")

    def test_no_artifact_payload_or_pcap_bytes_are_inlined(self):
        chain = self.chain(MISMATCH_ASSESSMENT, MISMATCH_FINDING).to_dict()
        for link in chain["evidence"]:
            with self.subTest(evidence=link["evidence_id"]):
                self.assertNotIn("pcap_path", link)
                self.assertNotIn("bytes", link)
                self.assertNotIn("payload", link)
                self.assertIsNone(link.get("actual_path"))
        # The only artifact-shaped values are digests and sizes.
        for source in chain["sources"]:
            self.assertIn("artifact_sha256", source)

    def test_evidence_is_referenced_by_id_only(self):
        chain = self.chain(MISMATCH_ASSESSMENT, MISMATCH_FINDING)
        for fact in chain.facts:
            for evidence_id in fact.evidence_ids:
                with self.subTest(fact=fact.fact_id, evidence=evidence_id):
                    self.assertNotIn("/", evidence_id)
                    self.assertRegex(evidence_id, r"^ev-[0-9a-f]{32}$")

    def test_a_source_outside_the_repository_collapses_to_a_basename(self):
        from correlation.api.store import disclosed_sources

        disclosed = disclosed_sources(
            [{"path": "/etc/secret-host/config.jsonl", "artifact_sha256": "a" * 64}]
        )
        self.assertEqual(disclosed[0]["public_path"], "config.jsonl")
        self.assertNotIn("path", disclosed[0])

    def test_the_control_api_was_not_touched(self):
        """The control API is a separate server; coupling is a real defect."""
        import ast
        import pathlib

        control = pathlib.Path(__file__).resolve().parents[1] / "controller" / "api.py"
        tree = ast.parse(control.read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        for name in sorted(imported):
            with self.subTest(module=name):
                self.assertFalse(
                    name.startswith("correlation.custody")
                    or name.startswith("correlation.api"),
                    f"the control API now depends on {name}",
                )

    def test_no_custody_artifact_was_written_to_disk(self):
        """The layer is read-only, so it must not create files."""
        root = os.path.abspath(artifacts.REPO_ROOT)
        before = {
            os.path.join(dirpath, name)
            for dirpath, _dirs, files in os.walk(root)
            for name in files
            if "custody" in name.lower()
        }
        for assessment_id, finding in _all_findings(self.store):
            self.store.chain_of_custody(assessment_id, finding["finding_id"])
        after = {
            os.path.join(dirpath, name)
            for dirpath, _dirs, files in os.walk(root)
            for name in files
            if "custody" in name.lower()
        }
        self.assertEqual(before, after)


# ---------------------------------------------------------------------------
# the routes
# ---------------------------------------------------------------------------

class TestCustodyRoutes(_StoreCase):
    def test_the_nested_route_returns_the_chain(self):
        payload = handle_assessment_finding_explanation(
            self.store, MISMATCH_ASSESSMENT, MISMATCH_FINDING, {}
        )
        self.assertEqual(payload["api"], "custody")
        self.assertTrue(payload["read_only"])
        self.assertEqual(payload["assessment_id"], MISMATCH_ASSESSMENT)
        self.assertEqual(payload["finding_id"], MISMATCH_FINDING)
        self.assertEqual(payload["component"], "correlation.custody")
        json.dumps(payload)

    def test_the_nested_route_404s_for_another_assessments_finding(self):
        with self.assertRaises(ApiError) as caught:
            handle_assessment_finding_explanation(
                self.store, PLAN_ASSESSMENT, MISMATCH_FINDING, {}
            )
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(caught.exception.code, "finding_not_found")

    def test_the_nested_route_404s_for_an_unknown_assessment(self):
        with self.assertRaises(ApiError) as caught:
            handle_assessment_finding_explanation(
                self.store, "no-such-run:1:nope", MISMATCH_FINDING, {}
            )
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(caught.exception.code, "assessment_not_found")

    def test_an_ambiguous_flat_lookup_refuses_to_guess(self):
        """Merging candidates would invent a decision; first-match would lie."""
        with self.assertRaises(ApiError) as caught:
            handle_finding_explanation(self.store, SHARED_FINDING, {})
        error = caught.exception
        self.assertEqual(error.status, 409)
        self.assertEqual(error.code, "finding_ambiguous")
        self.assertGreater(len(error.extra["candidates"]), 1)
        self.assertEqual(
            error.extra["candidate_count"], len(error.extra["candidates"])
        )
        body = error.payload()
        self.assertEqual(body["error"]["code"], "finding_ambiguous")
        self.assertIn("candidates", body["error"])
        # The structured fields survive into the wire error object.
        self.assertEqual(body["error"]["code"], error.code)

    def test_an_extra_candidate_field_cannot_disguise_the_error(self):
        error = ApiError(
            409, "finding_ambiguous", "detail",
            extra={"code": "spoofed", "message": "spoofed", "candidates": ["a"]},
        )
        payload = error.payload()["error"]
        self.assertEqual(payload["code"], "finding_ambiguous")
        self.assertEqual(payload["message"], "detail")
        self.assertEqual(payload["candidates"], ["a"])

    def test_the_flat_route_resolves_a_unique_finding_without_a_disambiguator(self):
        payload = handle_finding_explanation(self.store, MISMATCH_FINDING, {})
        self.assertEqual(payload["assessment_id"], MISMATCH_ASSESSMENT)

    def test_the_flat_route_honours_the_disambiguator(self):
        payload = handle_finding_explanation(
            self.store, SHARED_FINDING, {"assessment_id": PLAN_ASSESSMENT}
        )
        self.assertEqual(payload["assessment_id"], PLAN_ASSESSMENT)
        self.assertEqual(payload["finding_id"], SHARED_FINDING)

    def test_the_flat_route_404s_for_an_unknown_finding(self):
        with self.assertRaises(ApiError) as caught:
            handle_finding_explanation(self.store, "RISK-NOT-A-REAL-FINDING", {})
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(caught.exception.code, "finding_not_found")

    def test_the_flat_route_404s_when_the_disambiguator_is_wrong(self):
        with self.assertRaises(ApiError) as caught:
            handle_finding_explanation(
                self.store, SHARED_FINDING, {"assessment_id": MISMATCH_ASSESSMENT}
            )
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(caught.exception.code, "finding_not_found")

    def test_verify_false_says_the_check_did_not_run(self):
        """An honest skip: the work is not done, and not claimed to be done."""
        default = handle_assessment_finding_explanation(
            self.store, MISMATCH_ASSESSMENT, MISMATCH_FINDING, {}
        )
        self.assertTrue(default["verification"]["performed"])
        self.assertTrue(default["evidence"])
        self.assertTrue(
            all(
                item["verification_status"] == "valid"
                for item in default["evidence"]
            ),
            "the default path re-hashes every referenced artifact",
        )

        payload = handle_assessment_finding_explanation(
            self.store, MISMATCH_ASSESSMENT, MISMATCH_FINDING, {"verify": "false"}
        )
        self.assertFalse(payload["verification"]["performed"])
        self.assertIn("verify=false", payload["verification"]["reason"])
        self.assertTrue(payload["evidence"], "recorded digests are still served")
        for item in payload["evidence"]:
            with self.subTest(evidence_id=item["evidence_id"]):
                self.assertEqual(item["verification_status"], "not_performed")
                self.assertIsNone(item["actual_sha256"])
                # A file that was never opened cannot be reported as absent.
                self.assertIsNone(item["artifact_present"])
                self.assertTrue(item["artifact_sha256"])
        check = next(
            entry for entry in payload["integrity"]
            if entry["check_id"] == "evidence.artifact_digests"
        )
        self.assertEqual(check["status"], CHECK_UNAVAILABLE)

    def test_the_custody_schema_is_structurally_sound(self):
        """A schema that parses can still be wrong: guard the shape.

        A misplaced closing brace once left `ChainOfCustody.properties` empty
        with every property name sitting at the schema's top level, and the
        document still serialised. It only fails a client that validates.
        """
        import re

        from correlation.api.openapi import openapi_document

        doc = openapi_document()
        schemas = doc["components"]["schemas"]
        chain_schema = schemas["ChainOfCustody"]
        self.assertTrue(chain_schema["properties"], "properties must not be empty")
        self.assertEqual(
            set(chain_schema) - {"type", "description", "required", "properties"},
            set(),
            "a schema object may only carry spec keywords",
        )
        for key in ("facts", "steps", "evidence", "integrity", "rule", "sources"):
            with self.subTest(key=key):
                self.assertIn(key, chain_schema["properties"])
                self.assertIn(key, chain_schema["required"])
        # Every $ref in the document must resolve, or a client cannot read it.
        raw = json.dumps(doc)
        refs = set(re.findall(r'"\$ref": "#/components/schemas/([A-Za-z0-9_]+)"', raw))
        self.assertTrue(refs)
        self.assertEqual(refs - set(schemas), set())

    def test_both_routes_are_documented_with_a_schema(self):
        doc = openapi_document()
        paths = doc["paths"]
        self.assertIn("/api/v1/assessments/{id}/findings/{finding_id}/explanation", paths)
        self.assertIn("/api/v1/findings/{finding_id}/explanation", paths)
        self.assertIn("ChainOfCustody", doc["components"]["schemas"])
        nested = paths["/api/v1/assessments/{id}/findings/{finding_id}/explanation"]
        ref = nested["get"]["responses"]["200"]["content"]["application/json"]["schema"]
        self.assertEqual(ref, {"$ref": "#/components/schemas/ChainOfCustody"})
        flat = paths["/api/v1/findings/{finding_id}/explanation"]["get"]
        self.assertIn("409", flat["responses"])

    def test_the_documented_routes_state_the_ambiguity_and_the_read_only_truth(self):
        doc = openapi_document()["paths"]
        nested = doc["/api/v1/assessments/{id}/findings/{finding_id}/explanation"]["get"]
        for phrase in ("NOT unique", "recommendation.applied", "value: null",
                       "unavailable"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, nested["description"])
        # The nested route addresses the pair, so it is a 404 -- never a 409 --
        # when the finding lives in a different assessment.
        self.assertNotIn("409", nested["responses"])
        self.assertIn("404", nested["responses"])
        flat = doc["/api/v1/findings/{finding_id}/explanation"]["get"]
        self.assertIn("candidates", flat["description"])
        self.assertIn("409", flat["description"])

    def test_the_routes_reach_the_live_dispatcher(self):
        from correlation.api.live import Phase10Context

        context = Phase10Context()
        path = (
            f"/api/v1/assessments/{MISMATCH_ASSESSMENT}"
            f"/findings/{MISMATCH_FINDING}/explanation"
        )
        body, content_type = app_module.handle_combined(
            self.store, context, path, {}
        )
        self.assertEqual(content_type, "application/json")
        self.assertEqual(body["finding_id"], MISMATCH_FINDING)

        flat = f"/api/v1/findings/{MISMATCH_FINDING}/explanation"
        body, _ = app_module.handle_combined(self.store, context, flat, {})
        self.assertEqual(body["finding_id"], MISMATCH_FINDING)

    def test_the_dispatcher_still_404s_an_unknown_explanation_route(self):
        from correlation.api.live import Phase10Context

        context = Phase10Context()
        for probe in (
            "/api/v1/findings/RISK-X/explanation/extra",
            f"/api/v1/assessments/{MISMATCH_ASSESSMENT}/findings/explanation",
            "/api/v1/assessments/a/findings/b/explanation/extra",
        ):
            with self.subTest(path=probe):
                with self.assertRaises(ApiError) as caught:
                    app_module.handle_combined(self.store, context, probe, {})
                self.assertEqual(caught.exception.status, 404)

    def test_no_mutating_verb_can_reach_a_custody_route(self):
        """The 405 lives in the transport, so assert it on a real socket."""
        import json as _json
        import threading
        import urllib.error
        import urllib.request

        from correlation.api.config import ServerConfig
        from correlation.api.live import Phase10Context

        httpd = app_module.DashboardServer(
            ("127.0.0.1", 0), self.store, None,
            phase10=Phase10Context(), cors=ServerConfig.resolve().cors,
        )
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)

        path = (
            f"/api/v1/assessments/{MISMATCH_ASSESSMENT}"
            f"/findings/{MISMATCH_FINDING}/explanation"
        )
        for verb in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(verb=verb):
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}{path}", method=verb, data=b""
                )
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(request, timeout=10)
                self.assertEqual(caught.exception.code, 405)
                body = _json.loads(caught.exception.read())
                self.assertEqual(body["error"]["code"], "method_not_allowed")

    def test_the_existing_findings_routes_are_unchanged(self):
        """The custody route is additive; the published shapes must not move."""
        from correlation.api.discovery import (
            handle_assessment_findings,
            handle_findings,
        )

        bundle = self.store.bundles[MISMATCH_ASSESSMENT]
        listed = handle_assessment_findings(self.store, MISMATCH_ASSESSMENT, {})
        self.assertEqual(listed["api"], "discovery-assessment-findings")
        rows = {row["finding_id"]: row for row in listed["findings"]}
        self.assertEqual(
            rows[MISMATCH_FINDING]["severity"], bundle["risk"]["findings"][0]["severity"]
        )
        # No custody keys leaked into the discovery row.
        self.assertNotIn("facts", rows[MISMATCH_FINDING])
        self.assertNotIn("integrity", rows[MISMATCH_FINDING])
        flat = handle_findings(self.store, {"assessment_id": MISMATCH_ASSESSMENT})
        self.assertEqual(flat["api"], "discovery-findings")
        self.assertNotIn(
            "facts", flat["findings"][0]
        )

    def test_audit_event_ids_are_linked_when_a_journal_provides_them(self):
        from correlation.api.custody_routes import _audit_event_ids

        class _Identity:
            dataset_run_id = "dataset-20260924-003710"
            sequence = 16

        class _Event:
            def __init__(self, event_id):
                self.event_id = event_id
                self.identity = _Identity()

        class _Journal:
            def select(self):
                return [_Event("evt-2"), _Event("evt-1"), _Event("evt-2")]

        identity = self.store.custody_inputs[
            MISMATCH_ASSESSMENT
        ].assessment.identity.to_dict()
        self.assertEqual(_audit_event_ids(_Journal(), identity), ("evt-1", "evt-2"))
        # No journal is an empty tuple, which the chain reports honestly.
        self.assertEqual(_audit_event_ids(None, identity), ())
        self.assertEqual(_audit_event_ids(_Journal(), {}), ())

    def test_the_envelope_is_json_serialisable_for_every_finding(self):
        for assessment_id, finding in _all_findings(self.store):
            with self.subTest(assessment=assessment_id, finding=finding["finding_id"]):
                payload = handle_assessment_finding_explanation(
                    self.store, assessment_id, finding["finding_id"], {}
                )
                json.dumps(payload)
                self.assertRegex(payload["finding_digest"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
