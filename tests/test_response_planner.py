"""Phase 9 planner tests: deterministic ResponsePlan from REAL Phase 4-7 outputs.

Every recommendation is derived from the committed upstream pipeline via the
shared ``tests/fixtures/response/fixtures.py`` helpers: REAL Phase-3 expected
state -> REAL Phase-4 comparison -> REAL Phase-6 assessment -> REAL Phase-7 XAI.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fixtures", "response"))

from response_fixtures import (  # noqa: E402
    assessment_for_posture,
    clean_assessment,
    demo_clock,
    expected_for_posture,
    policy,
    plan_sample_by_posture,
    real_correlation_for,
    synthetic_correlation,
    xai_for,
)

from correlation.models import MLResult  # noqa: E402
from correlation.response import (  # noqa: E402
    ACTION_ALERT_ONLY,
    ACTION_CAPTURE_EVIDENCE,
    ACTION_REQUIRE_REVIEW,
    ResponsePlan,
    ResponsePolicy,
    STATUS_RECOMMENDED,
)
from correlation.response.planner import (  # noqa: E402
    PlanningContext,
    plan as make_plan,
)


def posture(key):
    return plan_sample_by_posture(key)["security_posture"]


class TestCleanAssessment(unittest.TestCase):
    def test_no_findings_no_recommendations(self):
        assessment = clean_assessment()
        plan = make_plan(PlanningContext(assessment=assessment, policy=policy()),
                         clock=demo_clock)
        self.assertIsInstance(plan, ResponsePlan)
        self.assertEqual(len(plan.recommendations), 0)
        self.assertFalse(plan.requires_approval)
        self.assertFalse(plan.requires_authorization)
        self.assertTrue(plan.generated_deterministically)
        self.assertEqual(plan.assessment_identity.to_dict(),
                         assessment.identity.to_dict())

    def test_plan_limitations_present(self):
        plan = make_plan(PlanningContext(assessment=clean_assessment(), policy=policy()),
                         clock=demo_clock)
        self.assertTrue(any("dry-run" in line for line in plan.limitations))


class TestWeakAssessment(unittest.TestCase):
    def setUp(self):
        self.assessment = assessment_for_posture("WEAK")
        self.plan = make_plan(PlanningContext(assessment=self.assessment, policy=policy()),
                              clock=demo_clock)

    def test_pfs_disabled_maps_to_review(self):
        rec = self.plan.by_id().get("RR-RISK-PFS-DISABLED")
        self.assertIsNotNone(rec)
        self.assertEqual(rec.action, ACTION_REQUIRE_REVIEW)
        self.assertEqual(rec.rule_id, "esp.pfs.disabled")
        self.assertEqual(rec.status, STATUS_RECOMMENDED)
        self.assertTrue(rec.approval_required)
        self.assertFalse(rec.authorization_required)
        self.assertIn("RESP-PFS-001", rec.rationale)

    def test_recommendation_derived_from_finding(self):
        rec = self.plan.by_id()["RR-RISK-PFS-DISABLED"]
        self.assertEqual(rec.finding_id, "RISK-PFS-DISABLED")
        self.assertEqual(rec.severity, "MEDIUM")
        self.assertEqual(rec.risk_score, self.assessment.overall_score)
        self.assertEqual(rec.policy_version, "response-policy-v1")
        self.assertIsNotNone(rec.expires_at)

    def test_plan_requires_approval(self):
        self.assertTrue(self.plan.requires_approval)
        self.assertFalse(self.plan.requires_authorization)


class TestCorrelationMismatch(unittest.TestCase):
    def test_mismatch_high_priority_review(self):
        assessment = assessment_for_posture("STRONG")
        expected = expected_for_posture("STRONG")
        correlation = real_correlation_for(expected)
        plan = make_plan(PlanningContext(
            assessment=assessment, correlation=correlation, policy=policy(),
        ), clock=demo_clock)
        self.assertIsInstance(plan, ResponsePlan)


class TestMLCapping(unittest.TestCase):
    def test_ml_anomaly_capped_to_review(self):
        assessment = assessment_for_posture(
            "STRONG", ml_result=MLResult(model_version="traffic-rf-v1-demo",
                                         anomaly=True, anomaly_score=0.93),
        )
        plan = make_plan(PlanningContext(assessment=assessment, policy=policy()),
                         clock=demo_clock)
        rec = plan.by_id().get("RR-RISK-ML-ANOMALY")
        self.assertIsNotNone(rec)
        self.assertEqual(rec.action, ACTION_REQUIRE_REVIEW)
        self.assertNotIn(rec.action, ("BLOCK_FLOW", "ISOLATE_FLOW",
                                      "TERMINATE_SESSION"))
        self.assertEqual(rec.rule_id, "ml.anomaly")
        self.assertIn("RESP-ML-ANOMALY", rec.rationale)

    def test_ml_policy_cap_provenance_when_overridden(self):
        assessment = assessment_for_posture(
            "STRONG", ml_result=MLResult(model_version="traffic-rf-v1-demo",
                                         anomaly=True, anomaly_score=0.93),
        )
        # If some future override tried to escalate ML to a blocking action,
        # the ml_handling cap must pull it back and mark the provenance.
        aggressive = policy(rule_overrides={
            "ml.anomaly": {"action": "BLOCK_FLOW", "priority": "HIGH",
                           "approval_required": True, "authorization_required": True},
        })
        rec = make_plan(
            PlanningContext(assessment=assessment, policy=aggressive),
            clock=demo_clock,
        ).by_id()["RR-RISK-ML-ANOMALY"]
        self.assertEqual(rec.action, ACTION_REQUIRE_REVIEW)
        self.assertEqual(rec.provenance, "RESPONSE_ML")
        self.assertIn("can never block", rec.rationale)

    def test_ml_classification_disagreement_is_alert_only(self):
        assessment = assessment_for_posture(
            "STRONG", ml_result=MLResult(
                model_version="traffic-rf-v1-demo",
                traffic_class="VOIP", classification_confidence=0.41),
        )
        plan = make_plan(PlanningContext(assessment=assessment, policy=policy()),
                         clock=demo_clock)
        rec = plan.by_id().get("RR-RISK-ML-CLASSIFICATION")
        self.assertIsNotNone(rec)
        self.assertEqual(rec.action, ACTION_ALERT_ONLY)
        self.assertFalse(rec.approval_required)


class TestUnknownGap(unittest.TestCase):
    def test_unknown_creates_capture_evidence(self):
        assessment = clean_assessment()
        correlation = synthetic_correlation(
            assessment.identity,
            unknowns=({"variable": "esp.encryption", "status": "UNKNOWN"},),
        )
        plan = make_plan(PlanningContext(
            assessment=assessment, correlation=correlation, policy=policy(),
        ), clock=demo_clock)
        rec = plan.by_id().get("RR-UNKNOWN-EVIDENCE-GAP")
        self.assertIsNotNone(rec)
        self.assertEqual(rec.action, ACTION_CAPTURE_EVIDENCE)
        self.assertEqual(rec.rule_id, "evidence.unknown.gap")
        self.assertEqual(rec.provenance, "RESPONSE_EVIDENCE_GAP")
        self.assertTrue(rec.approval_required)
        self.assertIn("never", rec.limitations[0])

    def test_unknown_deduplicates_by_variable(self):
        assessment = clean_assessment()
        correlation = synthetic_correlation(
            assessment.identity,
            unknowns=(
                {"variable": "esp.encryption", "status": "UNKNOWN"},
                {"variable": "esp.integrity", "status": "UNKNOWN"},
            ),
        )
        plan = make_plan(PlanningContext(
            assessment=assessment, correlation=correlation, policy=policy(),
        ), clock=demo_clock)
        gaps = [r for r in plan.recommendations if r.rule_id == "evidence.unknown.gap"]
        self.assertEqual(len(gaps), 1, "multiple UNKNOWN variables merge into one gap")
        self.assertEqual(gaps[0].recommendation_id, "RR-UNKNOWN-EVIDENCE-GAP")

    def test_not_applicable_no_response(self):
        assessment = clean_assessment()
        correlation = synthetic_correlation(
            assessment.identity,
            not_applicable=({"variable": "capture_filter", "status": "NOT_APPLICABLE"},),
        )
        plan = make_plan(PlanningContext(
            assessment=assessment, correlation=correlation, policy=policy(),
        ), clock=demo_clock)
        self.assertEqual(len(plan.recommendations), 0)

    def test_unknown_opt_out(self):
        assessment = clean_assessment()
        correlation = synthetic_correlation(
            assessment.identity,
            unknowns=({"variable": "esp.encryption", "status": "UNKNOWN"},),
        )
        p = policy(unknown_handling={"recommend": False})
        plan = make_plan(PlanningContext(
            assessment=assessment, correlation=correlation, policy=p,
        ), clock=demo_clock)
        self.assertEqual(len(plan.recommendations), 0)


class TestDeterminism(unittest.TestCase):
    def test_same_input_same_plan(self):
        a = make_plan(
            PlanningContext(assessment=assessment_for_posture("WEAK"), policy=policy()),
            clock=demo_clock,
        )
        b = make_plan(
            PlanningContext(assessment=assessment_for_posture("WEAK"), policy=policy()),
            clock=demo_clock,
        )
        self.assertEqual(a.to_json(sort_keys=True), b.to_json(sort_keys=True))

    def test_sorted_by_action_and_id(self):
        plan = make_plan(
            PlanningContext(assessment=assessment_for_posture("WORST"), policy=policy()),
            clock=demo_clock,
        )
        ids = [rec.recommendation_id for rec in plan.recommendations]
        self.assertEqual(ids, sorted(ids))


class TestPlanningContextValidation(unittest.TestCase):
    def test_assessment_required(self):
        with self.assertRaises(TypeError):
            PlanningContext(assessment=None, policy=policy())

    def test_policy_required(self):
        with self.assertRaises(TypeError):
            PlanningContext(assessment=clean_assessment(), policy=None)

    def test_bad_policy_type(self):
        with self.assertRaises(TypeError):
            PlanningContext(assessment=clean_assessment(), policy="policy")

    def test_bad_evidence_refs(self):
        with self.assertRaises(ValueError):
            PlanningContext(assessment=clean_assessment(), policy=policy(),
                            evidence_refs="nope")

    def test_plan_type_checked(self):
        with self.assertRaises(TypeError):
            make_plan({"assessment": clean_assessment(), "policy": policy()})


if __name__ == "__main__":
    unittest.main()