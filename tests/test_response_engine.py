"""Phase 9 ResponseEngine lifecycle tests (state machine end-to-end).

Drives REAL Phase-6 assessments (via the shared response fixtures) through the
full response lifecycle: plan -> approval -> authorization -> dry-run
execution -> result, plus rejection, denial, expiry, and audit integrity.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fixtures", "response"))

from response_fixtures import (  # noqa: E402
    assessment_for_posture,
    clean_assessment,
    demo_clock,
    demo_clock_after,
    engine,
    policy,
    real_correlation_for,
    synthetic_correlation,
)
from response_fixtures import DEMO_CLOCK_NS  # noqa: E402

from correlation.models import MLResult  # noqa: E402
from correlation.models import CorrelationIdentity  # noqa: E402
from correlation.response import (  # noqa: E402
    APPROVAL_APPROVED,
    ACTION_REQUIRE_REVIEW,
    DEFAULT_RESPONSE_POLICY_VERSION,
    ApprovalError,
    AuthorizationContext,
    ExpiredError,
    ResponsePlan,
    ResponsePolicy,
    ResponseRecommendation,
    ResponseStateError,
    ROLE_ANALYST,
    ROLE_SECURITY_OPERATOR,
    STATUS_APPROVED,
    STATUS_AUTHORIZED,
    STATUS_CANCELLED,
    STATUS_DENIED,
    STATUS_EXPIRED,
    STATUS_NOT_EVALUATED,
    STATUS_RECOMMENDED,
    STATUS_REJECTED,
    STATUS_SUCCEEDED,
)
from correlation.response.authorization import auth_context  # noqa: E402


def analyst_context(principal_id="analyst-1"):
    return auth_context(principal_id, (ROLE_ANALYST,))


def operator_context(principal_id="operator-1"):
    return auth_context(principal_id, (ROLE_SECURITY_OPERATOR,))


def expired_rec(recommendation_id="RR-EXPIRED"):
    """A RECOMMENDED recommendation already past its window."""
    return ResponseRecommendation(
        recommendation_id=recommendation_id,
        assessment_identity=CorrelationIdentity(
            dataset_run_id="dataset-20260916-231246",
            sequence=1,
            experiment_id="exp-response",
            attempt_number=1,
            window_index=0,
            window_start_ns=1_000_000_000,
            window_end_ns=60_000_000_000,
        ),
        finding_id="F-EXPIRED",
        rule_id="esp.pfs.disabled",
        action=ACTION_REQUIRE_REVIEW,
        priority="MEDIUM",
        reason="expired",
        rationale="response-policy-v1",
        severity="MEDIUM",
        risk_score=12,
        policy_version=DEFAULT_RESPONSE_POLICY_VERSION,
        authorization_required=False,
        approval_required=True,
        required_roles=(ROLE_ANALYST,),
        expires_at=DEMO_CLOCK_NS - 1,
        status=STATUS_RECOMMENDED,
    )


def weak_plan(eng, **plan_options):
    return eng.plan(assessment_for_posture("WEAK"), **plan_options)


class TestPlanEmit(unittest.TestCase):
    def test_plan_emits_recommendation_events(self):
        eng = engine()
        plan = eng.plan(assessment_for_posture("WEAK"))
        self.assertGreater(len(plan.recommendations), 0)
        self.assertEqual(len(eng.ledger), len(plan.recommendations))
        for event in eng.ledger.events():
            self.assertEqual(event.event_type, "RECOMMENDATION_CREATED")
        self.assertTrue(eng.ledger.verify())

    def test_plan_no_emit(self):
        eng = engine()
        plan = weak_plan(eng, emit_events=False)
        self.assertEqual(len(eng.ledger), 0)
        self.assertGreater(len(plan.recommendations), 0)

    def test_plan_type_checked(self):
        eng = engine()
        with self.assertRaises(TypeError):
            eng.plan({"not": "an assessment"})


class TestApprovalLifecycle(unittest.TestCase):
    def test_approve_review_action(self):
        eng = engine()
        plan = weak_plan(eng)
        rec = plan.by_id()["RR-RISK-PFS-DISABLED"]
        approval = eng.request_approval(rec, "analyst-1", reason="proceed")
        self.assertEqual(rec.status, "PENDING_APPROVAL")
        eng.approve(approval, rec, "analyst-1", roles=(ROLE_ANALYST,))
        self.assertEqual(rec.status, STATUS_APPROVED)
        self.assertEqual(approval.status, APPROVAL_APPROVED)

    def test_approval_requires_status_recommended(self):
        eng = engine()
        plan = weak_plan(eng)
        rec = plan.by_id()["RR-RISK-PFS-DISABLED"]
        eng.request_approval(rec, "analyst-1", "")
        with self.assertRaises(ApprovalError):
            eng.request_approval(rec, "analyst-1", "")

    def test_reject_path(self):
        eng = engine()
        plan = weak_plan(eng)
        rec = plan.by_id()["RR-RISK-PFS-DISABLED"]
        approval = eng.request_approval(rec, "analyst-1", "")
        eng.reject(approval, rec, "analyst-1", rejection_reason="not actionable")
        self.assertEqual(rec.status, STATUS_REJECTED)
        self.assertEqual(approval.status, "REJECTED")


class TestAuthorizationLifecycle(unittest.TestCase):
    def test_authorize_review_action(self):
        eng = engine()
        plan = weak_plan(eng)
        rec = plan.by_id()["RR-RISK-PFS-DISABLED"]
        approval = eng.request_approval(rec, "analyst-1", "proceed")
        eng.approve(approval, rec, "analyst-1", roles=(ROLE_ANALYST,))
        decision = eng.authorize(rec, analyst_context())
        self.assertTrue(decision.authorized)
        self.assertEqual(rec.status, STATUS_AUTHORIZED)

    def test_authorization_denied(self):
        from correlation.response import ROLE_VIEWER
        eng = engine()
        plan = weak_plan(eng)
        rec = plan.by_id()["RR-RISK-PFS-DISABLED"]
        with self.assertRaises(ApprovalError):
            eng.authorize(rec, auth_context("viewer-1", (ROLE_VIEWER,)))
        self.assertEqual(rec.status, STATUS_DENIED)

    def test_approval_required_before_authorization(self):
        eng = engine()
        plan = weak_plan(eng)
        rec = plan.by_id()["RR-RISK-PFS-DISABLED"]  # approval_required True
        self.assertTrue(rec.approval_required)
        with self.assertRaises(ResponseStateError):
            eng.authorize(rec, analyst_context())


class TestDryRunExecution(unittest.TestCase):
    def _full_executed_rec(self):
        eng = engine()
        plan = weak_plan(eng)
        rec = plan.by_id()["RR-RISK-PFS-DISABLED"]
        approval = eng.request_approval(rec, "analyst-1", "")
        eng.approve(approval, rec, "analyst-1", roles=(ROLE_ANALYST,))
        eng.authorize(rec, analyst_context())
        result, updated = eng.execute_dry_run(
            rec, analyst_context(), commanded_by="operator-1", reason="go",
        )
        return eng, rec, result, updated

    def test_full_lifecycle_succeeds(self):
        eng, rec, result, updated = self._full_executed_rec()
        self.assertTrue(result.success)
        self.assertFalse(result.network_effect)
        self.assertEqual(updated.status, STATUS_SUCCEEDED)
        self.assertEqual(rec.status, STATUS_SUCCEEDED)

    def test_full_lifecycle_audit_verifies(self):
        eng, rec, result, updated = self._full_executed_rec()
        self.assertTrue(eng.ledger.verify())
        event_types = [e.event_type for e in eng.ledger.events()]
        self.assertEqual(event_types[0], "RECOMMENDATION_CREATED")
        self.assertIn("APPROVAL_REQUESTED", event_types)
        self.assertIn("APPROVED", event_types)
        self.assertIn("AUTHORIZATION_CHECKED", event_types)
        self.assertIn("EXECUTION_REQUESTED", event_types)
        self.assertIn("DRY_RUN_EXECUTED", event_types)
        self.assertIn("EXECUTION_SUCCEEDED", event_types)

    def test_ungated_execution_missing_approval(self):
        eng = engine()
        plan = weak_plan(eng)
        rec = plan.by_id()["RR-RISK-PFS-DISABLED"]
        with self.assertRaises(ResponseStateError):
            eng.execute_dry_run(rec, analyst_context(), commanded_by="op-1")


class TestSimpleAction(unittest.TestCase):
    def test_alert_only_no_approval_required(self):
        eng = engine()
        assessment = assessment_for_posture(
            "STRONG", ml_result=MLResult(
                model_version="traffic-rf-v1-demo",
                traffic_class="VOIP", classification_confidence=0.41),
        )
        plan = eng.plan(assessment)
        rec = plan.by_id()["RR-RISK-ML-CLASSIFICATION"]
        self.assertFalse(rec.approval_required)
        self.assertFalse(rec.authorization_required)
        result, updated = eng.execute_dry_run(
            rec, analyst_context(), commanded_by="analyst-1",
        )
        self.assertTrue(result.success)
        self.assertEqual(updated.status, STATUS_SUCCEEDED)
        self.assertEqual(result.status, "DRY_RUN")


class TestExpiry(unittest.TestCase):
    def test_execution_expired_raises(self):
        eng = engine()
        rec = expired_rec()
        with self.assertRaises(ExpiredError):
            eng.execute_dry_run(rec, analyst_context(), commanded_by="op-1")
        # the status must not have moved
        self.assertEqual(rec.status, STATUS_RECOMMENDED)

    def test_expire_plan(self):
        eng = engine()
        plan = ResponsePlan(
            assessment_identity=expired_rec().assessment_identity,
            policy_version=DEFAULT_RESPONSE_POLICY_VERSION,
            recommendations=(expired_rec(),),
        )
        expired_ids = eng.expire(plan)
        self.assertEqual(expired_ids, ["RR-EXPIRED"])
        self.assertEqual(plan.recommendations[0].status, STATUS_EXPIRED)
        self.assertEqual(eng.ledger.last_event().event_type, "EXPIRED")
        self.assertTrue(eng.ledger.verify())

    def test_expire_ignores_terminal(self):
        eng = engine()
        rec = expired_rec()
        rec.status = STATUS_SUCCEEDED
        plan = ResponsePlan(
            assessment_identity=rec.assessment_identity,
            policy_version=DEFAULT_RESPONSE_POLICY_VERSION,
            recommendations=(rec,),
        )
        self.assertEqual(eng.expire(plan), [])


class TestCancel(unittest.TestCase):
    def test_cancel(self):
        eng = engine()
        plan = weak_plan(eng)
        rec = plan.by_id()["RR-RISK-PFS-DISABLED"]
        canceled = eng.cancel(rec, "operator-1", reason="planned maintenance")
        self.assertEqual(canceled.status, STATUS_CANCELLED)
        self.assertEqual(eng.ledger.last_event().event_type, "CANCELLED")
        self.assertTrue(eng.ledger.verify())


class TestAuditIntegrityAfterLifecycle(TestDryRunExecution):
    def test_ledger_matches_lifecycle(self):
        eng, _, _, _ = self._full_executed_rec()
        self.assertTrue(eng.ledger.verify())
        # re-derive from the serialized ledger -> still verifies
        from correlation.response.audit import AuditLedger
        restored = AuditLedger.from_dicts(eng.ledger.to_dicts())
        self.assertTrue(restored.verify())

    def test_for_recommendation_groups_events(self):
        eng, rec, _, _ = self._full_executed_rec()
        events = eng.ledger.for_recommendation(rec.recommendation_id)
        self.assertGreaterEqual(len(events), 6)


class TestEngineValidation(unittest.TestCase):
    def test_bad_policy_type(self):
        with self.assertRaises(TypeError):
            engine(policy="policy")

    def test_bad_clock(self):
        with self.assertRaises(TypeError):
            engine(clock="not-callable")

    def test_bad_ledger(self):
        with self.assertRaises(TypeError):
            engine(ledger="nope")

    def test_bad_executor(self):
        with self.assertRaises(TypeError):
            engine(executor="nope")


class TestDeterminism(unittest.TestCase):
    def test_plan_identical_across_engines(self):
        plan_a = engine().plan(assessment_for_posture("WEAK"), emit_events=False)
        plan_b = engine().plan(assessment_for_posture("WEAK"), emit_events=False)
        self.assertEqual(plan_a.to_json(sort_keys=True), plan_b.to_json(sort_keys=True))


if __name__ == "__main__":
    unittest.main()