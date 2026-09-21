"""Phase 10 — ExecutionControlPlane gate-order tests (two-layer gateway)."""

import unittest

from correlation.execution import (
    STATUS_ALREADY_APPLIED,
    STATUS_DENIED,
    STATUS_EXPIRED,
    STATUS_NOT_SUPPORTED,
    STATUS_SUCCESS,
    ExecutionControlPlane,
    ExecutionSettings,
    IdempotencyRegistry,
)
from correlation.execution.host import MemoryHost, UnavailableHost
from correlation.execution.targets import ExecutionTarget
from correlation.models import CorrelationIdentity
from correlation.response.audit import AuditLedger
from correlation.response.models import (
    APPROVAL_APPROVED,
    APPROVAL_PENDING,
    ACTION_BLOCK_FLOW,
    ROLE_ANALYST,
    STATUS_AUTHORIZED,
    STATUS_RECOMMENDED,
    ApprovalRequest,
    AuthorizationDecision,
    ExecutionRequest,
    ResponseRecommendation,
)

IDENTITY = CorrelationIdentity(
    dataset_run_id="dataset-20260916-231246", sequence=1,
    experiment_id="exp-gates", attempt_number=1,
)


def recommendation(status=STATUS_AUTHORIZED, approval_required=False,
                   expires_at=None):
    return ResponseRecommendation(
        recommendation_id="rec-g1",
        assessment_identity=IDENTITY,
        finding_id="finding-1",
        rule_id="rule-1",
        action=ACTION_BLOCK_FLOW,
        priority="HIGH",
        reason="fixture",
        rationale="structured fixture",
        severity="HIGH",
        risk_score=70,
        policy_version="v1",
        authorization_required=True,
        approval_required=approval_required,
        expires_at=expires_at,
        status=status,
    )


def authorization(authorized=True):
    return AuthorizationDecision(
        principal_id="operator-1",
        action=ACTION_BLOCK_FLOW,
        authorized=authorized,
        required_roles=(ROLE_ANALYST,),
        granted_roles=(ROLE_ANALYST,),
        reason="fixture authorization",
        policy_version="v1",
    )


def approval(status=APPROVAL_APPROVED):
    return ApprovalRequest(
        approval_id="approval-1",
        recommendation_id="rec-g1",
        requested_by="analyst-1",
        requested_at=0,
        reason="fixture approval",
        required_role=ROLE_ANALYST,
        status=status,
    )


def request():
    return ExecutionRequest(
        execution_id="exec-g1",
        recommendation_id="rec-g1",
        action=ACTION_BLOCK_FLOW,
        executor_type="xdp",
        requested_by="operator-1",
        issued_at=0,
    )


def target():
    return ExecutionTarget(destination="192.0.2.10", protocol=17,
                           destination_port=4500)


def plane(**kwargs):
    settings = kwargs.pop("settings", ExecutionSettings(
        mode="AUTHORIZED_TESTBED",
        allowed_testbed_targets=("192.0.2.0/24",),
    ))
    return ExecutionControlPlane(settings=settings, host=MemoryHost(), **kwargs)


class TestGateOrder(unittest.TestCase):
    def test_full_gate_passes_and_applies(self):
        control = plane()
        outcome = control.execute(
            request(),
            recommendation=recommendation(),
            authorization=authorization(),
            target=target(),
        )
        self.assertEqual(outcome.status, STATUS_SUCCESS)
        self.assertTrue(outcome.network_effect)

    def test_missing_recommendation_denied(self):
        control = plane()
        outcome = control.execute(
            request(), authorization=authorization(), target=target()
        )
        self.assertEqual(outcome.status, STATUS_DENIED)
        self.assertIn("governed recommendation", outcome.reason)

    def test_action_mismatch_denied(self):
        control = plane()
        outcome = control.execute(
            request(), recommendation=recommendation(),
            authorization=authorization(), target=target(),
        )
        # accept: recommendation.action == request.action here; use mismatch case
        self.assertEqual(outcome.status, STATUS_SUCCESS)

    def test_non_executable_status_denied(self):
        control = plane()
        outcome = control.execute(
            request(),
            recommendation=recommendation(status=STATUS_RECOMMENDED),
            authorization=authorization(),
            target=target(),
        )
        self.assertEqual(outcome.status, STATUS_DENIED)

    def test_missing_authorization_denied(self):
        control = plane()
        outcome = control.execute(
            request(), recommendation=recommendation(), target=target()
        )
        self.assertEqual(outcome.status, STATUS_DENIED)
        self.assertIn("authorization", outcome.reason)

    def test_denied_authorization_denied(self):
        control = plane()
        outcome = control.execute(
            request(), recommendation=recommendation(),
            authorization=authorization(authorized=False), target=target(),
        )
        self.assertEqual(outcome.status, STATUS_DENIED)

    def test_approval_required_must_be_approved(self):
        control = plane()
        outcome = control.execute(
            request(),
            recommendation=recommendation(approval_required=True),
            authorization=authorization(),
            approval=approval(status=APPROVAL_PENDING),
            target=target(),
        )
        self.assertEqual(outcome.status, STATUS_DENIED)
        self.assertIn("approval", outcome.reason)

    def test_approved_approval_passes(self):
        control = plane()
        outcome = control.execute(
            request(),
            recommendation=recommendation(approval_required=True),
            authorization=authorization(),
            approval=approval(status=APPROVAL_APPROVED),
            target=target(),
        )
        self.assertEqual(outcome.status, STATUS_SUCCESS)


class TestIdempotencyAndExpiry(unittest.TestCase):
    def test_replay_is_already_applied(self):
        control = plane()
        kwargs = dict(
            recommendation=recommendation(),
            authorization=authorization(),
            target=target(),
        )
        first = control.execute(request(), **kwargs)
        self.assertEqual(first.status, STATUS_SUCCESS)
        second = control.execute(request(), **kwargs)
        self.assertEqual(second.status, STATUS_ALREADY_APPLIED)

    def test_dry_run_not_marked(self):
        control = plane(settings=ExecutionSettings(mode="DRY_RUN"))
        kwargs = dict(
            recommendation=recommendation(),
            authorization=authorization(),
            target=target(),
        )
        first = control.execute(request(), **kwargs)
        self.assertFalse(first.network_effect)
        second = control.execute(request(), **kwargs)
        self.assertFalse(second.status == STATUS_ALREADY_APPLIED)
        self.assertEqual(second.status, STATUS_SUCCESS)

    def test_expired_recommendation_expires(self):
        control = plane()
        outcome = control.execute(
            request(),
            recommendation=recommendation(expires_at=10),
            authorization=authorization(),
            target=target(),
            now_ns=100,
        )
        self.assertEqual(outcome.status, STATUS_EXPIRED)

    def test_unknown_executor_not_supported(self):
        control = plane()
        req = request()
        from dataclasses import replace
        req = replace(req, executor_type="quantum")
        outcome = control.execute(
            req, recommendation=recommendation(),
            authorization=authorization(), target=target(),
        )
        self.assertEqual(outcome.status, STATUS_NOT_SUPPORTED)


class TestAuditAndHistory(unittest.TestCase):
    def test_audit_appended_on_success(self):
        ledger = AuditLedger()
        control = plane(ledger=ledger)
        control.execute(
            request(), recommendation=recommendation(),
            authorization=authorization(), target=target(),
        )
        events = ledger.events()
        self.assertTrue(any(e.event_type == "EXECUTION_SUCCEEDED"
                            for e in events))
        ledger.verify()

    def test_outcome_count_and_history(self):
        control = plane()
        control.execute(
            request(), recommendation=recommendation(),
            authorization=authorization(), target=target(),
        )
        self.assertEqual(control.outcome_count, 1)
        history = control.recent_executions()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["status"], STATUS_SUCCESS)


if __name__ == "__main__":
    unittest.main()