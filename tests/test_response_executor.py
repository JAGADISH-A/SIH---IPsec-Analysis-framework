"""Phase 9 dry-run executor tests (network_effect is ALWAYS False)."""

import unittest

from correlation.models import CorrelationIdentity
from correlation.response import (
    ACTION_ALERT_ONLY,
    ACTION_REQUIRE_REVIEW,
    ExecutionRequest,
    ExecutorError,
    ResponsePolicy,
    ResponseRecommendation,
    ROLE_ANALYST,
    STATUS_DRY_RUN,
)
from correlation.response.executor import (
    EXECUTOR_TYPE_DRY_RUN,
    DryRunExecutor,
)

NOW = 1_800_000_000_000_000_000


def identity():
    return CorrelationIdentity(
        dataset_run_id="dataset-20260916-231246",
        sequence=1,
        experiment_id="exp-exec",
        attempt_number=1,
        window_index=0,
        window_start_ns=1_000_000_000,
        window_end_ns=60_000_000_000,
    )


def rec(**overrides):
    kwargs = dict(
        recommendation_id="RR-ALERT",
        assessment_identity=identity(),
        finding_id="F1",
        rule_id="ml.classification.disagreement",
        action=ACTION_ALERT_ONLY,
        priority="LOW",
        reason="disagreement",
        rationale="response-policy-v1",
        severity="LOW",
        risk_score=0,
        policy_version="response-policy-v1",
        authorization_required=False,
        approval_required=False,
        required_roles=(ROLE_ANALYST,),
        status=STATUS_DRY_RUN,
    )
    kwargs.update(overrides)
    return ResponseRecommendation(**kwargs)


def request(recommendation=None, **overrides):
    recommendation = recommendation or rec()
    kwargs = dict(
        execution_id=f"EXEC-{recommendation.recommendation_id}",
        recommendation_id=recommendation.recommendation_id,
        action=recommendation.action,
        executor_type=EXECUTOR_TYPE_DRY_RUN,
        requested_by="operator-1",
        issued_at=NOW,
    )
    kwargs.update(overrides)
    return ExecutionRequest(**kwargs)


class TestValidate(unittest.TestCase):
    def setUp(self):
        self.executor = DryRunExecutor()

    def test_validation_passes(self):
        recommendation = rec()
        result = self.executor.validate(
            request(recommendation),
            recommendation=recommendation,
            policy=ResponsePolicy.default(),
            now_ns=NOW,
        )
        self.assertTrue(result["validated"])
        self.assertFalse(result["network_effect"])

    def test_wrong_executor_type_raises(self):
        with self.assertRaises(ExecutorError):
            self.executor.validate(request(executor_type="phase-10"))

    def test_action_mismatch_fails(self):
        recommendation = rec(action=ACTION_ALERT_ONLY)
        result = self.executor.validate(
            request(recommendation, action=ACTION_REQUIRE_REVIEW),
            recommendation=recommendation,
            policy=ResponsePolicy.default(),
        )
        self.assertFalse(result["validated"])
        self.assertIn("action_mismatch", result["reasons"])

    def test_expired_fails(self):
        recommendation = rec(expires_at=NOW - 1)
        result = self.executor.validate(
            request(recommendation),
            recommendation=recommendation,
            policy=ResponsePolicy.default(),
            now_ns=NOW,
        )
        self.assertIn("expired", result["reasons"])

    def test_approval_missing_fails(self):
        recommendation = rec(approval_required=True)
        result = self.executor.validate(
            request(recommendation),
            recommendation=recommendation,
            policy=ResponsePolicy.default(),
            approval_status="PENDING",
            now_ns=NOW,
        )
        self.assertIn("approval", result["reasons"])

    def test_authorization_missing_fails(self):
        recommendation = rec(authorization_required=True)
        result = self.executor.validate(
            request(recommendation),
            recommendation=recommendation,
            policy=ResponsePolicy.default(),
            now_ns=NOW,
        )
        self.assertIn("authorization_missing", result["reasons"])

    def test_denied_authorization_fails(self):
        from correlation.response import AuthorizationDecision
        recommendation = rec()
        decision = AuthorizationDecision(
            principal_id="op-1", action=recommendation.action,
            authorized=False, required_roles=(ROLE_ANALYST,),
            granted_roles=(), reason="denied", policy_version="v1",
        )
        result = self.executor.validate(
            request(recommendation),
            recommendation=recommendation,
            policy=ResponsePolicy.default(),
            authorization=decision,
            now_ns=NOW,
        )
        self.assertIn("authorization", result["reasons"])

    def test_policy_required(self):
        with self.assertRaises(ExecutorError):
            self.executor.validate(request(), recommendation=rec())

    def test_counter(self):
        self.executor.validate(request(), policy=ResponsePolicy.default())
        self.executor.validate(request(), policy=ResponsePolicy.default())
        self.assertEqual(self.executor.validations, 2)


class TestExecute(unittest.TestCase):
    def setUp(self):
        self.executor = DryRunExecutor()

    def test_no_network_action(self):
        recommendation = rec()
        result = self.executor.execute(
            request(recommendation),
            recommendation=recommendation,
            policy=ResponsePolicy.default(),
            approval_status="NOT_REQUIRED",
            now_ns=NOW,
            evidence_refs=(),
        )
        self.assertTrue(result.success)
        self.assertEqual(result.status, STATUS_DRY_RUN)
        self.assertFalse(result.network_effect)
        self.assertIn("NO_NETWORK_ACTION", result.message)
        self.assertEqual(result.executor_type, EXECUTOR_TYPE_DRY_RUN)

    def test_would_execute_still_no_network_effect(self):
        recommendation = rec(action=ACTION_REQUIRE_REVIEW)
        result = self.executor.execute(
            request(recommendation),
            recommendation=recommendation,
            policy=ResponsePolicy.default(),
            simulate_would_execute=True,
            now_ns=NOW,
        )
        self.assertTrue(result.success)
        self.assertIn("WOULD_EXECUTE", result.message)
        self.assertFalse(result.network_effect)

    def test_unvalidated_raises(self):
        recommendation = rec(approval_required=True)
        with self.assertRaises(ExecutorError):
            self.executor.execute(
                request(recommendation),
                recommendation=recommendation,
                policy=ResponsePolicy.default(),
            )


class TestCancel(unittest.TestCase):
    def test_cancel_never_network(self):
        result = DryRunExecutor().cancel(request(), now_ns=NOW)
        self.assertFalse(result.success)
        self.assertEqual(result.status, "CANCELLED")
        self.assertFalse(result.network_effect)
        self.assertIn("no network action", result.message.lower())
        self.assertTrue(result.execution_id.endswith("-C"))


if __name__ == "__main__":
    unittest.main()