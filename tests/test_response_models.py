"""Phase 9 response domain-model tests (vocabularies, state machine, models,
hashes, round-trips). All deterministic; no datetime/random/network."""

import json
import unittest

from correlation.models import CorrelationIdentity, EvidenceRef
from correlation.response.models import (
    validate_action,
    validate_status,
    validate_transition,
)
from correlation.response import (
    ACTION_ALERT_ONLY,
    ACTION_BLOCK_FLOW,
    ACTION_CAPTURE_EVIDENCE,
    ACTION_ISOLATE_FLOW,
    ACTION_NO_ACTION,
    ACTION_REQUIRE_REVIEW,
    ACTION_TERMINATE_SESSION,
    APPROVAL_APPROVED,
    APPROVAL_PENDING,
    APPROVAL_REJECTED,
    APPROVAL_STATUSES,
    APPROVAL_EXPIRED,
    ApprovalRequest,
    AuthorizationContext,
    AuthorizationDecision,
    ExecutionRequest,
    ExecutionResult,
    PRIORITIES,
    RESPONSE_ACTIONS,
    RESPONSE_EVENT_TYPES,
    RESPONSE_SCHEMA_VERSION,
    RESPONSE_STATUSES,
    ROLES,
    ResponseAuditEvent,
    ResponseDomainError,
    ResponsePlan,
    ResponseRecommendation,
    ResponseStateError,
    ROLE_ANALYST,
    ROLE_SECURITY_ADMIN,
    ROLE_SECURITY_OPERATOR,
    STATUS_APPROVED,
    STATUS_AUTHORIZED,
    STATUS_EXECUTION_REQUESTED,
    STATUS_NOT_EVALUATED,
    STATUS_PENDING_APPROVAL,
    STATUS_RECOMMENDED,
    compute_event_hash,
    is_high_impact,
)


def identity(**overrides):
    base = dict(
        dataset_run_id="dataset-20260916-231246",
        sequence=1,
        experiment_id="exp-response",
        attempt_number=1,
        window_index=0,
        window_start_ns=1_000_000_000,
        window_end_ns=60_000_000_000,
    )
    base.update(overrides)
    return CorrelationIdentity(**base)


def evidence(path="tests/fixtures/live/swanctl.conf"):
    return EvidenceRef(
        source="swanctl",
        audit_event_reference="audit://tap-events.jsonl#12",
        timestamp="2026-09-20T00:00:00Z",
    )


def recommendation(**overrides):
    base = dict(
        recommendation_id="RR-RISK-PFS-DISABLED",
        assessment_identity=identity(),
        finding_id="RISK-PFS-DISABLED",
        rule_id="esp.pfs.disabled",
        action=ACTION_REQUIRE_REVIEW,
        priority="MEDIUM",
        reason="PFS is disabled",
        rationale="Response rule RESP-PFS-001 under response-policy-v1.",
        severity="MEDIUM",
        risk_score=12,
        policy_version="response-policy-v1",
        authorization_required=False,
        approval_required=True,
        required_roles=(ROLE_ANALYST,),
        expires_at=1_800_000_000_000_000_000 + 3_600_000_000_000_000_000,
        evidence_refs=(evidence(),),
        limitations=("dry-run only",),
        status=STATUS_RECOMMENDED,
        provenance="RESPONSE_POLICY",
    )
    base.update(overrides)
    return ResponseRecommendation(**base)


class TestVocabularies(unittest.TestCase):
    def test_actions_finite_and_unique(self):
        self.assertGreaterEqual(len(RESPONSE_ACTIONS), 9)
        self.assertEqual(len(set(RESPONSE_ACTIONS)), len(RESPONSE_ACTIONS))
        for action in ("NO_ACTION", "ALERT_ONLY", "REQUIRE_REVIEW",
                       "CAPTURE_EVIDENCE", "ISOLATE_FLOW", "BLOCK_FLOW",
                       "TERMINATE_SESSION", "RENEGOTIATE_SESSION",
                       "REQUIRE_RECONFIGURATION"):
            self.assertIn(action, RESPONSE_ACTIONS)

    def test_validate_action_rejects_unknown(self):
        self.assertEqual(validate_action(ACTION_REQUIRE_REVIEW), ACTION_REQUIRE_REVIEW)
        with self.assertRaises(ValueError):
            validate_action("DROP_STUFF")

    def test_response_schema_version(self):
        self.assertEqual(RESPONSE_SCHEMA_VERSION, "v1")

    def test_roles_finite(self):
        self.assertIn(ROLE_ANALYST, ROLES)
        self.assertIn(ROLE_SECURITY_OPERATOR, ROLES)
        self.assertIn(ROLE_SECURITY_ADMIN, ROLES)
        self.assertEqual(len(set(ROLES)), len(ROLES))

    def test_priorities_finite(self):
        self.assertGreaterEqual(len(PRIORITIES), 5)
        self.assertEqual(len(set(PRIORITIES)), len(PRIORITIES))

    def test_event_types_finite(self):
        self.assertGreaterEqual(len(RESPONSE_EVENT_TYPES), 12)


class TestStateMachine(unittest.TestCase):
    def test_legal_transition(self):
        validate_transition(STATUS_RECOMMENDED, STATUS_PENDING_APPROVAL)
        validate_transition(STATUS_PENDING_APPROVAL, STATUS_APPROVED)
        validate_transition(STATUS_APPROVED, STATUS_AUTHORIZED)
        validate_transition(STATUS_AUTHORIZED, STATUS_EXECUTION_REQUESTED)

    def test_illegal_transition_raises(self):
        with self.assertRaises(ResponseStateError):
            validate_transition(STATUS_NOT_EVALUATED, STATUS_APPROVED)

    def test_validate_status_rejects_unknown(self):
        with self.assertRaises(ValueError):
            validate_status("QUEUED")


class TestResponseRecommendation(unittest.TestCase):
    def test_valid_construction(self):
        rec = recommendation()
        self.assertEqual(rec.rule_id, "esp.pfs.disabled")
        self.assertEqual(rec.status, STATUS_RECOMMENDED)

    def test_requires_non_empty_id(self):
        with self.assertRaises(ValueError):
            recommendation(recommendation_id="")

    def test_rejects_bad_action(self):
        with self.assertRaises(ValueError):
            recommendation(action="STEAL_FLOW")

    def test_rejects_bad_priority(self):
        with self.assertRaises(ValueError):
            recommendation(priority="URGENT")

    def test_rejects_bad_severity(self):
        with self.assertRaises(ValueError):
            recommendation(severity="SEVERE")

    def test_rejects_bad_risk_score(self):
        with self.assertRaises(ValueError):
            recommendation(risk_score=101)

    def test_rejects_bad_status(self):
        with self.assertRaises(ValueError):
            recommendation(status="EXECUTING_WHOOPS")

    def test_rejects_bad_provenance(self):
        with self.assertRaises(ValueError):
            recommendation(provenance="RESPONSE_HACKER")

    def test_rejects_unknown_role(self):
        with self.assertRaises(ValueError):
            recommendation(required_roles=("SUPERUSER",))

    def test_round_trip(self):
        rec = recommendation()
        restored = ResponseRecommendation.from_dict(rec.to_dict())
        self.assertEqual(restored.to_dict(), rec.to_dict())
        self.assertEqual(restored.assessment_identity.to_dict(),
                         rec.assessment_identity.to_dict())
        self.assertEqual(len(restored.evidence_refs), 1)

    def test_json_round_trip(self):
        rec = recommendation()
        self.assertEqual(
            ResponseRecommendation.from_json(rec.to_json()).to_dict(),
            rec.to_dict(),
        )

    def test_is_expired(self):
        rec = recommendation(expires_at=10)
        self.assertTrue(rec.is_expired(11))
        self.assertFalse(rec.is_expired(10))
        self.assertFalse(recommendation(expires_at=None).is_expired(999))

    def test_mutable_status_only(self):
        rec = recommendation()
        rec.status = STATUS_PENDING_APPROVAL
        self.assertEqual(rec.status, STATUS_PENDING_APPROVAL)


class TestResponsePlan(unittest.TestCase):
    def test_round_trip(self):
        plan = ResponsePlan(
            assessment_identity=identity(),
            policy_version="response-policy-v1",
            recommendations=(recommendation(),),
            requires_approval=True,
            requires_authorization=False,
            generated_deterministically=True,
            limitations=("dry-run only",),
        )
        restored = ResponsePlan.from_dict(plan.to_dict())
        self.assertEqual(restored.to_dict(), plan.to_dict())

    def test_by_id_high_impact(self):
        blocking = recommendation(
            recommendation_id="RR-BLOCK",
            finding_id="F2",
            rule_id="correlation.mismatch",
            action=ACTION_ISOLATE_FLOW,
            priority="HIGH",
        )
        alert = recommendation(
            recommendation_id="RR-ALERT",
            finding_id="F1",
            rule_id="ml.classification.disagreement",
            action=ACTION_ALERT_ONLY,
            priority="LOW",
        )
        plan = ResponsePlan(
            assessment_identity=identity(),
            policy_version="v1",
            recommendations=(alert, blocking),
        )
        self.assertEqual(plan.by_id()["RR-BLOCK"], blocking)
        self.assertEqual([r.recommendation_id for r in plan.high_impact()], ["RR-BLOCK"])

    def test_rejects_bad_recommendation(self):
        with self.assertRaises(ValueError):
            ResponsePlan(assessment_identity=identity(), policy_version="v1",
                         recommendations=({"not": "a rec"},))


class TestApprovalRequest(unittest.TestCase):
    def setUp(self):
        self.rec = recommendation()

    def test_round_trip(self):
        approval = ApprovalRequest(
            approval_id="APR-RR-RISK-PFS-DISABLED",
            recommendation_id=self.rec.recommendation_id,
            requested_by="analyst-1",
            requested_at=1_800_000_000_000_000_000,
            reason="approve review",
            required_role=ROLE_ANALYST,
            status=APPROVAL_PENDING,
            expires_at=1_800_000_000_000_000_000 + 86400 * 1_000_000_000,
        )
        restored = ApprovalRequest.from_dict(approval.to_dict())
        self.assertEqual(restored.to_dict(), approval.to_dict())

    def test_approved_status_round_trip(self):
        approval = ApprovalRequest(
            approval_id="APR-1",
            recommendation_id=self.rec.recommendation_id,
            requested_by="analyst-1",
            requested_at=0,
            reason="ok",
            required_role=ROLE_ANALYST,
            status=APPROVAL_APPROVED,
            approved_by="operator-1",
            approved_at=1,
        )
        self.assertEqual(ApprovalRequest.from_dict(approval.to_dict()).status,
                         APPROVAL_APPROVED)

    def test_reject_bad_role(self):
        with self.assertRaises(ValueError):
            ApprovalRequest(
                approval_id="A", recommendation_id="R",
                requested_by="analyst-1", requested_at=0, reason="r",
                required_role="HACKER",
            )

    def test_is_expired(self):
        approval = ApprovalRequest(
            approval_id="A", recommendation_id=self.rec.recommendation_id,
            requested_by="analyst-1", requested_at=0, reason="r",
            required_role=ROLE_ANALYST, expires_at=5,
        )
        self.assertTrue(approval.is_expired(6))
        self.assertFalse(approval.is_expired(5))


class TestAuthorizationModels(unittest.TestCase):
    def test_context_round_trip(self):
        ctx = AuthorizationContext(
            principal_id="p1",
            roles=(ROLE_SECURITY_OPERATOR,),
            scope="phase9",
            allowed_actions=(ACTION_BLOCK_FLOW,),
            reason="testing",
        )
        self.assertEqual(AuthorizationContext.from_dict(ctx.to_dict()).to_dict(),
                         ctx.to_dict())

    def test_context_requires_roles(self):
        with self.assertRaises(ValueError):
            AuthorizationContext(principal_id="p1", roles=())

    def test_decision_round_trip(self):
        decision = AuthorizationDecision(
            principal_id="p1",
            action=ACTION_REQUIRE_REVIEW,
            authorized=True,
            required_roles=(ROLE_ANALYST,),
            granted_roles=(ROLE_ANALYST,),
            reason="ok",
            policy_version="response-policy-v1",
        )
        self.assertEqual(
            AuthorizationDecision.from_dict(decision.to_dict()).to_dict(),
            decision.to_dict(),
        )


class TestExecutionModels(unittest.TestCase):
    def test_request_round_trip(self):
        request = ExecutionRequest(
            execution_id="EXEC-1", recommendation_id="RR-1",
            action=ACTION_ALERT_ONLY, executor_type="dry-run",
            requested_by="op-1", issued_at=7,
        )
        self.assertEqual(ExecutionRequest.from_dict(request.to_dict()).to_dict(),
                         request.to_dict())

    def test_result_network_effect_false_default(self):
        result = ExecutionResult(
            execution_id="EXEC-1", recommendation_id="RR-1",
            action=ACTION_ALERT_ONLY, status="DRY_RUN",
            executor_type="dry-run",
        )
        self.assertFalse(result.network_effect)
        self.assertFalse(result.success)

    def test_result_round_trip(self):
        result = ExecutionResult(
            execution_id="EXEC-1", recommendation_id="RR-1",
            action=ACTION_ALERT_ONLY, status="DRY_RUN",
            executor_type="dry-run", started_at=1, completed_at=2,
            success=True, message="NO_NETWORK_ACTION",
            network_effect=False, evidence_refs=(evidence(),),
        )
        self.assertEqual(ExecutionResult.from_dict(result.to_dict()).to_dict(),
                         result.to_dict())


class TestAuditEvent(unittest.TestCase):
    def test_round_trip(self):
        event = ResponseAuditEvent(
            event_id="EVT-0001",
            timestamp=1_800_000_000_000_000_000,
            assessment_identity=identity(),  # noqa: F821 (identity defined above)
            recommendation_id="RR-1",
            approval_id=None,
            principal="system:planner",
            event_type="RECOMMENDATION_CREATED",
            action=ACTION_REQUIRE_REVIEW,
            previous_status=STATUS_NOT_EVALUATED,
            new_status=STATUS_RECOMMENDED,
            reason="recommended",
            policy_version="response-policy-v1",
            evidence_refs=(),
            previous_hash="" * 64,
            event_hash="" * 64,
        )
        restored = ResponseAuditEvent.from_dict(event.to_dict())
        self.assertEqual(restored.to_dict(), event.to_dict())

    def test_requires_evt_prefix(self):
        with self.assertRaises(ValueError):
            ResponseAuditEvent(
                event_id="bad-1", timestamp=0, assessment_identity=identity(),
                recommendation_id="RR-1", approval_id=None,
                action=ACTION_REQUIRE_REVIEW,
                previous_status=STATUS_RECOMMENDED, new_status=STATUS_RECOMMENDED,
                principal="p", event_type="RECOMMENDATION_CREATED",
                reason="r", policy_version="v1",
            )


class TestHash(unittest.TestCase):
    def test_deterministic(self):
        payload = {"a": 1, "b": [1, 2, {"c": "x"}], "z": None}
        self.assertEqual(compute_event_hash(payload, "0" * 64),
                         compute_event_hash(payload, "0" * 64))

    def test_changes_with_payload(self):
        h1 = compute_event_hash({"a": 1}, "0" * 64)
        h2 = compute_event_hash({"a": 2}, "0" * 64)
        self.assertNotEqual(h1, h2)

    def test_changes_with_previous_hash(self):
        h1 = compute_event_hash({"a": 1}, "0" * 64)
        h2 = compute_event_hash({"a": 1}, "1" * 64)
        self.assertNotEqual(h1, h2)

    def test_sha256_length(self):
        self.assertEqual(len(compute_event_hash({"a": 1}, "0" * 64)), 64)


class TestHighImpact(unittest.TestCase):
    def test_high_impact_never_includes_review_only(self):
        self.assertFalse(is_high_impact(ACTION_REQUIRE_REVIEW))
        self.assertFalse(is_high_impact(ACTION_ALERT_ONLY))
        self.assertFalse(is_high_impact(ACTION_CAPTURE_EVIDENCE))

    def test_high_impact_includes_blocking(self):
        for action in (ACTION_ISOLATE_FLOW, ACTION_BLOCK_FLOW,
                       ACTION_TERMINATE_SESSION):
            self.assertTrue(is_high_impact(action))


class TestDomainError(unittest.TestCase):
    def test_payload(self):
        err = ResponseStateError(STATUS_NOT_EVALUATED, STATUS_APPROVED)
        payload = err.payload()
        self.assertEqual(payload["error"]["code"], "invalid_transition")
        self.assertIn("invalid status transition", payload["error"]["detail"])
        self.assertEqual(payload["error"]["current_status"],
                         STATUS_NOT_EVALUATED)


if __name__ == "__main__":
    unittest.main()