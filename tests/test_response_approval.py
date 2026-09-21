"""Phase 9 approval-gate tests (request / approve / reject / expire)."""

import unittest

from correlation.models import CorrelationIdentity
from correlation.response import (
    ACTION_ALERT_ONLY,
    ACTION_CAPTURE_EVIDENCE,
    ACTION_REQUIRE_REVIEW,
    APPROVAL_APPROVED,
    APPROVAL_EXPIRED,
    APPROVAL_PENDING,
    APPROVAL_REJECTED,
    ApprovalError,
    ApprovalRequest,
    ResponsePolicy,
    ResponseRecommendation,
    ROLE_ANALYST,
    STATUS_RECOMMENDED,
)
from correlation.response.approval import (
    approval_disposition,
    approval_id_for,
    approve,
    expire_approval,
    reject,
    request_approval,
)

NOW = 1_800_000_000_000_000_000
FUTURE = NOW + 3_600_000_000_000_000_000


def make_rec(**overrides):
    kwargs = dict(
        recommendation_id="RR-RISK-PFS-DISABLED",
        assessment_identity=CorrelationIdentity(
            dataset_run_id="dataset-20260916-231246",
            sequence=1,
            experiment_id="exp-response",
            attempt_number=1,
            window_index=0,
            window_start_ns=1_000_000_000,
            window_end_ns=60_000_000_000,
        ),
        finding_id="RISK-PFS-DISABLED",
        rule_id="esp.pfs.disabled",
        action=ACTION_REQUIRE_REVIEW,
        priority="MEDIUM",
        reason="PFS disabled",
        rationale="response-policy-v1",
        severity="MEDIUM",
        risk_score=12,
        policy_version="response-policy-v1",
        authorization_required=False,
        approval_required=True,
        required_roles=(ROLE_ANALYST,),
        expires_at=FUTURE,
        status=STATUS_RECOMMENDED,
    )
    kwargs.update(overrides)
    return ResponseRecommendation(**kwargs)


def policy(**updates):
    return ResponsePolicy(**updates)


def pending(rec, requested_by="analyst-1", now=NOW):
    return ApprovalRequest(
        approval_id=approval_id_for(rec.recommendation_id),
        recommendation_id=rec.recommendation_id,
        requested_by=requested_by,
        requested_at=now,
        reason="please approve",
        required_role=ROLE_ANALYST,
        status=APPROVAL_PENDING,
        expires_at=rec.expires_at,
    )


class TestRequestApproval(unittest.TestCase):
    def test_creates_pending(self):
        rec = make_rec(action=ACTION_REQUIRE_REVIEW, approval_required=True)
        approval = request_approval(rec, "analyst-1", reason="", now_ns=NOW,
                                    policy=policy())
        self.assertEqual(approval.status, APPROVAL_PENDING)
        self.assertEqual(approval.recommendation_id, rec.recommendation_id)
        self.assertEqual(approval.approval_id,
                         f"APR-{rec.recommendation_id}")
        self.assertIsNotNone(approval.expires_at)

    def test_wrong_status_raises(self):
        rec = make_rec(action=ACTION_REQUIRE_REVIEW, approval_required=True)
        rec.status = "APPROVED"
        with self.assertRaises(ApprovalError):
            request_approval(rec, "analyst-1", "", now_ns=NOW, policy=policy())

    def test_not_required_raises(self):
        rec = make_rec(action=ACTION_ALERT_ONLY, approval_required=False)
        with self.assertRaises(ApprovalError):
            request_approval(rec, "analyst-1", "", now_ns=NOW, policy=policy())

    def test_empty_commander_raises(self):
        rec = make_rec(action=ACTION_REQUIRE_REVIEW, approval_required=True)
        with self.assertRaises(ValueError):
            request_approval(rec, "  ", "", now_ns=NOW, policy=policy())


class TestApprove(unittest.TestCase):
    def test_approve_with_analyst_role(self):
        rec = make_rec(action=ACTION_REQUIRE_REVIEW, approval_required=True)
        approval = pending(rec)
        approved = approve(approval, rec, "analyst-1", roles=(ROLE_ANALYST,),
                           now_ns=NOW + 5, policy=policy())
        self.assertEqual(approved.status, APPROVAL_APPROVED)
        self.assertEqual(approved.approved_by, "analyst-1")
        self.assertEqual(approved.approved_at, NOW + 5)

    def test_approve_requires_capable_role(self):
        rec = make_rec(action=ACTION_BLOCK_FLOW if False else ACTION_CAPTURE_EVIDENCE,
                  approval_required=True)
        approval = pending(rec)
        with self.assertRaises(ApprovalError):
            approve(approval, rec, "viewer-1", roles=("VIEWER",),
                    now_ns=NOW, policy=policy())

    def test_approve_requires_approval_flag(self):
        rec = make_rec(action=ACTION_ALERT_ONLY, approval_required=False)
        approval = pending(rec)
        with self.assertRaises(ApprovalError):
            approve(approval, rec, "analyst-1", roles=(ROLE_ANALYST,),
                    now_ns=NOW, policy=policy())

    def test_approve_already_approved_raises(self):
        rec = make_rec(action=ACTION_REQUIRE_REVIEW, approval_required=True)
        approval = pending(rec)
        approve(approval, rec, "analyst-1", roles=(ROLE_ANALYST,),
                now_ns=NOW, policy=policy())
        with self.assertRaises(ApprovalError):
            approve(approval, rec, "analyst-2", roles=(ROLE_ANALYST,),
                    now_ns=NOW, policy=policy())

    def test_approve_expired_raises(self):
        rec = make_rec(action=ACTION_REQUIRE_REVIEW, approval_required=True,
                  expires_at=NOW + 10)
        approval = pending(rec)
        with self.assertRaises(ApprovalError):
            approve(approval, rec, "analyst-1", roles=(ROLE_ANALYST,),
                    now_ns=NOW + 100, policy=policy())


class TestReject(unittest.TestCase):
    def test_reject_records_reason(self):
        rec = make_rec(action=ACTION_REQUIRE_REVIEW, approval_required=True)
        approval = pending(rec)
        rejected = reject(approval, rec, "analyst-1",
                          rejection_reason="duplicate", now_ns=NOW)
        self.assertEqual(rejected.status, APPROVAL_REJECTED)
        self.assertEqual(rejected.rejection_reason, "duplicate")

    def test_reject_non_pending_raises(self):
        rec = make_rec(action=ACTION_REQUIRE_REVIEW, approval_required=True)
        approval = pending(rec)
        approve(approval, rec, "analyst-1", roles=(ROLE_ANALYST,),
                now_ns=NOW, policy=policy())
        with self.assertRaises(ApprovalError):
            reject(approval, rec, "analyst-1",
                   rejection_reason="after the fact", now_ns=NOW)

    def test_reject_empty_reason_raises(self):
        rec = make_rec(action=ACTION_REQUIRE_REVIEW, approval_required=True)
        approval = pending(rec)
        with self.assertRaises(ValueError):
            reject(approval, rec, "analyst-1", rejection_reason="", now_ns=NOW)


class TestExpireAndDisposition(unittest.TestCase):
    def test_expire_transitions(self):
        rec = make_rec(action=ACTION_REQUIRE_REVIEW, approval_required=True,
                  expires_at=NOW + 10)
        approval = pending(rec)
        result = expire_approval(approval, now_ns=NOW + 100)
        self.assertEqual(result.status, APPROVAL_EXPIRED)

    def test_expire_keeps_pending_within_window(self):
        rec = make_rec(action=ACTION_REQUIRE_REVIEW, approval_required=True,
                  expires_at=NOW + 1000)
        approval = pending(rec, now=NOW)
        result = expire_approval(approval, now_ns=NOW + 500)
        self.assertEqual(result.status, APPROVAL_PENDING)

    def test_expire_preserves_approved(self):
        rec = make_rec(action=ACTION_REQUIRE_REVIEW, approval_required=True)
        approval = pending(rec)
        approve(approval, rec, "analyst-1", roles=(ROLE_ANALYST,),
                now_ns=NOW, policy=policy())
        result = expire_approval(approval, now_ns=NOW + 999_999_999)
        self.assertEqual(result.status, APPROVAL_APPROVED)

    def test_disposition(self):
        self.assertEqual(approval_disposition(None), "NOT REQUESTED")
        self.assertEqual(approval_disposition(ApprovalRequest(
            approval_id="A", recommendation_id="R", requested_by="x",
            requested_at=0, reason="", required_role=ROLE_ANALYST,
        )), APPROVAL_PENDING)


if __name__ == "__main__":
    unittest.main()