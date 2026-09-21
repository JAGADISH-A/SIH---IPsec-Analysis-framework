"""Phase 9 authorization-model tests (roles, capabilities, decisions)."""

import unittest

from correlation.response import (
    ACTION_ALERT_ONLY,
    ACTION_BLOCK_FLOW,
    ACTION_CAPTURE_EVIDENCE,
    ACTION_NO_ACTION,
    ACTION_REQUIRE_REVIEW,
    AuthorizationContext,
    ResponsePolicy,
    ROLE_ANALYST,
    ROLE_SECURITY_ADMIN,
    ROLE_SECURITY_OPERATOR,
    ROLE_VIEWER,
)
from correlation.response.authorization import (
    allowed_actions_for,
    auth_context,
    authorize,
    min_role_for,
    role_can,
)


class TestRoleCan(unittest.TestCase):
    def test_viewer_only_no_action(self):
        self.assertTrue(role_can(ROLE_VIEWER, ACTION_NO_ACTION))
        self.assertFalse(role_can(ROLE_VIEWER, ACTION_ALERT_ONLY))
        self.assertFalse(role_can(ROLE_VIEWER, ACTION_REQUIRE_REVIEW))
        self.assertFalse(role_can(ROLE_VIEWER, ACTION_BLOCK_FLOW))

    def test_analyst_actions(self):
        for action in (ACTION_NO_ACTION, ACTION_ALERT_ONLY,
                       ACTION_REQUIRE_REVIEW, ACTION_CAPTURE_EVIDENCE):
            self.assertTrue(role_can(ROLE_ANALYST, action))
        self.assertFalse(role_can(ROLE_ANALYST, ACTION_BLOCK_FLOW))

    def test_operator_and_admin_high_impact(self):
        for role in (ROLE_SECURITY_OPERATOR, ROLE_SECURITY_ADMIN):
            self.assertTrue(role_can(role, ACTION_BLOCK_FLOW))
            self.assertTrue(role_can(role, ACTION_REQUIRE_REVIEW))

    def test_unknown_role_false(self):
        self.assertFalse(role_can("INTRUDER", ACTION_NO_ACTION))


class TestMinRole(unittest.TestCase):
    def test_min_role_by_action(self):
        self.assertEqual(min_role_for(ACTION_NO_ACTION), ROLE_VIEWER)
        self.assertEqual(min_role_for(ACTION_REQUIRE_REVIEW), ROLE_ANALYST)
        self.assertEqual(min_role_for(ACTION_BLOCK_FLOW), ROLE_SECURITY_OPERATOR)


class TestAllowedActions(unittest.TestCase):
    def test_stable_order(self):
        order = allowed_actions_for((ROLE_SECURITY_OPERATOR,))
        self.assertEqual(
            order,
            (ACTION_NO_ACTION, ACTION_ALERT_ONLY, ACTION_REQUIRE_REVIEW,
             ACTION_CAPTURE_EVIDENCE, "ISOLATE_FLOW", ACTION_BLOCK_FLOW,
             "TERMINATE_SESSION", "RENEGOTIATE_SESSION",
             "REQUIRE_RECONFIGURATION"),
        )

    def test_union_across_roles(self):
        order = allowed_actions_for((ROLE_ANALYST, ROLE_SECURITY_ADMIN))
        self.assertIn(ACTION_BLOCK_FLOW, order)
        self.assertIn(ACTION_CAPTURE_EVIDENCE, order)

    def test_empty_for_unknown_roles(self):
        self.assertEqual(allowed_actions_for(("ALIEN",)), ())


class TestAuthorize(unittest.TestCase):
    def setUp(self):
        self.policy = ResponsePolicy.default()

    def test_analyst_review_authorized(self):
        context = auth_context("analyst-1", (ROLE_ANALYST,))
        decision = authorize(context, ACTION_REQUIRE_REVIEW, self.policy)
        self.assertTrue(decision.authorized)
        self.assertEqual(decision.policy_version, self.policy.policy_version)
        self.assertIn(ROLE_ANALYST, decision.granted_roles)

    def test_viewer_review_denied(self):
        context = auth_context("viewer-1", (ROLE_VIEWER,))
        decision = authorize(context, ACTION_REQUIRE_REVIEW, self.policy)
        self.assertFalse(decision.authorized)
        self.assertNotIn(ROLE_ANALYST, decision.granted_roles)

    def test_analyst_block_denied(self):
        context = auth_context("analyst-1", (ROLE_ANALYST,))
        decision = authorize(context, ACTION_BLOCK_FLOW, self.policy)
        self.assertFalse(decision.authorized)

    def test_operator_block_authorized(self):
        context = auth_context("operator-1", (ROLE_SECURITY_OPERATOR,))
        decision = authorize(context, ACTION_BLOCK_FLOW, self.policy)
        self.assertTrue(decision.authorized)

    def test_scope_excludes_action_denied(self):
        context = AuthorizationContext(
            principal_id="op-1",
            roles=(ROLE_SECURITY_OPERATOR,),
            scope="review-only",
            allowed_actions=(ACTION_REQUIRE_REVIEW,),
            reason="limited scope",
        )
        decision = authorize(context, ACTION_BLOCK_FLOW, self.policy)
        self.assertFalse(decision.authorized)
        self.assertIn("scope excludes", decision.reason)

    def test_invalid_action_raises(self):
        with self.assertRaises(ValueError):
            authorize(auth_context("op-1", (ROLE_SECURITY_OPERATOR,)),
                      "DROP_STUFF", self.policy)

    def test_context_type_checked(self):
        with self.assertRaises(TypeError):
            authorize({"roles": (ROLE_ANALYST,)}, ACTION_ALERT_ONLY, self.policy)


if __name__ == "__main__":
    unittest.main()