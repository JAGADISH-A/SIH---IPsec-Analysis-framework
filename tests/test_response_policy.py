"""Phase 9 ResponsePolicy tests: lookups, gating, ML cap, immutability."""

import unittest

from correlation.risk import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)
from correlation.response import (
    ACTION_ALERT_ONLY,
    ACTION_BLOCK_FLOW,
    ACTION_CAPTURE_EVIDENCE,
    ACTION_ISOLATE_FLOW,
    ACTION_NO_ACTION,
    ACTION_REQUIRE_REVIEW,
    ACTION_REQUIRE_RECONFIGURATION,
    ACTION_TERMINATE_SESSION,
    DEFAULT_EXPIRY_NS,
    DEFAULT_RESPONSE_POLICY_VERSION,
    ROLE_ANALYST,
    ResponsePolicy,
    is_high_impact,
)


class TestDefaults(unittest.TestCase):
    def test_default_policy_version(self):
        self.assertEqual(ResponsePolicy.default().policy_version,
                         DEFAULT_RESPONSE_POLICY_VERSION)

    def test_severity_actions_conservative(self):
        policy = ResponsePolicy.default()
        for severity in (SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM,
                         SEVERITY_HIGH, SEVERITY_CRITICAL):
            action = policy.action_for("unknown.rule", severity)
            self.assertNotIn(action, (
                ACTION_ISOLATE_FLOW, ACTION_BLOCK_FLOW, ACTION_TERMINATE_SESSION,
                ACTION_REQUIRE_RECONFIGURATION,
            ), f"{severity} -> {action} must not be blocking by severity alone")

    def test_action_requirements_complete(self):
        policy = ResponsePolicy.default()
        for action in policy.action_requirements:
            requirements = policy.action_requirements[action]
            for key in ("authorization_required", "approval_required",
                        "required_roles", "dry_run_only"):
                self.assertIn(key, requirements, f"{action} requires {key}")

    def test_high_impact_always_gated(self):
        policy = ResponsePolicy.default()
        for action in (ACTION_ISOLATE_FLOW, ACTION_BLOCK_FLOW,
                       ACTION_TERMINATE_SESSION, ACTION_REQUIRE_RECONFIGURATION):
            requirements = policy.action_requirements[action]
            self.assertTrue(requirements["authorization_required"])
            self.assertTrue(requirements["approval_required"])
            self.assertTrue(requirements["dry_run_only"])
            self.assertTrue(is_high_impact(action))


class TestLookups(unittest.TestCase):
    def setUp(self):
        self.policy = ResponsePolicy.default()

    def test_rule_override_beat_severity_default(self):
        severity = SEVERITY_MEDIUM
        self.assertEqual(
            self.policy.action_for("esp.pfs.disabled", severity),
            ACTION_REQUIRE_REVIEW,
        )
        self.assertEqual(
            self.policy.priority_for("esp.pfs.disabled", severity),
            "MEDIUM",
        )

    def test_unregistered_rule_uses_severity_default(self):
        self.assertEqual(
            self.policy.action_for("some.rule", SEVERITY_LOW),
            ACTION_ALERT_ONLY,
        )
        self.assertEqual(
            self.policy.action_for("some.rule", SEVERITY_INFO),
            ACTION_NO_ACTION,
        )

    def test_requirements_merge_override(self):
        requirements = self.policy.requirements_for("esp.pfs.disabled",
                                                    ACTION_REQUIRE_REVIEW)
        self.assertTrue(requirements["approval_required"])
        self.assertFalse(requirements["authorization_required"])
        self.assertIn(ROLE_ANALYST, requirements["required_roles"])

    def test_requirements_fallback_to_action_base(self):
        requirements = self.policy.requirements_for("unknown.rule",
                                                    ACTION_CAPTURE_EVIDENCE)
        self.assertTrue(requirements["approval_required"])
        self.assertTrue(requirements["authorization_required"])


class TestMlCap(unittest.TestCase):
    def setUp(self):
        self.policy = ResponsePolicy.default()

    def test_review_cap_allowed(self):
        self.assertEqual(self.policy.cap_for_ml(ACTION_REQUIRE_REVIEW),
                         ACTION_REQUIRE_REVIEW)

    def test_blocking_capped_to_review(self):
        self.assertEqual(self.policy.cap_for_ml(ACTION_BLOCK_FLOW),
                         ACTION_REQUIRE_REVIEW)

    def test_isolation_capped_to_review(self):
        self.assertEqual(self.policy.cap_for_ml(ACTION_ISOLATE_FLOW),
                         ACTION_REQUIRE_REVIEW)

    def test_capture_capped_to_review(self):
        self.assertEqual(self.policy.cap_for_ml(ACTION_CAPTURE_EVIDENCE),
                         ACTION_REQUIRE_REVIEW)

    def test_alert_stays(self):
        self.assertEqual(self.policy.cap_for_ml(ACTION_ALERT_ONLY),
                         ACTION_ALERT_ONLY)


class TestExpiry(unittest.TestCase):
    def test_default_expiry_positive(self):
        self.assertGreater(DEFAULT_EXPIRY_NS, 0)

    def test_expiry_none_disables(self):
        policy = ResponsePolicy(expiry_ns=None)
        self.assertIsNone(policy.expiry_ns)


class TestValidation(unittest.TestCase):
    def test_rejects_bad_severity_default(self):
        with self.assertRaises(ValueError):
            ResponsePolicy(severity_defaults={"FATAL": ACTION_ALERT_ONLY})

    def test_rejects_bad_action_in_default(self):
        with self.assertRaises(ValueError):
            ResponsePolicy(severity_defaults={SEVERITY_LOW: "NOT_AN_ACTION"})

    def test_rejects_bad_rule_override_action(self):
        with self.assertRaises(ValueError):
            ResponsePolicy(rule_overrides={"esp.pfs.disabled": {"action": "NOPE"}})

    def test_rejects_non_bool_flag(self):
        with self.assertRaises(ValueError):
            ResponsePolicy(action_requirements={
                ACTION_ALERT_ONLY: {**ResponsePolicy.default().action_requirements[ACTION_ALERT_ONLY],
                                    "approval_required": "yes"},
            })

    def test_rejects_bad_expiry(self):
        with self.assertRaises(ValueError):
            ResponsePolicy(expiry_ns=0)

    def test_rejects_bad_ml_handling(self):
        with self.assertRaises(ValueError):
            ResponsePolicy(ml_handling={"max_action": "BOGUS", "eligible_actions": ()})


class TestImmutability(unittest.TestCase):
    def test_with_override_returns_new_policy(self):
        base = ResponsePolicy.default()
        updated = base.with_override("ml.anomaly", action=ACTION_ALERT_ONLY)
        self.assertNotEqual(updated.rule_overrides["ml.anomaly"]["action"],
                            base.rule_overrides["ml.anomaly"]["action"])
        self.assertEqual(updated.action_for("ml.anomaly", SEVERITY_LOW),
                         ACTION_ALERT_ONLY)
        self.assertEqual(base.action_for("ml.anomaly", SEVERITY_LOW),
                         ACTION_REQUIRE_REVIEW)

    def test_to_dict_round_trip(self):
        policy = ResponsePolicy.default()
        restored = ResponsePolicy(
            **{key: value for key, value in policy.to_dict().items()
               if key in ResponsePolicy.__dataclass_fields__},
        )
        self.assertEqual(restored.to_dict(), policy.to_dict())

    def test_default_dict_helper(self):
        from correlation.response.policy import default_response_policy_dict
        self.assertEqual(default_response_policy_dict(),
                         ResponsePolicy.default().to_dict())


if __name__ == "__main__":
    unittest.main()