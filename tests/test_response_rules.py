"""Phase 9 response-rule registry tests (RESPONSE_RULE_TRACEABILITY)."""

import unittest

from correlation.response import (
    ACTION_ALERT_ONLY,
    ACTION_CAPTURE_EVIDENCE,
    ACTION_REQUIRE_REVIEW,
    RESPONSE_ACTIONS,
    ALL_RESPONSE_RULES,
    RESPONSE_RULE_TRACEABILITY,
    traceability_for,
)
from correlation.response.rules import is_registered_response_rule


class TestRegistry(unittest.TestCase):
    def test_required_rules_registered(self):
        for rule in ("esp.pfs.disabled", "esp.encryption.cbc",
                     "esp.dh_group.weak", "correlation.mismatch",
                     "ml.anomaly", "ml.classification.disagreement",
                     "evidence.insufficient", "evidence.unknown.gap"):
            self.assertIn(rule, RESPONSE_RULE_TRACEABILITY, rule)

    def test_rule_shape(self):
        for rule_id, metadata in RESPONSE_RULE_TRACEABILITY.items():
            for key in ("rule_id", "finding_rule", "input", "condition",
                        "action", "priority", "approval_requirement",
                        "policy_dependency"):
                self.assertIn(key, metadata, f"{rule_id} missing {key}")
            # the evidence.unknown.gap entry documents its source finding as
            # correlation.unknowns (the origin of the evidence gap)
            if rule_id == "evidence.unknown.gap":
                self.assertEqual(metadata["finding_rule"], "correlation.unknowns")
            else:
                self.assertEqual(metadata["finding_rule"], rule_id)
            self.assertIn(metadata["action"], RESPONSE_ACTIONS)
            self.assertTrue(metadata["rule_id"].startswith("RESP-"))

    def test_traceability_for(self):
        trace = traceability_for("esp.pfs.disabled")
        self.assertEqual(trace["rule_id"], "RESP-PFS-001")
        self.assertEqual(trace["action"], ACTION_REQUIRE_REVIEW)
        self.assertEqual(trace, RESPONSE_RULE_TRACEABILITY["esp.pfs.disabled"])

    def test_traceability_for_unknown_returns_empty(self):
        self.assertEqual(traceability_for("no.such.rule"), {})

    def test_is_registered(self):
        self.assertTrue(is_registered_response_rule("ml.anomaly"))
        self.assertFalse(is_registered_response_rule("not.here"))

    def test_review_rules_never_block(self):
        for metadata in RESPONSE_RULE_TRACEABILITY.values():
            self.assertNotEqual(metadata["action"], "BLOCK_FLOW")
            self.assertNotEqual(metadata["action"], "ISOLATE_FLOW")

    def test_ml_rules_capped(self):
        self.assertEqual(RESPONSE_RULE_TRACEABILITY["ml.anomaly"]["action"],
                         ACTION_REQUIRE_REVIEW)
        self.assertEqual(
            RESPONSE_RULE_TRACEABILITY["ml.classification.disagreement"]["action"],
            ACTION_ALERT_ONLY,
        )

    def test_evidence_gap_never_blocking(self):
        self.assertEqual(
            RESPONSE_RULE_TRACEABILITY["evidence.unknown.gap"]["action"],
            ACTION_CAPTURE_EVIDENCE,
        )
        self.assertEqual(
            RESPONSE_RULE_TRACEABILITY["evidence.insufficient"]["action"],
            ACTION_CAPTURE_EVIDENCE,
        )

    def test_policy_dependency_documented(self):
        for metadata in RESPONSE_RULE_TRACEABILITY.values():
            self.assertIn("response-policy-v1", metadata["policy_dependency"])

    def test_all_rules_sorted(self):
        self.assertEqual(ALL_RESPONSE_RULES,
                         tuple(sorted(RESPONSE_RULE_TRACEABILITY.keys())))


if __name__ == "__main__":
    unittest.main()