"""Phase 10 — firewall (nftables/iptables) executor tests."""

import unittest

from correlation.execution import (
    STATUS_NOT_SUPPORTED,
    STATUS_SUCCESS,
    STATUS_TARGET_NOT_ALLOWED,
    FirewallExecutor,
)
from correlation.execution.host import MemoryHost
from correlation.execution.settings import (
    MODE_AUTHORIZED_TESTBED,
    MODE_DRY_RUN,
    ExecutionSettings,
)
from correlation.execution.targets import ExecutionTarget
from correlation.models import CorrelationIdentity
from correlation.response.models import (
    ACTION_BLOCK_FLOW,
    ACTION_ISOLATE_FLOW,
    ACTION_TERMINATE_SESSION,
    ExecutionRequest,
    ResponseRecommendation,
)

IDENTITY = CorrelationIdentity(
    dataset_run_id="dataset-20260916-231246", sequence=1,
    experiment_id="exp-fw", attempt_number=1,
)


def recommendation(action=ACTION_ISOLATE_FLOW):
    return ResponseRecommendation(
        recommendation_id="rec-fw-1",
        assessment_identity=IDENTITY,
        finding_id="finding-2",
        rule_id="rule-ike-replay",
        action=action,
        priority="MEDIUM",
        reason="fixture",
        rationale="structured fixture",
        severity="MEDIUM",
        risk_score=55,
        policy_version="v1",
        authorization_required=True,
        approval_required=True,
        status="AUTHORIZED",
    )


def request(action=ACTION_ISOLATE_FLOW):
    return ExecutionRequest(
        execution_id="exec-fw-1",
        recommendation_id="rec-fw-1",
        action=action,
        executor_type="firewall",
        requested_by="system:test",
        issued_at=0,
    )


def target():
    return ExecutionTarget(destination="198.51.100.20", protocol=50)


class TestFirewallExecutor(unittest.TestCase):
    def test_supported_actions(self):
        self.assertEqual(FirewallExecutor.supported_actions,
                         (ACTION_BLOCK_FLOW, ACTION_ISOLATE_FLOW))

    def test_dry_run(self):
        executor = FirewallExecutor(settings=ExecutionSettings(mode=MODE_DRY_RUN))
        outcome = executor.execute(request(), target=target())
        self.assertEqual(outcome.status, STATUS_SUCCESS)
        self.assertFalse(outcome.network_effect)

    def test_testbed_applies(self):
        settings = ExecutionSettings(
            mode=MODE_AUTHORIZED_TESTBED,
            allowed_testbed_targets=("198.51.100.0/24",),
        )
        executor = FirewallExecutor(settings=settings, host=MemoryHost())
        outcome = executor.execute(request(), target=target())
        self.assertEqual(outcome.status, STATUS_SUCCESS)
        self.assertTrue(outcome.network_effect)

    def test_not_allowlisted(self):
        settings = ExecutionSettings(
            mode=MODE_AUTHORIZED_TESTBED,
            allowed_testbed_targets=("192.0.2.0/24",),
        )
        executor = FirewallExecutor(settings=settings, host=MemoryHost())
        outcome = executor.execute(request(), target=target())
        self.assertEqual(outcome.status, STATUS_TARGET_NOT_ALLOWED)

    def test_unsupported_action(self):
        executor = FirewallExecutor(settings=ExecutionSettings(mode=MODE_DRY_RUN))
        outcome = executor.execute(
            request(action=ACTION_TERMINATE_SESSION), target=target()
        )
        self.assertEqual(outcome.status, STATUS_NOT_SUPPORTED)

    def test_descriptor_names_firewall(self):
        executor = FirewallExecutor(settings=ExecutionSettings(mode=MODE_DRY_RUN))
        descriptor = executor.operation_descriptor(request(), target=target())
        self.assertEqual(descriptor["executor"], "firewall")
        self.assertEqual(descriptor["op"], "firewall.isolate_flow")


if __name__ == "__main__":
    unittest.main()