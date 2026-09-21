"""Phase 10 — XDP executor tests (structured block/isolate operations)."""

import unittest

from correlation.execution import (
    STATUS_DEPENDENCY_UNAVAILABLE,
    STATUS_NOT_SUPPORTED,
    STATUS_SUCCESS,
    STATUS_TARGET_NOT_ALLOWED,
    XdpExecutor,
)
from correlation.execution.host import MemoryHost, UnavailableHost
from correlation.execution.settings import (
    MODE_AUTHORIZED_TESTBED,
    MODE_DRY_RUN,
    MODE_PRODUCTION,
    ExecutionSettings,
)
from correlation.execution.targets import ExecutionTarget
from correlation.models import CorrelationIdentity
from correlation.response.models import (
    ACTION_BLOCK_FLOW,
    ACTION_ISOLATE_FLOW,
    ACTION_TERMINATE_SESSION,
    RESPONSE_SCHEMA_VERSION,
    STATUS_AUTHORIZED,
    ExecutionRequest,
    ResponseRecommendation,
)

IDENTITY = CorrelationIdentity(
    dataset_run_id="dataset-20260916-231246", sequence=1,
    experiment_id="exp-xdp", attempt_number=1,
)


def recommendation(action=ACTION_BLOCK_FLOW):
    return ResponseRecommendation(
        recommendation_id="rec-xdp-1",
        assessment_identity=IDENTITY,
        finding_id="finding-1",
        rule_id="rule-esp-spi-reuse",
        action=action,
        priority="HIGH",
        reason="test recommendation",
        rationale="structured fixture",
        severity="HIGH",
        risk_score=70,
        policy_version=RESPONSE_SCHEMA_VERSION,
        authorization_required=True,
        approval_required=False,
        status=STATUS_AUTHORIZED,
    )


def request(action=ACTION_BLOCK_FLOW, executor_type="xdp"):
    return ExecutionRequest(
        execution_id="exec-xdp-1",
        recommendation_id="rec-xdp-1",
        action=action,
        executor_type=executor_type,
        requested_by="system:test",
        issued_at=0,
    )


def target(destination="192.0.2.9"):
    return ExecutionTarget(
        source="192.0.2.1", destination=destination, protocol=17,
        destination_port=4500,
    )


class TestXdpExecutor(unittest.TestCase):
    def test_supported_actions(self):
        self.assertEqual(XdpExecutor.supported_actions,
                         (ACTION_BLOCK_FLOW, ACTION_ISOLATE_FLOW))

    def test_dry_run_succeeds_without_network_effect(self):
        executor = XdpExecutor(settings=ExecutionSettings(mode=MODE_DRY_RUN))
        outcome = executor.execute(request(), target=target())
        self.assertEqual(outcome.status, STATUS_SUCCESS)
        self.assertTrue(outcome.success)
        self.assertFalse(outcome.network_effect)
        self.assertIn("WOULD_APPLY", outcome.reason)
        self.assertEqual(outcome.extras["mode"], MODE_DRY_RUN)

    def test_unsupported_action_not_supported(self):
        executor = XdpExecutor(settings=ExecutionSettings(mode=MODE_DRY_RUN))
        outcome = executor.execute(
            request(action=ACTION_TERMINATE_SESSION), target=target()
        )
        self.assertEqual(outcome.status, STATUS_NOT_SUPPORTED)

    def test_testbed_applies_when_allowlisted(self):
        settings = ExecutionSettings(
            mode=MODE_AUTHORIZED_TESTBED,
            allowed_testbed_targets=("192.0.2.0/24",),
        )
        executor = XdpExecutor(settings=settings, host=MemoryHost())
        outcome = executor.execute(request(), target=target("192.0.2.9"))
        self.assertEqual(outcome.status, STATUS_SUCCESS)
        self.assertTrue(outcome.network_effect)

    def test_testbed_denies_non_allowlisted(self):
        settings = ExecutionSettings(
            mode=MODE_AUTHORIZED_TESTBED,
            allowed_testbed_targets=("192.0.2.0/24",),
        )
        executor = XdpExecutor(settings=settings, host=MemoryHost())
        outcome = executor.execute(request(), target=target("203.0.113.7"))
        self.assertEqual(outcome.status, STATUS_TARGET_NOT_ALLOWED)
        self.assertFalse(outcome.network_effect)

    def test_production_requires_enable_flag_at_settings(self):
        # the settings layer REFUSES production without the explicit enable
        with self.assertRaises(ValueError):
            ExecutionSettings(
                mode=MODE_PRODUCTION,
                enable_production_execution=False,
                allowed_testbed_targets=("192.0.2.0/24",),
            )

    def test_production_unavailable_host_never_fakes(self):
        settings = ExecutionSettings(
            mode=MODE_PRODUCTION,
            enable_production_execution=True,
            allowed_testbed_targets=("192.0.2.0/24",),
        )
        executor = XdpExecutor(settings=settings, host=UnavailableHost())
        outcome = executor.execute(request(), target=target())
        self.assertEqual(outcome.status, STATUS_DEPENDENCY_UNAVAILABLE)

    def test_operation_descriptor_is_structured(self):
        executor = XdpExecutor(settings=ExecutionSettings(mode=MODE_DRY_RUN))
        descriptor = executor.operation_descriptor(request(), target=target())
        self.assertEqual(descriptor["executor"], "xdp")
        self.assertEqual(descriptor["op"], "xdp.block_flow")
        self.assertIsInstance(descriptor["target"], dict)
        self.assertNotIn("cmd", descriptor)

    def test_cancel_is_deterministic(self):
        executor = XdpExecutor(settings=ExecutionSettings(mode=MODE_DRY_RUN))
        outcome = executor.cancel(request(), target=target(), now_ns=5)
        self.assertEqual(outcome.status, "CANCELLED")
        self.assertFalse(outcome.network_effect)


if __name__ == "__main__":
    unittest.main()