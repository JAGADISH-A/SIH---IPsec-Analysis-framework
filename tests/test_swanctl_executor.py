"""Phase 10 — StrongSwan (swanctl) executor tests."""

import unittest

from correlation.execution import (
    STATUS_NOT_SUPPORTED,
    STATUS_SUCCESS,
    STATUS_TARGET_NOT_ALLOWED,
    StrongSwanExecutor,
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
    ACTION_RENEGOTIATE_SESSION,
    ACTION_TERMINATE_SESSION,
    ExecutionRequest,
    ResponseRecommendation,
)

IDENTITY = CorrelationIdentity(
    dataset_run_id="dataset-20260916-231246", sequence=1,
    experiment_id="exp-swan", attempt_number=1,
)


def recommendation(action=ACTION_TERMINATE_SESSION):
    return ResponseRecommendation(
        recommendation_id="rec-swan-1",
        assessment_identity=IDENTITY,
        finding_id="finding-3",
        rule_id="rule-sa-expiry",
        action=action,
        priority="HIGH",
        reason="fixture",
        rationale="structured fixture",
        severity="HIGH",
        risk_score=72,
        policy_version="v1",
        authorization_required=True,
        approval_required=True,
        status="AUTHORIZED",
    )


def request(action=ACTION_TERMINATE_SESSION):
    return ExecutionRequest(
        execution_id="exec-swan-1",
        recommendation_id="rec-swan-1",
        action=action,
        executor_type="strongswan",
        requested_by="system:test",
        issued_at=0,
    )


def target():
    return ExecutionTarget(destination="198.51.100.30", protocol=17,
                           destination_port=500)


class TestStrongSwanExecutor(unittest.TestCase):
    def test_supported_actions(self):
        self.assertEqual(StrongSwanExecutor.supported_actions,
                         (ACTION_TERMINATE_SESSION, ACTION_RENEGOTIATE_SESSION))

    def test_dry_run(self):
        executor = StrongSwanExecutor(settings=ExecutionSettings(mode=MODE_DRY_RUN))
        outcome = executor.execute(request(), target=target())
        self.assertEqual(outcome.status, STATUS_SUCCESS)
        self.assertFalse(outcome.network_effect)

    def test_testbed_applies(self):
        settings = ExecutionSettings(
            mode=MODE_AUTHORIZED_TESTBED,
            allowed_testbed_targets=("198.51.100.0/24",),
        )
        executor = StrongSwanExecutor(settings=settings, host=MemoryHost())
        outcome = executor.execute(request(), target=target())
        self.assertEqual(outcome.status, STATUS_SUCCESS)
        self.assertTrue(outcome.network_effect)

    def test_not_allowlisted(self):
        settings = ExecutionSettings(
            mode=MODE_AUTHORIZED_TESTBED,
            allowed_testbed_targets=("192.0.2.0/24",),
        )
        executor = StrongSwanExecutor(settings=settings, host=MemoryHost())
        outcome = executor.execute(request(), target=target())
        self.assertEqual(outcome.status, STATUS_TARGET_NOT_ALLOWED)

    def test_block_flow_unsupported(self):
        executor = StrongSwanExecutor(settings=ExecutionSettings(mode=MODE_DRY_RUN))
        outcome = executor.execute(request(action=ACTION_BLOCK_FLOW), target=target())
        self.assertEqual(outcome.status, STATUS_NOT_SUPPORTED)

    def test_renegotiate_supported(self):
        executor = StrongSwanExecutor(settings=ExecutionSettings(mode=MODE_DRY_RUN))
        outcome = executor.execute(request(action=ACTION_RENEGOTIATE_SESSION),
                                   target=target())
        self.assertEqual(outcome.status, STATUS_SUCCESS)

    def test_descriptor_names_swanctl(self):
        executor = StrongSwanExecutor(settings=ExecutionSettings(mode=MODE_DRY_RUN))
        descriptor = executor.operation_descriptor(request(), target=target())
        self.assertEqual(descriptor["executor"], "strongswan")
        self.assertEqual(descriptor["op"], "strongswan.terminate_session")


if __name__ == "__main__":
    unittest.main()