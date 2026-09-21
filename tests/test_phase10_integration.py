"""Phase 10 — end-to-end integration tests (streaming + execution + API)."""

import tempfile
import unittest

from tests.fixtures.risk.risk_fixtures import (
    build_identity,
    expected_from_plan_sample,
    plan_samples,
)

from correlation.api import live as api_live, v1
from correlation.api.pcap import PcapRegistry, PcapService
from correlation.execution import (
    STATUS_ALREADY_APPLIED,
    STATUS_SUCCESS,
    ExecutionControlPlane,
    ExecutionSettings,
)
from correlation.execution.host import MemoryHost
from correlation.execution.targets import ExecutionTarget
from correlation.models import CorrelationIdentity
from correlation.response.models import (
    APPROVAL_APPROVED,
    ACTION_BLOCK_FLOW,
    ROLE_ANALYST,
    STATUS_AUTHORIZED,
    ApprovalRequest,
    AuthorizationDecision,
    ExecutionRequest,
    ResponseRecommendation,
)
from correlation.streaming.dedup import Deduplicator
from correlation.streaming.live_adapter import CLASS_ESP, CLASS_IKE, XdpEventAdapter
from correlation.streaming.ml_provider import (
    MLInferenceProvider,
    TestDoubleClassifierModel,
    TestDoubleWindowBuilder,
)
from correlation.streaming.models import StreamEvent
from correlation.streaming.partitioning import partition_key
from correlation.streaming.pipeline import ContinuousPipeline
from correlation.streaming.schema import validate_event
from correlation.streaming.windowing import WindowEngine

WORST_ML_SAMPLE = 5  # plan.json worst-ml sample


def identity():
    return build_identity(experiment_id="exp-phase10-integration")


def window_record():
    engine = WindowEngine(window_ms=100, lookback=0)
    engine.accept(ts_ns=0, event_type=CLASS_ESP, spi=0x0001, seq=0x1000,
                  length=200, direction="A_TO_B")
    engine.accept(ts_ns=1, event_type=CLASS_ESP, spi=0x0001, seq=0x1001,
                  length=240, direction="A_TO_B")
    engine.accept(ts_ns=2, event_type=CLASS_IKE, length=90,
                  direction="B_TO_A")
    return engine.flush()[0]


class TestStreamingPipeline(unittest.TestCase):
    def test_pipeline_events_roundtrip(self):
        expected = expected_from_plan_sample(plan_samples()[WORST_ML_SAMPLE])
        pipeline = ContinuousPipeline(
            expected,
            identity(),
            ml=MLInferenceProvider(
                model=TestDoubleClassifierModel(), mode="test_double"
            ),
            window_builder=TestDoubleWindowBuilder(100_000_000),
            clock=lambda: 9000,
        )
        result = pipeline.process(window_record())
        self.assertEqual(result.ml.status, "completed")
        self.assertIsNotNone(result.correlation)
        self.assertIsNotNone(result.assessment)
        self.assertIsNotNone(result.explanation)

        events = result.to_events(source="integration", created_at=9000)
        kinds = {e.event_type for e in events}
        self.assertIn("correlation.result", kinds)
        self.assertIn("risk.assessment", kinds)
        self.assertIn("xai.explanation", kinds)

        for event in events:
            self.assertIsInstance(event, StreamEvent)
            validate_event(event)
            self.assertEqual(event.schema_version, "stream-schema-v1")
            self.assertEqual(partition_key(event),
                             f"{identity().dataset_run_id}|"
                             f"{identity().experiment_id}|"
                             f"{identity().attempt_number}")

    def test_pipeline_deterministic(self):
        expected = expected_from_plan_sample(plan_samples()[WORST_ML_SAMPLE])
        common = dict(
            expected=expected,
            identity=identity(),
            ml=MLInferenceProvider(
                model=TestDoubleClassifierModel(), mode="test_double"
            ),
            window_builder=TestDoubleWindowBuilder(100_000_000),
            clock=lambda: 5,
        )
        a = ContinuousPipeline(**common).process(window_record())
        b = ContinuousPipeline(**common).process(window_record())
        self.assertEqual(a.correlation.status, b.correlation.status)
        self.assertEqual(a.assessment.to_dict(), b.assessment.to_dict())
        self.assertEqual(
            [e.to_dict() for e in a.to_events("s")],
            [e.to_dict() for e in b.to_events("s")],
        )

    def test_ml_absent_produces_unrequested(self):
        expected = expected_from_plan_sample(plan_samples()[WORST_ML_SAMPLE])
        pipeline = ContinuousPipeline(
            expected,
            identity(),
            ml=MLInferenceProvider(),
            window_builder=TestDoubleWindowBuilder(100_000_000),
        )
        result = pipeline.process(window_record())
        self.assertEqual(result.ml.status, "unrequested")


class TestDedupAcrossPipeline(unittest.TestCase):
    def test_reprocessed_batch_is_duplicate(self):
        expected = expected_from_plan_sample(plan_samples()[WORST_ML_SAMPLE])
        pipeline = ContinuousPipeline(
            expected, identity(),
            ml=MLInferenceProvider(model=TestDoubleClassifierModel(), mode="test_double"),
            window_builder=TestDoubleWindowBuilder(100_000_000),
        )
        dedup = Deduplicator(size=100)
        first = pipeline.process(window_record()).to_events("s")
        for e in first:
            self.assertFalse(dedup.observe(e))
        second = pipeline.process(window_record()).to_events("s")
        for e in second:
            self.assertTrue(dedup.observe(e))
        self.assertEqual(dedup.admitted_count, len(first))
        self.assertEqual(dedup.duplicate_count, len(first))


class TestControlledExecution(unittest.TestCase):
    def _governed(self):
        rec = ResponseRecommendation(
            recommendation_id="rec-integration-1",
            assessment_identity=identity(),
            finding_id="finding-1",
            rule_id="rule-1",
            action=ACTION_BLOCK_FLOW,
            priority="HIGH",
            reason="integration fixture",
            rationale="structured fixture",
            severity="HIGH",
            risk_score=80,
            policy_version="v1",
            authorization_required=True,
            approval_required=True,
            status=STATUS_AUTHORIZED,
        )
        authorizer = AuthorizationDecision(
            principal_id="operator-1",
            action=ACTION_BLOCK_FLOW,
            authorized=True,
            required_roles=(ROLE_ANALYST,),
            granted_roles=(ROLE_ANALYST,),
            reason="fixture",
            policy_version="v1",
        )
        approval = ApprovalRequest(
            approval_id="approval-1",
            recommendation_id=rec.recommendation_id,
            requested_by="analyst-1",
            requested_at=0,
            reason="fixture",
            required_role=ROLE_ANALYST,
            status=APPROVAL_APPROVED,
        )
        target = ExecutionTarget(destination="192.0.2.50", protocol=17,
                                 destination_port=4500)
        request = ExecutionRequest(
            execution_id="exec-integration-1",
            recommendation_id=rec.recommendation_id,
            action=ACTION_BLOCK_FLOW,
            executor_type="xdp",
            requested_by="operator-1",
            issued_at=0,
        )
        return rec, authorizer, approval, target, request

    def test_approved_authorized_applies_then_replay_blocked(self):
        settings = ExecutionSettings(
            mode="AUTHORIZED_TESTBED",
            allowed_testbed_targets=("192.0.2.0/24",),
        )
        plane = ExecutionControlPlane(
            settings=settings, host=MemoryHost(),
        )
        rec, authorizer, approval, target, request = self._governed()
        first = plane.execute(
            request,
            recommendation=rec, authorization=authorizer,
            approval=approval, target=target, now_ns=1,
        )
        self.assertEqual(first.status, STATUS_SUCCESS)
        self.assertTrue(first.network_effect)

        second = plane.execute(
            request,
            recommendation=rec, authorization=authorizer,
            approval=approval, target=target, now_ns=2,
        )
        self.assertEqual(second.status, STATUS_ALREADY_APPLIED)
        self.assertFalse(second.network_effect)

    def test_ml_alone_cannot_trigger_execution(self):
        # no recommendation -> DENIED at the plane, even though ML exists
        settings = ExecutionSettings(mode="AUTHORIZED_TESTBED",
                                     allowed_testbed_targets=("192.0.2.0/24",))
        plane = ExecutionControlPlane(settings=settings, host=MemoryHost())
        _, authorizer, approval, target, request = self._governed()
        outcome = plane.execute(
            request, authorization=authorizer, approval=approval,
            target=target, now_ns=1,
        )
        self.assertEqual(outcome.status, "DENIED")


class TestLiveApiSurface(unittest.TestCase):
    def test_context_and_v1_over_pcap(self):
        with tempfile.TemporaryDirectory() as root:
            with open(f"{root}/cap.pcap", "wb") as handle:
                handle.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
            registry = PcapRegistry(root=root)
            registry.register("ev-integration", "cap.pcap")
            service = PcapService(registry)
            ctx = api_live.Phase10Context(pcap=service)
            meta, _ = v1.handle_v1_get(ctx, "/api/v1/evidence/ev-integration")
            self.assertEqual(meta["served_from"].split("\\")[-1], "cap.pcap")
            health, _ = v1.handle_v1_get(ctx, "/api/v1/health")
            self.assertIn("components", health)
            self.assertTrue(ctx.summary()["pcap_downloads"] >= 0)


class TestEventIdentityStability(unittest.TestCase):
    def test_same_payload_same_identity_stable(self):
        adapter = XdpEventAdapter(capture_ip="198.51.100.10")
        raw = {"proto": 17, "type": "IKE", "sport": 500, "dport": 500,
               "src": "192.0.2.1", "dst": "198.51.100.10"}
        e1 = adapter.to_stream_event(raw, identity(), created_at=1)
        e2 = adapter.to_stream_event(raw, identity(), created_at=1)
        self.assertEqual(e1.event_identity, e2.event_identity)
        e3 = adapter.to_stream_event(raw, build_identity(attempt_number=2),
                                     created_at=1)
        self.assertNotEqual(e1.event_identity, e3.event_identity)


if __name__ == "__main__":
    unittest.main()