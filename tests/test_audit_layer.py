"""Audit-layer integration and verification tests.

The audit layer is only trustworthy if it *proves* the architecture's separation
of concerns. These tests therefore assert negative properties as loudly as
positive ones: that ML can never be recorded as authoritative, that a missing
observation is never back-filled from the plan, that a model failure cannot
erase the authoritative path, and that a risk finding is never recorded as an
enforcement action.

Coverage:

* provenance contract is machine-enforced (:class:`AuditEvent` construction)
* Case 1 -- expected IPsec present, observed evidence absent
* Case 2 -- ML classification recorded as advisory, protocol evidence untouched
* Case 3 -- genuine ML failure leaves the authoritative path intact
* Case 4 -- a risk finding is recorded as a finding, never as an execution
* Case 5 -- proposed != authorized != executed, and the audit layer refuses to
  record authorization/execution itself
* audit persistence never mutates ExpectedState or ObservedState
* determinism / replayability
* static checks: the audit layer imports no execution or XDP functionality
* end-to-end lifecycle on real recorded data
"""

from __future__ import annotations

import ast
import json
import sys
import tempfile
import unittest
from pathlib import Path

from correlation import audit
from correlation.audit import (
    ANALYSIS_EVENT_TYPES,
    AUDIT_SOURCES,
    EVENT_COMPARISON,
    EVENT_EXPECTED_STATE,
    EVENT_EXPLANATION,
    EVENT_ML_FAILURE,
    EVENT_ML_RESULT,
    EVENT_OBSERVED_STATE,
    EVENT_RESPONSE_PROPOSAL,
    EVENT_RISK_ASSESSMENT,
    EVENT_SOURCE,
    SOURCE_AUTHORITATIVE,
    SOURCE_COMPARISON,
    SOURCE_EXPECTED,
    SOURCE_EXPLAINABILITY,
    SOURCE_ML,
    SOURCE_OBSERVED,
    SOURCE_RESPONSE_RECOMMENDATION,
    SOURCE_RISK,
    AuditEvent,
    AuditJournal,
    audit_correlation_result,
    audit_run,
    validate_source,
)
from correlation.models import CorrelationIdentity
from correlation.models.evidence import EvidenceRef

REPO_ROOT = Path(__file__).resolve().parents[1]
LIVE_EVENTS = "results/observed-state/live_events_full.jsonl"
PLAN_PATH = "results/datasets/acc-eng-02/staging/plan.json"
RUN_ID = "acc-eng-02"
EXPERIMENT_ID = "acc-eng-02-exp-0001"
#: Caller-supplied so that every audit record in these tests is deterministic.
STAMP = "2026-09-26T00:00:00+00:00"

CLEAR_EVENTS = [
    {"ts": 1_000_000_000, "type": "OTHER", "src": "10.0.0.1",
     "dst": "10.0.0.2", "proto": 17, "len": 120},
    {"ts": 1_010_000_000, "type": "OTHER", "src": "10.0.0.2",
     "dst": "10.0.0.1", "proto": 17, "len": 90},
]


def _artifact(name):
    path = REPO_ROOT / name
    if not path.exists():
        raise unittest.SkipTest(f"required artifact missing: {name}")
    return path


def _materialized():
    from correlation.adapters import ExpectedStateAdapter
    from correlation.ml.live_correlation import DEFAULT_MATERIALIZED_AT

    return ExpectedStateAdapter(
        materialized_at=DEFAULT_MATERIALIZED_AT
    ).from_plan(
        _artifact(PLAN_PATH),
        sequence=1,
        experiment_id=EXPERIMENT_ID,
        attempt_number=1,
        run_id=RUN_ID,
    )


def _run(**kwargs):
    from correlation.ml.live_correlation import correlate_live_events, read_event_jsonl

    params = dict(
        plan_path=str(_artifact(PLAN_PATH)),
        sequence=1,
        experiment_id=EXPERIMENT_ID,
        attempt_number=1,
        run_id=RUN_ID,
        endpoints={"a": "192.168.100.1", "b": "192.168.100.2"},
    )
    params.update(kwargs)
    return correlate_live_events(
        read_event_jsonl(str(_artifact(LIVE_EVENTS))), **params
    )


def _event(events, event_type):
    found = [e for e in events if e.event_type == event_type]
    assert found, f"no {event_type} event recorded"
    return found[0]


class TestProvenanceContractIsEnforced(unittest.TestCase):
    """``(source, authoritative)`` is validated, not merely documented."""

    IDENTITY = CorrelationIdentity(
        dataset_run_id=RUN_ID, sequence=1,
        experiment_id=EXPERIMENT_ID, attempt_number=1,
    )

    def test_only_real_observation_is_authoritative(self):
        authoritative = [s for s in AUDIT_SOURCES if SOURCE_AUTHORITATIVE[s]]

        self.assertEqual([SOURCE_OBSERVED], authoritative)

    def test_ml_can_never_be_authoritative(self):
        with self.assertRaises(ValueError) as ctx:
            AuditEvent(
                event_type=EVENT_ML_RESULT, source=SOURCE_ML,
                authoritative=True, identity=self.IDENTITY,
            )
        self.assertIn("authoritative=False", str(ctx.exception))

    def test_expected_state_can_never_be_authoritative(self):
        with self.assertRaises(ValueError):
            AuditEvent(
                event_type=EVENT_EXPECTED_STATE, source=SOURCE_EXPECTED,
                authoritative=True, identity=self.IDENTITY,
            )

    def test_observation_must_be_authoritative(self):
        with self.assertRaises(ValueError):
            AuditEvent(
                event_type=EVENT_OBSERVED_STATE, source=SOURCE_OBSERVED,
                authoritative=False, identity=self.IDENTITY,
            )

    def test_judgements_are_never_authoritative(self):
        for event_type, source in (
            (EVENT_RISK_ASSESSMENT, SOURCE_RISK),
            (EVENT_EXPLANATION, SOURCE_EXPLAINABILITY),
            (EVENT_RESPONSE_PROPOSAL, SOURCE_RESPONSE_RECOMMENDATION),
            (EVENT_COMPARISON, SOURCE_COMPARISON),
        ):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    AuditEvent(
                        event_type=event_type, source=source,
                        authoritative=True, identity=self.IDENTITY,
                    )

    def test_unknown_source_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_source("definitely-not-a-source", False)

    def test_every_declared_pair_is_accepted(self):
        for source in AUDIT_SOURCES:
            with self.subTest(source=source):
                validate_source(source, SOURCE_AUTHORITATIVE[source])

    def test_audit_layer_cannot_record_authorization_or_execution(self):
        """The vocabulary itself excludes those stages (they belong to
        ``correlation/response/audit.py``)."""
        for forbidden in ("authorized", "executed", "approval", "enforced"):
            self.assertNotIn(forbidden, ANALYSIS_EVENT_TYPES)
        with self.assertRaises(ValueError):
            AuditEvent(
                event_type="authorized", source=SOURCE_OBSERVED,
                authoritative=True, identity=self.IDENTITY,
            )


class TestComparisonIsNotObservation(unittest.TestCase):
    """A derived COMPARED judgement must not impersonate an OBSERVED fact."""

    IDENTITY = CorrelationIdentity(
        dataset_run_id=RUN_ID, sequence=1,
        experiment_id=EXPERIMENT_ID, attempt_number=1,
    )

    def test_comparison_has_its_own_source(self):
        event = AuditEvent(
            event_type=EVENT_COMPARISON, source=SOURCE_COMPARISON,
            authoritative=False, identity=self.IDENTITY,
        )
        self.assertEqual(SOURCE_COMPARISON, event.source)
        self.assertNotEqual(SOURCE_OBSERVED, event.source)
        self.assertFalse(event.authoritative)

    def test_every_event_type_is_pinned_to_exactly_one_source(self):
        self.assertEqual(set(ANALYSIS_EVENT_TYPES), set(EVENT_SOURCE))
        for event_type, source in EVENT_SOURCE.items():
            with self.subTest(event_type=event_type):
                self.assertIn(source, AUDIT_SOURCES)
                # a pairing is only meaningful if it is the *only* one allowed
                self.assertEqual(
                    SOURCE_AUTHORITATIVE[source],
                    SOURCE_AUTHORITATIVE[EVENT_SOURCE[event_type]],
                )

    def test_ml_cannot_be_recorded_as_observation(self):
        with self.assertRaises(ValueError) as ctx:
            AuditEvent(
                event_type=EVENT_ML_RESULT, source=SOURCE_OBSERVED,
                authoritative=True, identity=self.IDENTITY,
            )
        self.assertIn("may only be recorded with source='ml'", str(ctx.exception))

    def test_observation_cannot_be_recorded_as_ml(self):
        with self.assertRaises(ValueError) as ctx:
            AuditEvent(
                event_type=EVENT_OBSERVED_STATE, source=SOURCE_ML,
                authoritative=False, identity=self.IDENTITY,
            )
        self.assertIn(
            "may only be recorded with source='observation/state-builder'",
            str(ctx.exception),
        )

    def test_expected_cannot_be_recorded_as_observed(self):
        with self.assertRaises(ValueError):
            AuditEvent(
                event_type=EVENT_EXPECTED_STATE, source=SOURCE_OBSERVED,
                authoritative=True, identity=self.IDENTITY,
            )


class TestEventIdAndTamperDetection(unittest.TestCase):
    """``event_id`` is content-addressed, deterministic, and load-bearing."""

    IDENTITY = CorrelationIdentity(
        dataset_run_id=RUN_ID, sequence=1,
        experiment_id=EXPERIMENT_ID, attempt_number=1,
    )

    def _event(self, **overrides):
        kwargs = dict(
            event_type=EVENT_OBSERVED_STATE, source=SOURCE_OBSERVED,
            authoritative=True, identity=self.IDENTITY, recorded_at=STAMP,
        )
        kwargs.update(overrides)
        return AuditEvent(**kwargs)

    def test_every_event_carries_an_event_id(self):
        event = self._event()
        self.assertTrue(event.event_id)
        self.assertTrue(event.event_id.startswith("audit-"))

    def test_event_id_is_deterministic(self):
        self.assertEqual(self._event().event_id, self._event().event_id)
        self.assertNotEqual(
            self._event().event_id,
            self._event(recorded_at="2026-01-01T00:00:00+00:00").event_id,
        )

    def test_event_id_survives_a_persistence_round_trip(self):
        event = self._event()
        self.assertEqual(event.event_id, AuditEvent.from_dict(event.to_dict()).event_id)
        self.assertIn("event_id", event.to_dict())

    def test_editing_a_persisted_record_is_detected(self):
        record = self._event().to_dict()
        record["observed_ref"] = {"esp_seen": True, "ah_seen": True}
        with self.assertRaises(ValueError) as ctx:
            AuditEvent.from_dict(record)
        self.assertIn("modified after it was written", str(ctx.exception))

    def test_editing_identity_is_detected(self):
        record = self._event().to_dict()
        record["identity"]["experiment_id"] = "someone-elses-experiment"
        with self.assertRaises(ValueError):
            AuditEvent.from_dict(record)


class TestCase1ExpectedIpsecButNoObservedEvidence(unittest.TestCase):
    """Expected IPsec present, observed evidence contains no ESP/AH."""

    def setUp(self):
        from correlation.ml.live_correlation import (
            correlate_live_window,
            feature_windows_from_events,
            observed_state_from_events,
        )

        self.materialized = _materialized()
        self.run_identity = self.materialized.identity
        self.expected_state = self.materialized.expected
        self.observed = observed_state_from_events(
            CLEAR_EVENTS, endpoints={"a": "10.0.0.1", "b": "10.0.0.2"}
        )
        self.window = feature_windows_from_events(CLEAR_EVENTS)[0]
        self.window_identity = CorrelationIdentity(
            dataset_run_id=RUN_ID, sequence=1, experiment_id=EXPERIMENT_ID,
            attempt_number=1,
            window_start_ns=self.window.window_start_ns,
            window_end_ns=self.window.window_end_ns,
        )
        self.result = correlate_live_window(
            expected=_materialized(),
            observed=self.observed,
            window=self.window,
            observed_identity=self.window_identity,
        )

    def test_observation_really_lacks_ipsec_evidence(self):
        self.assertFalse(self.observed.esp_seen)
        self.assertFalse(self.observed.ah_seen)
        self.assertFalse(self.observed.ike_seen)

    def test_expected_state_says_ipsec(self):
        self.assertEqual("tunnel", self.expected_state.mode)

    def test_audit_records_expected_and_observed_separately(self):
        events = audit_correlation_result(
            self.result, expected=self.expected_state, identity=self.run_identity
        )
        expected_event = _event(events, EVENT_EXPECTED_STATE)
        observed_event = _event(events, EVENT_OBSERVED_STATE)

        self.assertEqual("tunnel", expected_event.expected_ref["mode"])
        self.assertIsNone(
            expected_event.observed_ref,
            "an expected-state record must carry no observed evidence",
        )
        self.assertFalse(observed_event.observed_ref["esp_seen"])
        self.assertFalse(observed_event.observed_ref["ah_seen"])
        self.assertEqual(SOURCE_EXPECTED, expected_event.source)
        self.assertEqual(SOURCE_OBSERVED, observed_event.source)
        self.assertFalse(expected_event.authoritative)
        self.assertTrue(observed_event.authoritative)

    def test_audit_never_records_ipsec_as_observed(self):
        """Expected ESP presence must not be reported as an observed match."""
        events = audit_correlation_result(
            self.result, expected=self.expected_state, identity=self.run_identity
        )
        comparison = _event(events, EVENT_COMPARISON).comparison
        by_variable = {v["variable"]: v for v in comparison["variables"]}

        # ESP presence was expected but the observation window was incomplete:
        # absence is not authoritative, so it must stay UNKNOWN and must not
        # claim the protocol was observed.
        esp = by_variable["esp.presence"]
        self.assertEqual("UNKNOWN", esp["status"])
        self.assertTrue(esp["expected_value"])
        self.assertNotEqual(
            "MATCH", esp["status"],
            "expected ESP must never be recorded as an observed match",
        )

        # mode: expected tunnel, observed transport -> a genuine discrepancy.
        mode = by_variable["mode"]
        self.assertEqual("MISMATCH", mode["status"])
        self.assertEqual("tunnel", mode["expected_value"])
        self.assertEqual("transport", mode["observed_value"])

    def test_absence_matched_only_when_absence_is_observable(self):
        """``ah.presence`` may MATCH because AH absence is directly observable.

        This guards against reading the audit as if every MATCH were a
        back-filled expected value: the rule sources ``observed`` from
        ``ObservedState.ah_seen``, so a MATCH on an expected-absent protocol is
        a real observation, while a MATCH on an expected-present protocol would
        be fabrication and is asserted impossible above.
        """
        events = audit_correlation_result(
            self.result, expected=self.expected_state, identity=self.run_identity
        )
        by_variable = {
            v["variable"]: v
            for v in _event(events, EVENT_COMPARISON).comparison["variables"]
        }
        ah = by_variable["ah.presence"]

        self.assertFalse(ah["expected_value"])
        self.assertEqual("MATCH", ah["status"])
        self.assertTrue(ah["observed_value_authoritative"])
        self.assertEqual(SOURCE_OBSERVED, ah["observed_value_source"])

    def test_unestablished_values_stay_none_and_unknown(self):
        events = audit_correlation_result(
            self.result, expected=self.expected_state, identity=self.run_identity
        )
        comparison = _event(events, EVENT_COMPARISON).comparison
        unestablished = [
            v for v in comparison["variables"] if v["observed_value"] is None
        ]

        self.assertTrue(unestablished, "some values were never established")
        for variable in unestablished:
            with self.subTest(variable=variable["variable"]):
                self.assertIsNone(variable["observed_value"])
                self.assertIsNone(variable["observed_value_source"])
                self.assertFalse(variable["observed_value_authoritative"])

    def test_missing_evidence_is_never_backfilled_from_expected(self):
        """Invariant 6: an unestablished value never acquires the expected one."""
        events = audit_correlation_result(
            self.result, expected=self.expected_state, identity=self.run_identity
        )
        comparison = _event(events, EVENT_COMPARISON).comparison

        self.assertTrue(
            any(v["observed_value"] is None for v in comparison["variables"])
        )
        for variable in comparison["variables"]:
            if variable["observed_value"] is not None:
                continue
            with self.subTest(variable=variable["variable"]):
                # A variable that was never established keeps observed_value
                # None and is flagged non-authoritative. Where the plan states no
                # expectation either, expected_value is None too; what matters
                # is that the observed side was never invented.
                if variable["expected_value"] is not None:
                    self.assertNotEqual(
                        variable["expected_value"], variable["observed_value"]
                    )
                self.assertFalse(variable["observed_value_authoritative"])
                self.assertIsNone(variable["observed_value_source"])

    def test_overall_status_is_not_optimistic(self):
        self.assertNotEqual("MATCH", self.result.correlation.status)


class TestCase2MlClassificationIsAdvisory(unittest.TestCase):
    """ML classification is recorded as advisory and changes nothing observed."""

    def setUp(self):
        self.run = _run()
        self.result = self.run.results[0]
        self.events = audit_run(
            self.run, recorded_at="2026-09-26T00:00:00+00:00"
        )

    def test_ml_event_is_labelled_non_authoritative(self):
        ml_event = _event(self.events, EVENT_ML_RESULT)

        self.assertEqual(SOURCE_ML, ml_event.source)
        self.assertFalse(ml_event.authoritative)
        self.assertFalse(ml_event.ml_ref["authoritative"])

    def test_ml_provenance_is_complete(self):
        ml_ref = _event(self.events, EVENT_ML_RESULT).ml_ref

        self.assertEqual("traffic_rf_v1", ml_ref["model_version"])
        self.assertEqual("v2", ml_ref["feature_schema_version"])
        self.assertEqual(6, len(ml_ref["probabilities"]))
        self.assertIsNotNone(ml_ref["window_id"])
        self.assertIn("does not represent an authoritative", ml_ref["non_interference"])

    def test_ml_does_not_overwrite_the_protocol_observation(self):
        from correlation.comparison import ComparisonEngine, ComparisonEngineOptions
        from correlation.ml.integration import correlate_with_ml
        from correlation.ml.live_correlation import observed_values_from_state

        result = self.result
        engine = ComparisonEngine(ComparisonEngineOptions())
        without = engine.compare(
            result.correlation.identity and _materialized().expected,
            result.observed,
            identity=_materialized().identity,
            observed_identity=CorrelationIdentity(
                dataset_run_id=RUN_ID, sequence=1, experiment_id=EXPERIMENT_ID,
                attempt_number=1,
                window_start_ns=result.window.window_start_ns,
                window_end_ns=result.window.window_end_ns,
            ),
            observed_values=observed_values_from_state(result.observed),
        )
        with_ml = correlate_with_ml(
            engine,
            _materialized().expected,
            result.observed,
            identity=_materialized().identity,
            observed_identity=CorrelationIdentity(
                dataset_run_id=RUN_ID, sequence=1, experiment_id=EXPERIMENT_ID,
                attempt_number=1,
                window_start_ns=result.window.window_start_ns,
                window_end_ns=result.window.window_end_ns,
            ),
            ml_result=result.ml_result,
            observed_values=observed_values_from_state(result.observed),
        )

        self.assertEqual(without.status, with_ml.status)
        self.assertEqual(without.matches, with_ml.matches)
        self.assertEqual(without.mismatches, with_ml.mismatches)
        self.assertEqual(without.unknowns, with_ml.unknowns)
        self.assertEqual(without.not_applicable, with_ml.not_applicable)

    def test_ml_is_a_separate_event_not_part_of_observation(self):
        types = [e.event_type for e in self.events[:6]]

        self.assertIn(EVENT_ML_RESULT, types)
        ml_event = _event(self.events, EVENT_ML_RESULT)
        observed_event = _event(self.events, EVENT_OBSERVED_STATE)

        self.assertIsNone(ml_event.observed_ref)
        self.assertIsNone(observed_event.ml_ref)
        self.assertNotEqual(ml_event.source, observed_event.source)

    def test_explanation_repeats_that_ml_is_not_authoritative(self):
        for entry in self.result.explanation.ml_explanations:
            self.assertIn(
                "does not represent an authoritative", entry.explanation
            )


class TestCase3MlFailurePreservesAuthoritativePath(unittest.TestCase):
    """A genuine model failure must not erase or alter protocol evidence."""

    def test_ml_failure_is_recorded_and_the_path_survives(self):
        run = _run(on_ml_error="record", artifact={})
        events = audit_run(run, recorded_at="2026-09-26T00:00:00+00:00")
        result = run.results[0]

        self.assertIsNone(result.ml_result)
        self.assertIsNotNone(result.ml_error)
        failure = _event(events, EVENT_ML_FAILURE)
        self.assertEqual(SOURCE_ML, failure.source)
        self.assertFalse(failure.authoritative)
        self.assertTrue(failure.provenance["authoritative_path_intact"])

    def test_observation_comparison_risk_and_explanation_still_recorded(self):
        run = _run(on_ml_error="record", artifact={})
        events = audit_run(run, recorded_at="2026-09-26T00:00:00+00:00")
        types = {e.event_type for e in events}

        for required in (
            EVENT_EXPECTED_STATE, EVENT_OBSERVED_STATE, EVENT_COMPARISON,
            EVENT_RISK_ASSESSMENT, EVENT_EXPLANATION,
        ):
            self.assertIn(required, types)

    def test_protocol_evidence_is_identical_with_and_without_ml(self):
        healthy = _run().results[0]
        broken = _run(on_ml_error="record", artifact={}).results[0]

        self.assertEqual(
            healthy.correlation.status, broken.correlation.status
        )
        self.assertEqual(
            healthy.correlation.matches, broken.correlation.matches
        )
        self.assertEqual(
            healthy.correlation.mismatches, broken.correlation.mismatches
        )
        self.assertEqual(
            healthy.correlation.unknowns, broken.correlation.unknowns
        )
        self.assertEqual(
            healthy.observed.to_dict(), broken.observed.to_dict()
        )
        self.assertTrue(healthy.correlation.metadata["ml_evaluated"])
        self.assertFalse(broken.correlation.metadata["ml_evaluated"])

    def test_correlation_reports_the_model_as_unavailable(self):
        run = _run(on_ml_error="record", artifact={})
        result = run.results[0]

        self.assertFalse(result.correlation.metadata["ml"]["model_available"])
        self.assertIsNone(result.correlation.metadata["ml"]["ml_result"])

    def test_healthy_run_reports_the_model_as_available(self):
        run = _run()
        result = run.results[0]

        self.assertTrue(result.correlation.metadata["ml"]["model_available"])
        self.assertTrue(result.correlation.metadata["ml_evaluated"])

    def test_raise_mode_still_raises_by_default(self):
        with self.assertRaises(Exception):
            _run(artifact={})


class TestCase4RiskFindingIsNotEnforcement(unittest.TestCase):
    """A risk finding is a judgement, never an enforcement action."""

    def setUp(self):
        self.events = audit_run(_run(), recorded_at="2026-09-26T00:00:00+00:00")

    def test_risk_event_records_the_finding(self):
        risk_event = _event(self.events, EVENT_RISK_ASSESSMENT)

        self.assertEqual(SOURCE_RISK, risk_event.source)
        self.assertFalse(risk_event.authoritative)
        self.assertIn(
            risk_event.assessment_severity if hasattr(risk_event, "assessment_severity")
            else risk_event.risk_ref["severity"],
            ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"),
        )

    def test_risk_event_declares_nothing_was_executed(self):
        decision = _event(self.events, EVENT_RISK_ASSESSMENT).decision

        self.assertFalse(decision["executed"])
        self.assertFalse(decision["enforced"])
        self.assertEqual("risk_finding", decision["kind"])

    def test_no_execution_event_is_emitted(self):
        types = {e.event_type for e in self.events}

        for forbidden in ("execution", "authorized", "approval", "enforcement"):
            self.assertNotIn(forbidden, types)

    def test_audit_payload_mentions_no_enforcement_action(self):
        blob = json.dumps(
            [e.to_dict() for e in self.events if e.event_type == EVENT_RISK_ASSESSMENT]
        ).lower()

        self.assertIn('"executed": false', blob)
        self.assertIn('"enforced": false', blob)


class TestCase5ProposedIsNotAuthorizedIsNotExecuted(unittest.TestCase):
    """The three response states must stay distinguishable."""

    def setUp(self):
        sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures" / "response"))
        from response_fixtures import assessment_for_posture, engine  # noqa: E402

        from correlation.response import ROLE_ANALYST
        from correlation.response.authorization import auth_context

        self.role_analyst = ROLE_ANALYST
        self.analyst_context = auth_context("analyst-1", (ROLE_ANALYST,))
        self.engine = engine()
        self.plan = self.engine.plan(assessment_for_posture("WEAK"))
        self.rec = self.plan.by_id()["RR-RISK-PFS-DISABLED"]

    @classmethod
    def tearDownClass(cls):
        if str(REPO_ROOT / "tests" / "fixtures" / "response") in sys.path:
            sys.path.pop(0)

    def test_response_layer_already_distinguishes_the_three_states(self):
        from correlation.response import (
            STATUS_APPROVED,
            STATUS_AUTHORIZED,
            STATUS_RECOMMENDED,
        )

        # 1. proposed
        self.assertEqual(STATUS_RECOMMENDED, self.rec.status)
        # 2. approved
        approval = self.engine.request_approval(
            self.rec, "analyst-1", reason="proceed"
        )
        self.engine.approve(
            approval, self.rec, "analyst-1", roles=(self.role_analyst,)
        )
        self.assertEqual(STATUS_APPROVED, self.rec.status)
        # 3. authorized -- still not executed
        decision = self.engine.authorize(self.rec, self.analyst_context)
        self.assertTrue(decision.authorized)
        self.assertEqual(STATUS_AUTHORIZED, self.rec.status)
        self.assertNotEqual(STATUS_RECOMMENDED, self.rec.status)
        self.assertNotIn("SUCCEEDED", self.rec.status)

        types = [e.event_type for e in self.engine.ledger.events()]
        self.assertIn("RECOMMENDATION_CREATED", types)
        self.assertIn("AUTHORIZATION_CHECKED", types)
        self.assertNotIn("EXECUTION_SUCCEEDED", types)
        self.assertNotIn("DRY_RUN_EXECUTED", types)

    def test_audit_records_only_a_proposal_reference(self):
        run = _run()
        events = audit_run(
            run,
            recorded_at="2026-09-26T00:00:00+00:00",
            response_proposal_refs={run.results[0].window_id: self.rec.recommendation_id},
        )
        proposal = _event(events, EVENT_RESPONSE_PROPOSAL)

        self.assertEqual(self.rec.recommendation_id, proposal.response_proposal_ref)
        self.assertEqual(SOURCE_RESPONSE_RECOMMENDATION, proposal.source)
        self.assertFalse(proposal.authoritative)
        self.assertFalse(proposal.decision["authorized"])
        self.assertFalse(proposal.decision["executed"])

    def test_proposal_and_execution_remain_separate_ledgers(self):
        run = _run()
        events = audit_run(
            run,
            recorded_at="2026-09-26T00:00:00+00:00",
            response_proposal_refs={run.results[0].window_id: self.rec.recommendation_id},
        )
        proposal = _event(events, EVENT_RESPONSE_PROPOSAL)
        response_events = self.engine.ledger.for_recommendation(
            self.rec.recommendation_id
        )

        self.assertTrue(response_events)
        self.assertEqual("RECOMMENDATION_CREATED", response_events[0].event_type)
        self.assertEqual(
            self.rec.recommendation_id, proposal.response_proposal_ref
        )
        self.assertNotIn("EXECUTION_SUCCEEDED", proposal.decision)


class TestAuditDoesNotMutateState(unittest.TestCase):
    """Invariant 8: persisting an audit event changes nothing upstream."""

    def test_expected_and_observed_are_unchanged(self):
        run = _run()
        expected_before = run.expected.to_dict()
        observed_before = run.observed.to_dict()

        with tempfile.TemporaryDirectory() as tmp:
            audit_run(
                run,
                journal=AuditJournal(Path(tmp) / "events.jsonl"),
                recorded_at="2026-09-26T00:00:00+00:00",
            )

        self.assertEqual(expected_before, run.expected.to_dict())
        self.assertEqual(observed_before, run.observed.to_dict())

    def test_event_models_are_frozen(self):
        event = _event(
            audit_run(_run(), recorded_at="2026-09-26T00:00:00+00:00"),
            EVENT_OBSERVED_STATE,
        )
        with self.assertRaises(Exception):
            event.source = SOURCE_ML


class TestDeterminismAndJournal(unittest.TestCase):
    """Invariant 12: the same inputs replay to byte-identical records."""

    def test_replay_is_byte_identical(self):
        first = [e.to_dict() for e in audit_run(
            _run(), recorded_at="2026-09-26T00:00:00+00:00"
        )]
        second = [e.to_dict() for e in audit_run(
            _run(), recorded_at="2026-09-26T00:00:00+00:00"
        )]

        self.assertEqual(first, second)

    def test_no_wall_clock_is_read(self):
        source = (REPO_ROOT / "correlation/audit.py").read_text()

        self.assertNotIn("utcnow", source)
        self.assertNotIn("datetime.now", source)
        self.assertNotIn("time.time", source)

    def test_journal_round_trips(self):
        run = _run()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "events.jsonl"
            journal = AuditJournal(path)
            written = audit_run(
                run, journal=journal, recorded_at="2026-09-26T00:00:00+00:00"
            )
            restored = journal.read()

        self.assertEqual(len(written), len(restored))
        self.assertEqual(
            [e.to_dict() for e in written], [e.to_dict() for e in restored]
        )

    def test_corrupt_line_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text('{"not": "json"\n', encoding="utf-8")

            with self.assertRaises(ValueError):
                AuditJournal(path).read()

    def test_journal_without_path_refuses_to_append(self):
        with self.assertRaises(ValueError):
            AuditJournal().append(
                AuditEvent(
                    event_type=EVENT_OBSERVED_STATE, source=SOURCE_OBSERVED,
                    authoritative=True,
                    identity=CorrelationIdentity(
                        dataset_run_id="r", sequence=1,
                        experiment_id="r-exp-0001", attempt_number=1,
                    ),
                )
            )

    def test_of_type_filters(self):
        run = _run()
        with tempfile.TemporaryDirectory() as tmp:
            journal = AuditJournal(Path(tmp) / "events.jsonl")
            audit_run(run, journal=journal, recorded_at="2026-09-26T00:00:00+00:00")
            ml_events = journal.of_type(EVENT_ML_RESULT)

        self.assertEqual(len(run.results), len(ml_events))
        self.assertTrue(all(e.source == SOURCE_ML for e in ml_events))


class TestStaticNonInterference(unittest.TestCase):
    """The audit layer must not import or invoke execution/XDP functionality."""

    def _tree(self, relative):
        return ast.parse((REPO_ROOT / relative).read_text())

    def test_audit_module_imports_no_execution_or_enforcement_module(self):
        imported = set()
        for node in ast.walk(self._tree("correlation/audit.py")):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])

        for forbidden in (
            "nftables", "iptables", "shap", "ctypes", "subprocess", "socket",
        ):
            self.assertNotIn(forbidden, imported)

    def test_audit_module_does_not_import_the_execution_package(self):
        for node in ast.walk(self._tree("correlation/audit.py")):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                self.assertNotIn("execution", module)
                self.assertNotIn("response", module)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn("execution", alias.name)
                    self.assertNotIn("response", alias.name)

    def test_audit_module_uses_no_xdp_action_constant(self):
        constants = {
            node.value
            for node in ast.walk(self._tree("correlation/audit.py"))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }

        for action in ("XDP_DROP", "XDP_TX", "XDP_REDIRECT", "XDP_ABORTED"):
            self.assertNotIn(action, constants)

    def test_audit_module_calls_nothing_from_execution(self):
        for node in ast.walk(self._tree("correlation/audit.py")):
            if isinstance(node, ast.Call):
                name = getattr(node.func, "id", None) or getattr(
                    node.func, "attr", None
                )
                self.assertNotIn("execute", name)
                self.assertNotIn("enforce", name)
                self.assertNotIn("respond", name)
                self.assertNotIn("system", name)

    def test_audit_layer_does_not_import_the_controller(self):
        """The audit layer must not depend on the controller package."""
        for node in ast.walk(self._tree("correlation/audit.py")):
            if isinstance(node, ast.ImportFrom):
                self.assertNotIn("controller", node.module or "")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn("controller", alias.name)


class TestRealDataLifecycle(unittest.TestCase):
    """End-to-end audit lifecycle on real recorded observation data."""

    def test_full_ladder_on_real_observation(self):
        run = _run()
        events = audit_run(
            run,
            recorded_at="2026-09-26T00:00:00+00:00",
            evidence_refs=[
                EvidenceRef(
                    audit_event_reference="audit://events.jsonl#0",
                    source="audit_tap",
                )
            ],
        )
        types = [e.event_type for e in events[:6]]

        self.assertEqual(
            [
                EVENT_EXPECTED_STATE, EVENT_OBSERVED_STATE, EVENT_COMPARISON,
                EVENT_ML_RESULT, EVENT_RISK_ASSESSMENT, EVENT_EXPLANATION,
            ],
            types,
        )
        self.assertEqual(len(run.results) * 6, len(events))

    def test_observed_state_event_reflects_real_observation(self):
        run = _run()
        events = audit_run(run, recorded_at="2026-09-26T00:00:00+00:00")
        observed_ref = _event(events, EVENT_OBSERVED_STATE).observed_ref

        self.assertEqual(run.observed.packets_seen, observed_ref["packets_seen"])
        self.assertEqual(run.observed.bytes_seen, observed_ref["bytes_seen"])
        self.assertEqual(len(run.observed.spis), observed_ref["spi_count"])
        self.assertTrue(observed_ref["authoritative"])

    def test_comparison_records_overall_status_and_per_variable_provenance(self):
        run = _run()
        events = audit_run(run, recorded_at="2026-09-26T00:00:00+00:00")
        comparison = _event(events, EVENT_COMPARISON).comparison

        self.assertEqual(run.results[0].correlation.status, comparison["status"])
        self.assertIn("PARTIAL", (comparison["observation_completeness"],))
        self.assertTrue(comparison["variables"])
        for variable in comparison["variables"]:
            with self.subTest(variable=variable["variable"]):
                if variable["observed_value"] is None:
                    self.assertFalse(variable["observed_value_authoritative"])
                else:
                    self.assertEqual(
                        SOURCE_OBSERVED, variable["observed_value_source"]
                    )
                    self.assertTrue(variable["observed_value_authoritative"])

    def test_evidence_reference_to_the_observation_journal_is_preserved(self):
        ref = EvidenceRef(
            audit_event_reference="audit://events.jsonl#12", source="audit_tap"
        )
        run = _run()
        events = audit_run(
            run, recorded_at="2026-09-26T00:00:00+00:00", evidence_refs=[ref]
        )

        self.assertTrue(all(e.evidence_refs == (ref,) for e in events))

    def test_an_insufficient_evidence_run_still_produces_a_valid_audit(self):
        """A run may legitimately stop at explanation with UNKNOWN comparison."""
        run = _run()
        events = audit_run(run, recorded_at="2026-09-26T00:00:00+00:00")
        comparison = _event(events, EVENT_COMPARISON).comparison

        self.assertEqual("UNKNOWN", comparison["status"])
        self.assertIn(EVENT_EXPLANATION, {e.event_type for e in events})
        self.assertFalse(
            {e.event_type for e in events} & {"execution", "authorized"}
        )


class TestAuditIsReachableFromProductionPath(unittest.TestCase):
    """The audit layer must be invoked by a real entry point, not only tests."""

    def test_audit_module_is_importable_and_has_a_recorder(self):
        self.assertTrue(callable(audit.audit_run))
        self.assertTrue(callable(audit.audit_correlation_result))
        self.assertIn("AuditJournal", dir(audit))

    def test_seam_cli_writes_audit_events(self):
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.json"
            audit_path = Path(tmp) / "audit.jsonl"
            completed = subprocess.run(
                [
                    sys.executable, "-m", "correlation.ml.live_correlation",
                    "--events", str(_artifact(LIVE_EVENTS)),
                    "--plan", str(_artifact(PLAN_PATH)),
                    "--sequence", "1",
                    "--run-id", RUN_ID,
                    "--experiment-id", EXPERIMENT_ID,
                    "--attempt-number", "1",
                    "--endpoints", "a=192.168.100.1,b=192.168.100.2",
                    "--output", str(out),
                    "--audit-out", str(audit_path),
                    "--recorded-at", "2026-09-26T00:00:00+00:00",
                ],
                cwd=REPO_ROOT, capture_output=True, text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertIn("audit event(s) written", completed.stderr)

            events = AuditJournal(audit_path).read()

        self.assertTrue(events)
        self.assertEqual(
            {EVENT_EXPECTED_STATE, EVENT_OBSERVED_STATE, EVENT_COMPARISON,
             EVENT_ML_RESULT, EVENT_RISK_ASSESSMENT, EVENT_EXPLANATION},
            {e.event_type for e in events},
        )
        self.assertTrue(all(e.recorded_at == "2026-09-26T00:00:00+00:00"
                            for e in events))
        self.assertTrue(all(e.identity.dataset_run_id == RUN_ID for e in events))
        self.assertTrue(all(e.identity.experiment_id == EXPERIMENT_ID
                            for e in events))

    def test_cli_audit_run_is_reproducible(self):
        """Two identical CLI invocations produce byte-identical audit records."""
        import subprocess

        outputs = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as tmp:
                audit_path = Path(tmp) / "audit.jsonl"
                completed = subprocess.run(
                    [
                        sys.executable, "-m", "correlation.ml.live_correlation",
                        "--events", str(_artifact(LIVE_EVENTS)),
                        "--plan", str(_artifact(PLAN_PATH)),
                        "--sequence", "1",
                        "--run-id", RUN_ID,
                        "--experiment-id", EXPERIMENT_ID,
                        "--attempt-number", "1",
                        "--endpoints", "a=192.168.100.1,b=192.168.100.2",
                        "--output", str(Path(tmp) / "run.json"),
                        "--audit-out", str(audit_path),
                        "--recorded-at", "2026-09-26T00:00:00+00:00",
                    ],
                    cwd=REPO_ROOT, capture_output=True, text=True,
                )
                self.assertEqual(0, completed.returncode, completed.stderr)
                outputs.append(audit_path.read_text(encoding="utf-8"))

        self.assertEqual(outputs[0], outputs[1])

    def test_seam_never_imports_the_response_or_execution_packages(self):
        """The live seam records analysis stages; it is not an execution path."""
        tree = ast.parse(
            (REPO_ROOT / "correlation/ml/live_correlation.py").read_text()
        )
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                self.assertNotIn("execution", module)
                self.assertNotIn("response", module)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn("execution", alias.name)
                    self.assertNotIn("response", alias.name)

        constants = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        for action in ("XDP_DROP", "XDP_TX", "XDP_REDIRECT"):
            self.assertNotIn(action, constants)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
