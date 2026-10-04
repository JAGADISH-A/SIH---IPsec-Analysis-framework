"""Gemini integration tests.

Two things are being defended here, and they are different:

1. **The provider works and fails honestly.** Success, missing key, timeout,
   network error, rate limit, malformed body, blocked response. No test in this
   file touches the network: a fake client is injected, so the normal suite runs
   with no Gemini key and no network.

2. **The context boundary holds.** That is the test that matters most. A
   language model must never receive the whole assessment, so
   :class:`TestContextBoundary` builds a :class:`GroundingContext` deliberately
   loaded with values that must NOT reach Gemini -- a dataset id, an internal
   finding id, a rule id, custody steps, the expected and observed
   configuration maps -- and asserts none of them appear in the serialized
   payload.

   Whitelisted authoritative verdicts are the opposite case and are asserted
   just as hard: the declared asset criticality, the recorded root cause, the
   recorded drift comparison and the recorded ML traffic profile are *supposed*
   to reach Gemini, and each is checked to arrive with the value the
   deterministic backend recorded. A boundary test only means something if the
   fixtures use the same shape the backend actually produces -- see
   :class:`TestWhitelistedVerdictsArriveIntact`, which exists because a
   flat-shaped asset fixture once made the criticality assertion pass for the
   wrong reason.

The boundary is also asserted structurally (exact key set, exact finding keys)
rather than only by substring search, so adding a new field to the context model
cannot silently widen what is sent.
"""

from __future__ import annotations

import json
import unittest

from correlation.ai.gemini import (
    SYSTEM_INSTRUCTION,
    GeminiProvider,
    build_gemini_messages,
    gemini_provider_from_env,
)
from correlation.ai.gemini_context import (
    MAX_CHANGED_VARIABLES,
    MAX_COMPARISON_ROWS,
    build_gemini_context,
    context_keys,
)
from correlation.ai.llm import ProviderError, provider_from_env
from correlation.ai.models import (
    GroundedComparison,
    GroundedCustody,
    GroundedDrift,
    GroundedFinding,
    GroundedMl,
    GroundingContext,
    ANSWER_ORIGIN_TEMPLATE,
)

# A real recorded assessment, used where the engine must read the live store
# rather than a synthetic context.
RECORDED_ASSESSMENT_ID = "dataset-20260924-003710:16:tunnel-v6"

# The mission context exactly as ``AssessmentStore.chain_of_custody`` publishes
# it: criticality lives under ``profile``, contextualised risk under ``risk``.
# Reproduced from ``configs/mission/asset_mission_profiles.json`` (``gw-b``).
RECORDED_MISSION_CONTEXT = {
    "status": "configured",
    "configured": True,
    "asset_id": "gw-b",
    "profile": {
        "criticality": "high",
        "role": "operational-communications",
        "mission_impact": "carries live operational traffic",
    },
    "risk": {
        "technical_risk": 18.0,
        "technical_severity": "MEDIUM",
        "contextualized_risk": 90.0,
        "contextualized_severity": "HIGH",
        "context_index": 5.0,
    },
    "context_source": "declared-mission-profile",
}


def make_context(**overrides) -> GroundingContext:
    """A context carrying both sentinel values and genuinely recorded verdicts.

    The sentinel values mark fields the whitelist must never reflect. The
    verdict values -- asset criticality, drift, ML -- are the opposite: they are
    deliberately whitelisted, so they use realistic values and are asserted to
    arrive intact by :class:`TestWhitelistedVerdictsArriveIntact`.

    ``asset`` deliberately uses the *nested* production shape the store emits
    (``{"profile": {"criticality": ...}}``). A flat ``{"criticality": ...}``
    fixture is silently ignored by :func:`_asset_block`, which once made the
    boundary assertion pass for the wrong reason; see
    :meth:`TestWhitelistedVerdictsArriveIntact.test_the_asset_fixture_uses_the_shape_the_store_actually_emits`.
    """
    base = dict(
        available=True,
        assessment_id="ASSESSMENT-ID-MUST-NOT-LEAK",
        scenario="SCENARIO-MUST-NOT-LEAK",
        dataset_run_id="DATASET-RUN-MUST-NOT-LEAK",
        severity="MEDIUM",
        risk_score=18,
        risk_policy_version="risk-policy-v1",
        risk_engine_version="risk-engine-v9",
        finding=GroundedFinding(
            finding_id="FINDING-ID-MUST-NOT-LEAK",
            rule_id="RULE-ID-MUST-NOT-LEAK",
            category="CONFIGURATION_WEAKNESS",
            severity="MEDIUM",
            title="Weak ESP cipher family",
            description="The configured cipher is in the CBC family.",
            reason="Expected esp.encryption is in the CBC family.",
            condition="esp.encryption in ('aes128cbc','aes256cbc')",
            source="configuration",
            related_variable="esp.encryption",
        ),
        expected={"esp.encryption": "aes256cbc", "ike.dh": "modp2048"},
        observed={"packets_seen": 1234, "esp_seen": True},
        comparisons=(
            GroundedComparison(
                variable="esp.encryption",
                status="UNKNOWN",
                expected_value="aes256cbc",
                observed_value=None,
                reason="the observed algorithms are not observable on the wire",
            ),
        ),
        evidence_sources=("artifact://run/evidence/1",),
        evidence_count=1,
        custody=GroundedCustody(
            available=True,
            stages=("STEP-MUST-NOT-LEAK",),
            facts=("CUSTODY-FACT-MUST-NOT-LEAK",),
            integrity_statuses=("sealed",),
        ),
        drift=GroundedDrift(
            configured=True,
            status="drift",
            reason="2 recorded variables differ from the validated baseline",
            changed_variables=("esp.presence", "ah.presence"),
            baseline_id="baseline-lab-20260919",
        ),
        ml=GroundedMl(
            present=True,
            traffic_class="video",
            classification_confidence=0.91,
            model_version="traffic_rf_v1",
        ),
        asset=RECORDED_MISSION_CONTEXT,
    )
    base.update(overrides)
    return GroundingContext(**base)


class FakeResponse:
    def __init__(self, text=None, finish_reason=None, candidates=None):
        self.text = text
        self.finish_reason = finish_reason
        self.candidates = candidates or []


class FakeModels:
    def __init__(self, *, response=None, error=None):
        self._response = response
        self._error = error
        self.calls = []

    def generate_content(self, *, model, contents, config):
        self.calls.append({"model": model, "contents": contents, "config": config})
        if self._error is not None:
            raise self._error
        return self._response


class FakeClient:
    def __init__(self, models):
        self.models = models


class _RaisingClient:
    """A Gemini client whose every call fails the same way.

    Used to test the engine's degradation path without a network, a key or a
    retry loop.
    """

    def __init__(self, error):
        self.models = FakeModels(error=error)


def _ApiError(code: int, message: str) -> Exception:
    """Build the SDK's own error type so classification is exercised."""
    from google.genai.errors import ClientError

    return ClientError(code, {"error": {"message": message}}, None)


def _scope():
    from correlation.ai.scope import classify

    return classify("Why is this MEDIUM?", has_context=True, has_finding=True)


def make_provider(**kwargs):
    defaults = dict(model="gemini-3.8-flash", api_key="test-key-not-real")
    defaults.update(kwargs)
    return GeminiProvider(**defaults)


def run_complete(provider, question="Why is this MEDIUM?", context=None):
    context = context if context is not None else make_context()
    messages = provider.build_messages(question, context, None)
    return provider.complete(messages)


# ---------------------------------------------------------------- provider ---


class TestGeminiSuccess(unittest.TestCase):
    def test_a_successful_call_returns_the_generated_text(self):
        models = FakeModels(response=FakeResponse(text="The backend recorded MEDIUM."))
        provider = make_provider(client=FakeClient(models))
        self.assertEqual(
            run_complete(provider), "The backend recorded MEDIUM."
        )

    def test_the_model_name_is_sent_and_reported(self):
        models = FakeModels(response=FakeResponse(text="ok"))
        provider = make_provider(client=FakeClient(models))
        run_complete(provider)
        self.assertEqual(models.calls[0]["model"], "gemini-3.8-flash")
        self.assertEqual(provider.info.provider, "gemini")
        self.assertEqual(provider.info.model_version, "gemini-3.8-flash")

    def test_the_system_instruction_is_the_reasoning_layer_instruction(self):
        models = FakeModels(response=FakeResponse(text="ok"))
        provider = make_provider(client=FakeClient(models))
        messages = provider.build_messages("Why?", make_context(), _scope())
        self.assertEqual(messages[0]["role"], "system")
        self.assertEqual(messages[0]["content"], SYSTEM_INSTRUCTION)
        run_complete(provider, question="Why?", context=make_context())
        self.assertEqual(
            models.calls[0]["config"]["system_instruction"].strip(),
            SYSTEM_INSTRUCTION.strip(),
        )

    def test_a_candidates_only_response_is_still_read(self):
        part = type("Part", (), {"text": "From candidates"})()
        content = type("Content", (), {"parts": [part]})()
        candidate = type("Candidate", (), {"content": content})()
        models = FakeModels(response=FakeResponse(candidates=[candidate]))
        provider = make_provider(client=FakeClient(models))
        self.assertEqual(run_complete(provider), "From candidates")

    def test_history_is_sent_for_follow_up_phrasing(self):
        models = FakeModels(response=FakeResponse(text="ok"))
        provider = make_provider(client=FakeClient(models))
        messages = provider.build_messages(
            "And why here?",
            make_context(),
            None,
            history=[{"role": "user", "content": "first"},
                     {"role": "assistant", "content": "answer"}],
        )
        contents = models.calls[0]["contents"] if run_complete(provider) else None
        self.assertTrue(any(m["role"] == "assistant" for m in messages))

    def test_assistant_history_is_mapped_to_the_model_role(self):
        models = FakeModels(response=FakeResponse(text="ok"))
        provider = make_provider(client=FakeClient(models))
        provider.complete(
            [{"role": "system", "content": "s"},
             {"role": "user", "content": "u"},
             {"role": "assistant", "content": "a"}]
        )
        roles = [c["role"] for c in models.calls[0]["contents"]]
        self.assertEqual(roles, ["user", "model"])


class TestGeminiFailure(unittest.TestCase):
    """No failure may produce an invented answer."""

    def test_missing_api_key_raises_rather_than_pretending(self):
        provider = GeminiProvider(model="gemini-3.8-flash", api_key=None)
        self.assertFalse(provider.info.configured)
        with self.assertRaises(ProviderError):
            run_complete(provider)

    def test_missing_key_is_reported_honestly_in_info(self):
        provider = GeminiProvider(model="gemini-3.8-flash", api_key=None)
        self.assertIn("GEMINI_API_KEY", provider.info.reason or "")

    def test_timeout_raises_a_timeout_reason(self):
        models = FakeModels(error=TimeoutError("deadline exceeded"))
        provider = make_provider(client=FakeClient(models))
        with self.assertRaises(ProviderError) as caught:
            run_complete(provider)
        self.assertIn("in time", caught.exception.reason)

    def test_network_failure_raises(self):
        models = FakeModels(error=ConnectionError("connection reset"))
        provider = make_provider(client=FakeClient(models))
        with self.assertRaises(ProviderError) as caught:
            run_complete(provider)
        self.assertIn("could not be reached", caught.exception.reason)

    def test_rate_limit_raises(self):
        class RateLimitError(Exception):
            pass

        models = FakeModels(error=RateLimitError("429 quota exceeded"))
        provider = make_provider(
            client=FakeClient(models), max_attempts=1, retry_backoff_seconds=0.0
        )
        with self.assertRaises(ProviderError) as caught:
            run_complete(provider)
        self.assertIn("rate limit", caught.exception.reason)

    def test_credential_rejection_raises_without_leaking_the_key(self):
        class PermissionDenied(Exception):
            pass

        provider = make_provider(api_key="super-secret-key-value")
        models = FakeModels(error=PermissionDenied("API key not valid: super-secret-key-value"))
        with self.assertRaises(ProviderError) as caught:
            run_complete(make_provider(client=FakeClient(models), api_key="super-secret-key-value"))
        self.assertNotIn("super-secret-key-value", caught.exception.reason)

    def test_malformed_empty_response_raises(self):
        provider = make_provider(client=FakeClient(FakeModels(response=FakeResponse(text="   "))))
        with self.assertRaises(ProviderError) as caught:
            run_complete(provider)
        self.assertIn("empty response", caught.exception.reason)

    def test_blocked_response_raises(self):
        provider = make_provider(
            client=FakeClient(FakeModels(response=FakeResponse(finish_reason="SAFETY")))
        )
        with self.assertRaises(ProviderError) as caught:
            run_complete(provider)
        self.assertIn("empty response", caught.exception.reason)

    def test_a_none_response_raises(self):
        provider = make_provider(client=FakeClient(FakeModels(response=None)))
        with self.assertRaises(ProviderError):
            run_complete(provider)

    def test_no_exception_message_ever_contains_the_api_key(self):
        """Whatever Gemini raises, the reason we surface must not carry the key."""
        secret = "sk-do-not-leak-this-value"

        class Hostile(Exception):
            pass

        class PermissionDenied(Exception):
            pass

        for error in (
            TimeoutError(f"timeout {secret}"),
            ConnectionError(f"conn {secret}"),
            Hostile(f"boom {secret}"),
            PermissionDenied(f"denied {secret}"),
        ):
            models = FakeModels(error=error)
            provider = make_provider(client=FakeClient(models), api_key=secret)
            try:
                run_complete(provider)
            except ProviderError as exc:
                self.assertNotIn(secret, exc.reason, msg=repr(error))
            else:
                self.fail("expected ProviderError")

    def test_info_never_exposes_the_key(self):
        provider = make_provider(api_key="sk-do-not-leak-this-value")
        self.assertNotIn("sk-do-not-leak", json.dumps(provider.info.to_dict()))
        self.assertTrue(provider.info.detail["authenticated"])

    def test_no_question_raises_rather_than_sending_an_empty_call(self):
        provider = make_provider(client=FakeClient(FakeModels(response=FakeResponse(text="x"))))
        with self.assertRaises(ProviderError):
            provider.complete([{"role": "system", "content": "s"}])


# ---------------------------------------------------------- context boundary ---


class TestContextBoundary(unittest.TestCase):
    """Only whitelisted fields may reach Gemini.

    ``MUST_NOT_APPEAR`` now lists only what is genuinely excluded: internal
    identifiers, the custody chain and the raw expected/observed maps. Asset
    criticality, drift and the ML traffic profile used to appear here, which was
    wrong twice over -- they are deliberately whitelisted, and the asset fixture
    did not have the shape ``_asset_block`` reads, so the assertion was passing
    for the wrong reason. They are asserted positively in
    :class:`TestWhitelistedVerdictsArriveIntact` instead.
    """

    MUST_NOT_APPEAR = (
        "ASSESSMENT-ID-MUST-NOT-LEAK",
        "SCENARIO-MUST-NOT-LEAK",
        "DATASET-RUN-MUST-NOT-LEAK",
        "FINDING-ID-MUST-NOT-LEAK",
        "RULE-ID-MUST-NOT-LEAK",
        "CUSTODY-FACT-MUST-NOT-LEAK",
        "STEP-MUST-NOT-LEAK",
        "risk-engine-v9",
        "modp2048",
        "packets_seen",
    )

    def test_the_payload_is_exactly_the_whitelist(self):
        payload = build_gemini_context(make_context())
        self.assertEqual(sorted(payload), sorted(context_keys()))

    def test_no_full_object_serialization_leaks_any_forbidden_value(self):
        """The single most important assertion in this file.

        Building the payload must not reflect any field the whitelist does not
        name, so none of the deliberately-planted sentinel values may appear.
        """
        payload = json.dumps(build_gemini_context(make_context()))
        for secret in self.MUST_NOT_APPEAR:
            self.assertNotIn(secret, payload, msg=f"{secret} reached Gemini")

    def test_the_finding_block_carries_only_named_fields(self):
        finding = build_gemini_context(make_context())["finding"]
        self.assertEqual(
            sorted(finding),
            ["category", "condition", "description", "reason", "severity",
             "source", "title"],
        )

    def test_the_assessment_block_is_only_severity_score_and_policy(self):
        assessment = build_gemini_context(make_context())["assessment"]
        self.assertEqual(
            sorted(assessment), ["risk_policy_version", "risk_score", "severity"]
        )

    def test_authority_values_from_the_backend_are_present_and_unchanged(self):
        payload = build_gemini_context(make_context())
        self.assertEqual(payload["assessment"]["severity"], "MEDIUM")
        self.assertEqual(payload["assessment"]["risk_score"], 18.0)
        self.assertEqual(payload["finding"]["severity"], "MEDIUM")

    def test_the_messages_carry_no_forbidden_value(self):
        """The check that covers the real call, not just the helper."""
        models = FakeModels(response=FakeResponse(text="ok"))
        provider = make_provider(client=FakeClient(models))
        run_complete(provider)
        blob = json.dumps(models.calls[0]["contents"])
        for secret in self.MUST_NOT_APPEAR:
            self.assertNotIn(secret, blob, msg=f"{secret} reached Gemini")

    def test_the_gemini_payload_is_far_smaller_than_the_full_context(self):
        """A volume check: the model gets a summary, not the assessment."""
        from correlation.ai.prompt import render_context

        context = make_context()
        gemini_size = len(json.dumps(build_gemini_context(context)))
        full_size = len(render_context(context))
        self.assertLess(gemini_size, full_size)

    def test_comparisons_are_capped(self):
        many = tuple(
            GroundedComparison(variable=f"var.{i}", status="MATCH",
                               expected_value="e", observed_value="o")
            for i in range(50)
        )
        payload = build_gemini_context(make_context(comparisons=many))
        self.assertLessEqual(len(payload["recorded_comparisons"]), MAX_COMPARISON_ROWS)

    def test_non_string_values_are_dropped_not_reflected(self):
        finding = GroundedFinding(
            finding_id="x", rule_id="r", category="c", severity="MEDIUM",
            title="t", description="d", reason="re", condition="co",
            source="s", expected_value={"secret": "NESTED-OBJECT-MUST-NOT-LEAK"},
        )
        payload = build_gemini_context(make_context(finding=finding))
        self.assertNotIn("NESTED-OBJECT-MUST-NOT-LEAK", json.dumps(payload))

    def test_an_unavailable_context_sends_no_values_at_all(self):
        payload = build_gemini_context(
            GroundingContext(available=False, reason="not in the recorded store")
        )
        self.assertFalse(payload["available"])
        self.assertIsNone(payload["finding"])
        self.assertIsNone(payload["assessment"])
        self.assertEqual(payload["key_factors"], [])
        self.assertEqual(payload["evidence_summary"], [])
        for key in ("asset", "root_cause", "drift", "traffic_profile"):
            self.assertIsNone(payload[key], msg=f"{key} leaked from an unavailable context")


class TestWhitelistedVerdictsArriveIntact(unittest.TestCase):
    """The four authoritative verdicts Gemini *is* allowed to be told.

    The complement of :class:`TestContextBoundary`. Each verdict is copied from
    the deterministic backend and must arrive with the value the backend
    recorded -- never softened, never recalculated, and never invented when the
    backend recorded nothing.

    Every test here is paired with a negative twin that removes the value from
    the source, so an implementation that simply omitted the field could not
    satisfy them.
    """

    def test_the_asset_fixture_uses_the_shape_the_store_actually_emits(self):
        """Guards the regression that made the old boundary test vacuous.

        ``_asset_block`` reads ``asset["profile"]["criticality"]``. A flat
        ``{"criticality": ...}`` fixture produces an empty block and a green
        assertion, which is exactly how this test was passing while the value
        was in fact being sent.
        """
        asset = make_context().asset
        self.assertIn("profile", asset)
        self.assertIn("criticality", asset["profile"])
        self.assertEqual(asset["profile"]["criticality"], "high")

    def test_the_declared_criticality_reaches_the_payload(self):
        asset = build_gemini_context(make_context())["asset"]
        self.assertEqual(asset["asset_id"], "gw-b")
        self.assertIs(asset["configured"], True)
        self.assertEqual(asset["criticality"], "high")

    def test_the_criticality_is_read_from_the_profile_and_not_invented(self):
        """Negative twin: drop the value at the source and it must disappear.

        If ``_asset_block`` defaulted or inferred a criticality, this would
        still produce a value and the assertion below would fail.
        """
        stored = {key: value for key, value in RECORDED_MISSION_CONTEXT.items()
                  if key != "profile"}
        stored["profile"] = {"role": "operational-communications"}
        asset = build_gemini_context(make_context(asset=stored))["asset"]
        self.assertNotIn("criticality", asset)

    def test_a_flat_asset_shape_yields_no_criticality_rather_than_a_guess(self):
        """The exact shape that used to make the boundary assertion vacuous."""
        asset = build_gemini_context(make_context(asset={"criticality": "high"}))["asset"]
        self.assertNotIn("criticality", asset)

    def test_an_undeclared_asset_is_absent_never_not_critical(self):
        self.assertIsNone(build_gemini_context(make_context(asset=None))["asset"])

    def test_the_asset_block_carries_only_named_fields(self):
        asset = build_gemini_context(make_context())["asset"]
        self.assertEqual(
            sorted(asset),
            ["asset_id", "configured", "context_index", "contextualized_risk",
             "contextualized_severity", "criticality", "mission_impact", "role",
             "technical_risk", "technical_severity"],
        )

    # ------------------------------------------------------------- root cause --

    def test_the_recorded_root_cause_reaches_the_payload_unchanged(self):
        context = make_context(root_cause={
            "root_cause": "AUTHENTICATION_FAILURE",
            "confidence": "high",
            "reason": "the configured PSK did not match the peer",
            "job_status": "COMPLETED",
        })
        self.assertEqual(
            build_gemini_context(context)["root_cause"]["root_cause"],
            "AUTHENTICATION_FAILURE",
        )

    def test_no_recorded_root_cause_is_absent_never_a_guess(self):
        self.assertIsNone(build_gemini_context(make_context(root_cause=None))["root_cause"])

    # ------------------------------------------------------------------ drift --

    def test_a_recorded_drift_reaches_the_payload_with_its_own_words(self):
        drift = build_gemini_context(make_context())["drift"]
        self.assertIs(drift["configured"], True)
        self.assertEqual(drift["status"], "drift")
        self.assertEqual(
            drift["changed_variables"], ["esp.presence", "ah.presence"]
        )
        self.assertEqual(drift["baseline_id"], "baseline-lab-20260919")
        self.assertIn("differ from the validated baseline", drift["reason"])

    def test_a_recorded_no_drift_reaches_the_payload_as_no_drift(self):
        context = make_context(drift=GroundedDrift(
            configured=True, status="no_drift", changed_variables=(),
            baseline_id="baseline-lab-20260919",
            reason="every compared variable is unchanged",
        ))
        drift = build_gemini_context(context)["drift"]
        self.assertEqual(drift["status"], "no_drift")
        self.assertIs(drift["configured"], True)

    def test_an_unconfigured_baseline_can_never_read_as_no_drift(self):
        """``C``: absence of a comparison is not agreement."""
        context = make_context(drift=GroundedDrift(
            configured=False, status="not_configured",
            reason="no validated baseline is configured, so no comparison was performed",
        ))
        drift = build_gemini_context(context)["drift"]
        self.assertIs(drift["configured"], False)
        self.assertEqual(drift["status"], "not_configured")
        self.assertNotEqual(drift["status"], "no_drift")
        # An empty list here would itself read as "no variable changed", which
        # is a claim that requires a comparison to have happened.
        self.assertNotIn("changed_variables", drift)

    def test_an_indeterminate_drift_keeps_its_own_verdict(self):
        context = make_context(drift=GroundedDrift(
            configured=True, status="indeterminate",
            reason="the current observation saw no traffic, so nothing was compared",
        ))
        drift = build_gemini_context(context)["drift"]
        self.assertEqual(drift["status"], "indeterminate")
        self.assertNotEqual(drift["status"], "no_drift")

    def test_an_absent_drift_block_carries_no_status_at_all(self):
        """The status key is absent rather than defaulted, so absence cannot lie."""
        self.assertIsNone(build_gemini_context(make_context(drift=None))["drift"])

    def test_the_drift_block_carries_only_named_fields(self):
        self.assertEqual(
            sorted(build_gemini_context(make_context())["drift"]),
            ["baseline_id", "changed_variables", "configured", "reason", "status"],
        )

    def test_changed_variables_are_capped(self):
        context = make_context(drift=GroundedDrift(
            configured=True, status="drift",
            changed_variables=tuple(f"var.{i}" for i in range(50)),
        ))
        drift = build_gemini_context(context)["drift"]
        self.assertLessEqual(len(drift["changed_variables"]), MAX_CHANGED_VARIABLES)

    # --------------------------------------------------------- traffic profile --

    def test_the_recorded_traffic_profile_reaches_the_payload(self):
        profile = build_gemini_context(make_context())["traffic_profile"]
        self.assertIs(profile["present"], True)
        self.assertEqual(profile["traffic_class"], "video")
        self.assertAlmostEqual(profile["classification_confidence"], 0.91)
        self.assertEqual(profile["model_version"], "traffic_rf_v1")

    def test_ml_that_did_not_run_is_never_a_classification(self):
        """``E``: no fabricated traffic class."""
        context = make_context(ml=GroundedMl(
            present=False, reason="ML was not executed for this assessment",
        ))
        profile = build_gemini_context(context)["traffic_profile"]
        self.assertIs(profile["present"], False)
        self.assertNotIn("traffic_class", profile)
        self.assertNotIn("classification_confidence", profile)
        self.assertIn("ML was not executed", profile["reason"])

    def test_a_profile_with_no_recorded_probability_stays_absent(self):
        """Absent is not ``0.0``: the nearest-centroid path records no probability."""
        context = make_context(ml=GroundedMl(
            present=True, traffic_class="web", model_version="nearest_centroid_v1",
        ))
        profile = build_gemini_context(context)["traffic_profile"]
        self.assertEqual(profile["traffic_class"], "web")
        self.assertNotIn("classification_confidence", profile)

    def test_an_absent_ml_block_carries_no_presence_flag(self):
        self.assertIsNone(build_gemini_context(make_context(ml=None))["traffic_profile"])

    def test_the_traffic_profile_block_carries_only_named_fields(self):
        self.assertEqual(
            sorted(build_gemini_context(make_context())["traffic_profile"]),
            ["classification_confidence", "model_version", "present", "traffic_class"],
        )

    # -------------------------------------------------- reaches the real call --

    def test_every_verdict_reaches_the_messages_the_model_is_shown(self):
        """The check that covers the real call, not just the helper."""
        models = FakeModels(response=FakeResponse(text="ok"))
        provider = make_provider(client=FakeClient(models))
        run_complete(provider)
        blob = json.dumps(models.calls[0]["contents"])
        for recorded in ("high", "gw-b", "drift", "esp.presence",
                         "baseline-lab-20260919", "video", "traffic_rf_v1"):
            self.assertIn(recorded, blob, msg=f"{recorded} did not reach Gemini")
        for secret in TestContextBoundary.MUST_NOT_APPEAR:
            self.assertNotIn(secret, blob, msg=f"{secret} reached Gemini")


# ------------------------------------------------------------ configuration ---


class TestGeminiConfiguration(unittest.TestCase):
    def test_env_configures_gemini(self):
        provider = gemini_provider_from_env(
            {"GEMINI_API_KEY": "k", "GEMINI_MODEL": "gemini-2.5-pro"}
        )
        self.assertIsNotNone(provider)
        self.assertEqual(provider.info.provider, "gemini")
        self.assertEqual(provider.info.model_version, "gemini-2.5-pro")

    def test_absent_key_configures_nothing(self):
        self.assertIsNone(gemini_provider_from_env({}))

    def test_a_default_model_is_used_when_only_a_key_is_set(self):
        provider = gemini_provider_from_env({"GEMINI_API_KEY": "k"})
        self.assertTrue(provider.info.configured)

    def test_gemini_is_selected_over_the_openai_compatible_path(self):
        provider = provider_from_env(
            {"GEMINI_API_KEY": "k", "GEMINI_MODEL": "gemini-3.8-flash",
             "ANALYTICS_AI_BASE_URL": "http://localhost:9/v1", "ANALYTICS_AI_MODEL": "other"}
        )
        self.assertEqual(provider.info.provider, "gemini")

    def test_the_openai_compatible_path_still_works_without_gemini(self):
        provider = provider_from_env(
            {"ANALYTICS_AI_BASE_URL": "http://localhost:9/v1", "ANALYTICS_AI_MODEL": "m"}
        )
        self.assertEqual(provider.info.provider, "openai-compatible")

    def test_no_configuration_is_the_working_default(self):
        self.assertEqual(provider_from_env({}).info.provider, "none")

    def test_the_base_providers_still_build_the_full_context(self):
        """The default provider contract is unchanged, so nothing else moved."""
        from correlation.ai.llm import NullProvider

        from correlation.ai.scope import classify

        scope = classify("Why is this MEDIUM?", has_context=True, has_finding=True)
        messages = NullProvider().build_messages("Why?", make_context(), scope)
        blob = json.dumps(messages)
        self.assertIn("ASSESSMENT-ID-MUST-NOT-LEAK", blob)


if __name__ == "__main__":
    unittest.main()

class TestEngineReportsProviderDegradation(unittest.TestCase):
    """A failed model call must never look like a model answered.

    The analyst has to be able to distinguish "Gemini said this" from "Gemini
    was unavailable, so the recorded values are being explained without it".
    """

    def _engine(self, error):
        from correlation.ai.context import StoreContextSource
        from correlation.ai.engine import AiExplanationEngine
        from correlation.ai.gemini import GeminiProvider
        from correlation.api.store import build_store

        provider = GeminiProvider(
            model="gemini-3.8-flash",
            api_key="k",
            max_attempts=1,
            retry_backoff_seconds=0.0,
        )
        provider._client = _RaisingClient(error)
        return AiExplanationEngine(StoreContextSource(build_store()), provider)

    def _ask(self, error):
        return self._engine(error).explain(
            "Why is this HIGH?",
            assessment_id=RECORDED_ASSESSMENT_ID,
            finding_id="RISK-WEAK-ESP-CRYPTO",
        )

    def _no_model(self):
        """The same question with no model at all, for comparison."""
        from correlation.ai.context import StoreContextSource
        from correlation.ai.engine import AiExplanationEngine
        from correlation.ai.llm import NullProvider
        from correlation.api.store import build_store

        return AiExplanationEngine(
            StoreContextSource(build_store()), NullProvider()
        ).explain(
            "Why is this HIGH?",
            assessment_id=RECORDED_ASSESSMENT_ID,
            finding_id="RISK-WEAK-ESP-CRYPTO",
        )

    def test_credential_failure_is_named(self):
        answer = self._ask(_ApiError(400, "API key not valid"))
        self.assertEqual(answer.origin, ANSWER_ORIGIN_TEMPLATE)
        self.assertEqual(answer.provider, "none")
        self.assertIsNotNone(answer.provider_unavailable_reason)
        self.assertIn("credential", answer.provider_unavailable_reason)

    def test_the_recorded_assessment_survives_the_failure(self):
        answer = self._ask(_ApiError(400, "API key not valid"))
        baseline = self._no_model()
        self.assertEqual(answer.answer, baseline.answer)
        self.assertEqual(answer.authoritative, baseline.authoritative)
        self.assertEqual(answer.citations, baseline.citations)
        # A failed model must not leave a version string implying it answered.
        self.assertIsNone(answer.model_version)
        self.assertEqual(
            baseline.authoritative.get("severity"),
            baseline.authoritative.get("severity"),
        )

    def test_timeout_is_named(self):
        answer = self._ask(TimeoutError("read timed out"))
        self.assertIn("did not respond", answer.provider_unavailable_reason.lower())
        self.assertEqual(answer.authoritative, self._no_model().authoritative)

    def test_rate_limit_is_named(self):
        answer = self._ask(_ApiError(429, "quota exceeded"))
        self.assertIsNotNone(answer.provider_unavailable_reason)
        self.assertEqual(answer.authoritative, self._no_model().authoritative)

    def test_the_failure_reason_never_contains_the_key(self):
        """A key is a secret even when the provider echoes it back in an error."""
        secret = "AIzaSy-THIS-IS-NOT-A-REAL-KEY-1234"
        provider = self._engine(_ApiError(400, "API key not valid: " + secret))
        provider._provider._api_key = secret
        answer = provider.explain(
            "Why is this HIGH?",
            assessment_id=RECORDED_ASSESSMENT_ID,
            finding_id="RISK-WEAK-ESP-CRYPTO",
        )
        reason = answer.provider_unavailable_reason or ""
        self.assertNotIn(secret, reason)
        self.assertNotIn(secret, answer.answer)
        self.assertNotIn("AIza", reason)

    def test_a_configured_timeout_reaches_the_sdk_client(self):
        from correlation.ai.gemini import GeminiProvider

        provider = GeminiProvider(
            model="gemini-3.8-flash", api_key="k", timeout=7.0
        )
        client = provider._build_client()
        self.assertEqual(
            client._api_client._http_options.timeout, 7000
        )


class TestTransientCapacityIsRetried(unittest.TestCase):
    """Gemini's flash endpoint intermittently answers 500/UNAVAILABLE.

    Those clear in seconds, so a single failure would drop the assistant to the
    deterministic template and tell the analyst the model was unavailable when
    the truth was a momentary shortage of capacity. A wrong request (400/401/
    403) must not be retried, or the assistant would stall instead of
    reporting the problem.
    """

    class _Flaky:
        """Fails with a chosen error `times` times, then succeeds."""

        def __init__(self, error, times):
            self._error = error
            self._remaining = times
            self.attempts = 0
            self.models = self

        def generate_content(self, *, model, contents, config):
            self.attempts += 1
            if self._remaining > 0:
                self._remaining -= 1
                raise self._error
            return FakeResponse(text="the explanation")

    def _provider(self, error, times):
        from correlation.ai.gemini import GeminiProvider

        flaky = self._Flaky(error, times)
        return (
            GeminiProvider(
                model="gemini-3.8-flash",
                api_key="k",
                client=flaky,
                retry_backoff_seconds=0.0,
            ),
            flaky,
        )

    def _messages(self):
        return [{"role": "user", "content": "why?"}]

    def _server_error(self):
        from google.genai.errors import ServerError

        return ServerError(503, {"error": {"message": "backend overloaded"}}, None)

    def _bad_request(self):
        from google.genai.errors import ClientError

        return ClientError(400, {"error": {"message": "bad request"}}, None)

    def test_a_transient_failure_is_retried_and_then_succeeds(self):
        provider, flaky = self._provider(self._server_error(), times=2)
        out = provider.complete(self._messages())
        self.assertEqual(out, "the explanation")
        self.assertEqual(flaky.attempts, 3)

    def test_a_bad_request_is_not_retried(self):
        provider, flaky = self._provider(self._bad_request(), times=5)
        with self.assertRaises(ProviderError):
            provider.complete(self._messages())
        self.assertEqual(flaky.attempts, 1)

    def test_retries_are_bounded_and_the_reason_is_honest(self):
        provider, flaky = self._provider(self._server_error(), times=99)
        with self.assertRaises(ProviderError) as caught:
            provider.complete(self._messages())
        self.assertEqual(flaky.attempts, 3)
        self.assertIn("error", caught.exception.reason)

    def test_transient_detection_matches_the_sdk_statuses(self):
        from correlation.ai.gemini import _is_transient

        self.assertTrue(_is_transient(self._server_error()))
        self.assertFalse(_is_transient(self._bad_request()))
        self.assertFalse(_is_transient(ValueError("nope")))

    def test_the_default_attempt_count_is_bounded(self):
        from correlation.ai.gemini import DEFAULT_MAX_ATTEMPTS

        self.assertGreaterEqual(DEFAULT_MAX_ATTEMPTS, 2)
        self.assertLessEqual(DEFAULT_MAX_ATTEMPTS, 5)


class TestTruncatedAnswersAreRefused(unittest.TestCase):
    """A response cut off mid-sentence is not an explanation.

    ``gemini-3.8-flash`` is a thinking model: its reasoning tokens come out of
    the same output budget as the answer, so a cap that is too small produces
    text that starts normally and stops in the middle of a bullet. ``.text`` is
    non-empty in that case, so a naive extraction would publish a fragment as
    though it were complete.
    """

    def test_max_tokens_finish_reason_is_refused(self):
        from correlation.ai.gemini import GeminiProvider

        class _Candidate:
            finish_reason = "MAX_TOKENS"

        response = FakeResponse(
            text="* **Primary driver: an address_family mismatch", candidates=[_Candidate()]
        )
        provider = make_provider(client=FakeClient(FakeModels(response=response)))
        with self.assertRaises(ProviderError) as caught:
            run_complete(provider)
        self.assertIn("output budget", caught.exception.reason)

    def test_a_finished_response_is_accepted(self):
        from correlation.ai.gemini import GeminiProvider

        class _Candidate:
            finish_reason = "STOP"

        response = FakeResponse(text="a complete explanation", candidates=[_Candidate()])
        provider = make_provider(client=FakeClient(FakeModels(response=response)))
        self.assertEqual(run_complete(provider), "a complete explanation")

    def test_the_default_budget_leaves_room_for_thinking(self):
        from correlation.ai.gemini import DEFAULT_MAX_TOKENS

        self.assertGreaterEqual(DEFAULT_MAX_TOKENS, 2048)
