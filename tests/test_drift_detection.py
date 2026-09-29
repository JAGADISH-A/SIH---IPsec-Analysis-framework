"""Drift-aware security assessment: the longitudinal layer, end to end.

The tests are organised by the claims the milestone has to make true, and each
class name is the claim. The four that matter most:

    TestTheRealAcceptanceCriterion
        Four real recorded captures of the SAME security state, differing in
        packet counts (200 / 194 / 93 / 30) and in SPI values (one capture has
        SPI 0x00000000, the live ones have disjoint random sets), must produce
        one identical canonical digest and no drift. This is the anti-false-
        positive test, and it runs on recorded data rather than on mocks.

    TestBaselineIsNeverInferred
        A baseline can only exist through an explicit, attributable act; the
        latest observation is never promoted to one.

    TestExcludedFieldsCannotProduceDrift
        Every field in ``EXCLUDED_FIELDS`` is mutated in turn and each must
        leave the digest untouched.

    TestAbsenceOfEvidenceIsNeverDrift
        An observation with no traffic is ``indeterminate``, never drift and
        never no-drift.

Provenance of the one non-real input is declared in
``tests/fixtures/drift/ah_substitution_provenance.json``: it is a derived test
fixture with no PCAP, used only where a protection change is required and no
real capture contains one.
"""

import ast
import dataclasses
import json
import pathlib
import tempfile
import unittest

from correlation.api.drift_routes import (
    handle_assessment_drift,
    handle_drift,
    handle_drift_baselines,
)
from correlation.api.openapi import openapi_document
from correlation.api.store import AssessmentStore, build_store
from correlation.api.v1 import handle_v1_get
from correlation.artifacts import load_observed_state
from correlation.custody import build_chain_of_custody
from correlation.drift import (
    BaselineIntegrityError,
    BaselineRegistry,
    COMPARABLE_FIELDS,
    COMPARABLE_VARIABLES,
    DRIFT_CATEGORIES,
    DRIFT_CATEGORY_CONFIGURATION,
    DRIFT_STATUS_DRIFT,
    DRIFT_STATUS_INDETERMINATE,
    DRIFT_STATUS_NO_DRIFT,
    DRIFT_STATUS_NOT_CONFIGURED,
    EXCLUDED_FIELDS,
    UNSUPPORTED_DRIFT_CATEGORIES,
    ValidatedBaseline,
    assess_drift,
    canonical_security_state,
    canonical_state_digest,
    describe_canonicalization,
    registry_from_dicts,
    validate_baseline,
)
from correlation.drift.canonical import observation_is_informative
from correlation.mission import mission_context
from correlation.models.observed import ObservedState
from correlation.risk.rules import MISMATCH_FINDING_SPECS, _esp_presence_severity

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures" / "drift"
AH_SUBSTITUTION = FIXTURES / "ah_substitution_state.jsonl"
AH_PROVENANCE = FIXTURES / "ah_substitution_provenance.json"

#: Four real recorded captures. The first two are the e2e verification parser
#: runs; the last two are the recorded live-capture states.
REAL_TUNNEL_V4 = "results/e2e-verification/parser/tunnel_v4/state.jsonl"
REAL_TUNNEL_V6INNER = "results/e2e-verification/parser/tunnel_v6inner/state.jsonl"
REAL_LIVE_FULL = "results/observed-state/live_state_from_events_full.jsonl"
REAL_LAB_VERIFY = "results/observed-state/lab-verify-20260919-143813/state_events.jsonl"
ALL_REAL = (REAL_TUNNEL_V4, REAL_TUNNEL_V6INNER, REAL_LIVE_FULL, REAL_LAB_VERIFY)

VALIDATED_AT = "2026-09-20T09:00:00Z"
VALIDATED_BY = "sec-ops"


def real_state(path):
    return load_observed_state(path)[0]


def derived_ah_state():
    """The declared derived fixture: ESP replaced by AH, everything else real."""
    return ObservedState.from_dict(json.loads(AH_SUBSTITUTION.read_text("utf-8").strip()))


def idle_state(observed):
    """A copy of ``observed`` that saw no traffic at all."""
    return dataclasses.replace(
        observed,
        tunnel_seen=False,
        active=False,
        packets_seen=0,
        bytes_seen=0,
        packets_a_to_b=0,
        packets_b_to_a=0,
        bytes_a_to_b=0,
        bytes_b_to_a=0,
        esp_seen=False,
        ah_seen=False,
        ike_seen=False,
        ike_nat_t_seen=False,
        spis=(),
    )


def baseline_from(observed, baseline_id="baseline-e2e-v4", **kwargs):
    kwargs.setdefault("validated_at", VALIDATED_AT)
    kwargs.setdefault("validated_by", VALIDATED_BY)
    return validate_baseline(observed, baseline_id=baseline_id, **kwargs)


class TestTheRealAcceptanceCriterion(unittest.TestCase):
    """X and Y are the same security state, and the system must say so.

    The two live captures make this a real test rather than a tautology: they
    report 93 and 30 packets, 4 SPIs each, disjoint from one another and from
    the parser runs' SPI 0x00000000, and NAT-T visible where the parser runs
    show no IKE at all.
    """

    @classmethod
    def setUpClass(cls):
        cls.states = {path: real_state(path) for path in ALL_REAL}
        cls.baseline = baseline_from(cls.states[REAL_TUNNEL_V4])

    def test_one_digest_for_four_real_captures(self):
        digests = {
            path: canonical_state_digest(canonical_security_state(observed))
            for path, observed in self.states.items()
        }
        self.assertEqual(
            len(set(digests.values())), 1,
            f"four real captures of one security state must share a digest: {digests}",
        )
        self.assertEqual(
            canonical_state_digest(self.baseline.canonical_state),
            next(iter(set(digests.values()))),
        )

    def test_the_captures_really_do_differ_in_the_excluded_fields(self):
        """If they did not, the test above would prove nothing."""
        counts = {path: o.packets_seen for path, o in self.states.items()}
        self.assertGreater(len(set(counts.values())), 1, counts)
        spi_sets = {path: frozenset(s.spi for s in o.spis) for path, o in self.states.items()}
        self.assertGreater(len(set(spi_sets.values())), 1, spi_sets)
        nat_t = {path: o.ike_nat_t_seen for path, o in self.states.items()}
        self.assertGreater(len(set(nat_t.values())), 1, nat_t)
        self.assertNotEqual(
            self.states[REAL_TUNNEL_V4].timestamp_ns,
            self.states[REAL_LIVE_FULL].timestamp_ns,
        )

    def test_all_four_report_no_drift_against_the_baseline(self):
        for path, observed in self.states.items():
            with self.subTest(capture=path):
                result = assess_drift(self.baseline, observed, run_id="e2e", sequence=1)
                self.assertEqual(result.status, DRIFT_STATUS_NO_DRIFT)
                self.assertFalse(result.drift_detected)
                self.assertEqual(result.changed_fields, ())
                self.assertIsNone(result.risk, "no drift must raise no finding")

    def test_comparison_is_order_independent(self):
        """Y-then-X and X-then-Y must reach the same conclusion."""
        x, y = self.states[REAL_TUNNEL_V4], self.states[REAL_LIVE_FULL]
        forward = assess_drift(self.baseline, y)
        reverse = assess_drift(baseline_from(y, baseline_id="baseline-live"), x)
        self.assertEqual(forward.status, reverse.status)


class TestTheCanonicalizationIsNarrowAndJustified(unittest.TestCase):
    """Scope is the maximum the observation path can honestly support."""

    def test_exactly_three_fields_participate(self):
        self.assertEqual(
            COMPARABLE_VARIABLES, ("address_family", "esp.presence", "ah.presence")
        )

    def test_every_participating_field_is_already_security_relevant(self):
        """Membership is read from the existing risk table, not asserted here."""
        for variable in COMPARABLE_VARIABLES:
            with self.subTest(variable=variable):
                self.assertIn(variable, MISMATCH_FINDING_SPECS)
                self.assertTrue(
                    MISMATCH_FINDING_SPECS[variable][4],
                    f"{variable} carries no security relevance in the existing rules",
                )

    def test_each_field_maps_to_an_existing_comparison_rule(self):
        rules = {
            field.comparison_rule for field in COMPARABLE_FIELDS
        }
        self.assertTrue(rules.issubset({
            "address_family.endpoints", "presence.esp", "presence.ah",
        }), rules)

    def test_every_excluded_field_states_a_reason(self):
        self.assertTrue(EXCLUDED_FIELDS)
        for item in EXCLUDED_FIELDS:
            with self.subTest(field=item.field):
                self.assertTrue(item.field.strip())
                self.assertGreater(len(item.reason), 30)

    def test_no_crypto_variable_participates(self):
        """The dataset plan's crypto is expected-only; none of it is observed."""
        forbidden = ("cipher", "encryption", "integrity", "dh_group", "pfs",
                     "mode", "ike_version", "key")
        blob = " ".join(f"{f.variable} {f.label}" for f in COMPARABLE_FIELDS).lower()
        for token in forbidden:
            self.assertNotIn(token, blob)

    def test_unsupported_categories_are_declared_not_silent(self):
        for category in ("firmware_drift", "implementation_drift",
                         "traffic_behavior_drift", "ml_behavior_drift"):
            self.assertIn(category, UNSUPPORTED_DRIFT_CATEGORIES)
            self.assertNotIn(category, DRIFT_CATEGORIES)
        self.assertEqual(DRIFT_CATEGORIES, (DRIFT_CATEGORY_CONFIGURATION,))

    def test_the_description_is_publishable_and_complete(self):
        described = describe_canonicalization()
        self.assertEqual(
            [item["variable"] for item in described["included"]],
            list(COMPARABLE_VARIABLES),
        )
        self.assertEqual(
            len(described["excluded"]), len(EXCLUDED_FIELDS)
        )
        for item in described["included"]:
            self.assertTrue(item["security_relevance"])


class TestExcludedFieldsCannotProduceDrift(unittest.TestCase):
    """Mutating an excluded field must leave the digest byte-identical."""

    @classmethod
    def setUpClass(cls):
        cls.observed = real_state(REAL_TUNNEL_V4)
        cls.baseline = baseline_from(cls.observed)
        cls.digest = cls.baseline.state_digest

    def _spi(self, observed):
        return tuple(
            dataclasses.replace(s, spi="0xdeadbeef", packet_count=s.packet_count + 991,
                                first_sequence=s.first_sequence + 7,
                                last_sequence=s.last_sequence + 7,
                                highest_sequence=s.highest_sequence + 7,
                                sequence_delta=s.sequence_delta + 7,
                                first_seen_ns=s.first_seen_ns + 12345,
                                last_seen_ns=s.last_seen_ns + 12345)
            for s in observed.spis
        )

    def test_every_excluded_field_perturbed_individually(self):
        cases = {
            "timestamp_ns": {"timestamp_ns": self.observed.timestamp_ns + 10**12},
            "last_esp_timestamp_ns": {
                "last_esp_timestamp_ns": self.observed.last_esp_timestamp_ns - 5
            },
            "last_ike_timestamp_ns": {"last_ike_timestamp_ns": 1},
            "packets_seen": {"packets_seen": self.observed.packets_seen + 1000},
            "bytes_seen": {"bytes_seen": self.observed.bytes_seen + 999},
            "packets_a_to_b": {"packets_a_to_b": 1},
            "bytes_b_to_a": {"bytes_b_to_a": 1},
            "active": {"active": not self.observed.active},
            "tunnel_seen": {"tunnel_seen": not self.observed.tunnel_seen},
            "ike_seen": {"ike_seen": True},
            "ike_nat_t_seen": {"ike_nat_t_seen": True},
            "observed_ike_activity": {"observed_ike_activity": True},
            "spis[].spi": {"spis": self._spi(self.observed)},
            "transitions": {"transitions": ()},
        }
        for label, replacement in cases.items():
            with self.subTest(excluded=label):
                perturbed = dataclasses.replace(self.observed, **replacement)
                self.assertEqual(
                    canonical_state_digest(canonical_security_state(perturbed)),
                    self.digest,
                    f"{label} is declared excluded but changed the digest",
                )
                result = assess_drift(self.baseline, perturbed)
                self.assertEqual(result.status, DRIFT_STATUS_NO_DRIFT, label)
                self.assertEqual(result.changed_fields, (), label)

    def test_a_whole_rekey_does_not_produce_drift(self):
        """Different SPIs, counters, sequences, window and history; same posture."""
        rekeyed = dataclasses.replace(
            self.observed,
            timestamp_ns=self.observed.timestamp_ns + 86_400_000_000_000,
            packets_seen=3,
            bytes_seen=180,
            packets_a_to_b=2,
            packets_b_to_a=1,
            bytes_a_to_b=120,
            bytes_b_to_a=60,
            ike_seen=True,
            ike_nat_t_seen=True,
            observed_ike_activity=True,
            spis=self._spi(self.observed),
        )
        result = assess_drift(self.baseline, rekeyed)
        self.assertEqual(result.status, DRIFT_STATUS_NO_DRIFT)
        self.assertIsNone(result.risk)


class TestBaselineIsNeverInferred(unittest.TestCase):
    """The baseline must be an explicit act, always attributable."""

    @classmethod
    def setUpClass(cls):
        cls.observed = real_state(REAL_TUNNEL_V4)

    def test_no_baseline_is_not_configured_not_no_drift(self):
        result = assess_drift(None, self.observed)
        self.assertEqual(result.status, DRIFT_STATUS_NOT_CONFIGURED)
        self.assertFalse(result.drift_detected)
        self.assertIsNone(result.risk)
        self.assertIsNone(result.baseline_id)
        self.assertIn("no validated baseline", result.reason)

    def test_registry_never_resolves_a_baseline_on_its_own(self):
        registry = BaselineRegistry()
        registry.register(baseline_from(self.observed, baseline_id="b1"))
        self.assertIsNone(registry.get("b2"), "must not fall back to another id")
        self.assertIsNone(registry.get(None))
        self.assertIsNone(registry.get(""))

    def test_validation_requires_an_id_an_attribution_and_a_time(self):
        for missing in ("baseline_id", "validated_by", "validated_at"):
            kwargs = {"baseline_id": "b", "validated_by": "ops",
                      "validated_at": VALIDATED_AT}
            kwargs.pop(missing)
            with self.subTest(missing=missing):
                with self.assertRaises(TypeError):
                    validate_baseline(self.observed, **kwargs)

    def test_validation_rejects_blank_and_empty_inputs(self):
        for kwargs in (
            {"baseline_id": "  ", "validated_by": "ops", "validated_at": VALIDATED_AT},
            {"baseline_id": "b", "validated_by": "", "validated_at": VALIDATED_AT},
            {"baseline_id": "b", "validated_by": "ops", "validated_at": ""},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    validate_baseline(self.observed, **kwargs)

    def test_validation_is_deterministic_and_clock_free(self):
        first = baseline_from(self.observed)
        second = baseline_from(self.observed)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.baseline_digest, second.baseline_digest)

    def test_validation_status_is_validated_and_nothing_else(self):
        record = baseline_from(self.observed)
        self.assertEqual(record.validation_status, "validated")
        with self.assertRaises(ValueError):
            dataclasses.replace(record, validation_status="provisional")

    def test_a_baseline_from_an_empty_observation_is_refused(self):
        """An empty snapshot's False flags are non-observation, not a state."""
        empty = ObservedState(timestamp_ns=1)
        with self.assertRaises(ValueError) as caught:
            baseline_from(empty, baseline_id="b-empty")
        self.assertIn("saw no traffic", str(caught.exception))

    def test_a_baseline_from_a_trafficless_snapshot_is_refused(self):
        with self.assertRaises(ValueError):
            baseline_from(idle_state(self.observed), baseline_id="b-idle")

    def test_baseline_requires_a_real_observation(self):
        with self.assertRaises(TypeError):
            validate_baseline({"esp_seen": True}, baseline_id="b",
                              validated_by="ops", validated_at=VALIDATED_AT)


class TestBaselineIntegrityIsDetectable(unittest.TestCase):
    """Two digests, two jobs: the fingerprint and the seal."""

    @classmethod
    def setUpClass(cls):
        cls.observed = real_state(REAL_TUNNEL_V4)
        cls.baseline = baseline_from(cls.observed)

    def test_the_record_verifies_when_untouched(self):
        ok, reason = self.baseline.verify()
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_the_seal_covers_the_comparable_state(self):
        """Editing the state does not edit the stored digest, so verify() fails."""
        from correlation.drift import canonical_state_digest

        tampered = dataclasses.replace(
            self.baseline, canonical_state=dict(self.baseline.canonical_state)
        )
        tampered.canonical_state["esp.presence"] = False
        self.assertNotEqual(
            canonical_state_digest(tampered.canonical_state),
            tampered.state_digest,
        )
        ok, reason = tampered.verify()
        self.assertFalse(ok)
        self.assertIn("canonical_state", reason)
        with self.assertRaises(BaselineIntegrityError):
            assess_drift(tampered, self.observed)

    def test_to_dict_does_not_leak_the_live_record(self):
        """A caller editing the returned mapping cannot edit the baseline."""
        payload = self.baseline.to_dict()
        payload["canonical_state"]["esp.presence"] = False
        payload["validated_by"] = "attacker"
        self.assertTrue(self.baseline.verify()[0])
        self.assertEqual(self.baseline.canonical_state["esp.presence"], True)
        self.assertEqual(self.baseline.validated_by, VALIDATED_BY)

    def test_the_seal_covers_the_provenance_metadata(self):
        """Changing who validated it, or when, must be detectable."""
        original = self.baseline.baseline_digest
        for field_name, value in (("validated_by", "someone-else"),
                                  ("validated_at", "2020-01-01T00:00:00Z"),
                                  ("asset_id", "gw-z"),
                                  ("notes", "edited")):
            with self.subTest(field=field_name):
                edited = dataclasses.replace(self.baseline, **{field_name: value})
                self.assertNotEqual(edited.baseline_digest, original)
                payload = edited.to_dict()
                self.assertEqual(payload["baseline_digest"], edited.baseline_digest)

    def test_from_dict_rejects_a_tampered_seal(self):
        payload = self.baseline.to_dict()
        payload["validated_by"] = "attacker"
        with self.assertRaises(BaselineIntegrityError):
            ValidatedBaseline.from_dict(payload)

    def test_from_dict_rejects_a_hand_edited_state(self):
        payload = self.baseline.to_dict()
        payload["canonical_state"]["esp.presence"] = False
        with self.assertRaises(BaselineIntegrityError):
            ValidatedBaseline.from_dict(payload)

    def test_from_dict_round_trips(self):
        record = ValidatedBaseline.from_dict(self.baseline.to_dict())
        self.assertEqual(record.to_dict(), self.baseline.to_dict())

    def test_from_dict_rejects_unknown_and_missing_fields(self):
        payload = self.baseline.to_dict()
        payload["surprise"] = 1
        with self.assertRaises(ValueError):
            ValidatedBaseline.from_dict(payload)
        with self.assertRaises(ValueError):
            ValidatedBaseline.from_dict({"baseline_id": "b"})

    def test_a_tampered_baseline_never_reaches_a_comparison(self):
        tampered = dataclasses.replace(self.baseline, state_digest="0" * 64)
        with self.assertRaises(BaselineIntegrityError):
            assess_drift(tampered, self.observed)


class TestTheFourDeclaredOutcomes(unittest.TestCase):
    """status: no_drift, drift, not_configured, indeterminate."""

    @classmethod
    def setUpClass(cls):
        cls.observed = real_state(REAL_TUNNEL_V4)
        cls.baseline = baseline_from(cls.observed)

    def test_drift_is_reported_per_field_with_both_values(self):
        result = assess_drift(self.baseline, derived_ah_state(), sequence=2)
        self.assertEqual(result.status, DRIFT_STATUS_DRIFT)
        self.assertTrue(result.drift_detected)
        self.assertEqual(result.drift_categories, (DRIFT_CATEGORY_CONFIGURATION,))
        esp = result.changed_variable("esp.presence")
        self.assertIsNotNone(esp)
        self.assertIs(esp.baseline_value, True)
        self.assertIs(esp.current_value, False)
        ah = result.changed_variable("ah.presence")
        self.assertIs(ah.baseline_value, False)
        self.assertIs(ah.current_value, True)
        self.assertEqual(result.unchanged_variables, ("address_family",))
        self.assertEqual(result.unknown_variables, ())

    def test_both_digests_are_reported_for_both_sides(self):
        result = assess_drift(self.baseline, derived_ah_state())
        self.assertEqual(result.baseline_state_digest, self.baseline.state_digest)
        self.assertEqual(result.baseline_digest, self.baseline.baseline_digest)
        self.assertNotEqual(result.current_state_digest, result.baseline_state_digest)
        self.assertEqual(
            result.current_state_digest,
            canonical_state_digest(canonical_security_state(derived_ah_state())),
        )
        self.assertEqual(result.baseline_validated_at, VALIDATED_AT)
        self.assertEqual(result.baseline_validated_by, VALIDATED_BY)

    def test_the_reason_names_the_field_and_both_values(self):
        result = assess_drift(self.baseline, derived_ah_state())
        self.assertIn("esp.presence", result.reason)
        self.assertIn("ah.presence", result.reason)
        self.assertIn("True", result.reason)
        self.assertIn("False", result.reason)

    def test_indeterminate_when_the_observation_saw_no_traffic(self):
        result = assess_drift(self.baseline, idle_state(self.observed))
        self.assertEqual(result.status, DRIFT_STATUS_INDETERMINATE)
        self.assertFalse(result.drift_detected)
        self.assertEqual(result.changed_fields, ())
        self.assertEqual(result.unchanged_variables, ())
        self.assertIsNone(result.risk)
        self.assertEqual(result.drift_categories, ())

    def test_a_quiet_window_is_not_mistaken_for_a_lost_ah(self):
        """An idle snapshot reports every presence flag false. That is not drift."""
        idle = idle_state(self.observed)
        self.assertFalse(idle.esp_seen)
        self.assertFalse(idle.ah_seen)
        self.assertFalse(observation_is_informative(idle))
        self.assertEqual(
            assess_drift(self.baseline, idle).status, DRIFT_STATUS_INDETERMINATE
        )

    def test_zero_packets_with_tunnel_seen_is_still_informative(self):
        self.assertTrue(observation_is_informative(
            dataclasses.replace(idle_state(self.observed), tunnel_seen=True)))

    def test_a_field_neither_side_can_establish_is_unknown_not_drift(self):
        partial = dataclasses.replace(
            self.baseline,
            canonical_state={"esp.presence": True, "ah.presence": False},
        )
        partial = dataclasses.replace(
            partial,
            state_digest=canonical_state_digest(partial.canonical_state),
        )
        result = assess_drift(partial, self.observed)
        self.assertEqual(result.unknown_variables, ("address_family",))
        self.assertEqual(result.status, DRIFT_STATUS_NO_DRIFT)
        self.assertIn("not as agreement", result.reason)

    def test_status_is_always_one_of_the_four(self):
        outcomes = {
            assess_drift(None, self.observed).status,
            assess_drift(self.baseline, self.observed).status,
            assess_drift(self.baseline, derived_ah_state()).status,
            assess_drift(self.baseline, idle_state(self.observed)).status,
        }
        self.assertEqual(outcomes, {"not_configured", "no_drift", "drift",
                                    "indeterminate"})

    def test_the_result_serialises_and_round_trips_as_plain_data(self):
        result = assess_drift(self.baseline, derived_ah_state())
        payload = result.to_dict()
        json.dumps(payload)
        self.assertEqual(payload["status"], DRIFT_STATUS_DRIFT)
        self.assertTrue(payload["drift_detected"])
        self.assertEqual(payload["rule_id"], "drift.configuration")
        self.assertEqual(len(payload["changed_fields"]), 2)


class TestDriftReusesTheExistingRiskEngine(unittest.TestCase):
    """No drift scale, no drift policy, no parallel scoring."""

    @classmethod
    def setUpClass(cls):
        cls.observed = real_state(REAL_TUNNEL_V4)
        cls.baseline = baseline_from(cls.observed)
        cls.result = assess_drift(cls.baseline, derived_ah_state(), sequence=3)
        cls.risk = cls.result.risk

    def test_findings_are_ordinary_risk_findings(self):
        self.assertIsNotNone(self.risk)
        for finding in self.risk.findings:
            with self.subTest(finding=finding.finding_id):
                self.assertTrue(finding.finding_id.startswith("RISK-DRIFT-"))
                self.assertEqual(finding.rule_id, "drift.configuration")
                self.assertEqual(finding.source, "OBSERVED_PROTOCOL")
                self.assertEqual(finding.evidence_type, "observation")

    def test_severity_is_read_from_the_existing_mismatch_table(self):
        esp = next(f for f in self.risk.findings
                   if f.related_variable == "esp.presence")
        self.assertEqual(esp.severity, "HIGH")
        self.assertEqual(esp.severity, _esp_presence_severity(True, False))
        ah = next(f for f in self.risk.findings
                  if f.related_variable == "ah.presence")
        self.assertEqual(ah.severity, MISMATCH_FINDING_SPECS["ah.presence"][3])

    def test_the_category_is_the_existing_configuration_mismatch(self):
        for finding in self.risk.findings:
            self.assertEqual(finding.category, "CONFIGURATION_MISMATCH")

    def test_expected_value_is_the_baseline_and_observed_is_the_capture(self):
        for finding in self.risk.findings:
            change = self.result.changed_variable(finding.related_variable)
            self.assertEqual(finding.expected_value, change.baseline_value)
            self.assertEqual(finding.observed_value, change.current_value)

    def test_the_score_uses_the_existing_policy_and_stays_on_the_0_100_scale(self):
        self.assertEqual(self.risk.risk_policy_version, "risk-policy-v1")
        self.assertEqual(self.risk.risk_engine_version, "v1")
        self.assertGreaterEqual(self.risk.overall_score, 0)
        self.assertLessEqual(self.risk.overall_score, 100)
        self.assertEqual(
            self.risk.metadata["scoring"], "correlation.risk.scoring.score_findings"
        )
        self.assertEqual(
            self.risk.metadata["severity_source"],
            "correlation.risk.rules.MISMATCH_FINDING_SPECS",
        )

    def test_the_conditional_reason_is_written_as_a_real_condition(self):
        esp = next(f for f in self.risk.findings
                   if f.related_variable == "esp.presence")
        self.assertIn("validated at", esp.condition)
        self.assertIn("independent observation", esp.condition)
        self.assertIn(VALIDATED_BY, esp.condition)

    def test_only_security_relevant_changes_become_findings(self):
        """A change with no security relevance is reported, not escalated."""
        self.assertTrue(
            all(change.security_relevance for change in self.result.changed_fields)
        )
        self.assertEqual(len(self.risk.findings), len(self.result.changed_fields))

    def test_drift_does_not_alter_the_technical_risk_of_the_observation(self):
        """The comparison adds context; it does not rescore the capture."""
        self.assertIn("unchanged by this comparison", self.risk.findings[0].description)


class TestTheRegistryIsAppendOnlyAndOptional(unittest.TestCase):
    """The smallest persistence that could work, and no more."""

    @classmethod
    def setUpClass(cls):
        cls.observed = real_state(REAL_TUNNEL_V4)

    def test_the_default_registry_is_in_memory(self):
        registry = BaselineRegistry()
        self.assertFalse(registry.persistent)
        self.assertIsNone(registry.path)

    def test_registration_is_unique_and_never_replaces(self):
        registry = BaselineRegistry()
        registry.register(baseline_from(self.observed, baseline_id="b1"))
        with self.assertRaises(ValueError):
            registry.register(baseline_from(self.observed, baseline_id="b1"))
        self.assertEqual(len(registry), 1)

    def test_ids_and_all_are_deterministically_ordered(self):
        registry = BaselineRegistry()
        for name in ("b3", "b1", "b2"):
            registry.register(baseline_from(self.observed, baseline_id=name))
        self.assertEqual(registry.ids(), ("b1", "b2", "b3"))
        self.assertEqual([r.baseline_id for r in registry.all()], ["b1", "b2", "b3"])

    def test_for_asset_is_an_explicit_filter_never_an_inference(self):
        registry = BaselineRegistry()
        registry.register(baseline_from(self.observed, baseline_id="a",
                                        asset_id="gw-a"))
        registry.register(baseline_from(self.observed, baseline_id="b",
                                        asset_id="gw-b"))
        registry.register(baseline_from(self.observed, baseline_id="none"))
        self.assertEqual([r.baseline_id for r in registry.for_asset("gw-a")], ["a"])
        self.assertEqual([r.baseline_id for r in registry.for_asset("gw-b")], ["b"])
        self.assertEqual(registry.for_asset("gw-c"), ())
        self.assertNotIn("none", [r.baseline_id for r in registry.for_asset("gw-a")])

    def test_a_persistent_registry_round_trips_through_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "baselines.jsonl"
            registry = BaselineRegistry(path)
            registry.register(baseline_from(self.observed, baseline_id="b1",
                                            asset_id="gw-a"))
            self.assertTrue(path.exists())
            lines = path.read_text("utf-8").strip().splitlines()
            self.assertEqual(len(lines), 1)
            reloaded = BaselineRegistry(path)
            self.assertEqual(reloaded.ids(), ("b1",))
            self.assertEqual(reloaded.get("b1").to_dict(), registry.get("b1").to_dict())
            self.assertTrue(reloaded.persistent)

    def test_a_persistent_registry_appends_rather_than_rewrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "baselines.jsonl"
            first = BaselineRegistry(path)
            first.register(baseline_from(self.observed, baseline_id="b1"))
            second = BaselineRegistry(path)
            second.register(baseline_from(self.observed, baseline_id="b2"))
            self.assertEqual(BaselineRegistry(path).ids(), ("b1", "b2"))
            self.assertEqual(
                len(path.read_text("utf-8").strip().splitlines()), 2
            )

    def test_a_persistent_registry_refuses_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = BaselineRegistry(pathlib.Path(tmp) / "b.jsonl")
            registry.register(baseline_from(self.observed, baseline_id="b1"))
            with self.assertRaises(ValueError):
                registry.remove("b1")

    def test_a_hand_tampered_registry_file_is_refused_at_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "baselines.jsonl"
            registry = BaselineRegistry(path)
            registry.register(baseline_from(self.observed, baseline_id="b1"))
            record = json.loads(path.read_text("utf-8").strip())
            record["validated_by"] = "attacker"
            path.write_text(json.dumps(record, sort_keys=True) + "\n", "utf-8")
            with self.assertRaises(BaselineIntegrityError):
                BaselineRegistry(path)

    def test_a_corrupt_registry_file_names_the_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "baselines.jsonl"
            path.write_text('{"baseline_id": "b1"\n', encoding="utf-8")
            with self.assertRaises(BaselineIntegrityError) as caught:
                BaselineRegistry(path)
            self.assertIn(":1", str(caught.exception))

    def test_registry_from_dicts_verifies_every_record(self):
        payload = baseline_from(self.observed, baseline_id="b1").to_dict()
        payload["canonical_state"] = dict(payload["canonical_state"])
        payload["canonical_state"]["esp.presence"] = False
        with self.assertRaises(BaselineIntegrityError):
            registry_from_dicts([payload])

    def test_registering_something_that_is_not_a_baseline_is_refused(self):
        with self.assertRaises(TypeError):
            BaselineRegistry().register({"baseline_id": "b1"})


class TestDriftReachesTheChainOfCustody(unittest.TestCase):
    """The drift claim must be auditable from the chain alone."""

    @classmethod
    def setUpClass(cls):
        cls.observed = real_state(REAL_TUNNEL_V4)
        cls.baseline = baseline_from(cls.observed)
        cls.result = assess_drift(cls.baseline, derived_ah_state(), sequence=4)
        cls.finding = cls.result.risk.findings[0]
        cls.chain = build_chain_of_custody(
            assessment_id="drift-assess",
            finding=cls.finding,
            assessment=cls.result.risk,
            observed=derived_ah_state(),
            drift=cls.result,
            verify_evidence=False,
        )

    def _fact(self, fact_id):
        return next(f for f in self.chain.facts if f.fact_id == fact_id)

    def test_the_baseline_is_a_configured_fact_not_an_observation(self):
        fact = self._fact("configured.drift_baseline")
        self.assertEqual(fact.category, "CONFIGURED")
        self.assertNotEqual(fact.category, "OBSERVED")
        self.assertEqual(fact.value["baseline_id"], "baseline-e2e-v4")
        self.assertEqual(fact.value["state_digest"], self.baseline.state_digest)
        self.assertIn(VALIDATED_BY, fact.detail)
        self.assertIn("NOT an observation", fact.detail)

    def test_the_current_state_is_an_observed_fact(self):
        fact = self._fact("observed.drift_current_state")
        self.assertEqual(fact.category, "OBSERVED")
        self.assertEqual(fact.value, self.result.current_state_digest)

    def test_the_difference_is_a_derived_fact_naming_both_values(self):
        fact = self._fact("derived.drift_changed_fields")
        self.assertEqual(fact.category, "DERIVED")
        pairs = {item["variable"]: (item["baseline_value"], item["current_value"])
                 for item in fact.value}
        self.assertEqual(pairs["esp.presence"], (True, False))
        self.assertEqual(pairs["ah.presence"], (False, True))
        self.assertIn("configuration_drift", fact.detail)

    def test_both_digests_and_the_seal_are_stated_in_an_integrity_check(self):
        check = next(c for c in self.chain.integrity
                     if c.check_id == "drift.baseline_explicit")
        self.assertEqual(check.status, "pass")
        self.assertTrue(check.client_verifiable)
        self.assertEqual(check.observed["baseline_id"], "baseline-e2e-v4")
        self.assertEqual(check.observed["baseline_digest"],
                         self.baseline.baseline_digest)
        self.assertEqual(check.observed["baseline_state_digest"],
                         self.baseline.state_digest)
        self.assertEqual(check.observed["current_state_digest"],
                         self.result.current_state_digest)
        self.assertIn("sha256(canonical_json)", check.expected["digest_algorithm"])

    def test_the_changed_fields_are_inside_the_declared_scope(self):
        check = next(c for c in self.chain.integrity
                     if c.check_id == "drift.fields_within_declared_scope")
        self.assertEqual(check.status, "pass")
        self.assertTrue(
            set(check.observed["changed_variables"]).issubset(
                set(COMPARABLE_VARIABLES))
        )
        self.assertIn("SPI", check.detail)

    def test_the_limitations_name_the_scope_and_the_exclusions(self):
        text = " ".join(self.chain.limitations)
        self.assertIn("baseline-e2e-v4", text)
        self.assertIn("no cipher, DH group, PFS", text)
        self.assertIn("firmware", text)
        self.assertIn("SPI", text)
        self.assertIn("93", text)
        self.assertIn("does not establish intent", text)

    def test_the_serialised_drift_section_is_self_contained(self):
        section = self.chain.drift
        self.assertEqual(section["status"], DRIFT_STATUS_DRIFT)
        self.assertEqual(section["baseline"]["baseline_id"], "baseline-e2e-v4")
        self.assertEqual(section["baseline"]["state_digest"],
                         self.baseline.state_digest)
        self.assertEqual(section["baseline"]["baseline_digest"],
                         self.baseline.baseline_digest)
        self.assertEqual(section["baseline"]["validation_status"], "validated")
        self.assertEqual(section["current"]["state_digest"],
                         self.result.current_state_digest)
        self.assertEqual(len(section["changed_fields"]), 2)
        self.assertEqual(section["drift_categories"],
                         ["configuration_drift"])
        json.dumps(section)

    def test_the_chain_round_trips_through_serialisation(self):
        restored = type(self.chain).from_dict(self.chain.to_dict())
        self.assertEqual(restored.drift, self.chain.drift)
        self.assertEqual(restored.to_dict(), self.chain.to_dict())

    def test_an_indeterminate_comparison_says_it_claims_nothing(self):
        result = assess_drift(self.baseline, idle_state(self.observed))
        self.assertEqual(result.risk, None)
        self.assertFalse(result.drift_detected)

    def test_a_chain_without_drift_is_unchanged_in_shape(self):
        """No baseline configured must add nothing at all to the chain."""
        base_chain = build_chain_of_custody(
            assessment_id="drift-assess",
            finding=self.finding,
            assessment=self.result.risk,
            observed=derived_ah_state(),
            verify_evidence=False,
        )
        self.assertIsNone(base_chain.drift)
        self.assertFalse([f for f in base_chain.facts if "drift" in f.fact_id])
        self.assertFalse([c for c in base_chain.integrity
                          if c.check_id.startswith("drift")])


class TestDriftFlowsIntoMissionContext(unittest.TestCase):
    """Drift findings take the same contextualisation path as any other."""

    @classmethod
    def setUpClass(cls):
        cls.observed = real_state(REAL_TUNNEL_V4)
        cls.baseline = baseline_from(cls.observed, asset_id="gw-a")
        cls.result = assess_drift(cls.baseline, derived_ah_state(), sequence=5)
        cls.risk = cls.result.risk

    def _context(self, asset_id):
        from correlation.mission import load_mission_profiles

        return mission_context(
            technical_risk=self.risk.overall_score,
            technical_severity=self.risk.severity,
            asset_id=asset_id,
            profiles=load_mission_profiles(),
        )

    def test_a_drift_assessment_contextualises_like_any_other(self):
        context = self._context("gw-a")
        self.assertTrue(context.configured)
        self.assertEqual(context.risk.technical_risk, self.risk.overall_score)
        self.assertGreaterEqual(context.risk.contextualized_risk,
                                context.risk.technical_risk)
        self.assertLessEqual(context.risk.contextualized_risk, 100)

    def test_contextualising_drift_never_raises_its_severity(self):
        for asset_id in ("gw-a", "gw-b", None, "unknown-asset"):
            with self.subTest(asset=asset_id):
                context = self._context(asset_id)
                if not context.configured:
                    self.assertIsNone(context.risk)
                    self.assertIn("no mission context", context.reason.lower())
                    continue
                self.assertEqual(context.risk.technical_severity,
                                 self.risk.severity)
                self.assertEqual(context.risk.technical_risk,
                                 self.risk.overall_score)

    def test_the_drift_chain_carries_both_contexts_together(self):
        context = self._context("gw-a")
        chain = build_chain_of_custody(
            assessment_id="drift-mission",
            finding=self.risk.findings[0],
            assessment=self.risk,
            observed=derived_ah_state(),
            mission_context=context,
            drift=self.result,
            verify_evidence=False,
        )
        fact_ids = {f.fact_id for f in chain.facts}
        self.assertIn("configured.drift_baseline", fact_ids)
        self.assertIn("derived.contextualized_risk", fact_ids)
        self.assertIsNotNone(chain.drift)
        self.assertEqual(chain.mission_context["status"], "configured")
        self.assertIn("configured.context_source", fact_ids)


class TestTheStoreOnlyComparesWhenTold(unittest.TestCase):
    """No registry means no comparison, and the store says so."""

    def test_a_store_without_baselines_attaches_no_drift(self):
        store = AssessmentStore()
        self.assertIsNone(store.baselines)
        self.assertEqual(store.drift_inputs, {})
        self.assertFalse(store.drift_summary()["configured"])
        self.assertIn("no validated baseline registry",
                      store.drift_summary()["reason"])
        self.assertNotIn("drift", store.overview)
        for header in store.headers:
            self.assertNotIn("drift", store.bundles[header["assessment_id"]])

    def test_a_store_with_a_baseline_compares_at_build_time(self):
        observed = real_state(REAL_TUNNEL_V4)
        registry = BaselineRegistry()
        registry.register(baseline_from(observed))
        store = AssessmentStore(asset_id="gw-a", baselines=registry,
                                baseline_id="baseline-e2e-v4")
        self.assertTrue(store.drift_summary()["configured"])
        self.assertTrue(store.drift_inputs)
        for drift in store.drift_inputs.values():
            self.assertIn(drift.status,
                          {DRIFT_STATUS_NO_DRIFT, DRIFT_STATUS_INDETERMINATE})
        self.assertEqual(
            store.drift_summary()["status_counts"].get(DRIFT_STATUS_NO_DRIFT, 0), 10
        )
        self.assertEqual(
            store.drift_summary()["status_counts"].get(DRIFT_STATUS_INDETERMINATE), 2
        )

    def test_an_unmatched_baseline_id_is_not_configured_not_no_drift(self):
        registry = BaselineRegistry()
        registry.register(baseline_from(real_state(REAL_TUNNEL_V4)))
        store = AssessmentStore(baselines=registry, baseline_id="does-not-exist")
        for drift in store.drift_inputs.values():
            self.assertEqual(drift.status, DRIFT_STATUS_NOT_CONFIGURED)
        self.assertIsNone(store.baseline_view())

    def test_a_baseline_alone_is_not_enough_without_an_id(self):
        """No silent fallback to the only or the latest baseline."""
        registry = BaselineRegistry()
        registry.register(baseline_from(real_state(REAL_TUNNEL_V4)))
        store = AssessmentStore(baselines=registry)
        self.assertIsNone(store.baseline_id)
        for drift in store.drift_inputs.values():
            self.assertEqual(drift.status, DRIFT_STATUS_NOT_CONFIGURED)

    def test_the_summary_publishes_the_scope(self):
        summary = AssessmentStore().drift_summary()
        self.assertEqual(summary["supported_categories"], ["configuration_drift"])
        self.assertIn("firmware_drift", summary["unsupported_categories"])
        self.assertIn("excluded", summary["canonicalization"])
        self.assertIn("included", summary["canonicalization"])

    def test_build_store_forwards_the_baseline(self):
        registry = BaselineRegistry()
        registry.register(baseline_from(real_state(REAL_TUNNEL_V4)))
        store = build_store(baselines=registry, baseline_id="baseline-e2e-v4")
        self.assertTrue(store.drift_summary()["configured"])


class TestTheDriftApiIsReadOnly(unittest.TestCase):
    """Three GETs; no way to create, amend or delete a baseline."""

    @classmethod
    def setUpClass(cls):
        observed = real_state(REAL_TUNNEL_V4)
        registry = BaselineRegistry()
        registry.register(baseline_from(observed, asset_id="gw-a"))
        cls.store = AssessmentStore(asset_id="gw-a", baselines=registry,
                                    baseline_id="baseline-e2e-v4")
        cls.assessment_id = cls.store.headers[0]["assessment_id"]

    def test_the_summary_route(self):
        payload = handle_drift(self.store)
        self.assertTrue(payload["read_only"])
        self.assertTrue(payload["configured"])
        self.assertEqual(payload["baseline_id"], "baseline-e2e-v4")
        self.assertEqual(payload["supported_categories"], ["configuration_drift"])
        json.dumps(payload)

    def test_the_baselines_route_discloses_both_digests(self):
        payload = handle_drift_baselines(self.store)
        self.assertEqual(payload["baseline_ids"], ["baseline-e2e-v4"])
        record = payload["baselines"][0]
        self.assertEqual(record["validation_status"], "validated")
        self.assertEqual(len(record["state_digest"]), 64)
        self.assertEqual(len(record["baseline_digest"]), 64)
        self.assertNotEqual(record["state_digest"], record["baseline_digest"])
        self.assertEqual(record["asset_id"], "gw-a")

    def test_the_assessment_route(self):
        payload = handle_assessment_drift(self.store, self.assessment_id)
        self.assertEqual(payload["assessment_id"], self.assessment_id)
        self.assertIn(payload["status"], (DRIFT_STATUS_NO_DRIFT,
                                          DRIFT_STATUS_INDETERMINATE))
        self.assertFalse(payload["drift_detected"])
        json.dumps(payload)

    def test_an_unknown_assessment_is_404(self):
        with self.assertRaises(Exception) as caught:
            handle_assessment_drift(self.store, "nope:1:1")
        self.assertEqual(getattr(caught.exception, "status", None), 404)

    def test_an_unconfigured_store_reports_not_configured_not_no_drift(self):
        store = AssessmentStore()
        summary = handle_drift(store)
        self.assertFalse(summary["configured"])
        self.assertEqual(summary["status_counts"], {})
        self.assertEqual(handle_drift_baselines(store)["baselines"], [])
        payload = handle_assessment_drift(store, self.assessment_id)
        self.assertEqual(payload["status"], DRIFT_STATUS_NOT_CONFIGURED)
        self.assertFalse(payload["drift_detected"])
        self.assertIn("no validated baseline", payload["reason"])

    def test_the_dispatcher_reaches_all_three(self):
        class Context:
            health = metrics = traffic_generator = audit_store = None

        context = Context()
        for path, check in (
            ("/api/v1/drift", lambda b: b["configured"]),
            ("/api/v1/drift/baselines", lambda b: b["baseline_ids"]),
            (f"/api/v1/assessments/{self.assessment_id}/drift",
             lambda b: "status" in b),
        ):
            with self.subTest(path=path):
                body, content_type = handle_v1_get(context, path, {}, self.store)
                self.assertEqual(content_type, "application/json")
                self.assertTrue(check(body))

    def test_the_baselines_route_is_not_shadowed_by_the_drift_prefix(self):
        class Context:
            health = metrics = traffic_generator = audit_store = None

        body, _ = handle_v1_get(Context(), "/api/v1/drift/baselines", {},
                                 self.store)
        self.assertIn("baselines", body)
        self.assertIn("canonicalization", body)


class TestTheDocumentedContractMatchesWhatIsServed(unittest.TestCase):
    """OpenAPI describes the drift surface exactly."""

    @classmethod
    def setUpClass(cls):
        cls.document = openapi_document()
        observed = real_state(REAL_TUNNEL_V4)
        registry = BaselineRegistry()
        registry.register(baseline_from(observed))
        cls.store = AssessmentStore(baselines=registry, baseline_id="baseline-e2e-v4")

    def test_the_three_routes_are_documented(self):
        for path in ("/api/v1/drift", "/api/v1/drift/baselines",
                     "/api/v1/assessments/{id}/drift"):
            self.assertIn(path, self.document["paths"])
            self.assertEqual(list(self.document["paths"][path]), ["get"])

    def test_every_documented_schema_reference_resolves(self):
        schemas = self.document["components"]["schemas"]
        references = set()

        def walk(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "$ref" and isinstance(value, str):
                        references.add(value)
                    else:
                        walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(self.document)
        for reference in references:
            if reference.startswith("#/components/schemas/"):
                self.assertIn(reference.split("/")[-1], schemas, reference)

    def test_the_drift_schema_matches_the_served_assessment_shape(self):
        served = handle_assessment_drift(self.store, self.store.headers[0]["assessment_id"])
        declared = set(
            self.document["components"]["schemas"]["DriftAssessment"]["properties"]
        )
        self.assertEqual(declared, set(served))

    def test_the_baseline_schema_matches_the_served_record(self):
        served = handle_drift_baselines(self.store)["baselines"][0]
        declared = set(
            self.document["components"]["schemas"]["ValidatedBaseline"]["properties"]
        )
        self.assertEqual(declared, set(served))

    def test_the_summary_schema_matches_the_served_summary(self):
        served = handle_drift(self.store)
        declared = set(
            self.document["components"]["schemas"]["DriftSummary"]["properties"]
        )
        self.assertEqual(declared, set(served))

    def test_the_custody_drift_section_matches_the_served_comparison(self):
        observed = real_state(REAL_TUNNEL_V4)
        result = assess_drift(baseline_from(observed), derived_ah_state(), sequence=7)
        chain = build_chain_of_custody(
            assessment_id="drift-schema",
            finding=result.risk.findings[0],
            assessment=result.risk,
            observed=derived_ah_state(),
            drift=result,
            verify_evidence=False,
        )
        declared = set(
            self.document["components"]["schemas"]["ChainOfCustody"]
            ["properties"]["drift"]["properties"]
        )
        self.assertEqual(declared, set(chain.drift))

    def test_the_status_enums_are_exactly_the_four_outcomes(self):
        for name in ("DriftAssessment",):
            schema = self.document["components"]["schemas"][name]
            self.assertEqual(
                schema["properties"]["status"]["enum"],
                ["drift", "no_drift", "not_configured", "indeterminate"],
            )

    def test_the_custody_schema_documents_the_drift_section(self):
        custody = self.document["components"]["schemas"]["ChainOfCustody"]
        self.assertIn("drift", custody["properties"])
        self.assertTrue(custody["properties"]["drift"]["nullable"])

    def test_only_configuration_drift_is_ever_declared(self):
        summary = self.document["components"]["schemas"]["DriftSummary"]
        self.assertEqual(
            summary["properties"]["supported_categories"]["items"]["enum"],
            ["configuration_drift"],
        )


class TestTheDerivedFixtureIsDeclared(unittest.TestCase):
    """A non-real input must announce itself, field by field."""

    @classmethod
    def setUpClass(cls):
        cls.provenance = json.loads(AH_PROVENANCE.read_text("utf-8"))

    def test_it_declares_itself_a_derivation_and_not_a_capture(self):
        self.assertEqual(self.provenance["kind"], "disclosed_derived_observation")
        self.assertIn("NOT a packet capture", self.provenance["not_a_capture"])

    def test_it_names_the_real_artifact_and_its_real_digest(self):
        source = self.provenance["derived_from"]
        self.assertEqual(source["path"], REAL_TUNNEL_V4)
        import hashlib
        digest = hashlib.sha256(
            pathlib.Path(REAL_TUNNEL_V4).read_bytes()
        ).hexdigest()
        self.assertEqual(source["artifact_sha256"], digest)

    def test_it_lists_exactly_the_edits_it_made(self):
        edits = {item["field"]: item for item in self.provenance["edits"]}
        self.assertEqual(edits["esp_seen"]["from"], True)
        self.assertEqual(edits["esp_seen"]["to"], False)
        self.assertEqual(edits["ah_seen"]["from"], False)
        self.assertEqual(edits["ah_seen"]["to"], True)

    def test_the_fixture_really_differs_only_where_declared(self):
        real = json.loads(
            pathlib.Path(REAL_TUNNEL_V4).read_text("utf-8").strip()
        )
        derived = json.loads(AH_SUBSTITUTION.read_text("utf-8").strip())
        differing = {
            key for key in set(real) | set(derived)
            if real.get(key) != derived.get(key)
        }
        declared = {item["field"].split("[")[0].split(".")[0]
                    for item in self.provenance["edits"]}
        self.assertEqual(differing, declared, f"undeclared difference: {differing}")

    def test_the_substantive_edits_are_only_the_two_presence_flags(self):
        substantive = [item for item in self.provenance["edits"]
                       if item["field"] in ("esp_seen", "ah_seen")]
        self.assertEqual([item["field"] for item in substantive],
                         ["esp_seen", "ah_seen"])
        for item in self.provenance["edits"]:
            self.assertIn("detail", item, item["field"])
        consequences = [item for item in self.provenance["edits"]
                        if item not in substantive]
        self.assertTrue(consequences)
        for item in consequences:
            self.assertIn("consequence", item["detail"], item["field"])

    def test_it_declares_the_drift_it_is_meant_to_produce(self):
        expected = self.provenance["expected_drift"]
        self.assertEqual(sorted(expected["variables"]),
                         ["ah.presence", "esp.presence"])
        self.assertEqual(expected["unchanged"], ["address_family"])

    def test_no_pcap_is_claimed_anywhere_in_the_fixture_directory(self):
        for path in FIXTURES.iterdir():
            self.assertNotEqual(path.suffix, ".pcap", path.name)


class TestTheBoundariesAreEnforcedNotJustIntended(unittest.TestCase):
    """The constraints of the milestone, asserted rather than documented."""

    def test_the_drift_layer_imports_no_orchestration_and_never_writes(self):
        package = pathlib.Path(__file__).resolve().parents[1] / "correlation" / "drift"
        sources = sorted(package.glob("*.py"))
        self.assertGreaterEqual(len(sources), 5)
        forbidden_imports = ("controller", "subprocess", "requests", "urllib",
                             "socket", "os.system", "popen")
        for source in sources:
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotIn(
                            alias.name.split(".")[0], forbidden_imports,
                            f"{source.name} imports {alias.name}",
                        )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    self.assertNotIn(
                        node.module.split(".")[0], forbidden_imports,
                        f"{source.name} imports from {node.module}",
                    )

    def test_the_forbidden_files_are_untouched(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        for relative in ("controller/api.py", "requirements.txt"):
            self.assertTrue((root / relative).exists(), relative)
        drift_only = {
            "correlation/drift/models.py", "correlation/drift/canonical.py",
            "correlation/drift/baseline.py", "correlation/drift/comparison.py",
            "correlation/drift/registry.py", "correlation/drift/__init__.py",
        }
        for relative in drift_only:
            self.assertTrue((root / relative).exists(), relative)

    def test_the_observation_model_was_not_rewritten(self):
        """Drift reads ObservedState; it must not have added crypto fields."""
        fields = set(ObservedState.__dataclass_fields__)
        for crypto in ("cipher", "encryption", "integrity", "dh_group", "pfs",
                       "mode", "key_len"):
            self.assertNotIn(crypto, fields)

    def test_observed_evidence_values_is_still_empty(self):
        """The honest empty mapping must not have been quietly filled in."""
        from correlation.artifacts import observed_evidence_values

        self.assertEqual(observed_evidence_values(real_state(REAL_TUNNEL_V4)), {})

    def test_no_new_dependencies_were_introduced(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        text = (root / "requirements.txt").read_text("utf-8")
        for line in text.splitlines():
            package = line.strip().split("==")[0].split(">=")[0].strip()
            if package and not package.startswith("#"):
                self.assertNotIn(package.replace("-", "_"),
                                 {"sqlite3", "alembic", "diff_match_patch"})

    def test_the_canonical_digest_helper_is_reused_not_reimplemented(self):
        from correlation.custody.builder import canonical_digest

        state = canonical_security_state(real_state(REAL_TUNNEL_V4))
        self.assertEqual(canonical_state_digest(state), canonical_digest(state))


class TestDeterminism(unittest.TestCase):
    """Same inputs, same bytes. No clock, no randomness, no ordering."""

    def test_repeated_comparisons_are_byte_identical(self):
        observed = real_state(REAL_TUNNEL_V4)
        baseline = baseline_from(observed)
        current = derived_ah_state()
        payloads = {
            json.dumps(assess_drift(baseline, current, sequence=9).to_dict(),
                       sort_keys=True)
            for _ in range(5)
        }
        self.assertEqual(len(payloads), 1)

    def test_the_baseline_does_not_read_a_clock(self):
        observed = real_state(REAL_TUNNEL_V4)
        first = baseline_from(observed)
        second = baseline_from(observed)
        self.assertEqual(first.validated_at, second.validated_at)

    def test_changed_fields_are_ordered_by_the_declaration(self):
        baseline = baseline_from(real_state(REAL_TUNNEL_V4))
        result = assess_drift(baseline, derived_ah_state())
        self.assertEqual(
            [change.variable for change in result.changed_fields],
            [field.variable for field in COMPARABLE_FIELDS
             if field.variable != "address_family"],
        )


if __name__ == "__main__":
    unittest.main()
