"""The live transport/IPv4 -> transport/IPv6 configuration-drift demonstration.

Both sides of this demonstration are genuine testbed captures of the SAME asset
under the SAME encapsulation mode, taken from the same passive sensor:

    baseline   transport + IPv4   10.20.1.10<->.20        job affdc9c9
    current    transport + IPv6   2001:db8:20::10<->.20   job 0ec8f9fe

They differ on the outer address family and on nothing else, so the existing
deterministic detector -- unmodified -- reports configuration drift:

    address_family  ipv4 -> ipv6  RISK-DRIFT-ADDRESS_FAMILY  MEDIUM

Nothing here fabricates a result. Every test below reads the recorded
artifacts off disk through the authoritative loader, and the non-vacuity tests
exist to prove that removing the wiring, swapping the IPv6 capture for the IPv4
one, bypassing the address-family comparison, hardcoding drift, deleting the
protection guardrails, or substituting a hand-edited fixture each makes this
suite fail rather than quietly pass.
"""

import json
import os
import unittest
from unittest import mock

from correlation.api.app import _load_drift_baseline
from correlation.api.store import RECORDED_CASES, build_store
from correlation.artifacts import load_observed_state
from correlation.drift import BaselineRegistry, assess_drift, validate_baseline
from correlation.drift.baseline import ValidatedBaseline
from correlation.drift.canonical import (
    COMPARABLE_FIELDS,
    canonical_security_state,
)
from correlation.drift.comparison import COMPARABLE_FIELDS as COMPARISON_FIELDS
from correlation.models.observed import ObservedState

#: Genuine testbed captures. Neither lives under tests/fixtures/.
BASELINE_CAPTURE = "results/e2e-verification/parser/transport_v4_live/state.jsonl"
CURRENT_CAPTURE = "results/e2e-verification/parser/transport_v6_live/state.jsonl"
BASELINE_EVENTS = "results/e2e-verification/parser/transport_v4_live/events.jsonl"
CURRENT_EVENTS = "results/e2e-verification/parser/transport_v6_live/events.jsonl"
BASELINE_ID = "baseline-transport-ipv4"

#: The baseline registry the demo is started with.
REGISTRY = "results/drift-demo/baselines.jsonl"


#: The source-address -> direction mapping each capture was built with, so the
#: state can be re-derived from the journal exactly as it was first derived.
REPRODUCIBILITY = (
    (BASELINE_EVENTS, BASELINE_CAPTURE,
     {"10.20.1.10": "A_TO_B", "10.20.1.20": "B_TO_A"}),
    (CURRENT_EVENTS, CURRENT_CAPTURE,
     {"2001:db8:20::10": "A_TO_B", "2001:db8:20::20": "B_TO_A"}),
)


def _state(path):
    state, record = load_observed_state(path)
    return state, record


class TestBothObservationsAreGenuineCaptures(unittest.TestCase):
    """Neither side of the comparison is an edited file."""

    def test_neither_capture_is_a_fixture(self):
        for path in (BASELINE_CAPTURE, CURRENT_CAPTURE,
                     BASELINE_EVENTS, CURRENT_EVENTS):
            self.assertTrue(
                os.path.exists(path), f"{path} is missing from the repository")
            self.assertFalse(
                path.startswith("tests/fixtures/"),
                f"{path} is a fixture, not a recorded capture",
            )
            self.assertTrue(
                path.startswith("results/"),
                f"{path} is not a recorded result artifact",
            )

    def test_each_capture_is_backed_by_its_own_raw_event_journal(self):
        # The state snapshot is derived from the sensor journal beside it. If the
        # journal were absent the snapshot would be an unsourced assertion.
        for events in (BASELINE_EVENTS, CURRENT_EVENTS):
            self.assertGreater(
                os.path.getsize(events), 0, f"{events} is empty")
            with open(events, encoding="utf-8") as handle:
                rows = [json.loads(line) for line in handle if line.strip()]
            self.assertGreater(len(rows), 100, f"{events} has too few events")
            # A raw XDP monitor event: source/destination addresses, an SPI, a
            # protocol number and a timestamp. No security-state verdict here --
            # the verdict is derived from these rows by the state builder.
            for row in rows:
                for field in ("src", "dst", "proto", "ts", "type"):
                    self.assertIn(field, row)
            esp_rows = [row for row in rows if row.get("proto") == 50]
            self.assertGreater(
                len(esp_rows), 100,
                f"{events} contains almost no protocol-50 (ESP) traffic")
            self.assertTrue(
                all(row.get("spi") for row in esp_rows),
                f"{events} has ESP rows without an SPI")

    def test_both_captures_are_admitted_by_the_authoritative_loader(self):
        for path in (BASELINE_CAPTURE, CURRENT_CAPTURE):
            state, record = _state(path)
            self.assertIsInstance(state, ObservedState)
            self.assertEqual(record.artifact_sha256.__class__.__name__, "str")
            self.assertTrue(record.artifact_sha256)

    def test_the_two_captures_declared_different_endpoints(self):
        v4, _ = _state(BASELINE_CAPTURE)
        v6, _ = _state(CURRENT_CAPTURE)
        self.assertEqual(set(v4.endpoints.values()), {"10.20.1.10", "10.20.1.20"})
        self.assertEqual(
            set(v6.endpoints.values()), {"2001:db8:20::10", "2001:db8:20::20"})

    def test_the_recorded_state_is_reproducible_from_the_journal(self):
        """Re-deriving the state from the raw journal yields the same canonical."""
        import subprocess
        import sys
        import tempfile
        for events, recorded, endpoints in REPRODUCIBILITY:
            state, _ = _state(recorded)
            endpoints = json.dumps(endpoints)
            with tempfile.TemporaryDirectory(dir="results") as tmp:
                out = os.path.join(tmp, "state.jsonl")
                subprocess.run(
                    [sys.executable, "-m", "ebpf.ipsec_state_builder",
                     "--events", events, "--endpoints", endpoints,
                     "--output", out],
                    check=True, capture_output=True,
                )
                rebuilt, _ = load_observed_state(out)
            self.assertEqual(
                canonical_security_state(rebuilt),
                canonical_security_state(state),
                f"{recorded} is not what the journal says it is",
            )


class TestTheCanonicalStates(unittest.TestCase):
    """The exact canonical state the demo design specifies."""

    def test_the_baseline_is_transport_ipv4(self):
        state, _ = _state(BASELINE_CAPTURE)
        self.assertEqual(
            canonical_security_state(state),
            {"address_family": "ipv4", "esp.presence": True, "ah.presence": False},
        )

    def test_the_current_observation_is_transport_ipv6(self):
        state, _ = _state(CURRENT_CAPTURE)
        self.assertEqual(
            canonical_security_state(state),
            {"address_family": "ipv6", "esp.presence": True, "ah.presence": False},
        )

    def test_the_two_differ_only_on_the_address_family(self):
        base, _ = _state(BASELINE_CAPTURE)
        cur, _ = _state(CURRENT_CAPTURE)
        differing = {
            field.variable
            for field in COMPARABLE_FIELDS
            if canonical_security_state(base)[field.variable]
            != canonical_security_state(cur)[field.variable]
        }
        self.assertEqual(differing, {"address_family"})


class TestTheExistingDetectorProducesTheResult(unittest.TestCase):
    """The detector is authoritative and unmodified."""

    def setUp(self):
        self.registry = BaselineRegistry()
        base, _ = _state(BASELINE_CAPTURE)
        self.baseline = self.registry.register(validate_baseline(
            base, baseline_id=BASELINE_ID, validated_by="live-demo-test",
            validated_at="2026-01-01T00:00:00Z"))
        current, _ = _state(CURRENT_CAPTURE)
        self.result = assess_drift(
            self.baseline, current, current_source_ref=CURRENT_CAPTURE)

    def test_it_reports_configuration_drift(self):
        self.assertEqual(self.result.status, "drift")
        self.assertTrue(self.result.drift_detected)
        self.assertEqual(list(self.result.drift_categories),
                         ["configuration_drift"])

    def test_the_changed_field_is_the_address_family(self):
        self.assertEqual(
            [change.variable for change in self.result.changed_fields],
            ["address_family"],
        )
        change = self.result.changed_fields[0]
        self.assertEqual(change.baseline_value, "ipv4")
        self.assertEqual(change.current_value, "ipv6")

    def test_the_finding_and_severity_are_the_existing_ones(self):
        self.assertEqual(self.result.changed_fields[0].finding_id,
                         "RISK-DRIFT-ADDRESS_FAMILY")
        self.assertEqual(self.result.changed_fields[0].severity, "MEDIUM")

    def test_protection_presence_is_reported_unchanged(self):
        self.assertEqual(sorted(self.result.unchanged_variables),
                         ["ah.presence", "esp.presence"])


class TestTheResultIsNotVacuous(unittest.TestCase):
    """Each way of faking the demo must make these fail."""

    def setUp(self):
        self.registry = BaselineRegistry()
        base, _ = _state(BASELINE_CAPTURE)
        self.baseline = self.registry.register(validate_baseline(
            base, baseline_id=BASELINE_ID, validated_by="live-demo-test",
            validated_at="2026-01-01T00:00:00Z"))

    def test_swapping_the_ipv6_capture_for_the_ipv4_one_removes_the_drift(self):
        """The drift comes from the IPv6 capture, not from the baseline alone."""
        for path, expected in ((CURRENT_CAPTURE, "drift"),
                               (BASELINE_CAPTURE, "no_drift")):
            state, _ = _state(path)
            result = assess_drift(self.baseline, state, current_source_ref=path)
            self.assertEqual(
                result.status, expected,
                f"{path} should compare as {expected}; the demo's drift must "
                "depend on the genuine IPv6 observation",
            )

    def test_bypassing_the_address_family_comparison_removes_the_drift(self):
        """address_family must actually be compared, not merely reported."""
        current, _ = _state(CURRENT_CAPTURE)
        without_family = tuple(
            field for field in COMPARISON_FIELDS
            if field.variable != "address_family")
        self.assertNotEqual(
            len(without_family), len(COMPARISON_FIELDS),
            "address_family is not part of the comparison at all",
        )
        with mock.patch(
            "correlation.drift.comparison.COMPARABLE_FIELDS", without_family
        ):
            bypassed = assess_drift(self.baseline, current)
        self.assertNotEqual(
            bypassed.status, "drift",
            "the demo survives removing address_family from the comparison, so "
            "it is not actually testing that field",
        )

    def test_a_hand_edited_canonical_state_is_refused_by_the_registry(self):
        """A doctored state cannot become a baseline."""
        import dataclasses
        base, _ = _state(BASELINE_CAPTURE)
        tampered = dataclasses.replace(
            base, endpoints={"a": "2001:db8:20::10", "b": "2001:db8:20::20"})
        # The forged state really is IPv6; the point is that the registry must
        # not accept a record whose canonical state disagrees with its digest.
        self.assertEqual(
            canonical_security_state(tampered)["address_family"], "ipv6")
        baseline = validate_baseline(
            tampered, baseline_id="tampered", validated_by="live-demo-test",
            validated_at="2026-01-01T00:00:00Z")
        record = json.loads(json.dumps(baseline.to_dict()))
        record["canonical_state"]["address_family"] = "ipv4"
        with self.assertRaises(Exception):
            ValidatedBaseline.from_dict(record)

    def test_the_store_reports_no_drift_when_no_baseline_is_configured(self):
        """Drift is never hardcoded: no baseline means no claim."""
        store = build_store()
        summary = store.drift_summary()
        self.assertFalse(summary["configured"])
        self.assertEqual(summary["status_counts"], {})
        for drift in store.drift_inputs.values():
            self.assertEqual(drift.status, "not_configured")


class TestStartupWiring(unittest.TestCase):
    """--drift-baseline / --baseline-id reach the existing registry."""

    def _args(self, **kwargs):
        defaults = {"drift_baseline": None, "baseline_id": None}
        defaults.update(kwargs)
        return mock.Mock(**defaults)

    def test_no_flags_configures_nothing(self):
        registry, baseline_id = _load_drift_baseline(self._args())
        self.assertIsNone(registry)
        self.assertIsNone(baseline_id)

    def test_the_flags_load_the_existing_registry_and_keep_the_id(self):
        registry, baseline_id = _load_drift_baseline(
            self._args(drift_baseline=REGISTRY, baseline_id=BASELINE_ID))
        self.assertIsNotNone(registry)
        self.assertIsInstance(registry, BaselineRegistry)
        self.assertEqual(baseline_id, BASELINE_ID)
        self.assertEqual(list(registry.ids()), [BASELINE_ID])
        self.assertTrue(registry.persistent)

    def test_the_loaded_baseline_is_the_transport_ipv4_capture(self):
        registry, _ = _load_drift_baseline(
            self._args(drift_baseline=REGISTRY, baseline_id=BASELINE_ID))
        self.assertEqual(
            registry.get(BASELINE_ID).canonical_state,
            {"address_family": "ipv4", "esp.presence": True, "ah.presence": False},
        )

    def test_an_id_without_a_registry_is_refused(self):
        with self.assertRaises(SystemExit):
            _load_drift_baseline(self._args(baseline_id=BASELINE_ID))

    def test_an_unknown_id_is_refused_rather_than_silently_unconfigured(self):
        with self.assertRaises(SystemExit):
            _load_drift_baseline(
                self._args(drift_baseline=REGISTRY, baseline_id="no-such-id"))

    def test_a_registry_without_an_id_is_refused(self):
        with self.assertRaises(SystemExit):
            _load_drift_baseline(self._args(drift_baseline=REGISTRY))


class TestTheStoreServesTheDrift(unittest.TestCase):
    """The store built from the real registry carries the real result."""

    @classmethod
    def setUpClass(cls):
        cls.registry = BaselineRegistry(REGISTRY)
        cls.store = build_store(baselines=cls.registry, baseline_id=BASELINE_ID)

    def test_the_summary_reports_configured_and_preserves_the_baseline_id(self):
        summary = self.store.drift_summary()
        self.assertTrue(summary["configured"])
        self.assertEqual(summary["baseline_id"], BASELINE_ID)

    def test_the_transport_ipv6_assessment_reports_the_drift(self):
        assessment = "dataset-20260924-003710:46:transport-v6"
        drift = self.store.drift_inputs[assessment]
        self.assertEqual(drift.status, "drift")
        change = drift.changed_fields[0]
        self.assertEqual(change.variable, "address_family")
        self.assertEqual(change.baseline_value, "ipv4")
        self.assertEqual(change.current_value, "ipv6")
        self.assertEqual(change.finding_id, "RISK-DRIFT-ADDRESS_FAMILY")
        self.assertEqual(change.severity, "MEDIUM")

    def test_the_drift_is_backed_by_a_recorded_capture_not_a_declaration(self):
        drift = self.store.drift_inputs[
            "dataset-20260924-003710:46:transport-v6"]
        self.assertEqual(drift.current_source.kind, "recorded_capture")
        self.assertTrue(drift.current_source.is_capture)

    def test_the_ipv4_slots_report_no_drift_against_their_own_state(self):
        statuses = {
            drift.status for drift in self.store.drift_inputs.values()
            if drift.status != "indeterminate"
            and not drift.changed_fields
        }
        self.assertEqual(statuses, {"no_drift"})
        # Only the IPv6 capture disagrees with the IPv4 baseline.
        changed = {
            (change.variable, change.baseline_value, change.current_value)
            for drift in self.store.drift_inputs.values()
            for change in drift.changed_fields
        }
        self.assertEqual(changed, {("address_family", "ipv4", "ipv6")})


class TestTheCaptureIsRegisteredAsARecordedCase(unittest.TestCase):
    def test_the_current_capture_is_a_recorded_case_in_transport_mode(self):
        cases = {case.name: case for case in RECORDED_CASES}
        self.assertIn("transport-v6", cases)
        case = cases["transport-v6"]
        self.assertEqual(case.state_path, CURRENT_CAPTURE)
        self.assertEqual(case.address_family, "ipv6")
        self.assertEqual(case.mode, "transport")

    def test_the_case_is_pairable_with_a_real_transport_ipv6_plan_sample(self):
        cases = {case.name: case for case in RECORDED_CASES}
        sequence = build_store()._case_sequence(
            self.store_plan(), cases["transport-v6"])
        self.assertIsInstance(sequence, int)

    @staticmethod
    def store_plan():
        import json as _json
        store = build_store()
        with open(store.plan_path, encoding="utf-8") as handle:
            return _json.load(handle)["samples"]


class TestProtectionGuardrailsStillHold(unittest.TestCase):
    """The anti-fabrication guardrails must survive this demonstration."""

    def test_the_repo_still_reports_esp_absent_only_in_the_declared_fixture(self):
        import glob
        found = []
        for pattern in ("results/**/*.json", "results/**/*.jsonl",
                        "tests/**/*.json", "tests/**/*.jsonl",
                        "configs/**/*.json", "ebpf/**/*.json"):
            for path in glob.glob(pattern, recursive=True):
                try:
                    with open(path, encoding="utf-8",
                              errors="ignore") as handle:
                        text = handle.read()
                except OSError:
                    continue
                if '"esp_seen": false' in text or '"esp_seen":false' in text:
                    found.append(path)
        self.assertEqual(found, ["tests/fixtures/drift/ah_substitution_state.jsonl"])

    def test_no_recorded_artifact_reports_ah_present(self):
        import glob
        found = []
        for pattern in ("results/**/*.json", "results/**/*.jsonl",
                        "tests/**/*.json", "tests/**/*.jsonl",
                        "configs/**/*.json", "ebpf/**/*.json"):
            for path in glob.glob(pattern, recursive=True):
                try:
                    with open(path, encoding="utf-8",
                              errors="ignore") as handle:
                        text = handle.read()
                except OSError:
                    continue
                if '"ah_seen": true' in text or '"ah_seen":true' in text:
                    if not path.startswith("tests/fixtures/"):
                        found.append(path)
        self.assertEqual(
            found, [],
            "a recorded capture reports AH, so protection drift would be real")

    def test_the_derived_esp_ah_fixture_is_untouched_and_still_a_fixture(self):
        path = "tests/fixtures/drift/ah_substitution_state.jsonl"
        state, _ = _state(path)
        canonical = canonical_security_state(state)
        self.assertFalse(canonical["esp.presence"])
        self.assertTrue(canonical["ah.presence"])
        self.assertNotIn(
            path, [case.state_path for case in RECORDED_CASES],
            "the derived fixture was promoted into the live demo",
        )

    def test_the_guardrail_tests_themselves_are_still_present(self):
        """Deleting the guardrails must fail this suite, not silently pass."""
        from tests import test_novel_feature_validation as guard
        for name in ("test_only_the_declared_fixture_reports_esp_absent",
                     "test_no_recorded_artifact_reports_ah_present"):
            self.assertTrue(
                hasattr(guard.TestTheRealCorpusContainsNoProtectionChange, name),
                f"the protection guardrail {name} was removed",
            )
            self.assertTrue(
                callable(getattr(guard.TestTheRealCorpusContainsNoProtectionChange,
                                 name)))


if __name__ == "__main__":
    unittest.main()