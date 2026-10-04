"""Novel-feature acceptance validation: the real recorded corpus.

These tests exist because of a measured gap, not for coverage's sake. The drift
milestone's own acceptance test compares FOUR real captures; this repository
actually holds TEN usable recorded state artifacts, plus three that the
observation model refuses. Nothing asserted the whole corpus, so "no real pair
exercises a protection change" was a claim rather than a checked fact.

Every test here runs on recorded artifacts. None uses a mock, a fixture, or a
controlled input, because the whole point is to establish what the real data
does and does not contain.

    TestTheRealCorpusAgreesOnProtectionPresence
        Every usable recorded state artifact agrees on PROTECTION state (ESP
        in force, AH absent), so no real pair can produce protection drift.
        This is the anti-fabrication test: it is what licenses the controlled
        fixture. The address family is deliberately not pinned -- two real
        captures of one asset under different configurations legitimately
        disagree there, and that is genuine configuration drift. Drift is
        additionally pinned to the canonical states themselves, so a result can
        be neither fabricated nor missed.

    TestTheRealCorpusContainsNoProtectionChange
        The only artifact anywhere in the repository that reports ESP absent is
        the declared fixture. Read straight off disk, including files the
        loader will not admit, so the claim covers more than the loader does.

    TestRefusedArtifactsAreRefusedWithAReason
        Snapshots that contradict themselves are rejected with their reason
        rather than coerced into shape.

    TestCrossEndpointComparisonIsNotScoped
        A recorded, documented limitation: nothing in the drift comparison
        establishes that the two sides describe the same tunnel, so comparing
        two different endpoint pairs reports address-family drift. Pinned here
        so the limitation is visible in the suite rather than only in prose.
"""

import glob
import hashlib
import json
import os
import unittest

from correlation.artifacts import (
    ArtifactUnavailable,
    INCONSISTENT_STATE_ARTIFACTS,
    load_observed_state,
)
from correlation.drift import BaselineRegistry, assess_drift, validate_baseline
from correlation.drift.canonical import canonical_security_state
from correlation.models.observed import ObservedState

#: Every recorded state artifact in the repository, however it is stored. The
#: corpus is discovered rather than listed so a new capture cannot be added
#: without this validation seeing it.
STATE_GLOBS = (
    "results/e2e-verification/parser/*/state.jsonl",
    "results/observed-state/live_state_from_*.jsonl",
    "results/observed-state/*/state_*.jsonl",
    "results/e2e-verification/transport/*state_snapshot*.json",
)

#: Artifacts that are not observations of a real system, and so are never part
#: of the real corpus.
NON_CAPTURE = "tests/fixtures/"


def real_state_artifacts():
    """Recorded state artifacts, in a stable order."""
    return sorted(
        set(path for pattern in STATE_GLOBS for path in glob.glob(pattern))
    )


def usable_real_artifacts():
    """Those the authoritative loader admits."""
    usable = []
    for path in real_state_artifacts():
        try:
            load_observed_state(path)
        except ArtifactUnavailable:
            continue
        usable.append(path)
    return usable


def observations_in(path):
    """Yield every ObservedState-shaped record in a file, JSONL or JSON."""
    with open(path, encoding="utf-8", errors="ignore") as handle:
        text = handle.read()
    candidates = (
        [line.strip() for line in text.splitlines() if line.strip()]
        if path.endswith(".jsonl")
        else [text]
    )
    for candidate in candidates:
        try:
            payload = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(payload, dict) and "esp_seen" in payload and "timestamp_ns" in payload:
            yield payload
            return


class TestTheRealCorpusAgreesOnProtectionPresence(unittest.TestCase):
    """The anti-fabrication test, scoped to what it can actually prove.

    Every usable recorded capture reports the same PROTECTION state: ESP in
    force, AH absent. That is what licenses the controlled ESP/AH fixture --
    no real capture can show a protection change, so a protection-drift demo
    must come from a declared fixture rather than from recorded data.

    The address family is deliberately NOT pinned. Two real captures of the
    same asset under different configurations (transport/IPv4 and
    transport/IPv6) legitimately disagree on it, and that disagreement is
    genuine configuration drift, not fabrication. The invariant is therefore
    stated on the protection axis, which is where fabrication would live.
    """

    def test_the_corpus_is_not_empty(self):
        # Guards every other assertion here: a corpus that silently vanished
        # would make them vacuously true.
        self.assertGreaterEqual(len(usable_real_artifacts()), 8)

    def test_every_usable_capture_agrees_on_protection_presence(self):
        presence = set()
        for path in usable_real_artifacts():
            state, _ = load_observed_state(path)
            canonical = canonical_security_state(state)
            presence.add((canonical["esp.presence"], canonical["ah.presence"]))
        self.assertEqual(
            presence,
            {(True, False)},
            "the real corpus was expected to agree that ESP is in force and AH "
            f"is absent; found {sorted(presence)}",
        )

    def test_no_pair_of_real_captures_reports_protection_drift(self):
        # Protection drift cannot come from the real corpus. An address-family
        # difference is allowed and expected; an ESP/AH presence difference is
        # not, because no recorded capture supports one.
        for baseline_path in usable_real_artifacts():
            baseline_observation, _ = load_observed_state(baseline_path)
            registry = BaselineRegistry()
            registry.register(
                validate_baseline(
                    baseline_observation,
                    baseline_id="acceptance-baseline",
                    validated_by="acceptance-validation",
                    validated_at="2026-01-01T00:00:00Z",
                )
            )
            for current_path in usable_real_artifacts():
                current_observation, _ = load_observed_state(current_path)
                result = assess_drift(
                    registry.get("acceptance-baseline"),
                    current_observation,
                    current_source_ref=current_path,
                )
                presence_fields = {
                    "esp.presence", "ah.presence",
                } & {change.variable for change in result.changed_fields}
                self.assertEqual(
                    presence_fields,
                    set(),
                    f"{current_path} reported protection drift against "
                    f"{baseline_path}: {sorted(presence_fields)}",
                )

    def test_drift_is_reported_exactly_where_canonical_states_differ(self):
        """The positive half: drift is never invented and never missed.

        Whatever the axis, the real detector must agree with the canonical
        states themselves -- report drift when they differ, no_drift when they
        match. This is what makes an address-family result trustworthy: the
        same rule that produces it also has to withhold it.
        """
        states = {path: canonical_security_state(load_observed_state(path)[0])
                  for path in usable_real_artifacts()}
        for baseline_path, baseline_canonical in states.items():
            baseline_observation, _ = load_observed_state(baseline_path)
            registry = BaselineRegistry()
            registry.register(
                validate_baseline(
                    baseline_observation,
                    baseline_id="acceptance-baseline",
                    validated_by="acceptance-validation",
                    validated_at="2026-01-01T00:00:00Z",
                )
            )
            for current_path, current_canonical in states.items():
                current_observation, _ = load_observed_state(current_path)
                result = assess_drift(
                    registry.get("acceptance-baseline"),
                    current_observation,
                    current_source_ref=current_path,
                )
                differs = baseline_canonical != current_canonical
                self.assertEqual(
                    result.status == "drift",
                    differs,
                    f"{baseline_path} vs {current_path}: canonical states "
                    f"{'differ' if differs else 'match'} but the detector "
                    f"reported {result.status!r}",
                )

    def test_the_canonical_state_is_only_the_three_declared_fields(self):
        state, _ = load_observed_state(usable_real_artifacts()[0])
        self.assertEqual(
            set(canonical_security_state(state)),
            {"address_family", "esp.presence", "ah.presence"},
        )


class TestTheRealCorpusContainsNoProtectionChange(unittest.TestCase):
    """Read off disk, wider than the loader, so nothing hides in an unadmitted file."""

    def _esp_absent_artifacts(self):
        """Every file in the repository, of any form, reporting ESP absent."""
        found = []
        for pattern in ("results/**/*.json", "results/**/*.jsonl",
                        "tests/**/*.json", "tests/**/*.jsonl",
                        "configs/**/*.json", "ebpf/**/*.json"):
            for path in glob.glob(pattern, recursive=True):
                try:
                    with open(path, encoding="utf-8", errors="ignore") as handle:
                        text = handle.read()
                except OSError:
                    continue
                if '"esp_seen": false' in text or '"esp_seen":false' in text:
                    found.append(path)
        return sorted(found)

    def _ah_present_artifacts(self):
        found = []
        for pattern in ("results/**/*.json", "results/**/*.jsonl",
                        "tests/**/*.json", "tests/**/*.jsonl",
                        "configs/**/*.json", "ebpf/**/*.json"):
            for path in glob.glob(pattern, recursive=True):
                try:
                    with open(path, encoding="utf-8", errors="ignore") as handle:
                        text = handle.read()
                except OSError:
                    continue
                if '"ah_seen": true' in text or '"ah_seen":true' in text:
                    found.append(path)
        return sorted(found)

    def test_only_the_declared_fixture_reports_esp_absent(self):
        # Searched across every file of every form, not only the artifacts the
        # loader admits, so nothing can hide in an unread file.
        self.assertEqual(
            self._esp_absent_artifacts(),
            [NON_CAPTURE + "drift/ah_substitution_state.jsonl"],
        )

    def test_no_recorded_artifact_reports_ah_present(self):
        # The declared fixture does report AH; it is the only file that does,
        # and it is not a recording.
        self.assertEqual(
            [p for p in self._ah_present_artifacts()
             if not p.startswith(NON_CAPTURE)],
            [],
            "a recorded capture reports AH, so protection drift would be real",
        )

    def test_observed_state_has_no_crypto_fields_to_infer(self):
        # The reason a cipher/PFS/DH change is undetectable: the authoritative
        # model has nowhere to put such a value.
        forbidden = (
            "encryption", "cipher", "dh_group", "pfs", "integrity",
            "ike_version", "firmware", "implementation", "key_length",
        )
        for name in forbidden:
            self.assertFalse(
                any(name in field for field in ObservedState.__dataclass_fields__),
                f"ObservedState unexpectedly exposes {name!r}; the "
                "unsupported-drift-category claim must be re-examined",
            )


class TestRefusedArtifactsAreRefusedWithAReason(unittest.TestCase):
    def test_every_declared_inconsistent_artifact_is_actually_inconsistent(self):
        for path, reason in INCONSISTENT_STATE_ARTIFACTS.items():
            self.assertTrue(os.path.isfile(path), path)
            with self.assertRaises(ArtifactUnavailable) as caught:
                load_observed_state(path)
            self.assertIn("not a usable observation", str(caught.exception))

    def test_every_refusal_is_either_declared_or_a_form_rejection(self):
        # Two distinct reasons an artifact may not enter the pipeline, and
        # neither may be silent: an internally contradictory snapshot must be
        # declared with its reason, and a snapshot stored in a form the loader
        # does not accept must be rejected as a form problem rather than
        # coerced. Anything else would be a hidden gap in the corpus.
        for path in real_state_artifacts():
            try:
                load_observed_state(path)
            except ArtifactUnavailable as error:
                message = str(error)
                if "is not a usable observation" in message:
                    self.assertIn(
                        path,
                        INCONSISTENT_STATE_ARTIFACTS,
                        f"{path} is refused as inconsistent but is not declared",
                    )
                else:
                    self.assertIn(
                        "not valid JSON",
                        message,
                        f"{path} was refused for an undeclared reason: {message}",
                    )
            except ValueError:
                continue

    def test_form_rejection_is_confined_to_non_jsonl_snapshots(self):
        # The loader reads JSONL only. Every recorded JSON state snapshot is
        # therefore outside its accepted form, which is a scope limit and not
        # an integrity verdict.
        for path in real_state_artifacts():
            if path.endswith(".json"):
                with self.assertRaises(ArtifactUnavailable):
                    load_observed_state(path)


class TestCrossEndpointComparisonIsNotScoped(unittest.TestCase):
    """A recorded limitation, pinned so it cannot be forgotten.

    The drift comparison establishes that two canonical states differ. It does
    not establish that the two observations describe the same tunnel. The
    repository holds a recorded IPv6 state snapshot whose endpoints
    (2001:db8:20::10/20) belong to a different test run from the IPv4 baseline
    (192.168.100.1/2); comparing them reports address-family drift, and the
    payload does not disclose that the endpoints differ.
    """

    V6 = (
        "results/e2e-verification/transport/ipv6-parser-rerun/"
        "traffic_phase_state_snapshot.json"
    )
    V4 = "results/e2e-verification/parser/tunnel_v4/state.jsonl"

    def test_the_v6_snapshot_is_recorded_but_not_loadable(self):
        # It is real recorded data in a form the authoritative loader rejects,
        # which is why it cannot silently become a "real capture" demo.
        with self.assertRaises(ArtifactUnavailable):
            load_observed_state(self.V6)

    def test_comparing_two_different_tunnels_reports_drift_without_scoping(self):
        baseline_observation, _ = load_observed_state(self.V4)
        with open(self.V6, encoding="utf-8") as handle:
            other = ObservedState.from_dict(json.load(handle))
        self.assertNotEqual(
            baseline_observation.endpoints,
            other.endpoints,
            "this limitation only means anything while the endpoints differ",
        )
        registry = BaselineRegistry()
        registry.register(
            validate_baseline(
                baseline_observation,
                baseline_id="acceptance-baseline",
                validated_by="acceptance-validation",
                validated_at="2026-01-01T00:00:00Z",
            )
        )
        result = assess_drift(registry.get("acceptance-baseline"), other)
        self.assertEqual(result.status, "drift")
        self.assertEqual(
            [change.variable for change in result.changed_fields],
            ["address_family"],
        )
        payload = json.dumps(result.to_dict())
        for endpoint in ("192.168.100.1", "2001:db8"):
            self.assertNotIn(
                endpoint,
                payload,
                "the comparison now discloses the endpoints, so this "
                "limitation no longer holds and the report must be updated",
            )


if __name__ == "__main__":
    unittest.main()
