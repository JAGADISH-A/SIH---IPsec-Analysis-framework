"""Phase 15: automatic response -> PCAP evidence linkage.

Covers the evidence-reference contract, SHA-256 identity/integrity, the
automatic observation -> comparison -> risk -> response propagation, the
non-authoritative nature of a capture, per-window binding, read-only API
exposure, and every negative case in the milestone brief.

The negative tests are the point of this file: a missing artifact, a corrupted
artifact, a foreign run, a foreign experiment and a sibling window must all be
*rejected or reported honestly* rather than papered over.
"""

import json
import os
import shutil
import struct
import sys
import tempfile
import unittest

# The real risk/plan fixtures live beside this test file, as in
# tests/test_risk_engine.py, so the pipeline runs on real plan samples.
_RISK_FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "fixtures", "risk")
_RESPONSE_FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "fixtures", "response")
for _fixtures in (_RISK_FIXTURES, _RESPONSE_FIXTURES):
    if _fixtures not in sys.path:
        sys.path.insert(0, _fixtures)
from risk_fixtures import (  # noqa: E402
    build_identity,
    build_observed,
    expected_from_plan_sample,
    observed_values_for,
    plan_samples,
    run_comparison,
)
from response_fixtures import demo_clock, policy as response_policy  # noqa: E402

from correlation.api import evidence_routes, v1
from correlation.api.audit_store import AuditStore
from correlation.api.evidence_routes import register_journal_evidence

from correlation.api.live import Phase10Context
from correlation.api.pcap import PcapRegistry, PcapService
from correlation.api.routes import ApiError
from correlation.audit import (  # noqa: E402
    EVENT_EVIDENCE,
    SOURCE_AUTHORITATIVE,
    SOURCE_EVIDENCE,
    AuditJournal,
)
from correlation.evidence_linkage import (  # noqa: E402
    bind_window,
    evidence_map_for_windows,
    EvidenceCatalog,
    bind_window,
    capture_relative_path,
    discover_capture,
    evidence_from_artifact,
    evidence_from_comparison,
    inspect_artifact,
    merge_evidence_refs,
    read_pcap_interval,
    window_packet_coverage,
)
from correlation.models.correlation import CorrelationResult
from correlation.models.evidence import (
    ARTIFACT_TYPE_PCAP,
    ARTIFACT_TYPE_XDP_JSONL,
    EVIDENCE_STATUS_INVALID,
    EVIDENCE_STATUS_UNAVAILABLE,
    EVIDENCE_STATUS_VALID,
    EVIDENCE_STATUS_UNVERIFIED,
    EvidenceIdentityMismatch,
    EvidenceRef,
    resolve_within_root,
)
from correlation.models.identity import CorrelationIdentity
from correlation.risk.engine import RiskEngine
from correlation.response import (
    ROLE_ANALYST,
    ROLE_SECURITY_OPERATOR,
    ResponseEngine,
)
from correlation.response.audit import AuditLedger
from correlation.response.authorization import auth_context
from correlation.response.policy import ResponsePolicy

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEALTHY_JOURNAL = REPO_ROOT + "/tests/fixtures/audit/analysis_events_acc-eng-02.jsonl"
ML_FAILURE_JOURNAL = REPO_ROOT + "/tests/fixtures/audit/analysis_events_ml_failure.jsonl"
REAL_SHA256 = ("bfd5c205549eedb460ede653c9458e1774245c27af01cec04219244a7551087d")
REAL_RUN = "acc-eng-02"
REAL_EXPERIMENT = "acc-eng-02-exp-0001"


def write_test_pcap(directory: str, name: str = "cap.pcap", packets: int = 4) -> str:
    """Write a minimal, valid classic pcap (readable by the real parser)."""
    path = os.path.join(directory, name)
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
    body = b""
    for index in range(packets):
        body += struct.pack("<IIII", 1_700_000_000 + index, 500_000, 60, 60)
        body += b"\x00" * 60
    with open(path, "wb") as handle:
        handle.write(header + body)
    return path


def make_ref(
    path: str,
    *,
    run_id: str = "run-1",
    experiment_id: str = "run-1-exp-0001",
    sequence: int = 1,
    window_index=None,
) -> EvidenceRef:
    """A self-verifying reference to a real artifact under a temp root."""
    from correlation.evidence_linkage import inspect_artifact as _inspect

    info = _inspect(path, None)
    return EvidenceRef(
        pcap_path=path,
        capture_sequence=sequence,
        source="training_pcap",
        artifact_type=info.artifact_type,
        artifact_sha256=info.artifact_sha256,
        byte_size=info.byte_size,
        run_id=run_id,
        experiment_id=experiment_id,
        sequence=sequence,
        window_index=window_index,
        capture_start_ns=info.capture_start_ns,
        capture_end_ns=info.capture_end_ns,
    )


class EvidenceRefContractTest(unittest.TestCase):
    def test_legacy_reference_still_round_trips(self):
        ref = EvidenceRef(
            pcap_path="results/datasets/run-1/captures/1/exp-video.pcap",
            capture_sequence=1,
            source="training_pcap",
        )
        self.assertEqual(EvidenceRef.from_dict(ref.to_dict()), ref)
        self.assertTrue(ref.evidence_id.startswith("ev-"))

    def test_evidence_id_is_deterministic_and_content_addressed(self):
        kwargs = dict(pcap_path="a.pcap", run_id="r", experiment_id="e",
                      sequence=1, window_index=3, artifact_sha256="ab" * 32)
        first = EvidenceRef(**kwargs)
        second = EvidenceRef(**kwargs)
        self.assertEqual(first.evidence_id, second.evidence_id)

    def test_evidence_id_differs_per_window_and_per_run(self):
        base = dict(pcap_path="a.pcap", experiment_id="e", sequence=1,
                    artifact_sha256="ab" * 32)
        w0 = EvidenceRef(run_id="r", window_index=0, **base)
        w1 = EvidenceRef(run_id="r", window_index=1, **base)
        other = EvidenceRef(run_id="other", window_index=0, **base)
        self.assertNotEqual(w0.evidence_id, w1.evidence_id)
        self.assertNotEqual(w0.evidence_id, other.evidence_id)

    def test_edited_reference_no_longer_matches_its_recorded_id(self):
        ref = EvidenceRef(pcap_path="a.pcap", run_id="r", artifact_sha256="ab" * 32)
        payload = ref.to_dict()
        payload["artifact_sha256"] = "cd" * 32
        with self.assertRaises(ValueError):
            EvidenceRef.from_dict(payload)

    def test_short_or_non_hex_digest_is_rejected(self):
        with self.assertRaises(ValueError):
            EvidenceRef(pcap_path="a.pcap", artifact_sha256="abc")
        with self.assertRaises(ValueError):
            EvidenceRef(pcap_path="a.pcap", artifact_sha256="ZZ" * 32)

    def test_digest_without_a_location_is_rejected(self):
        with self.assertRaises(ValueError):
            EvidenceRef(artifact_sha256="ab" * 32)

    def test_artifact_type_must_not_contradict_the_path(self):
        with self.assertRaises(ValueError):
            EvidenceRef(pcap_path="capture.jsonl", artifact_type=ARTIFACT_TYPE_PCAP)
        with self.assertRaises(ValueError):
            EvidenceRef(pcap_path="capture.pcap", artifact_type="made_up")

    def test_sequence_and_capture_sequence_must_agree(self):
        with self.assertRaises(ValueError):
            EvidenceRef(pcap_path="a.pcap", capture_sequence=1, sequence=2)

    def test_reversed_intervals_are_rejected(self):
        with self.assertRaises(ValueError):
            EvidenceRef(capture_start_ns=10, capture_end_ns=5)
        with self.assertRaises(ValueError):
            EvidenceRef(packet_start=10, packet_end=5)

    def test_zero_timestamped_windows_are_accepted_as_recorded(self):
        # The real recorded journal has windows with 0/0 bounds; a reference
        # must be able to carry that verbatim rather than reject it.
        ref = EvidenceRef(window_index=17, capture_start_ns=0, capture_end_ns=0)
        self.assertEqual(ref.capture_start_ns, 0)


class ArtifactInspectionTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.pcap = write_test_pcap(self.root)

    def test_pcap_interval_and_packet_count_come_from_the_file(self):
        info = read_pcap_interval(self.pcap)
        self.assertEqual(info["packet_count"], 4)
        self.assertEqual(info["link_type"], 1)
        self.assertEqual(info["capture_start_ns"], 1_700_000_000 * 10**9 + 500_000_000)
        self.assertEqual(info["capture_end_ns"], 1_700_000_003 * 10**9 + 500_000_000)

    def test_inspect_reports_identity_from_real_bytes(self):
        info = inspect_artifact(self.pcap, None)
        self.assertEqual(info.artifact_type, ARTIFACT_TYPE_PCAP)
        self.assertEqual(info.byte_size, os.path.getsize(self.pcap))
        self.assertEqual(len(info.artifact_sha256), 64)

    def test_truncated_pcap_yields_no_invented_interval(self):
        with open(self.pcap, "rb") as handle:
            data = handle.read()
        truncated = os.path.join(self.root, "short.pcap")
        with open(truncated, "wb") as handle:
            handle.write(data[: len(data) - 20])
        self.assertEqual(read_pcap_interval(truncated), {})

    def test_pcapng_container_is_not_guessed_at(self):
        container = os.path.join(self.root, "modern.pcapng")
        with open(container, "wb") as handle:
            handle.write(struct.pack("<I", 0x0A0D0D0A) + b"\x00" * 40)
        self.assertEqual(read_pcap_interval(container), {})

    def test_unsupported_extension_is_rejected(self):
        other = os.path.join(self.root, "notes.txt")
        with open(other, "w", encoding="utf-8") as handle:
            handle.write("x")
        with self.assertRaises(ValueError):
            inspect_artifact(other, None)

    def test_jsonl_artifact_is_classified_without_a_capture_interval(self):
        path = os.path.join(self.root, "events.jsonl")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write('{"ts":1}\n')
        info = inspect_artifact(path, None)
        self.assertEqual(info.artifact_type, ARTIFACT_TYPE_XDP_JSONL)
        self.assertIsNone(info.capture_start_ns)


class RootContainmentTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        write_test_pcap(self.root, "inside.pcap")

    def test_relative_path_inside_root_resolves(self):
        self.assertIsNotNone(resolve_within_root("inside.pcap", self.root))

    def test_parent_traversal_is_refused(self):
        self.assertIsNone(resolve_within_root("../inside.pcap", self.root))
        self.assertIsNone(resolve_within_root("../../etc/passwd", self.root))

    def test_absolute_path_is_refused_under_a_root(self):
        self.assertIsNone(resolve_within_root("/etc/passwd", self.root))

    def test_symlink_escape_is_refused(self):
        outside = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, outside, True)
        target = write_test_pcap(outside, "secret.pcap")
        link = os.path.join(self.root, "link.pcap")
        os.symlink(target, link)
        self.assertIsNone(resolve_within_root("link.pcap", self.root))

    def test_inspect_refuses_a_traversing_path(self):
        with self.assertRaises(ValueError):
            inspect_artifact("../inside.pcap", self.root)


class IdentityBindingTest(unittest.TestCase):
    """Negative tests: wrong run / experiment / window must be rejected."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.pcap = write_test_pcap(self.root)
        self.ref = make_ref(self.pcap, window_index=5)

    def test_binding_to_a_foreign_run_is_rejected(self):
        with self.assertRaises(EvidenceIdentityMismatch):
            self.ref.with_window(window_index=5, run_id="some-other-run")

    def test_binding_to_a_foreign_experiment_is_rejected(self):
        with self.assertRaises(EvidenceIdentityMismatch):
            self.ref.with_window(window_index=5, experiment_id="run-1-exp-0002")

    def test_binding_to_a_foreign_sequence_is_rejected(self):
        with self.assertRaises(EvidenceIdentityMismatch):
            self.ref.with_window(window_index=5, sequence=2)

    def test_rebinding_to_a_sibling_window_is_rejected(self):
        with self.assertRaises(EvidenceIdentityMismatch):
            self.ref.with_window(window_index=6)
        with self.assertRaises(EvidenceIdentityMismatch):
            bind_window([self.ref], window_index=6)

    def test_rebinding_the_same_window_is_idempotent(self):
        once = self.ref.with_window(window_index=5)
        twice = once.with_window(window_index=5)
        self.assertEqual(once, twice)
        self.assertEqual(once.evidence_id, twice.evidence_id)

    def test_a_window_never_inherits_a_sibling_windows_artifact(self):
        w5 = self.ref.with_window(window_index=5)
        catalog = EvidenceCatalog()
        catalog.register(w5)
        self.assertEqual(len(catalog.for_window("run-1", 5)), 1)
        self.assertEqual(catalog.for_window("run-1", 6), ())
        self.assertEqual(catalog.for_window("other-run", 5), ())

    def test_merge_is_idempotent_and_order_stable(self):
        first = merge_evidence_refs([self.ref])
        self.assertEqual(merge_evidence_refs(first), first)
        self.assertEqual(merge_evidence_refs([self.ref], [self.ref]), first)
        self.assertEqual(len(merge_evidence_refs([self.ref], [self.ref])), 1)


class IntegrityTest(unittest.TestCase):
    """Negative tests: missing artifact and corrupted artifact."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.pcap = write_test_pcap(self.root)
        self.ref = make_ref(self.pcap)

    def test_real_artifact_verifies_valid(self):
        verification = self.ref.verify(self.root)
        self.assertEqual(verification.status, EVIDENCE_STATUS_VALID)
        self.assertEqual(verification.actual_sha256, self.ref.artifact_sha256)

    def test_missing_artifact_is_unavailable_not_substituted(self):
        ref = make_ref(self.pcap)
        os.remove(self.pcap)
        verification = ref.verify(self.root)
        self.assertEqual(verification.status, EVIDENCE_STATUS_UNAVAILABLE)
        self.assertFalse(verification.artifact_present)

    def test_corrupted_artifact_is_invalid_and_never_repaired(self):
        ref = make_ref(self.pcap)
        original_digest = ref.artifact_sha256
        with open(self.pcap, "ab") as handle:
            handle.write(b"tampered")
        verification = ref.verify(self.root)
        self.assertEqual(verification.status, EVIDENCE_STATUS_INVALID)
        self.assertNotEqual(verification.actual_sha256, original_digest)
        self.assertEqual(verification.expected_sha256, original_digest)
        # The reference is not silently updated to the new bytes, and the file
        # is left exactly as found -- verification never repairs or rewrites.
        self.assertEqual(ref.artifact_sha256, original_digest)
        self.assertEqual(
            EvidenceRef.from_dict(ref.to_dict()).artifact_sha256, original_digest
        )

    def test_reference_without_a_digest_is_unverified_not_valid(self):
        ref = EvidenceRef(pcap_path=self.pcap, source="training_pcap")
        self.assertEqual(ref.verify(self.root).status, EVIDENCE_STATUS_UNVERIFIED)

    def test_verification_reports_a_size_drift_without_claiming_failure(self):
        ref = self.ref
        self.assertEqual(ref.verify(self.root).status, EVIDENCE_STATUS_VALID)
        # A reference whose recorded byte_size drifted still verifies: the
        # digest is the authority, and the drift is described in the detail.
        drifted = EvidenceRef(
            pcap_path=ref.pcap_path, capture_sequence=ref.capture_sequence,
            source=ref.source, artifact_type=ref.artifact_type,
            artifact_sha256=ref.artifact_sha256,
            byte_size=(ref.byte_size or 0) + 5,
            run_id=ref.run_id, experiment_id=ref.experiment_id,
            sequence=ref.sequence, window_index=ref.window_index,
            capture_start_ns=ref.capture_start_ns,
            capture_end_ns=ref.capture_end_ns,
        )
        verification = drifted.verify(self.root)
        self.assertEqual(verification.status, EVIDENCE_STATUS_VALID)
        self.assertIn("size", verification.detail)

    def test_catalog_verifies_every_registered_reference(self):
        catalog = EvidenceCatalog(evidence_root=self.root)
        catalog.register(self.ref)
        os.remove(self.pcap)
        self.assertEqual(catalog.integrity_summary(),
                         {EVIDENCE_STATUS_UNAVAILABLE: 1})

    def test_unknown_id_reports_unavailable_instead_of_raising(self):
        catalog = EvidenceCatalog(evidence_root=self.root)
        self.assertEqual(catalog.verify("ev-nope").status,
                         EVIDENCE_STATUS_UNAVAILABLE)

    def test_a_registered_id_cannot_be_repointed_at_other_content(self):
        catalog = EvidenceCatalog(evidence_root=self.root)
        catalog.register(self.ref)
        impostor = EvidenceRef(
            pcap_path=self.pcap, run_id="run-1", experiment_id="run-1-exp-0001",
            sequence=1, artifact_sha256="ab" * 32, source="training_pcap",
        )
        impostor = EvidenceRef(
            pcap_path=self.pcap, run_id="run-1", experiment_id="run-1-exp-0001",
            sequence=1, artifact_sha256="cd" * 32, source="training_pcap",
        )
        # A different content set yields a different id, so it is simply a
        # second reference rather than a silent overwrite.
        self.assertNotEqual(impostor.evidence_id, self.ref.evidence_id)
        catalog.register(impostor)
        self.assertEqual(len(catalog.all()), 2)


class WindowCoverageTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.pcap = write_test_pcap(self.root)
        self.ref = make_ref(self.pcap)

    def test_overlapping_window_is_covered_at_capture_granularity(self):
        result = window_packet_coverage(
            self.ref, self.ref.capture_start_ns, self.ref.capture_end_ns
        )
        self.assertTrue(result["covered"])
        self.assertIsNone(result["packet_start"])
        self.assertIn("capture granularity", result["reason"])

    def test_window_in_another_clock_domain_is_not_forced_onto_packets(self):
        result = window_packet_coverage(self.ref, 0, 100)
        self.assertFalse(result["covered"])
        self.assertIsNone(result["packet_start"])
        self.assertIsNone(result["packet_end"])
        self.assertIn("different clock domains", result["reason"])

    def test_missing_bounds_are_reported_not_guessed(self):
        result = window_packet_coverage(self.ref, None, None)
        self.assertFalse(result["covered"])
        self.assertIn("no time bounds", result["reason"])


class AutomaticPropagationTest(unittest.TestCase):
    """observation -> comparison -> risk -> response, with no manual join.

    These run the REAL Phase-4 comparison engine and the REAL risk engine over a
    real plan sample, so the propagation is exercised through the actual
    pipeline rather than a hand-built correlation.
    """

    def setUp(self):
        from risk_fixtures import (
            build_identity,
            build_observed,
            expected_from_plan_sample,
            plan_samples,
        )

        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.pcap = write_test_pcap(self.root)
        self.ref = make_ref(self.pcap, window_index=11)
        self.identity = build_identity(dataset_run_id="run-1",
                                       experiment_id="run-1-exp-0001",
                                       window_index=11)
        # A WEAK-posture real plan sample, so the run produces genuine findings
        # (a STRONG sample yields none for a single contradicted variable).
        weak = next(s for s in plan_samples() if s["security_posture"] == "WEAK")
        self.expected = expected_from_plan_sample(weak)
        self.observed = build_observed()

    def _mismatch_correlation(self, evidence):
        """A real comparison whose mismatching variables carry the evidence.

        One observed value is deliberately contradicted so the run produces a
        genuine MISMATCH (and therefore real findings) rather than an all-MATCH
        comparison that would carry evidence but assert nothing.
        """
        observed_values = observed_values_for(self.expected)
        observed_values["esp.encryption"] = "aes128gcm16"
        return run_comparison(
            self.expected, self.observed,
            identity=self.identity, observed_identity=self.identity,
            observed_values=observed_values,
            evidence_refs=evidence,
        )

    def test_comparison_carries_the_reference(self):
        correlation = self._mismatch_correlation([self.ref])
        self.assertEqual(evidence_from_comparison(correlation), (self.ref,))

    def test_risk_derives_evidence_from_the_comparison_with_no_caller_input(self):
        correlation = self._mismatch_correlation([self.ref])
        # NOTE: no evidence_refs passed to assess() -- the whole point.
        assessment = RiskEngine().assess(expected=self.expected,
                                         correlation=correlation)
        self.assertEqual(assessment.evidence_refs, (self.ref,))

    def test_evidence_survives_an_ml_failure(self):
        """ML unavailable must not destroy the evidence relationship."""
        correlation = self._mismatch_correlation([self.ref])
        assessment = RiskEngine().assess(expected=self.expected,
                                         correlation=correlation,
                                         ml_result=None)
        self.assertEqual(assessment.evidence_refs, (self.ref,))
        self.assertTrue(assessment.findings,
                        "a mismatch must still produce findings without ML")

    def test_an_explicit_caller_set_wins_over_the_derived_one(self):
        correlation = self._mismatch_correlation([self.ref])
        other = EvidenceRef(pcap_path=self.pcap, run_id="run-9",
                            artifact_sha256="ab" * 32, source="training_pcap")
        assessment = RiskEngine().assess(expected=self.expected,
                                         correlation=correlation,
                                         evidence_refs=[other])
        self.assertEqual(assessment.evidence_refs, (other,))

    def test_a_finding_without_evidence_stays_valid_and_invents_nothing(self):
        correlation = self._mismatch_correlation([])
        assessment = RiskEngine().assess(expected=self.expected,
                                         correlation=correlation)
        self.assertEqual(assessment.evidence_refs, ())
        self.assertEqual(evidence_from_comparison(correlation), ())
        # The run is still a valid assessment; only the evidence is absent.
        self.assertIsNotNone(assessment.severity)

    def test_malformed_reference_in_an_outcome_is_skipped_not_propagated(self):
        from risk_fixtures import make_correlation

        correlation = make_correlation(
            self.identity,
            mismatches=[{
                "variable": "esp.encryption",
                "status": "MISMATCH",
                "expected_value": "aes256gcm16",
                "observed_value": "aes128gcm16",
                "evidence_refs": [{"artifact_sha256": "too-short"}],
            }],
        )
        self.assertEqual(evidence_from_comparison(correlation), ())


class AuditEvidenceEventTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.pcap = write_test_pcap(self.root)
        self.ref = make_ref(self.pcap, window_index=3)

    def test_evidence_source_is_never_authoritative(self):
        self.assertFalse(SOURCE_AUTHORITATIVE[SOURCE_EVIDENCE])
        with self.assertRaises(ValueError):
            from correlation.audit import AuditEvent, validate_source

            validate_source(SOURCE_EVIDENCE, True)

    def test_evidence_event_records_references_not_bytes(self):
        from correlation.audit import AuditEvent

        event = AuditEvent(
            event_type=EVENT_EVIDENCE,
            source=SOURCE_EVIDENCE,
            authoritative=False,
            identity=CorrelationIdentity(
                dataset_run_id="run-1", sequence=1, attempt_number=1,
                experiment_id="run-1-exp-0001", window_index=3,
            ),
            evidence_refs=(self.ref,),
        )
        payload = event.to_dict()
        self.assertEqual(payload["evidence_refs"][0]["evidence_id"],
                         self.ref.evidence_id)
        blob = json.dumps(payload)
        self.assertNotIn("packet_data", blob)
        # The recorded bytes of the artifact must not appear in the event.
        with open(self.pcap, "rb") as handle:
            raw = handle.read()
        self.assertNotIn(raw[:16].hex(), blob)

    def test_evidence_refs_are_covered_by_the_event_id(self):
        from correlation.audit import AuditEvent

        base = dict(
            event_type=EVENT_EVIDENCE, source=SOURCE_EVIDENCE, authoritative=False,
            identity=CorrelationIdentity(
                dataset_run_id="run-1", sequence=1, attempt_number=1,
                experiment_id="run-1-exp-0001", window_index=3,
            ),
            evidence_refs=(self.ref,),
        )
        original = AuditEvent(**base)
        payload = original.to_dict()
        payload["evidence_refs"][0]["window_index"] = 4
        with self.assertRaises(ValueError):
            AuditEvent.from_dict(payload)


class EvidenceApiTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.pcap = write_test_pcap(self.root)
        self.ref = make_ref(self.pcap, window_index=5)
        registry = PcapRegistry(root=self.root)
        registry.register(self.ref.evidence_id, "cap.pcap")
        registry.register_reference(self.ref)
        self.context = Phase10Context(pcap=PcapService(registry=registry))

    def test_reference_is_served_with_integrity_and_no_bytes(self):
        body, content_type = v1.handle_v1_get(
            self.context, f"/api/v1/evidence/{self.ref.evidence_id}"
        )
        self.assertEqual(content_type, "application/json")
        self.assertEqual(body["evidence_id"], self.ref.evidence_id)
        self.assertEqual(body["integrity"]["status"], EVIDENCE_STATUS_VALID)
        self.assertEqual(body["reference"]["artifact_sha256"],
                         self.ref.artifact_sha256)
        self.assertFalse(body["authoritative"])
        self.assertNotIn("bytes", body["reference"])

    def test_list_route_exposes_references(self):
        body, _ = v1.handle_v1_get(self.context, "/api/v1/evidence")
        self.assertEqual(body["api"], "evidence-list")
        self.assertEqual(body["evidence_count"], 1)
        self.assertEqual(body["evidence"][0]["evidence_id"], self.ref.evidence_id)

    def test_run_route_groups_evidence_by_window(self):
        body, _ = v1.handle_v1_get(self.context, "/api/v1/runs/run-1/evidence")
        self.assertEqual(body["run_id"], "run-1")
        self.assertEqual(body["windows"][0]["window_index"], 5)

    def test_run_route_can_narrow_to_one_window(self):
        body, _ = v1.handle_v1_get(
            self.context, "/api/v1/runs/run-1/evidence",
            {"window_index": "5"},
        )
        self.assertEqual(body["evidence_count"], 1)
        with self.assertRaises(ApiError) as raised:
            v1.handle_v1_get(self.context, "/api/v1/runs/run-1/evidence",
                             {"window_index": "6"})
        self.assertEqual(raised.exception.status, 404)

    def test_run_route_rejects_a_non_integer_window(self):
        with self.assertRaises(ApiError) as raised:
            v1.handle_v1_get(self.context, "/api/v1/runs/run-1/evidence",
                             {"window_index": "abc"})
        self.assertEqual(raised.exception.status, 400)

    def test_unknown_ids_are_404_not_guessed(self):
        for path in ("/api/v1/evidence/ev-nope",
                     "/api/v1/runs/other-run/evidence"):
            with self.assertRaises(ApiError) as raised:
                v1.handle_v1_get(self.context, path)
            self.assertEqual(raised.exception.status, 404)

    def test_no_route_accepts_a_filesystem_path(self):
        for path in ("/api/v1/evidence/..%2F..%2Fetc%2Fpasswd",
                     "/api/v1/evidence/../../etc/passwd",
                     "/api/v1/evidence//etc/passwd"):
            with self.assertRaises(ApiError):
                v1.handle_v1_get(self.context, path)

    def test_pcap_bytes_remain_behind_the_existing_download_route(self):
        descriptor, _ = v1.handle_v1_get(
            self.context, f"/api/v1/evidence/{self.ref.evidence_id}/pcap"
        )
        self.assertEqual(descriptor["evidence_id"], self.ref.evidence_id)
        data = self.context.pcap.download(self.ref.evidence_id)
        self.assertEqual(data[:4], b"\xd4\xc3\xb2\xa1")

    def test_registry_reference_registration_is_type_checked(self):
        registry = PcapRegistry(root=self.root)
        with self.assertRaises(TypeError):
            registry.register_reference("not-a-ref")
        with self.assertRaises(TypeError):
            registry.register_reference({"evidence_id": "ev-x"})

    def test_registering_a_reference_is_idempotent(self):
        registry = PcapRegistry(root=self.root)
        first = registry.register_reference(self.ref)
        second = registry.register_reference(self.ref)
        self.assertEqual(first, second)
        self.assertEqual(len(registry.references()), 1)

    def test_event_evidence_route_requires_an_attached_journal(self):
        with self.assertRaises(ApiError) as raised:
            v1.handle_v1_get(
                self.context, "/api/v1/audit/events/audit-x/evidence"
            )
        self.assertEqual(raised.exception.status, 503)


class RealRecordedEvidenceTest(unittest.TestCase):
    """End-to-end over the committed capture and analysis journal."""

    def setUp(self):
        self.pcap_rel = discover_capture(REAL_RUN, 1, REAL_EXPERIMENT, 1,
                                         evidence_root=REPO_ROOT)
        self.ref = evidence_from_artifact(
            self.pcap_rel, evidence_root=REPO_ROOT, run_id=REAL_RUN,
            experiment_id=REAL_EXPERIMENT, sequence=1,
        )

    def test_the_real_capture_is_a_verifying_reference(self):
        self.assertEqual(self.ref.artifact_type, ARTIFACT_TYPE_PCAP)
        self.assertEqual(self.ref.verify(REPO_ROOT).status, EVIDENCE_STATUS_VALID)
        self.assertEqual(len(self.ref.artifact_sha256), 64)
        self.assertGreater(self.ref.byte_size, 0)

    def test_composed_path_matches_the_committed_layout(self):
        self.assertEqual(
            self.pcap_rel,
            "results/datasets/acc-eng-02/captures/0001/"
            "acc-eng-02-exp-0001-attempt-01.pcap",
        )
        self.assertEqual(
            capture_relative_path(REAL_RUN, 1, REAL_EXPERIMENT, 1), self.pcap_rel
        )

    def test_real_capture_interval_comes_from_the_file(self):
        self.assertIsNotNone(self.ref.capture_start_ns)
        self.assertLessEqual(self.ref.capture_start_ns, self.ref.capture_end_ns)

    def test_no_capture_exists_for_an_unknown_experiment(self):
        with self.assertRaises(ValueError):
            discover_capture(REAL_RUN, 1, "acc-eng-02-exp-9999", 1,
                             evidence_root=REPO_ROOT)


class JournalBackedEvidenceApiTest(unittest.TestCase):
    """The journal is the only source of which evidence ids exist."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.pcap = write_test_pcap(self.root)
        self.ref = make_ref(self.pcap, window_index=2)
        self.registry = PcapRegistry(root=self.root)
        self.store = AuditStore(str(HEALTHY_JOURNAL))
        self.context = Phase10Context(pcap=PcapService(registry=self.registry))
        self.context.attach_audit_store(self.store)

    def test_journal_references_are_registered_and_verified(self):
        summary = register_journal_evidence(self.store, self.registry,
                                           root=REPO_ROOT)
        self.assertEqual(summary["registered"], 44)
        self.assertEqual(summary["skipped"], [])
        served = self.registry.reference(
            [e.evidence_refs[0].evidence_id for e in self.store.select()
             if e.event_type == "evidence"][0]
        )
        self.assertIsNotNone(served)
        self.assertEqual(served.artifact_sha256,
                         "bfd5c205549eedb460ede653c9458e1774245c27af01cec04219244a7551087d")

    def test_a_reference_outside_the_root_is_skipped_not_served(self):
        outside = EvidenceRef(pcap_path="/etc/hosts",
                              artifact_sha256="ab" * 32, source="training_pcap")
        registry = PcapRegistry(root=self.root)
        summary = register_journal_evidence(_StoreWithRefs([outside]), registry,
                                           root=self.root)
        self.assertEqual(summary["registered"], 0)
        self.assertEqual(len(summary["skipped"]), 1)
        self.assertIsNone(registry.reference(outside.evidence_id))

    def test_a_recorded_window_with_no_evidence_is_empty_not_missing(self):
        """A window that was analysed but has no capture answers 0, not 404."""
        register_journal_evidence(self.store, self.registry, root=REPO_ROOT)
        # window 43 is the last real window; strip its reference so the window
        # still exists in the journal but carries no evidence at all.
        self.registry._references.pop(
            [e.evidence_refs[0].evidence_id for e in self.store.select()
             if e.event_type == "evidence" and e.identity.window_index == 43][0],
            None,
        )
        body, _ = v1.handle_v1_get(
            self.context, "/api/v1/runs/acc-eng-02/evidence",
            {"window_index": "43"},
        )
        self.assertEqual(body["evidence_count"], 0)
        self.assertEqual(body["windows"][0]["evidence"], [])
        self.assertIn("no evidence reference", body["no_evidence_reason"])

    def test_a_window_that_does_not_exist_is_a_404(self):
        register_journal_evidence(self.store, self.registry, root=REPO_ROOT)
        with self.assertRaises(ApiError) as raised:
            v1.handle_v1_get(self.context, "/api/v1/runs/acc-eng-02/evidence",
                             {"window_index": "9999"})
        self.assertEqual(raised.exception.status, 404)

    def test_evidence_survives_the_ml_failure_journal(self):
        store = AuditStore(str(ML_FAILURE_JOURNAL))
        registry = PcapRegistry(root=REPO_ROOT)
        summary = register_journal_evidence(store, registry, root=REPO_ROOT)
        self.assertEqual(summary["registered"], 44)
        failures = [e for e in store.select() if e.event_type == "ml_failure"]
        self.assertEqual(len(failures), 44)
        context = Phase10Context(pcap=PcapService(registry=registry))
        context.attach_audit_store(store)
        body, _ = v1.handle_v1_get(
            context, f"/api/v1/audit/events/{failures[0].event_id}/evidence"
        )
        self.assertEqual(body["evidence_count"], 1)
        self.assertEqual(
            body["evidence"][0]["integrity"]["status"], EVIDENCE_STATUS_VALID
        )


class _StoreWithRefs:
    """Minimal audit-store stand-in exposing only what registration reads."""

    def __init__(self, refs):
        self._refs = refs

    def select(self):
        return [_EventWithRefs(ref) for ref in self._refs]


class _EventWithRefs:
    def __init__(self, ref):
        self.evidence_refs = (ref,)


class ResponseLifecycleEvidenceTest(unittest.TestCase):
    """Evidence must survive the whole response lifecycle, not just the plan."""

    def setUp(self):
        self.root = REPO_ROOT
        self.store = AuditStore(HEALTHY_JOURNAL)
        self.registry = PcapRegistry(root=REPO_ROOT)
        register_journal_evidence(self.store, self.registry, root=REPO_ROOT)
        self.ledger = AuditLedger()
        self.store.response_ledger = self.ledger
        self.context = Phase10Context(pcap=PcapService(registry=self.registry))
        self.context.attach_audit_store(self.store)

        self.ref = EvidenceRef(
            pcap_path="results/datasets/acc-eng-02/captures/0001/"
                      "acc-eng-02-exp-0001-attempt-01.pcap",
            run_id="run-1", experiment_id="run-1-exp-0001", sequence=1,
            window_index=11,
            artifact_sha256=REAL_SHA256, byte_size=270276, source="training_pcap",
        )
        weak = next(s for s in plan_samples() if s["security_posture"] == "WEAK")
        self.expected = expected_from_plan_sample(weak)
        identity = build_identity(dataset_run_id="run-1",
                                  experiment_id="run-1-exp-0001", window_index=11)
        values = observed_values_for(self.expected)
        values["esp.encryption"] = "aes256gcm16"
        self.correlation = run_comparison(
            self.expected, build_observed(), identity=identity,
            observed_identity=identity, observed_values=values,
            evidence_refs=[self.ref],
        )
        self.assessment = RiskEngine().assess(expected=self.expected,
                                             correlation=self.correlation)

    def _plan(self):
        engine = ResponseEngine(policy=response_policy(), clock=demo_clock,
                                ledger=self.ledger)
        plan = engine.plan(self.assessment, correlation=self.correlation)
        return engine, plan

    def test_the_finder_and_the_proposal_carry_the_reference_automatically(self):
        self.assertTrue(self.assessment.findings)
        self.assertEqual(self.assessment.evidence_refs, (self.ref,))
        for finding in self.assessment.findings:
            self.assertEqual(finding.evidence_refs, (self.ref,))
        engine, plan = self._plan()
        self.assertTrue(plan.recommendations)
        for rec in plan.recommendations:
            self.assertEqual(rec.evidence_refs, (self.ref,))

    def test_evidence_reaches_the_response_api_and_verifies(self):
        engine, plan = self._plan()
        rec = plan.recommendations[0]
        body, _ = v1.handle_v1_get(
            self.context, f"/api/v1/responses/{rec.recommendation_id}/evidence"
        )
        self.assertEqual(body["api"], "response-evidence")
        self.assertGreaterEqual(body["evidence_count"], 1)
        payload = body["evidence"][0]
        self.assertEqual(payload["evidence_id"], self.ref.evidence_id)
        self.assertEqual(payload["integrity"]["status"], EVIDENCE_STATUS_VALID)
        self.assertEqual(payload["reference"]["artifact_sha256"], REAL_SHA256)
        self.assertTrue(body["read_only"])

    def test_approval_authorization_and_dry_run_keep_the_reference(self):
        engine, plan = self._plan()
        rec = plan.recommendations[0]
        approval = engine.request_approval(rec, "analyst-1")
        engine.approve(approval, rec, "analyst-1", roles=(ROLE_ANALYST,))
        engine.authorize(rec, auth_context("operator-1",
                                           (ROLE_SECURITY_OPERATOR,)))
        engine.execute_dry_run(rec, auth_context("operator-1",
                                                 (ROLE_SECURITY_OPERATOR,)),
                               "operator-1")
        seen = {e.event_type for e in self.ledger.events()}
        for wanted in ("RECOMMENDATION_CREATED", "APPROVAL_REQUESTED", "APPROVED",
                       "AUTHORIZATION_CHECKED"):
            self.assertIn(wanted, seen)
        for event in self.ledger.events():
            self.assertEqual(event.evidence_refs, (self.ref,),
                             f"{event.event_type} dropped the reference")
        self.assertTrue(self.ledger.verify())
        body, _ = v1.handle_v1_get(
            self.context, f"/api/v1/responses/{rec.recommendation_id}/evidence"
        )
        self.assertGreaterEqual(body["evidence_count"], 1)

    def test_evidence_does_not_imply_authorization_or_execution(self):
        engine, plan = self._plan()
        rec = plan.recommendations[0]
        body, _ = v1.handle_v1_get(
            self.context, f"/api/v1/responses/{rec.recommendation_id}/evidence"
        )
        stages = {e["event_type"] for e in body["lifecycle"]}
        self.assertIn("RECOMMENDATION_CREATED", stages)
        for claimed in ("AUTHORIZATION_CHECKED", "EXECUTED", "AUTHORIZED"):
            self.assertNotIn(claimed, stages)
        # evidence_count is reported per lifecycle record as recorded
        self.assertTrue(all(e["evidence_count"] >= 1 for e in body["lifecycle"]))

    def test_a_finding_without_evidence_stays_valid_and_invents_nothing(self):
        values = observed_values_for(self.expected)
        values["esp.encryption"] = "aes256gcm16"
        identity = build_identity(dataset_run_id="run-1",
                                  experiment_id="run-1-exp-0001", window_index=11)
        bare = RiskEngine().assess(
            expected=self.expected,
            correlation=run_comparison(self.expected, build_observed(),
                                       identity=identity,
                                       observed_identity=identity,
                                       observed_values=values),
        )
        self.assertTrue(bare.findings)
        self.assertEqual(bare.evidence_refs, ())
        engine = ResponseEngine(policy=response_policy(), clock=demo_clock,
                                ledger=self.ledger)
        plan = engine.plan(bare)
        for rec in plan.recommendations:
            self.assertEqual(rec.evidence_refs, ())


class PerWindowBindingTest(unittest.TestCase):
    """``bind_window`` is what stops a window inheriting another window.

    ``audit_run`` also accepts a flat reference sequence for convenience, but a
    flat sequence attaches the same artifact to every window. The binding logic
    is what makes the per-window mapping safe, so it is pinned directly here;
    the full 44-window run is verified end-to-end over HTTP against the real
    journal in the live evidence traversal.
    """

    def _ref(self, name, window=None):
        return EvidenceRef(
            pcap_path=f"captures/{name}.pcap", run_id="run-1",
            experiment_id="run-1-exp-0001", sequence=1, window_index=window,
            artifact_sha256="ab" * 32, source="training_pcap",
        )

    def test_binding_stamps_the_window_and_makes_a_new_id(self):
        shared = self._ref("run-wide")
        bound = bind_window([shared], window_index=4, run_id="run-1",
                            experiment_id="run-1-exp-0001", sequence=1)
        self.assertEqual(len(bound), 1)
        self.assertEqual(bound[0].window_index, 4)
        self.assertNotEqual(bound[0].evidence_id, shared.evidence_id)

    def test_the_same_artifact_in_two_windows_stays_two_addressable_ids(self):
        shared = self._ref("run-wide")
        first = bind_window([shared], window_index=0, run_id="run-1",
                            experiment_id="run-1-exp-0001", sequence=1)
        second = bind_window([shared], window_index=1, run_id="run-1",
                             experiment_id="run-1-exp-0001", sequence=1)
        self.assertNotEqual(first[0].evidence_id, second[0].evidence_id)
        self.assertEqual(first[0].pcap_path, second[0].pcap_path)

    def test_binding_refuses_a_reference_that_names_a_different_window(self):
        """A ref already addressed to window 0 cannot be smuggled into window 1."""
        with self.assertRaises(EvidenceIdentityMismatch):
            bind_window([self._ref("w0", 0)], window_index=1, run_id="run-1",
                        experiment_id="run-1-exp-0001", sequence=1)

    def test_a_window_absent_from_the_map_is_simply_absent(self):
        mapping = evidence_map_for_windows({1: [self._ref("w1")]})
        self.assertEqual(sorted(mapping), [1])
        self.assertNotIn(0, mapping)
        self.assertNotIn(2, mapping)

    def test_binding_is_idempotent_for_an_already_bound_reference(self):
        once = bind_window([self._ref("w0")], window_index=2, run_id="run-1",
                           experiment_id="run-1-exp-0001", sequence=1)
        twice = bind_window(once, window_index=2, run_id="run-1",
                            experiment_id="run-1-exp-0001", sequence=1)
        self.assertEqual(once[0].evidence_id, twice[0].evidence_id)

    def test_binding_preserves_several_references_in_order(self):
        bound = bind_window([self._ref("a"), self._ref("b")], window_index=0,
                            run_id="run-1", experiment_id="run-1-exp-0001",
                            sequence=1)
        self.assertEqual([r.pcap_path for r in bound],
                         ["captures/a.pcap", "captures/b.pcap"])


if __name__ == "__main__":
    unittest.main()
