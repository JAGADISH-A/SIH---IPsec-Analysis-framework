"""Phase 7 XAI evidence tests: exact preservation, dedup, no fabrication."""

import unittest

from correlation.models import EvidenceRef
from correlation.risk import CATEGORY_CONFIGURATION_WEAKNESS, SEVERITY_HIGH, SOURCE_CORRELATION, RiskFinding
from correlation.xai import build_evidence_summary, explain_finding

REF_A = EvidenceRef(
    pcap_path="results/datasets/dataset-20260916-231246/captures/1/x.pcap",
    capture_sequence=1,
    audit_event_reference="audit://tap-events.jsonl#100",
    source="training_pcap",
    timestamp="2026-09-16T23:12:46Z",
)
REF_B = EvidenceRef(
    pcap_path="results/datasets/dataset-20260916-231246/captures/2/y.pcap",
    capture_sequence=2,
    audit_event_reference="audit://tap-events.jsonl#220",
    source="audit_tap",
    timestamp="2026-09-16T23:13:20Z",
)


def make_finding(**overrides):
    base = dict(
        finding_id="RISK-MODE-MISMATCH",
        rule_id="correlation.mismatch.mode",
        category=CATEGORY_CONFIGURATION_WEAKNESS,
        severity=SEVERITY_HIGH,
        title="t",
        description="d",
        reason="r",
        condition="c",
        source=SOURCE_CORRELATION,
        evidence_type="observation",
        related_variable="mode",
    )
    base.update(overrides)
    return RiskFinding(**base)


class TestEvidenceSummary(unittest.TestCase):
    def test_refs_preserved_exactly(self):
        summary = build_evidence_summary(assessment_refs=(REF_A, REF_B))
        expected = [REF_A.to_dict(), REF_B.to_dict()]
        sorted_expected = sorted(expected, key=lambda d: d["capture_sequence"])
        self.assertEqual(list(summary.refs), sorted_expected)
        self.assertEqual(summary.total_refs, 2)
        self.assertFalse(summary.fabricated)

    def test_all_fields_preserved(self):
        summary = build_evidence_summary(assessment_refs=(REF_A,))
        ref = list(summary.refs)[0]
        self.assertEqual(ref["pcap_path"], REF_A.pcap_path)
        self.assertEqual(ref["capture_sequence"], 1)
        self.assertEqual(ref["audit_event_reference"], "audit://tap-events.jsonl#100")
        self.assertEqual(ref["source"], "training_pcap")
        self.assertEqual(ref["timestamp"], "2026-09-16T23:12:46Z")

    def test_dedup(self):
        summary = build_evidence_summary(
            assessment_refs=(REF_A,),
            caller_refs=(REF_A,),
            finding_refs=(REF_A,),
        )
        self.assertEqual(summary.total_refs, 1)
        self.assertEqual(list(summary.refs), [REF_A.to_dict()])

    def test_caller_and_finding_union(self):
        summary = build_evidence_summary(
            assessment_refs=(REF_A,),
            caller_refs=(REF_B,),
            finding_refs=(REF_A,),
        )
        self.assertEqual(summary.total_refs, 2)

    def test_source_counts(self):
        summary = build_evidence_summary(assessment_refs=(REF_A, REF_B))
        self.assertIn(("training_pcap", 1), summary.source_counts)
        self.assertIn(("audit_tap", 1), summary.source_counts)

    def test_empty_has_limitation(self):
        summary = build_evidence_summary(assessment_refs=())
        self.assertEqual(summary.total_refs, 0)
        self.assertEqual(summary.refs, ())
        self.assertIsNotNone(summary.limitation)
        self.assertIn("No evidence references were supplied", summary.limitation)

    def test_refuses_non_evidence(self):
        with self.assertRaises(ValueError):
            build_evidence_summary(assessment_refs=("not-an-evidence-ref",))
        with self.assertRaises(ValueError):
            build_evidence_summary(
                assessment_refs=(),
                caller_refs=[{"pcap_path": "made/up.pcap"}],
            )

    def test_sort_deterministic(self):
        a = build_evidence_summary(assessment_refs=(REF_B, REF_A))
        b = build_evidence_summary(assessment_refs=(REF_A, REF_B))
        self.assertEqual(a.to_dict(), b.to_dict())


class TestFindingEvidenceRefs(unittest.TestCase):
    def test_finding_uses_own_refs(self):
        f = make_finding(evidence_refs=(REF_A,))
        exp = explain_finding(f, evidence_refs=(REF_B,))
        self.assertEqual(list(exp.evidence_refs), [REF_A.to_dict()])

    def test_finding_falls_back_to_assessment_refs(self):
        f = make_finding()
        exp = explain_finding(f, evidence_refs=(REF_A,))
        self.assertEqual(list(exp.evidence_refs), [REF_A.to_dict()])

    def test_no_refs_never_fabricated(self):
        f = make_finding()
        exp = explain_finding(f, evidence_refs=())
        self.assertEqual(exp.evidence_refs, ())
        self.assertTrue(
            any("No PCAP or audit evidence reference was attached" in line
                for line in exp.limitations)
        )


if __name__ == "__main__":
    unittest.main()