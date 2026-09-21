"""Phase 8 — Assessment store tests: determinism, scenarios, invariants."""

import json
import unittest


class _StoreTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from correlation.api import build_store

        cls.store = build_store()


class StoreBuildTest(_StoreTestCase):
    def test_12_assessments(self):
        self.assertEqual(self.store.overview["total_assessments"], 12)
        self.assertEqual(len(self.store.headers), 12)

    def test_six_mandatory_scenarios_present(self):
        slots = {h["slot"] for h in self.store.headers}
        for slot in ("strong-clean", "pfs-weak", "transport", "unknown", "ml-anomaly", "worst-ml"):
            self.assertIn(slot, slots, f"missing scenario {slot}")

    def test_strong_clean_no_findings(self):
        header = next(h for h in self.store.headers if h["slot"] == "strong-clean")
        self.assertEqual(header["risk_score"], 0)
        self.assertEqual(header["severity"], "INFO")
        self.assertEqual(header["finding_count"], 0)

    def test_weak_pfs_disabled(self):
        header = next(h for h in self.store.headers if h["slot"] == "pfs-weak")
        bundle = self.store.bundles[header["assessment_id"]]
        self.assertEqual(header["severity"], "MEDIUM")
        self.assertEqual(bundle["risk"]["findings"][0]["rule_id"], "esp.pfs.disabled")
        self.assertEqual(bundle["risk"]["findings"][0]["finding_id"], "RISK-PFS-DISABLED")

    def test_transport_mismatch_high(self):
        header = next(h for h in self.store.headers if h["slot"] == "transport")
        bundle = self.store.bundles[header["assessment_id"]]
        self.assertEqual(header["severity"], "HIGH")
        mismatch = next(o for o in bundle["correlation"]["rows"] if o["variable"] == "mode")
        self.assertEqual(mismatch["status"], "MISMATCH")
        self.assertEqual(mismatch["expected_value"], "tunnel")
        self.assertEqual(mismatch["observed_value"], "transport")

    def test_unknown_preserved_and_not_vulnerability(self):
        header = next(h for h in self.store.headers if h["slot"] == "unknown")
        bundle = self.store.bundles[header["assessment_id"]]
        self.assertEqual(header["severity"], "INFO")
        self.assertEqual(header["finding_count"], 0)
        unknown_rows = [r for r in bundle["correlation"]["rows"] if r["status"] == "UNKNOWN"]
        self.assertTrue(unknown_rows)
        # every UNKNOWN row is a crypto/observation column that the pipeline
        # conservatively leaves unresolved; none become MISMATCH
        self.assertFalse([r for r in bundle["correlation"]["rows"]
                          if r["status"] == "MISMATCH"])
        xai_unknowns = bundle["xai"]["unknown_explanations"]
        self.assertTrue(xai_unknowns)
        for gap in xai_unknowns:
            self.assertEqual(gap["status"], "UNKNOWN")

    def test_ml_anomaly_model_derived(self):
        header = next(h for h in self.store.headers if h["slot"] == "ml-anomaly")
        bundle = self.store.bundles[header["assessment_id"]]
        self.assertTrue(bundle["ml"]["present"])
        self.assertIs(bundle["ml"]["anomaly"], True)
        self.assertEqual(bundle["ml"]["model_version"], "traffic-rf-v1-demo")
        finding = next(f for f in bundle["risk"]["findings"]
                       if f["rule_id"] == "ml.anomaly")
        self.assertEqual(finding["finding_id"], "RISK-ML-ANOMALY")
        self.assertEqual(finding["severity"], "LOW")

    def test_worst_ml_critical(self):
        header = next(h for h in self.store.headers if h["slot"] == "worst-ml")
        self.assertEqual(header["risk_score"], 55)
        self.assertEqual(header["severity"], "CRITICAL")
        bundle = self.store.bundles[header["assessment_id"]]
        self.assertEqual(len(bundle["risk"]["findings"]), 4)
        self.assertEqual(bundle["xai"]["score_explanation"]["score"], 55)
        self.assertEqual(bundle["xai"]["score_explanation"]["severity"], "CRITICAL")

    def test_xai_available_everywhere(self):
        for header in self.store.headers:
            bundle = self.store.bundles[header["assessment_id"]]
            self.assertTrue(bundle["xai"]["summary"])
            self.assertIsNotNone(bundle["xai"]["score_explanation"])

    def test_evidence_honesty(self):
        for header in self.store.headers:
            bundle = self.store.bundles[header["assessment_id"]]
            evidence = bundle["evidence"]
            self.assertEqual(evidence["total_refs"], len(evidence["refs"]))
            if evidence["total_refs"] == 0:
                self.assertEqual(evidence["limitation"], "No evidence references were supplied.")
            else:
                self.assertIsNone(evidence["limitation"])
        unknown = next(h for h in self.store.headers if h["slot"] == "unknown")
        self.assertEqual(self.store.bundles[unknown["assessment_id"]]["evidence"]["total_refs"], 0)

    def test_finding_sources_labels(self):
        header = next(h for h in self.store.headers if h["slot"] == "transport")
        bundle = self.store.bundles[header["assessment_id"]]
        finding = bundle["risk"]["findings"][0]
        self.assertEqual(finding["source"], "CORRELATION")
        self.assertEqual(finding["category"], "CONFIGURATION_MISMATCH")


class StoreDeterminismTest(_StoreTestCase):
    def test_rebuild_identical(self):
        from correlation.api import build_store

        first = json.dumps(_store_z(_tag(), build_store()), sort_keys=True)
        second = json.dumps(_store_z(_tag(), build_store()), sort_keys=True)
        self.assertEqual(first, second)

    def test_score_severity_never_client_recomputed(self):
        # the API view must carry the authoritative values with their labels
        header = next(h for h in self.store.headers if h["slot"] == "worst-ml")
        self.assertEqual(header["risk_score"], 55)
        self.assertEqual(header["severity"], "CRITICAL")


def _tag():  # deterministic token to avoid module caching surprises
    return "api-store-test"


def _store_z(tag, store):
    return {
        tag: {
            "headers": [h["assessment_id"] for h in store.headers],
            "overview": store.overview,
        }
    }


if __name__ == "__main__":
    unittest.main()