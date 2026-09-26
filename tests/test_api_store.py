"""Phase 8 - Assessment store tests: real inputs, determinism, invariants.

The store used to be fed stand-ins (a formula-derived SPI snapshot, a two-key
feature window, an ``MLResult`` with a typed-in anomaly, and observed values
copied from the expected state). These tests pin the replacement: every input is
a recorded artifact, no assessment claims an anomaly the model cannot produce,
and what a passive sensor genuinely cannot establish stays UNKNOWN.

The provenance tests are the point. A dashboard that reports real findings while
quietly inventing its inputs is worse than one that reports less, so "the input
came from this file, with this digest" is asserted, not assumed.
"""

import json
import os
import unittest


class _StoreTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from correlation.api import build_store

        cls.store = build_store()

    def header(self, slot):
        return next(h for h in self.store.headers if h["slot"] == slot)

    def bundle(self, slot):
        return self.store.bundles[self.header(slot)["assessment_id"]]


class StoreBuildTest(_StoreTestCase):
    def test_12_assessments(self):
        self.assertEqual(self.store.overview["total_assessments"], 12)
        self.assertEqual(len(self.store.headers), 12)

    def test_every_scenario_slot_is_present(self):
        from correlation.api.store import SCENARIO_SLOTS

        slots = {h["slot"] for h in self.store.headers}
        for slot in SCENARIO_SLOTS:
            self.assertIn(slot, slots, f"missing scenario {slot}")

    def test_five_posture_bands_from_the_real_plan(self):
        from correlation.api.store import POSTURE_BANDS

        bands = {h["slot"] for h in self.store.headers
                 if h["slot"].startswith("band-")}
        self.assertEqual(bands, {f"band-{b.lower()}" for b in POSTURE_BANDS})

    def test_strong_clean_no_findings(self):
        header = self.header("strong-clean")
        self.assertEqual(header["risk_score"], 0)
        self.assertEqual(header["severity"], "INFO")
        self.assertEqual(header["finding_count"], 0)

    def test_weak_pfs_disabled(self):
        header = self.header("pfs-weak")
        bundle = self.bundle("pfs-weak")
        self.assertEqual(header["severity"], "MEDIUM")
        self.assertEqual(bundle["risk"]["findings"][0]["rule_id"], "esp.pfs.disabled")
        self.assertEqual(bundle["risk"]["findings"][0]["finding_id"], "RISK-PFS-DISABLED")

    def test_posture_bands_are_monotonic_in_risk(self):
        """The trend is the planner's own posture scoring, not a hand-picked order."""
        order = ["band-strong", "band-good", "band-medium", "band-weak", "band-worst"]
        scores = [self.header(slot)["risk_score"] for slot in order]
        self.assertEqual(scores, sorted(scores))
        self.assertEqual(scores[0], 0)
        self.assertGreater(scores[-1], 0)

    def test_unknown_preserved_and_not_vulnerability(self):
        header = self.header("unknown")
        bundle = self.bundle("unknown")
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
        unknown = self.header("unknown")
        self.assertEqual(self.store.bundles[unknown["assessment_id"]]["evidence"]["total_refs"], 0)


class RealInputTest(_StoreTestCase):
    """Every input is a recorded artifact, with the artifact's own digest."""

    def test_expected_state_comes_from_the_real_plan(self):
        from correlation import artifacts
        from correlation.api.store import DATASET_RUN_ID

        self.assertEqual(DATASET_RUN_ID, artifacts.REAL_PLAN_RUN_ID)
        self.assertTrue(os.path.isfile(self.store.plan_path))
        self.assertTrue(self.store.plan_path.endswith(artifacts.REAL_PLAN_PATH))
        self.assertGreater(len(self.store._load_plan_samples()), 5)

    def test_every_bundle_names_the_artifacts_it_was_built_from(self):
        for header in self.store.headers:
            bundle = self.store.bundles[header["assessment_id"]]
            if header["slot"] == "unknown":
                self.assertEqual(bundle["sources"], [])
                continue
            self.assertTrue(bundle["sources"], header["assessment_id"])
            for source in bundle["sources"]:
                self.assertTrue(source["path"].startswith("results/"))
                self.assertTrue(source["artifact_sha256"])
                self.assertTrue(os.path.isfile(
                    os.path.join(os.path.dirname(os.path.dirname(
                        os.path.abspath(__file__))), source["path"])))

    def test_observed_state_is_a_real_snapshot(self):
        """SPI values come from the state builder, not from a formula."""
        bundle = self.bundle("tunnel-v4")
        observed = bundle["observed"]
        self.assertTrue(observed["spis"])
        for spi in observed["spis"]:
            self.assertTrue(spi["spi"].startswith("0x"))
        self.assertEqual(observed["endpoints"]["a"], "192.168.100.1")

    def test_feature_window_is_a_real_v2_window(self):
        from correlation import artifacts

        window, record = artifacts.load_feature_window(
            "results/e2e-verification/parser/tunnel_v4/windows.jsonl")
        self.assertEqual(window.feature_schema_version, "v2")
        self.assertEqual(len(window.features), 59)
        self.assertEqual(window.window_end_ns - window.window_start_ns,
                         20_500_000_000)
        self.assertEqual(record.byte_size, os.path.getsize(record.path))

    def test_short_real_window_keeps_absence_conservative(self):
        """20.5 s of real window < 30 s expected trial, so COMPLETE is not claimed.

        A padded or invented window would flip this to COMPLETE and let absence
        rules resolve to MATCH. The recorded window does not, and must not.
        """
        bundle = self.bundle("tunnel-v4")
        self.assertEqual(bundle["correlation"]["metadata"]["observation_completeness"],
                         "PARTIAL")
        self.assertEqual(bundle["expected"]["traffic"]["duration"], 30)

    def test_no_stand_in_spi_formula_survives(self):
        """0x06000000 + sequence * 0x10000 was the old synthetic value."""
        for header in self.store.headers:
            bundle = self.store.bundles[header["assessment_id"]]
            for spi in bundle["observed"]["spis"]:
                self.assertNotEqual(
                    int(spi["spi"], 16) & 0xFFFF0000, 0x06000000,
                    f"{header['assessment_id']} still carries a synthetic SPI")

    def test_crypto_variables_are_unknown_not_assumed(self):
        """A passive snapshot establishes no cipher, so nothing is invented."""
        from correlation.models import CANONICAL_VARIABLES

        crypto = [v for v in CANONICAL_VARIABLES
                  if v.startswith(("ike.", "esp.")) or v == "mode"]
        for header in self.store.headers:
            bundle = self.store.bundles[header["assessment_id"]]
            rows = {r["variable"]: r for r in bundle["correlation"]["rows"]}
            for variable in crypto:
                if variable in rows:
                    self.assertIn(rows[variable]["status"], ("UNKNOWN",),
                                  f"{header['assessment_id']}: {variable} was "
                                  f"resolved without a passive observation")

    def test_observed_values_are_never_copied_from_expected(self):
        """The old store derived observed values from the expected state."""
        from correlation import artifacts

        self.assertEqual(artifacts.observed_evidence_values(object()), {})

    def test_no_state_is_borrowed_from_another_capture(self):
        """A window is only ever paired with the state of its own capture.

        The nat-t live-tap run recorded packet counters but no v2 window, so it
        is assessed from its state snapshot alone rather than being handed
        tunnel_v4's window to look fuller.
        """
        from correlation.api.store import RECORDED_CASES, load_recorded_observation

        by_name = {case.name: case for case in RECORDED_CASES}
        for header in self.store.headers:
            bundle = self.store.bundles[header["assessment_id"]]
            case = by_name.get(header["slot"])
            paths = [source["path"] for source in bundle["sources"]]
            if case is None:
                continue
            self.assertIn(case.state_path, paths)
            foreign = [
                path for path in paths
                if path.endswith("windows.jsonl") and path != case.window_path
            ]
            self.assertEqual(foreign, [], f"{header['slot']} borrowed a window")
        self.assertIsNone(by_name["nat-t"].window_path)
        nat_t = load_recorded_observation(by_name["nat-t"])
        self.assertIsNone(nat_t.window)
        self.assertEqual(len(nat_t.provenance()), 1)

    def test_the_inconsistent_snapshot_is_refused_with_its_reason(self):
        from correlation import artifacts
        from correlation.artifacts import ArtifactUnavailable

        refused = next(iter(artifacts.INCONSISTENT_STATE_ARTIFACTS))
        with self.assertRaises(ArtifactUnavailable) as caught:
            artifacts.load_observed_state(refused)
        self.assertIn("last_esp_timestamp_ns", str(caught.exception))
        # and the refusal is published, not hidden
        sources = self.store.overview["sources"]
        self.assertTrue(any(
            source["path"] == refused and "REFUSED" in source["role"]
            for source in sources))


class RealMlTest(_StoreTestCase):
    """The model has no anomaly capability, and the store says so."""

    def test_no_assessment_claims_an_anomaly(self):
        for header in self.store.headers:
            bundle = self.store.bundles[header["assessment_id"]]
            if bundle["ml"]["present"]:
                self.assertIsNone(bundle["ml"]["anomaly"])
                self.assertIsNone(bundle["ml"]["anomaly_score"])
        self.assertEqual(self.store.overview["ml_anomalies"], 0)
        self.assertFalse([f for h in self.store.headers
                          for f in self.store.bundles[h["assessment_id"]]["risk"]["findings"]
                          if f["rule_id"] == "ml.anomaly"])

    def test_ml_result_is_real_model_output(self):
        bundle = self.bundle("ml-mismatch")
        self.assertTrue(bundle["ml"]["present"])
        self.assertEqual(bundle["ml"]["model_version"], "traffic_rf_v1")
        self.assertGreater(bundle["ml"]["classification_confidence"], 0.0)
        self.assertLessEqual(bundle["ml"]["classification_confidence"], 1.0)

    def test_classification_disagreement_is_the_real_finding(self):
        """A misclassification is reported as a disagreement, never an anomaly."""
        bundle = self.bundle("ml-mismatch")
        finding = next(f for f in bundle["risk"]["findings"]
                       if f["rule_id"] == "ml.classification.disagreement")
        self.assertEqual(finding["category"], "ML_CLASSIFICATION_DISAGREEMENT")
        self.assertNotEqual(bundle["ml"]["traffic_class"],
                            bundle["expected"]["traffic"]["profile"])
        self.assertEqual(self.store.overview["ml_classification_disagreements"], 1)

    def test_ml_only_assessment_invents_no_observation(self):
        """The misclassification is reported; no state is made up to go with it.

        The capture the misclassified window came from has no
        ipsec_state_builder snapshot. Attaching one from an unrelated capture
        would have produced a confident-looking MISMATCH that no record
        supports, so this assessment resolves to UNKNOWN and reports only the
        model's real disagreement.
        """
        bundle = self.bundle("ml-mismatch")
        self.assertEqual(bundle["correlation"]["status"], "UNKNOWN")
        self.assertEqual([r for r in bundle["correlation"]["rows"]
                          if r["status"] == "MISMATCH"], [])
        self.assertEqual(bundle["observed"]["timestamp_ns"], 0)
        self.assertEqual(bundle["observed"]["spis"], [])
        self.assertFalse([f for f in bundle["risk"]["findings"]
                          if f["category"] == "OBSERVED_MISMATCH"])
        self.assertEqual([source["path"] for source in bundle["sources"]],
                         ["results/ml/live_bridge/window_path_100ms.jsonl"])

    def test_ml_provenance_names_the_capture_it_came_from(self):
        bundle = self.bundle("ml-mismatch")
        ml_source = [s for s in bundle["sources"] if s.get("window_id")]
        self.assertEqual(len(ml_source), 1)
        self.assertTrue(ml_source[0]["window_id"])
        self.assertIn("capture", ml_source[0])
        self.assertNotEqual(ml_source[0]["expected_profile"],
                            ml_source[0]["predicted_profile"])
        self.assertTrue(ml_source[0]["artifact_sha256"])
        self.assertGreater(ml_source[0]["byte_size"], 0)


class FindingSourceTest(_StoreTestCase):
    def test_observed_mismatch_is_labelled_correlation(self):
        """A mismatch the recorded observation genuinely supports."""
        header = self.header("tunnel-v6")
        bundle = self.store.bundles[header["assessment_id"]]
        finding = next(f for f in bundle["risk"]["findings"]
                       if f["category"] == "OBSERVED_MISMATCH")
        self.assertEqual(finding["source"], "CORRELATION")
        row = next(r for r in bundle["correlation"]["rows"]
                   if r["status"] == "MISMATCH")
        self.assertNotEqual(row["expected_value"], row["observed_value"])
        # the scenario says why the recorded family differs from the plan's
        self.assertIn("outer SA", bundle["scenario"])

    def test_configuration_findings_are_labelled_expected(self):
        bundle = self.bundle("pfs-weak")
        finding = bundle["risk"]["findings"][0]
        self.assertEqual(finding["source"], "EXPECTED_CONFIGURATION")
        self.assertEqual(finding["category"], "CONFIGURATION_WEAKNESS")
        self.assertIsNone(finding["observed_value"])


class StoreDeterminismTest(_StoreTestCase):
    def test_rebuild_identical(self):
        from correlation.api import build_store

        first = json.dumps(_store_z(_tag(), build_store()), sort_keys=True)
        second = json.dumps(_store_z(_tag(), build_store()), sort_keys=True)
        self.assertEqual(first, second)

    def test_score_severity_never_client_recomputed(self):
        # the API view must carry the authoritative values with their labels
        header = self.header("ml-mismatch")
        bundle = self.bundle("ml-mismatch")
        self.assertEqual(header["risk_score"], bundle["risk"]["overall_score"])
        self.assertEqual(header["severity"], bundle["risk"]["severity"])
        self.assertEqual(bundle["xai"]["score_explanation"]["score"],
                         header["risk_score"])
        self.assertEqual(bundle["xai"]["score_explanation"]["severity"],
                         header["severity"])


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
