"""Phase 8 — API route tests: contract, structured 404s, determinism."""

import json
import unittest


from correlation.api import build_store
from correlation.api.routes import ApiError, handle_get, serializable


class _RoutesTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = build_store()


class HealthTest(_RoutesTestCase):
    def test_health(self):
        payload = handle_get(self.store, "/api/health")
        self.assertEqual(payload["status"], "ok")
        # 13 = one assessment per scenario slot, including transport-v6.
        self.assertEqual(payload["total_assessments"], 13)
        self.assertTrue(payload["read_only"])

    def test_unknown_route_404(self):
        with self.assertRaises(ApiError) as ctx:
            handle_get(self.store, "/api/nope")
        self.assertEqual(ctx.exception.status, 404)


class AssessmentsListTest(_RoutesTestCase):
    def test_overview_and_headers(self):
        payload = handle_get(self.store, "/api/assessments")
        self.assertEqual(payload["api"], "assessments")
        self.assertEqual(len(payload["headers"]), 13)
        required = {"assessment_id", "sequence", "experiment_id", "risk_score",
                    "severity", "finding_count", "correlation_status",
                    "traffic_profile", "security_posture"}
        for header in payload["headers"]:
            self.assertTrue(required.issubset(header.keys()))

    def test_overview_sums(self):
        payload = handle_get(self.store, "/api/assessments")
        self.assertEqual(
            sum(payload["overview"]["severity_counts"].values()),
            payload["overview"]["total_assessments"],
        )
        self.assertEqual(payload["overview"]["highest_risk"],
                         max(h["risk_score"] for h in payload["headers"]))
        from correlation.risk.models import SEVERITY_RANK

        self.assertEqual(
            payload["overview"]["highest_severity"],
            max((h["severity"] for h in payload["headers"]),
                key=lambda severity: SEVERITY_RANK[severity]))
        # the store reports the real run it was built from, not a fixture label
        self.assertEqual(payload["overview"]["dataset_run_id"],
                         self.store.overview["dataset_run_id"])

    def test_overview_reports_no_anomalies_but_real_disagreements(self):
        payload = handle_get(self.store, "/api/assessments")
        self.assertEqual(payload["overview"]["ml_anomalies"], 0)
        self.assertEqual(payload["overview"]["ml_classification_disagreements"], 1)


class AssessmentDetailTest(_RoutesTestCase):
    def aid(self):
        return next(h["assessment_id"] for h in self.store.headers
                    if h["slot"] == "ml-mismatch")

    def test_full_bundle_sections(self):
        aid = self.aid()
        payload = handle_get(self.store, f"/api/assessments/{aid}")
        for section in ("identity", "expected", "observed", "correlation",
                        "ml", "risk", "xai", "evidence", "ipsec_state"):
            self.assertIn(section, payload, f"missing {section}")
        header = next(h for h in self.store.headers
                      if h["assessment_id"] == aid)
        self.assertEqual(payload["risk"]["overall_score"], header["risk_score"])
        self.assertEqual(payload["risk"]["severity"], header["severity"])
        self.assertEqual(payload["xai"]["score_explanation"]["score"],
                         header["risk_score"])
        self.assertEqual(payload["ml"]["anomaly"], None)
        # the bundle names the recorded artifacts it came from
        self.assertTrue(payload["sources"])
        for source in payload["sources"]:
            self.assertTrue(source["path"].startswith("results/"))

    def test_missing_assessment_404(self):
        with self.assertRaises(ApiError) as ctx:
            handle_get(self.store, "/api/assessments/dataset-20260924-003710:9:ghost")
        self.assertEqual(ctx.exception.status, 404)
        self.assertEqual(ctx.exception.code, "assessment_not_found")

    def test_invalid_id_format_404(self):
        with self.assertRaises(ApiError) as ctx:
            handle_get(self.store, "/api/assessments/garbage-id")
        self.assertEqual(ctx.exception.status, 404)
        self.assertEqual(ctx.exception.code, "invalid_assessment_id")

    def test_unknown_sub_resource_404(self):
        with self.assertRaises(ApiError) as ctx:
            handle_get(self.store, f"/api/assessments/{self.aid()}/crypto")
        self.assertEqual(ctx.exception.status, 404)
        self.assertEqual(ctx.exception.code, "unknown_resource")


class SubResourceTest(_RoutesTestCase):
    def aid(self):
        return next(h["assessment_id"] for h in self.store.headers
                    if h["slot"] == "unknown")

    def test_each_sub_resource(self):
        aid = self.aid()
        for resource in ("expected", "observed", "correlation", "risk", "xai",
                         "ml", "evidence", "ipsec-state"):
            payload = handle_get(self.store, f"/api/assessments/{aid}/{resource}")
            self.assertEqual(payload["resource"], resource)
            self.assertEqual(payload["assessment_id"], aid)
            self.assertIn("data", payload)

    def test_ipsec_state_equals_observed(self):
        aid = self.aid()
        payload = handle_get(self.store, f"/api/assessments/{aid}/ipsec-state")
        observed = handle_get(self.store, f"/api/assessments/{aid}/observed")
        self.assertEqual(payload["data"], observed["data"])

    def test_unknown_status_preserved(self):
        payload = handle_get(self.store, f"/api/assessments/{self.aid()}/correlation")
        self.assertEqual(payload["data"]["status"], "UNKNOWN")
        unknown_rows = [r for r in payload["data"]["rows"] if r["status"] == "UNKNOWN"]
        self.assertTrue(unknown_rows)


class SerializationTest(_RoutesTestCase):
    def test_deterministic_bytes(self):
        store_a = build_store()
        store_b = build_store()
        self.assertEqual(
            json.dumps(handle_get(store_a, "/api/assessments"), sort_keys=True),
            json.dumps(handle_get(store_b, "/api/assessments"), sort_keys=True),
        )

    def test_serializable_snapshot_shapes(self):
        snap = serializable(self.store)
        self.assertEqual(len(snap["headers"]), 13)
        self.assertEqual(len(snap["assessments"]), 13)
        self.assertEqual(snap["overview"]["total_assessments"], 13)
        for aid, bundle in snap["assessments"].items():
            self.assertEqual(bundle["assessment_id"], aid)


if __name__ == "__main__":
    unittest.main()