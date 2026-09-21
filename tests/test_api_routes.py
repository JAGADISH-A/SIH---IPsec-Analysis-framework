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
        self.assertEqual(payload["total_assessments"], 12)
        self.assertTrue(payload["read_only"])

    def test_unknown_route_404(self):
        with self.assertRaises(ApiError) as ctx:
            handle_get(self.store, "/api/nope")
        self.assertEqual(ctx.exception.status, 404)


class AssessmentsListTest(_RoutesTestCase):
    def test_overview_and_headers(self):
        payload = handle_get(self.store, "/api/assessments")
        self.assertEqual(payload["api"], "assessments")
        self.assertEqual(len(payload["headers"]), 12)
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
        self.assertEqual(payload["overview"]["highest_risk"], 55)
        self.assertEqual(payload["overview"]["highest_severity"], "CRITICAL")


class AssessmentDetailTest(_RoutesTestCase):
    AID = "dataset-20260916-231246:5:worst-ml"

    def test_full_bundle_sections(self):
        payload = handle_get(self.store, f"/api/assessments/{self.AID}")
        for section in ("identity", "expected", "observed", "correlation",
                        "ml", "risk", "xai", "evidence", "ipsec_state"):
            self.assertIn(section, payload, f"missing {section}")
        self.assertEqual(payload["risk"]["overall_score"], 55)
        self.assertEqual(payload["risk"]["severity"], "CRITICAL")
        self.assertEqual(payload["xai"]["score_explanation"]["score"], 55)

    def test_missing_assessment_404(self):
        with self.assertRaises(ApiError) as ctx:
            handle_get(self.store, "/api/assessments/dataset-20260916-231246:9:ghost")
        self.assertEqual(ctx.exception.status, 404)
        self.assertEqual(ctx.exception.code, "assessment_not_found")

    def test_invalid_id_format_404(self):
        with self.assertRaises(ApiError) as ctx:
            handle_get(self.store, "/api/assessments/garbage-id")
        self.assertEqual(ctx.exception.status, 404)
        self.assertEqual(ctx.exception.code, "invalid_assessment_id")

    def test_unknown_sub_resource_404(self):
        with self.assertRaises(ApiError) as ctx:
            handle_get(self.store, f"/api/assessments/{self.AID}/crypto")
        self.assertEqual(ctx.exception.status, 404)
        self.assertEqual(ctx.exception.code, "unknown_resource")


class SubResourceTest(_RoutesTestCase):
    AID = "dataset-20260916-231246:2:unknown"

    def test_each_sub_resource(self):
        for resource in ("expected", "observed", "correlation", "risk", "xai",
                         "ml", "evidence", "ipsec-state"):
            payload = handle_get(self.store, f"/api/assessments/{self.AID}/{resource}")
            self.assertEqual(payload["resource"], resource)
            self.assertEqual(payload["assessment_id"], self.AID)
            self.assertIn("data", payload)

    def test_ipsec_state_equals_observed(self):
        payload = handle_get(self.store, f"/api/assessments/{self.AID}/ipsec-state")
        observed = handle_get(self.store, f"/api/assessments/{self.AID}/observed")
        self.assertEqual(payload["data"], observed["data"])

    def test_unknown_status_preserved(self):
        payload = handle_get(self.store, f"/api/assessments/{self.AID}/correlation")
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
        self.assertEqual(len(snap["headers"]), 12)
        self.assertEqual(len(snap["assessments"]), 12)
        self.assertEqual(snap["overview"]["total_assessments"], 12)
        for aid, bundle in snap["assessments"].items():
            self.assertEqual(bundle["assessment_id"], aid)


if __name__ == "__main__":
    unittest.main()