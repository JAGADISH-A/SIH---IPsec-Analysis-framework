"""Phase 8 — HTTP transport smoke tests (real sockets on an ephemeral port)."""

import json
import threading
import unittest
import urllib.error
import urllib.request

from correlation.api.app import DashboardServer
from correlation.api import build_store


class _ServerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = build_store()
        cls.server = DashboardServer(("127.0.0.1", 0), cls.store, static_dir=None)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))


class HttpContractTest(_ServerTestCase):
    def test_health(self):
        status, payload = self.get("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["total_assessments"], 12)

    def test_assessments_list(self):
        status, payload = self.get("/api/assessments")
        self.assertEqual(status, 200)
        self.assertEqual(len(payload["headers"]), 12)
        self.assertEqual(payload["overview"]["highest_risk"], 55)

    def test_detail_with_url_encoded_id(self):
        import urllib.parse

        aid = urllib.parse.quote("dataset-20260916-231246:5:worst-ml", safe="")
        status, payload = self.get(f"/api/assessments/{aid}")
        self.assertEqual(status, 200)
        self.assertEqual(payload["risk"]["overall_score"], 55)
        self.assertEqual(payload["risk"]["severity"], "CRITICAL")

    def test_sub_resource(self):
        status, payload = self.get("/api/assessments/dataset-20260916-231246:1:strong-clean/risk")
        self.assertEqual(status, 200)
        self.assertEqual(payload["data"]["overall_score"], 0)
        self.assertEqual(payload["data"]["severity"], "INFO")

    def test_missing_assessment_404(self):
        with self.assertRaisesRegex(urllib.error.HTTPError, "404") as ctx:
            self.get("/api/assessments/dataset-20260916-231246:99:ghost")
        body = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertEqual(body["error"]["code"], "assessment_not_found")

    def test_invalid_route_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.get("/api/health/extra")
        self.assertEqual(ctx.exception.code, 404)

    def test_post_405(self):
        request = urllib.request.Request(
            self.base + "/api/assessments", method="POST",
            data=b"{}", headers={"Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(request, timeout=10)
        self.assertEqual(ctx.exception.code, 405)
        self.assertEqual(ctx.exception.headers.get("Content-Type"), "application/json")

    def test_static_unavailable_message(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.get("/")
        body = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertEqual(body["error"]["code"], "api_only")


if __name__ == "__main__":
    unittest.main()