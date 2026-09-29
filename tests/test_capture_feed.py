"""Capture feed: the read-only /api/v1/capture/events surface.

Covers the CaptureFeedService (byte-offset tail of the xdp_monitor JSONL
journal), the verbatim SPI->risk projection and the v1 handler (503 when no
feed is attached, envelope otherwise). No fake packets are ever served: the
service fixture is the real recorded capture
``results/observed-state/live_events_full.jsonl``.
"""

import os
import tempfile
import time
import unittest

from correlation.api import live, v1
from correlation.api.capture_feed import (
    DEFAULT_CAPTURE_FEED_PATH,
    CaptureFeedService,
    build_risk_index,
    packet_info,
    protocol_label,
    risk_for_spi,
)
from correlation.api.routes import ApiError

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REAL_CAPTURE = os.path.join(REPO_ROOT, DEFAULT_CAPTURE_FEED_PATH)


def _fake_store_service(capture_path=None):
    """A service wired to a stub store so risk mapping is deterministic."""
    headers = [
        {"assessment_id": "a1", "severity": "HIGH", "risk_score": 72, "finding_count": 3},
        {"assessment_id": "a2", "severity": "INFO", "risk_score": 0, "finding_count": 0},
    ]
    bundles = {
        "a1": {
            "observed": {
                "spis": [{"spi": "0xcda30093"}, {"spi": 0xCA1A0913}],
            }
        },
        "a2": {
            "observed": {
                "spis": [{"spi": "0xdeadbeef"}],
            }
        },
    }
    store = type("Store", (), {"headers": headers, "bundles": bundles})()
    return CaptureFeedService(
        capture_path or REAL_CAPTURE, risk_index=build_risk_index(store)
    )


class TestProtocolLabels(unittest.TestCase):
    def test_esp(self):
        self.assertEqual(protocol_label({"protocol": 50, "classification": "ESP"}), "ESP")

    def test_ah(self):
        self.assertEqual(protocol_label({"protocol": 51, "classification": "AH"}), "AH")

    def test_ike_on_udp500(self):
        self.assertEqual(
            protocol_label(
                {"protocol": 17, "classification": "IKE",
                 "source_port": 500, "destination_port": 4500}
            ),
            "IKE",
        )

    def test_esp_in_udp_nat_t(self):
        self.assertEqual(
            protocol_label(
                {"protocol": 17, "classification": "ESP_IN_UDP",
                 "source_port": 4500, "destination_port": 4500}
            ),
            "ESP_IN_UDP",
        )

    def test_udp4500_without_evidence_is_udp(self):
        self.assertEqual(
            protocol_label(
                {"protocol": 17, "classification": "UNKNOWN",
                 "source_port": 4500, "destination_port": 4500}
            ),
            "UDP",
        )

    def test_dns(self):
        self.assertEqual(
            protocol_label({"protocol": 17, "classification": "UNKNOWN",
                            "source_port": 53000, "destination_port": 53}),
            "DNS",
        )

    def test_tcp(self):
        self.assertEqual(protocol_label({"protocol": 6, "classification": "UNKNOWN"}), "TCP")

    def test_icmp(self):
        self.assertEqual(protocol_label({"protocol": 1, "classification": "UNKNOWN"}), "ICMP")

    def test_unknown_proto(self):
        self.assertEqual(protocol_label({"protocol": 99, "classification": "UNKNOWN"}), "UNKNOWN")


class TestPacketInfo(unittest.TestCase):
    def test_esp_info(self):
        info = packet_info({"protocol": 50, "classification": "ESP", "spi": 0xCDA30093, "sequence": 7})
        self.assertIn("0xcda30093", info)
        self.assertIn("seq 7", info)

    def test_ports(self):
        self.assertEqual(
            packet_info({"protocol": 17, "classification": "UNKNOWN",
                         "source_port": 53000, "destination_port": 53}),
            "53000 \u2192 53",
        )


class TestRiskProjection(unittest.TestCase):
    def test_verbatim_from_store(self):
        index = build_risk_index(
            type(
                "Store",
                (),
                {
                    "headers": [
                        {"assessment_id": "a1", "severity": "HIGH",
                         "risk_score": 72, "finding_count": 3}
                    ],
                    "bundles": {"a1": {"observed": {"spis": [{"spi": "0xcda30093"}]}}},
                },
            )()
        )
        risk = risk_for_spi(0xCDA30093, index)
        self.assertTrue(risk["present"])
        self.assertEqual(risk["highest_severity"], "HIGH")
        self.assertEqual(risk["highest_risk_score"], 72)
        self.assertEqual(risk["assessments"][0]["assessment_id"], "a1")
        self.assertEqual(risk["assessments"][0]["finding_count"], 3)

    def test_unmatched_spi_is_not_present(self):
        index = build_risk_index(
            type("Store", (), {"headers": [], "bundles": {}})()
        )
        risk = risk_for_spi(0xCDA30093, index)
        self.assertFalse(risk["present"])

    def test_missing_spi_is_not_present(self):
        self.assertFalse(risk_for_spi(None, {1: []})["present"])

    def test_highest_severity_is_ranked(self):
        index = build_risk_index(
            type(
                "Store",
                (),
                {
                    "headers": [
                        {"assessment_id": "a1", "severity": "HIGH", "risk_score": 20,
                         "finding_count": 1},
                        {"assessment_id": "a2", "severity": "CRITICAL", "risk_score": 10,
                         "finding_count": 2},
                    ],
                    "bundles": {
                        "a1": {"observed": {"spis": [{"spi": "0xabc"}]}},
                        "a2": {"observed": {"spis": [{"spi": "0xabc"}]}},
                    },
                },
            )()
        )
        risk = risk_for_spi(0xABC, index)
        self.assertTrue(risk["present"])
        # CRITICAL ranks above HIGH even though its score is lower.
        self.assertEqual(risk["highest_severity"], "CRITICAL")


class TestCaptureFeedServiceRealCapture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.feed = _fake_store_service()

    def test_feature_file_is_real(self):
        self.assertTrue(os.path.isfile(REAL_CAPTURE))

    def test_tails_real_packets(self):
        page = self.feed.poll(cursor=0, limit=5)
        self.assertTrue(page["present"])
        self.assertTrue(page["read_only"])
        self.assertEqual(page["count"], 5)
        self.assertGreater(page["total"], 5)
        self.assertTrue(page["has_more"])
        self.assertEqual(page["events"][0]["schema"], "packet")
        self.assertEqual(page["events"][0]["packet"]["classification"], "ESP")

    def test_cursor_resumes(self):
        page1 = self.feed.poll(cursor=0, limit=3)
        page2 = self.feed.poll(cursor=page1["cursor"], limit=3)
        self.assertNotEqual(page2["events"][0]["id"], page1["events"][0]["id"])
        self.assertEqual(page2["start_cursor"], page1["cursor"])

    def test_ids_deterministic(self):
        a = self.feed.poll(cursor=0, limit=2)["events"]
        b = self.feed.poll(cursor=0, limit=2)["events"]
        self.assertEqual([e["id"] for e in a], [e["id"] for e in b])

    def test_full_tail_reaches_eof(self):
        end = self.feed.poll(cursor=0, limit=500)
        self.assertEqual(end["count"], end["total"])
        self.assertFalse(end["has_more"])
        self.assertEqual(end["cursor"], end["size"])

    def test_torn_tail_is_never_surfaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "feed.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('{"type":"ESP","proto":50,"src":"10.0.0.1","dst":"10.0.0.2","len":100,"spi":1,"seq":1,"ts":1}\n')
                fh.write('{"type":"ES')  # torn line still being written
            feed = CaptureFeedService(path)
            page = feed.poll(cursor=0, limit=10)
            self.assertEqual(page["count"], 1)
            self.assertEqual(page["events"][0]["packet"]["spi"], 1)

    def test_waiting_state_when_journal_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            feed = _fake_store_service(os.path.join(tmp, "missing.jsonl"))
            page = feed.poll(cursor=0, limit=10)
            self.assertFalse(page["present"])
            self.assertEqual(page["count"], 0)
            self.assertEqual(page["cursor"], 0)
            self.assertTrue(page["reason"])

    def test_waiting_state_when_journal_exists_but_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "feed.jsonl")
            with open(path, "w", encoding="utf-8"):
                pass
            feed = _fake_store_service(path)
            page = feed.poll(cursor=0, limit=10)
            self.assertFalse(page["present"])
            self.assertEqual(page["count"], 0)
            self.assertEqual(page["total"], 0)
            self.assertEqual(page["cursor"], 0)
            self.assertIn("is empty", page["reason"])

    def test_matching_spi_carries_assessment_risk(self):
        from correlation.api.store import build_store

        feed = CaptureFeedService(REAL_CAPTURE, risk_index=build_risk_index(build_store()))
        page = feed.poll(cursor=0, limit=200)
        matched = next((e for e in page["events"] if e["risk"]["present"]), None)
        self.assertIsNotNone(matched, "a capture SPI should match the store's natt assessment")
        self.assertEqual(matched["risk"]["assessments"][0]["assessment_id"], "dataset-20260924-003710:1:nat-t")


class TestCaptureFeedCurrentness(unittest.TestCase):
    """The ``current`` verdict: a journal is live only while it is actively
    being appended to. A static recorded artifact must never count as current
    traffic, whatever its contents."""

    _LINE = (
        '{"type":"ESP","proto":50,"src":"10.0.0.1","dst":"10.0.0.2",'
        '"len":100,"spi":1,"seq":1,"ts":17260803212308}\n'
    )

    def _feed_with_mtime(self, path, mtime_ms):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self._LINE)
        os.utime(path, (mtime_ms / 1000.0, mtime_ms / 1000.0))
        return CaptureFeedService(path)

    def test_fresh_journal_is_current(self):
        with tempfile.TemporaryDirectory() as tmp:
            feed = self._feed_with_mtime(os.path.join(tmp, "live.jsonl"), int(time.time() * 1000))
            page = feed.poll(cursor=0, limit=10)
            self.assertTrue(page["present"])
            self.assertTrue(page["current"])
            self.assertEqual(page["count"], 1)

    def test_stale_journal_is_not_current(self):
        with tempfile.TemporaryDirectory() as tmp:
            feed = self._feed_with_mtime(
                os.path.join(tmp, "recorded.jsonl"), int(time.time() * 1000) - 86_400_000
            )
            page = feed.poll(cursor=0, limit=10)
            self.assertTrue(page["present"])
            self.assertFalse(page["current"])
            # The recorded rows are still readable, so they are never deleted —
            # they just must not be presented as current traffic.
            self.assertEqual(page["count"], 1)
            self.assertGreater(page["last_write_age_ms"], 0)

    def test_journal_within_window_is_current_at_eof_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            feed = self._feed_with_mtime(os.path.join(tmp, "live.jsonl"), int(time.time() * 1000))
            page = feed.poll(cursor=0, limit=10)
            page = feed.poll(cursor=page["cursor"], limit=10)  # at EOF, no new events
            self.assertTrue(page["present"])
            self.assertTrue(page["current"])
            self.assertEqual(page["count"], 0)

    def test_missing_journal_is_never_current(self):
        with tempfile.TemporaryDirectory() as tmp:
            feed = CaptureFeedService(os.path.join(tmp, "missing.jsonl"))
            page = feed.poll(cursor=0, limit=10)
            self.assertFalse(page["present"])
            self.assertFalse(page["current"])
            self.assertIsNone(page["last_write_age_ms"])

    def test_empty_journal_is_never_current(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "feed.jsonl")
            with open(path, "w", encoding="utf-8"):
                pass
            os.utime(path, (time.time(), time.time()))
            feed = CaptureFeedService(path)
            page = feed.poll(cursor=0, limit=10)
            self.assertFalse(page["present"])
            self.assertFalse(page["current"])

    def test_currentness_flows_to_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            feed = self._feed_with_mtime(os.path.join(tmp, "live.jsonl"), int(time.time() * 1000))
            status = feed.status()
            self.assertTrue(status["current"])
            self.assertIn("freshness_window_ms", status)
            self.assertIn("newest_observed_at_ms", status)

    def test_window_is_serialized_in_the_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            feed = self._feed_with_mtime(os.path.join(tmp, "live.jsonl"), int(time.time() * 1000))
            page = feed.poll(cursor=0, limit=10)
            self.assertGreater(page["freshness_window_ms"], 0)
            self.assertIn("server_time_ms", page)
            self.assertIsInstance(page["newest_observed_at_ms"], int)


class TestV1CaptureHandler(unittest.TestCase):
    def test_503_when_no_feed_attached(self):
        ctx = live.Phase10Context()
        with self.assertRaises(ApiError) as raised:
            v1.handle_v1_capture(ctx, {})
        self.assertEqual(raised.exception.status, 503)
        self.assertEqual(raised.exception.code, "capture_feed_unavailable")

    def test_503_when_v1_not_wired(self):
        ctx = live.Phase10Context()
        with self.assertRaises(ApiError):
            v1.handle_v1_get(ctx, "/api/v1/capture/events")

    def test_envelope_when_attached(self):
        ctx = live.Phase10Context()
        feed = _fake_store_service()
        ctx.attach_capture_feed(feed)
        body = v1.handle_v1_capture(ctx, {"limit": "2"})
        self.assertTrue(body["read_only"])
        self.assertEqual(body["count"], 2)
        self.assertEqual(body["limit"], 2)

    def test_bad_params_coerce(self):
        ctx = live.Phase10Context()
        ctx.attach_capture_feed(CaptureFeedService(REAL_CAPTURE))
        body = v1.handle_v1_capture(ctx, {"cursor": "abc", "limit": "xyz"})
        self.assertEqual(body["start_cursor"], 0)
        self.assertLessEqual(body["count"], 200)

    def test_openapi_documents_the_path(self):
        from correlation.api.openapi import openapi_document
        self.assertIn("/api/v1/capture/events", openapi_document()["paths"])


if __name__ == "__main__":
    unittest.main()