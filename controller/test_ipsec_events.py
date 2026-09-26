"""Unit tests for the TShark JSON -> audit-event parser (ipsec_events.py)."""

import json
import os
import unittest
from pathlib import Path

from controller import ipsec_events as events_mod

WAN_IP = "192.168.100.1"

_ESP_PKT = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "10",
                "frame.len": "136",
                "frame.time_epoch": "2026-09-16T19:37:22.244784000Z",
                "frame.protocols": "eth:ethertype:ip:esp",
            },
            "ip": {
                "ip.src": "192.168.100.1",
                "ip.dst": "192.168.100.2",
                "ip.proto": "50",
            },
            "esp": {"esp.spi": "0xc8d12d4a", "esp.sequence": "7"},
        }
    }
}

_IKE_SA_INIT_PKT = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "1",
                "frame.len": "512",
                "frame.time_epoch": "2026-09-16T19:37:20.500000000Z",
                "frame.protocols": "eth:ethertype:ip:udp:isakmp",
            },
            "ip": {"ip.src": "192.168.100.1", "ip.dst": "192.168.100.2",
                   "ip.proto": "17", "ip.len": "498"},
            "udp": {"udp.srcport": "500", "udp.dstport": "500",
                    "udp.length": "478"},
            "isakmp": {
                "isakmp.exchangetype": "34",
                "isakmp.messageid": "0x00000000",
                "isakmp.length": "478",
            },
        }
    }
}

_IKE_AUTH_PKT_4500 = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "3",
                "frame.len": "120",
                "frame.time_epoch": "2026-09-16T19:37:21.100000000Z",
                "frame.protocols": "eth:ethertype:ip:udp:udpencap:isakmp",
            },
            "ip": {"ip.src": "192.168.100.2", "ip.dst": "192.168.100.1",
                   "ip.proto": "17", "ip.len": "112"},
            "udp": {"udp.srcport": "4500", "udp.dstport": "4500",
                    "udp.length": "92"},
            "udpencap": {},
            "isakmp": {
                "isakmp.exchangetype": "35",
                "isakmp.messageid": "0x00000001",
                "isakmp.length": "80",
            },
        }
    }
}

# IPv6-outer variants (TShark field names from real IPv6 captures): no ``ip``
# layer is present -- the outer header is exposed as ``ipv6.*``.
_ESP_PKT_V6 = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "5",
                "frame.len": "174",
                "frame.time_epoch": "2026-09-22T18:44:16.163358000Z",
                "frame.protocols": "eth:ethertype:ipv6:esp",
            },
            "ipv6": {
                "ipv6.src": "2001:db8:20::10",
                "ipv6.dst": "2001:db8:20::20",
                "ipv6.nxt": "50",
            },
            "esp": {"esp.spi": "0xcb407ab6", "esp.sequence": "1"},
        }
    }
}

_IKE_SA_INIT_PKT_V6 = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "11",
                "frame.len": "464",
                "frame.time_epoch": "2026-09-22T18:44:03.952871000Z",
                "frame.protocols": "eth:ethertype:ipv6:udp:isakmp",
            },
            "ipv6": {
                "ipv6.src": "2001:db8:20::10",
                "ipv6.dst": "2001:db8:20::20",
                "ipv6.nxt": "17",
            },
            "udp": {"udp.srcport": "500", "udp.dstport": "500",
                    "udp.length": "472"},
            "isakmp": {
                "isakmp.exchangetype": "34",
                "isakmp.messageid": "0x00000000",
                "isakmp.length": "464",
            },
        }
    }
}

# Non-ESP/non-IKE (IPv6 TCP): must be ignored by the parser.
_TCP_PKT_V6 = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "8",
                "frame.len": "64",
                "frame.time_epoch": "2026-09-22T18:50:10.000000000Z",
                "frame.protocols": "eth:ethertype:ipv6:tcp",
            },
            "ipv6": {"ipv6.src": "2001:db8:20::10", "ipv6.dst": "2001:db8:20::20",
                     "ipv6.nxt": "6"},
            "tcp": {"tcp.srcport": "9995", "tcp.dstport": "9995"},
        }
    }
}

WAN_IP_V6 = "2001:db8:20::10"

# Regression fixture: identical to _IKE_SA_INIT_PKT except ``isakmp.length`` is
# absent, which is the case that previously raised ``NameError: name 'ip' is
# not defined`` (line 143 referenced the ``ip`` dict bound only inside
# _outer_addrs).  Every other required field is retained.
_IKE_SA_INIT_PKT_NO_ISAKMP_LENGTH = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "1",
                "frame.len": "512",
                "frame.time_epoch": "2026-09-16T19:37:20.500000000Z",
                "frame.protocols": "eth:ethertype:ip:udp:isakmp",
            },
            "ip": {"ip.src": "192.168.100.1", "ip.dst": "192.168.100.2",
                   "ip.proto": "17", "ip.len": "498"},
            "udp": {"udp.srcport": "500", "udp.dstport": "500",
                    "udp.length": "478"},
            "isakmp": {
                "isakmp.exchangetype": "34",
                "isakmp.messageid": "0x00000000",
            },
        }
    }
}

# Same, with the IPv4 total length also absent: nothing in the packet supports
# a length, so ``packet_length`` must be None rather than fabricated.
_IKE_SA_INIT_PKT_NO_LENGTH_EVIDENCE = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "2",
                "frame.len": "300",
                "frame.time_epoch": "2026-09-16T19:37:21.000000000Z",
                "frame.protocols": "eth:ethertype:ip:udp:isakmp",
            },
            "ip": {"ip.src": "192.168.100.1", "ip.dst": "192.168.100.2",
                   "ip.proto": "17"},
            "udp": {"udp.srcport": "500", "udp.dstport": "500"},
            "isakmp": {
                "isakmp.exchangetype": "36",
                "isakmp.messageid": "0x00000002",
            },
        }
    }
}


def _with_frame_number(packet, number):
    """A copy of ``packet`` at a distinct frame number.

    ``_dedupe`` keys on ``(frame_number, spi or message id)``, so a fixture pair
    that differs only in one field would collapse into a single event in a mixed
    feed.  Mixed-feed tests renumber their packets to keep both.
    """
    clone = json.loads(json.dumps(packet))
    clone["_source"]["layers"]["frame"]["frame.number"] = str(number)
    return clone


# ``isakmp.length`` present but zero: a malformed header the field *is* exposed
# for.  ``_as_int`` returns 0, which is falsy, so this reaches the same
# ``or``-fallback branch as an absent field and crashed identically before the fix.
_IKE_SA_INIT_PKT_ZERO_ISAKMP_LENGTH = json.loads(
    json.dumps(_IKE_SA_INIT_PKT_NO_ISAKMP_LENGTH)
)
_IKE_SA_INIT_PKT_ZERO_ISAKMP_LENGTH["_source"]["layers"]["isakmp"][
    "isakmp.length"
] = "0"


class TestNormalizeEsp(unittest.TestCase):
    def test_esp_metadata_and_direction(self):
        event = events_mod.normalize_esp_event(
            _ESP_PKT["_source"]["layers"], WAN_IP
        )
        self.assertEqual(event["spi"], "0xc8d12d4a")
        self.assertEqual(event["sequence"], 7)
        self.assertEqual(event["direction"], "outbound")
        self.assertEqual(event["ip_protocol"], events_mod.IP_PROTO_ESP)
        self.assertEqual(event["frame_number"], 10)
        self.assertEqual(event["timestamp"], "2026-09-16T19:37:22.244784000Z")

    def test_esp_inbound(self):
        pkt = json.loads(json.dumps(_ESP_PKT))
        pkt["_source"]["layers"]["ip"]["ip.src"] = "192.168.100.2"
        pkt["_source"]["layers"]["ip"]["ip.dst"] = WAN_IP
        event = events_mod.normalize_esp_event(pkt["_source"]["layers"], WAN_IP)
        self.assertEqual(event["direction"], "inbound")


class TestNormalizeIke(unittest.TestCase):
    def test_ike_via_udp500(self):
        event = events_mod.normalize_ike_event(
            _IKE_SA_INIT_PKT["_source"]["layers"], WAN_IP
        )
        self.assertEqual(event["source_port"], 500)
        self.assertEqual(event["destination_port"], 500)
        self.assertEqual(event["ike_exchange_type"], 34)
        self.assertEqual(event["ike_exchange_name"], "IKE_SA_INIT")
        self.assertEqual(event["message_id"], "0x00000000")
        self.assertEqual(event["packet_length"], 478)
        self.assertEqual(event["direction"], "outbound")

    def test_ike_via_udp4500_udpencap_inbound(self):
        event = events_mod.normalize_ike_event(
            _IKE_AUTH_PKT_4500["_source"]["layers"], WAN_IP
        )
        self.assertEqual(event["source_port"], 4500)
        self.assertEqual(event["destination_port"], 4500)
        self.assertEqual(event["ike_exchange_type"], 35)
        self.assertEqual(event["ike_exchange_name"], "IKE_AUTH")
        self.assertEqual(event["direction"], "inbound")


class TestNormalizeIkeMissingIsakmpLength(unittest.TestCase):
    """Regression: ``isakmp.length`` absent must not crash normalization.

    Previously line 143 evaluated ``ip.get("ip.len")`` where ``ip`` was bound
    only inside :func:`_outer_addrs`, so any IKE packet without
    ``isakmp.length`` raised ``NameError`` and aborted the whole observation
    run.  Existing fixtures all carried ``isakmp.length`` and hid the defect.
    """

    def test_missing_isakmp_length_falls_back_to_ipv4_total_length(self):
        event = events_mod.normalize_ike_event(
            _IKE_SA_INIT_PKT_NO_ISAKMP_LENGTH["_source"]["layers"], WAN_IP
        )
        # No NameError: a normalized event is returned.
        self.assertIsInstance(event, dict)
        # All pre-existing metadata is preserved and correct.
        self.assertEqual(event["source_ip"], "192.168.100.1")
        self.assertEqual(event["destination_ip"], "192.168.100.2")
        self.assertEqual(event["source_port"], 500)
        self.assertEqual(event["destination_port"], 500)
        self.assertEqual(event["ike_exchange_type"], 34)
        self.assertEqual(event["ike_exchange_name"], "IKE_SA_INIT")
        self.assertEqual(event["message_id"], "0x00000000")
        self.assertEqual(event["frame_number"], 1)
        self.assertEqual(event["timestamp"], "2026-09-16T19:37:20.500000000Z")
        self.assertEqual(event["direction"], "outbound")
        # The fallback uses the length already present in the packet.
        self.assertEqual(event["packet_length"], 498)

    def test_no_length_evidence_yields_none_and_invents_nothing(self):
        event = events_mod.normalize_ike_event(
            _IKE_SA_INIT_PKT_NO_LENGTH_EVIDENCE["_source"]["layers"], WAN_IP
        )
        self.assertIsInstance(event, dict)
        self.assertIsNone(event["packet_length"])
        # No length is derived from the frame size or any other field.
        self.assertNotEqual(event["packet_length"], 300)
        # Remaining metadata is still correct.
        self.assertEqual(event["ike_exchange_type"], 36)
        self.assertEqual(event["ike_exchange_name"], "CREATE_CHILD_SA")
        self.assertEqual(event["message_id"], "0x00000002")
        self.assertEqual(event["source_port"], 500)
        self.assertEqual(event["direction"], "outbound")

    def test_isakmp_length_present_still_takes_precedence(self):
        # Unchanged behavior when isakmp.length exists: it wins over ip.len.
        event = events_mod.normalize_ike_event(
            _IKE_SA_INIT_PKT["_source"]["layers"], WAN_IP
        )
        self.assertEqual(event["packet_length"], 478)
        self.assertEqual(event["ike_exchange_name"], "IKE_SA_INIT")

    def test_ipv6_ike_without_isakmp_length_does_not_crash(self):
        pkt = json.loads(json.dumps(_IKE_SA_INIT_PKT_V6))
        del pkt["_source"]["layers"]["isakmp"]["isakmp.length"]
        event = events_mod.normalize_ike_event(pkt["_source"]["layers"], WAN_IP_V6)
        self.assertIsInstance(event, dict)
        self.assertIsNone(event["packet_length"])
        self.assertEqual(event["ike_exchange_name"], "IKE_SA_INIT")
        self.assertEqual(event["source_ip"], "2001:db8:20::10")

    def test_parse_tshark_json_survives_missing_isakmp_length(self):
        text = json.dumps([_IKE_SA_INIT_PKT_NO_ISAKMP_LENGTH,
                           _IKE_SA_INIT_PKT_NO_LENGTH_EVIDENCE])
        esp_events, ike_events = events_mod.parse_tshark_json(text, WAN_IP)
        self.assertEqual(esp_events, [])
        self.assertEqual(len(ike_events), 2)
        self.assertEqual(ike_events[0]["packet_length"], 498)
        self.assertIsNone(ike_events[1]["packet_length"])

    def test_zero_isakmp_length_takes_the_fallback_without_crashing(self):
        """A present-but-zero length is falsy and hit the same defect."""
        event = events_mod.normalize_ike_event(
            _IKE_SA_INIT_PKT_ZERO_ISAKMP_LENGTH["_source"]["layers"], WAN_IP
        )
        self.assertIsInstance(event, dict)
        self.assertEqual(event["packet_length"], 498)
        self.assertEqual(event["ike_exchange_name"], "IKE_SA_INIT")

    def test_valid_packets_are_untouched_by_a_neighbouring_bad_one(self):
        """A malformed packet in the same feed changes nothing about a good one."""
        # Distinct frame numbers: ``_dedupe`` keys on (frame_number, message id),
        # so identical frame numbers would collapse the two packets on purpose.
        feed = [_IKE_SA_INIT_PKT,
                _with_frame_number(_IKE_SA_INIT_PKT_NO_ISAKMP_LENGTH, 2),
                _with_frame_number(_IKE_SA_INIT_PKT_NO_LENGTH_EVIDENCE, 3),
                _ESP_PKT]
        esp_events, ike_events = events_mod.parse_tshark_json(
            json.dumps(feed), WAN_IP)
        self.assertEqual(len(esp_events), 1)
        self.assertEqual(len(ike_events), 3)
        alone = events_mod.normalize_ike_event(
            _IKE_SA_INIT_PKT["_source"]["layers"], WAN_IP)
        self.assertEqual(ike_events[0], alone)
        self.assertEqual([e["packet_length"] for e in ike_events], [478, 498, None])


class TestRecordedTsharkArtifacts(unittest.TestCase):
    """The recorded TShark artifacts must keep parsing exactly as they did.

    Every recorded ``isakmp`` frame carries ``isakmp.length`` (16 frames across
    the four committed parser taps), which is precisely why the defect stayed
    latent: no fixture nor recorded input ever took the fallback branch.  These
    tests pin that the real corpus is unaffected by the fix.
    """

    ARTIFACTS = (
        "results/e2e-verification/transport/v6_parser_tap.json",
        "results/e2e-verification/transport/icmp_parser_tap.json",
        "results/e2e-verification/transport/ipv6-parser-rerun/v6_parser_tap_fixed.json",
        "results/e2e-verification/transport/ipv6-parser-rerun/v4_icmp_raw.json",
    )

    def test_recorded_ike_events_are_unchanged_and_never_none(self):
        root = Path(__file__).resolve().parent.parent
        checked = 0
        for name in self.ARTIFACTS:
            path = root / name
            if not path.is_file():
                self.skipTest(f"recorded artifact not present: {name}")
            _esp_events, ike_events = events_mod.parse_tshark_json(
                path.read_text(encoding="utf-8"), WAN_IP)
            self.assertEqual(len(ike_events), 4, name)
            for event in ike_events:
                checked += 1
                # isakmp.length is present in the recorded corpus, so the
                # fallback is not consulted and the values are the originals.
                self.assertIsInstance(event["packet_length"], int)
                self.assertGreater(event["packet_length"], 0)
                self.assertIn(event["ike_exchange_name"],
                              events_mod.IKEV2_EXCHANGE_NAMES.values())
                self.assertNotEqual(event["source_ip"], "None")
                self.assertNotEqual(event["destination_ip"], "None")
        self.assertEqual(checked, 16)


class TestLiveObservationPathWithMissingIsakmpLength(unittest.TestCase):
    """The audit/live path must survive a length-less IKE packet end to end.

    ``observe_live`` is the only production entry point: provision -> TShark ->
    parse -> ``record_event``.  The TShark and provisioning calls are the only
    parts stubbed here; the parse and the audit recording are the real code, so
    this proves a malformed IKE frame cannot abort a live observation run.  The
    audit sink is redirected to a temporary file: the committed
    ``results/audit/events.jsonl`` is never written by a test.
    """

    def _run(self, packets):
        import tempfile

        from controller import audit as audit_mod
        from controller import observation as observation_mod

        payloads = {}
        originals = (
            events_mod.run_tshark_on_tap,
            observation_mod.provision_observation,
            observation_mod.observation_target,
            audit_mod.default_events_path,
        )
        events_mod.run_tshark_on_tap = (
            lambda container, tap, wan_ip, seconds, out: (
                open(out, "w", encoding="utf-8").write(json.dumps(packets)),
                str(out),
            )[1]
        )
        observation_mod.provision_observation = lambda *a, **k: {
            "container": "clab-ipsec-sensor", "mirror_interface": "eth1",
        }
        observation_mod.observation_target = lambda *a, **k: (None, WAN_IP)
        handle = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        handle.close()
        events = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        events.close()
        audit_mod.default_events_path = lambda: Path(events.name)
        try:
            result = events_mod.observe_live(
                "tunnel", "ipv4", 1, events_out=handle.name, record=True)
        finally:
            (events_mod.run_tshark_on_tap,
             observation_mod.provision_observation,
             observation_mod.observation_target,
             audit_mod.default_events_path) = originals
        self.addCleanup(os.unlink, handle.name)
        self.addCleanup(os.unlink, events.name)
        return result, Path(events.name)

    def test_live_run_records_the_packet_and_keeps_going(self):
        result, events_path = self._run([
            _IKE_SA_INIT_PKT,
            _with_frame_number(_IKE_SA_INIT_PKT_NO_ISAKMP_LENGTH, 2),
            _with_frame_number(_IKE_SA_INIT_PKT_NO_LENGTH_EVIDENCE, 3),
            _ESP_PKT,
        ])
        # The run completed: no NameError, no abort, the summary is real.
        self.assertEqual(result["summary"]["esp_packets"], 1)
        self.assertEqual(result["summary"]["ike_packets"], 3)
        self.assertEqual(result["summary"]["ike_exchanges"],
                         {"IKE_SA_INIT": 2, "CREATE_CHILD_SA": 1})

        recorded = [json.loads(line) for line in
                    events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        ike = [r for r in recorded if r["event_type"] == events_mod.audit_mod.EVENT_IKE_PACKET]
        self.assertEqual(len(ike), 3)
        # In feed order: isakmp.length present, then the ip.len fallback, then
        # no length evidence at all.
        self.assertEqual([r["data"]["packet_length"] for r in ike],
                         [478, 498, None])
        for record in ike:
            data = record["data"]
            self.assertIn("packet_length", data)
            if data["packet_length"] is None:
                # No length is derived from the frame size or any other field.
                self.assertNotEqual(data["packet_length"], 300)
            # An IKE observation is metadata only: no payload ever appears.
            self.assertFalse([k for k in data if "payload" in k or k == "data"])
        # The complete run still wrote its session boundaries.
        types = [r["event_type"] for r in recorded]
        self.assertIn(events_mod.audit_mod.EVENT_OBSERVATION_SESSION_START, types)
        self.assertIn(events_mod.audit_mod.EVENT_OBSERVATION_SESSION_END, types)


class TestNormalizeEspV6(unittest.TestCase):
    def test_esp_ipv6_metadata_outbound(self):
        event = events_mod.normalize_esp_event(
            _ESP_PKT_V6["_source"]["layers"], WAN_IP_V6
        )
        self.assertEqual(event["source_ip"], "2001:db8:20::10")
        self.assertEqual(event["destination_ip"], "2001:db8:20::20")
        self.assertEqual(event["ip_protocol"], events_mod.IP_PROTO_ESP)
        self.assertEqual(event["spi"], "0xcb407ab6")
        self.assertEqual(event["sequence"], 1)
        self.assertEqual(event["frame_number"], 5)
        self.assertEqual(event["direction"], "outbound")
        self.assertEqual(event["timestamp"], "2026-09-22T18:44:16.163358000Z")

    def test_esp_ipv6_inbound(self):
        pkt = json.loads(json.dumps(_ESP_PKT_V6))
        pkt["_source"]["layers"]["ipv6"]["ipv6.src"] = "2001:db8:20::20"
        pkt["_source"]["layers"]["ipv6"]["ipv6.dst"] = WAN_IP_V6
        event = events_mod.normalize_esp_event(pkt["_source"]["layers"], WAN_IP_V6)
        self.assertEqual(event["source_ip"], "2001:db8:20::20")
        self.assertEqual(event["destination_ip"], "2001:db8:20::10")
        self.assertEqual(event["direction"], "inbound")


class TestNormalizeIkeV6(unittest.TestCase):
    def test_ike_over_ipv6(self):
        event = events_mod.normalize_ike_event(
            _IKE_SA_INIT_PKT_V6["_source"]["layers"], WAN_IP_V6
        )
        self.assertEqual(event["source_ip"], "2001:db8:20::10")
        self.assertEqual(event["destination_ip"], "2001:db8:20::20")
        self.assertEqual(event["source_port"], 500)
        self.assertEqual(event["destination_port"], 500)
        self.assertEqual(event["ike_exchange_type"], 34)
        self.assertEqual(event["ike_exchange_name"], "IKE_SA_INIT")
        self.assertEqual(event["packet_length"], 464)
        self.assertEqual(event["direction"], "outbound")


class TestParseTsharkJsonV6(unittest.TestCase):
    def test_parse_mixed_ipv4_ipv6(self):
        text = json.dumps([_ESP_PKT, _IKE_SA_INIT_PKT, _ESP_PKT_V6,
                           _IKE_SA_INIT_PKT_V6])
        esp_events, ike_events = events_mod.parse_tshark_json(text, WAN_IP)
        self.assertEqual(len(esp_events), 2)
        self.assertEqual(len(ike_events), 2)
        for event in esp_events:
            self.assertNotEqual(event["source_ip"], "None")
            self.assertIsNotNone(event["ip_protocol"])

    def test_ipv6_direction_when_wan_ip_is_ipv6(self):
        text = json.dumps([_ESP_PKT_V6, json.loads(json.dumps(_ESP_PKT_V6))])
        esp_events, _ = events_mod.parse_tshark_json(text, WAN_IP_V6)
        self.assertEqual(len(esp_events), 1)
        self.assertEqual(esp_events[0]["direction"], "outbound")

    def test_non_esp_non_ike_ignored(self):
        text = json.dumps([_ESP_PKT, _TCP_PKT_V6, _IKE_SA_INIT_PKT])
        esp_events, ike_events = events_mod.parse_tshark_json(text, WAN_IP)
        self.assertEqual(len(esp_events), 1)
        self.assertEqual(len(ike_events), 1)

    def test_invalid_json_lines_skipped_safely(self):
        text = "\n".join([
            json.dumps(_ESP_PKT),
            "this-is-not-json",
            json.dumps(_ESP_PKT_V6),
            "{\"broken\": ",
        ])
        esp_events, _ = events_mod.parse_tshark_json(text, WAN_IP_V6)
        self.assertEqual(len(esp_events), 2)


class TestParseTsharkJson(unittest.TestCase):
    def test_parse_json_array(self):
        text = json.dumps([_ESP_PKT, _IKE_SA_INIT_PKT, _IKE_AUTH_PKT_4500])
        esp_events, ike_events = events_mod.parse_tshark_json(text, WAN_IP)
        self.assertEqual(len(esp_events), 1)
        self.assertEqual(len(ike_events), 2)

    def test_parse_json_lines(self):
        lines = "\n".join(json.dumps(p) for p in
                          [_ESP_PKT, _IKE_SA_INIT_PKT, _IKE_AUTH_PKT_4500])
        esp_events, ike_events = events_mod.parse_tshark_json(lines, WAN_IP)
        self.assertEqual(len(esp_events), 1)
        self.assertEqual(len(ike_events), 2)

    def test_empty_input(self):
        self.assertEqual(events_mod.parse_tshark_json("", WAN_IP), ([], []))
        self.assertEqual(events_mod.parse_tshark_json("   ", WAN_IP), ([], []))

    def test_dedupe_duplicate_frame(self):
        text = json.dumps([_ESP_PKT, json.loads(json.dumps(_ESP_PKT))])
        esp_events, _ = events_mod.parse_tshark_json(text, WAN_IP)
        self.assertEqual(len(esp_events), 1)

    def test_summarize(self):
        esp_events, ike_events = events_mod.parse_tshark_json(
            json.dumps([_ESP_PKT, _IKE_SA_INIT_PKT, _IKE_AUTH_PKT_4500]), WAN_IP
        )
        summary = events_mod.summarize(esp_events, ike_events)
        self.assertEqual(summary["esp_packets"], 1)
        self.assertEqual(summary["ike_packets"], 2)
        self.assertEqual(summary["esp_outbound"], 1)
        self.assertEqual(summary["esp_inbound"], 0)
        self.assertEqual(summary["ike_exchanges"]["IKE_SA_INIT"], 1)
        self.assertEqual(summary["ike_exchanges"]["IKE_AUTH"], 1)


if __name__ == "__main__":
    unittest.main()