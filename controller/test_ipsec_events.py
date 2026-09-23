"""Unit tests for the TShark JSON -> audit-event parser (ipsec_events.py)."""

import json
import unittest

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