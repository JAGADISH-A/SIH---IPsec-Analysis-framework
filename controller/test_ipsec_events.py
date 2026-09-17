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