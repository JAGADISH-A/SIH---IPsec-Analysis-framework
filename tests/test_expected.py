import unittest

from correlation.models import (
    ALLOWED_MODES,
    CANONICAL_VARIABLES,
    EspExpected,
    ExpectedState,
    IkeExpected,
    TrafficExpected,
)


def make_expected():
    return ExpectedState(
        mode="tunnel",
        address_family="ipv4",
        ike=IkeExpected(version=2, encryption="aes256", integrity="sha256", dh_group="modp2048"),
        esp=EspExpected(encryption="aes256gcm16", integrity=None, dh_group="modp2048", pfs=True),
        traffic=TrafficExpected(profile="video", duration=30, port=20000),
        capture_filter="udp port 500 or udp port 4500 or esp or ah",
        configuration_id=None,
        security_posture="STRONG",
    )


class TestExpectedState(unittest.TestCase):
    def test_valid_expected_state_uses_canonical_names(self):
        exp = make_expected()
        self.assertEqual(exp.mode, "tunnel")
        self.assertEqual(exp.address_family, "ipv4")
        self.assertEqual(exp.ike.version, 2)
        self.assertEqual(exp.ike.encryption, "aes256")
        self.assertEqual(exp.ike.integrity, "sha256")
        self.assertEqual(exp.ike.dh_group, "modp2048")
        self.assertEqual(exp.esp.encryption, "aes256gcm16")
        self.assertIsNone(exp.esp.integrity)
        self.assertEqual(exp.esp.dh_group, "modp2048")
        self.assertTrue(exp.esp.pfs)
        self.assertEqual(exp.traffic.profile, "video")
        self.assertEqual(exp.traffic.duration, 30)
        self.assertEqual(exp.traffic.port, 20000)
        self.assertEqual(
            exp.capture_filter, "udp port 500 or udp port 4500 or esp or ah"
        )

    def test_nested_ipsec_variables_preserved(self):
        exp = make_expected()
        d = exp.to_dict()
        self.assertEqual(d["ike"]["version"], 2)
        self.assertEqual(d["ike"]["encryption"], "aes256")
        self.assertEqual(d["ike"]["integrity"], "sha256")
        self.assertEqual(d["ike"]["dh_group"], "modp2048")
        self.assertEqual(d["esp"]["encryption"], "aes256gcm16")
        self.assertIsNone(d["esp"]["integrity"])
        self.assertEqual(d["esp"]["dh_group"], "modp2048")
        self.assertTrue(d["esp"]["pfs"])

    def test_transport_mode_allowed(self):
        exp = ExpectedState(
            mode="transport",
            address_family="ipv4",
            ike=IkeExpected(version=2, encryption="aes256", integrity="sha256", dh_group="modp2048"),
            esp=EspExpected(encryption="aes256gcm16", integrity=None, dh_group="modp2048", pfs=False),
            traffic=TrafficExpected(profile="video", duration=30, port=20000),
            capture_filter="udp port 500 or udp port 4500 or esp or ah",
        )
        self.assertEqual(exp.mode, "transport")

    def test_invalid_mode_rejected(self):
        with self.assertRaises(ValueError):
            ExpectedState(
                mode="carrier-pigeon",
                address_family="ipv4",
                ike=IkeExpected(version=2, encryption="aes256", integrity="sha256", dh_group="modp2048"),
                esp=EspExpected(encryption="aes256gcm16", integrity=None, dh_group="modp2048", pfs=True),
                traffic=TrafficExpected(profile="video", duration=30, port=20000),
                capture_filter="udp port 500",
            )

    def test_invalid_address_family_rejected(self):
        with self.assertRaises(ValueError):
            ExpectedState(
                mode="tunnel",
                address_family="ipv9",
                ike=IkeExpected(version=2, encryption="aes256", integrity="sha256", dh_group="modp2048"),
                esp=EspExpected(encryption="aes256gcm16", integrity=None, dh_group="modp2048", pfs=True),
                traffic=TrafficExpected(profile="video", duration=30, port=20000),
                capture_filter="udp port 500",
            )

    def test_esp_integrity_none_allowed(self):
        exp = make_expected()
        self.assertIsNone(exp.esp.integrity)

    def test_derive_configuration_id(self):
        exp = make_expected()
        self.assertEqual(
            exp.derive_configuration_id(),
            "tunnel-ipv4-aes256gcm16-none-modp2048-true",
        )

    def test_observability_metadata_present(self):
        exp = make_expected()
        obs = exp.observability()
        self.assertEqual(obs["esp.encryption"], "INDIRECTLY_OBSERVABLE")
        self.assertEqual(obs["ike.version"], "AUDIT_ONLY")
        self.assertEqual(obs["traffic.port"], "NOT_CURRENTLY_OBSERVABLE")
        self.assertEqual(exp.observability_of("mode"), "DIRECTLY_OBSERVABLE")

    def test_canonical_variable_list_complete(self):
        self.assertEqual(
            CANONICAL_VARIABLES,
            (
                "mode",
                "address_family",
                "ike.version",
                "ike.encryption",
                "ike.integrity",
                "ike.dh_group",
                "esp.encryption",
                "esp.integrity",
                "esp.dh_group",
                "esp.pfs",
                "traffic.profile",
                "traffic.duration",
                "traffic.port",
                "capture_filter",
            ),
        )

    def test_round_trip(self):
        exp = make_expected()
        restored = ExpectedState.from_json(exp.to_json())
        self.assertEqual(restored, exp)


if __name__ == "__main__":
    unittest.main()