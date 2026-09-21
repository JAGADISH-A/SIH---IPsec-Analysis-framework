import unittest

from correlation.models import (
    ObservedState,
    SpiObservation,
    TransitionObservation,
)


def make_spi():
    return SpiObservation(
        spi=0xC0A80164,
        direction="A_TO_B",
        active=True,
        first_seen_ns=1000,
        last_seen_ns=1100,
        packet_count=60,
        first_sequence=1,
        last_sequence=60,
        highest_sequence=60,
        sequence_delta=59,
    )


def make_observed():
    return ObservedState(
        timestamp_ns=1100,
        endpoints={"a": "192.0.2.100", "b": "192.0.2.200"},
        tunnel_seen=True,
        active=True,
        packets_seen=120,
        bytes_seen=48000,
        packets_a_to_b=60,
        packets_b_to_a=60,
        bytes_a_to_b=24000,
        bytes_b_to_a=24000,
        ike_seen=True,
        ike_nat_t_seen=False,
        esp_seen=True,
        ah_seen=False,
        observed_ike_activity=True,
        last_ike_timestamp_ns=900,
        last_esp_timestamp_ns=1050,
        spis=[make_spi()],
        transitions=[
            TransitionObservation(
                name="ACTIVE",
                timestamp_ns=1000,
                details={"spi": 0xC0A80164, "direction": "A_TO_B"},
            )
        ],
    )


class TestObservedState(unittest.TestCase):
    def test_matches_state_builder_structure(self):
        obs = make_observed()
        self.assertEqual(obs.tunnel_seen, True)
        self.assertEqual(obs.active, True)
        self.assertEqual(obs.packets_seen, 120)
        self.assertEqual(obs.bytes_seen, 48000)
        self.assertEqual(obs.packets_a_to_b, 60)
        self.assertEqual(obs.packets_b_to_a, 60)
        self.assertEqual(obs.bytes_a_to_b, 24000)
        self.assertEqual(obs.bytes_b_to_a, 24000)
        self.assertTrue(obs.ike_seen)
        self.assertFalse(obs.ike_nat_t_seen)
        self.assertTrue(obs.esp_seen)
        self.assertFalse(obs.ah_seen)
        self.assertTrue(obs.observed_ike_activity)
        self.assertEqual(obs.last_ike_timestamp_ns, 900)
        self.assertEqual(obs.last_esp_timestamp_ns, 1050)

    def test_no_crypto_fields_invented(self):
        d = make_observed().to_dict()
        for forbidden in ("encryption", "integrity", "ike_sa_established"):
            self.assertFalse(
                any(forbidden in key for key in d.keys()),
                f"observed state must not expose {forbidden!r}",
            )

    def test_spi_survives_serialization(self):
        obs = make_observed()
        d = obs.to_dict()
        spi = d["spis"][0]
        self.assertEqual(spi["spi"], 0xC0A80164)
        self.assertEqual(spi["direction"], "A_TO_B")
        self.assertEqual(spi["packet_count"], 60)
        self.assertEqual(spi["sequence_delta"], 59)
        restored = ObservedState.from_json(obs.to_json())
        self.assertEqual(restored, obs)

    def test_transitions_preserved(self):
        obs = make_observed()
        d = obs.to_dict()
        self.assertEqual(d["transitions"][0]["name"], "ACTIVE")
        self.assertEqual(d["transitions"][0]["timestamp_ns"], 1000)
        self.assertEqual(d["transitions"][0]["details"]["spi"], 0xC0A80164)

    def test_last_event_after_snapshot_rejected(self):
        with self.assertRaises(ValueError):
            ObservedState(timestamp_ns=100, last_esp_timestamp_ns=200)

    def test_zero_epoch_state_allowed(self):
        obs = ObservedState(timestamp_ns=0)
        self.assertEqual(obs.packets_seen, 0)
        self.assertFalse(obs.tunnel_seen)

    def test_unknown_spi_direction_allowed(self):
        spi = SpiObservation(spi=123)
        self.assertIsNone(spi.direction)

    def test_bad_spi_direction_rejected(self):
        with self.assertRaises(ValueError):
            SpiObservation(spi=1, direction="UPSTREAM")


if __name__ == "__main__":
    unittest.main()