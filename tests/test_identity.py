import unittest

from correlation.models import CorrelationIdentity


class TestIdentityValidation(unittest.TestCase):
    def test_valid_identity(self):
        ident = CorrelationIdentity(
            dataset_run_id="run-20260920-001",
            sequence=1,
            experiment_id="exp-aes256gcm16-video",
            attempt_number=1,
            window_index=123,
            window_start_ns=12300000000,
            window_end_ns=12400000000,
        )
        self.assertEqual(ident.dataset_run_id, "run-20260920-001")
        self.assertEqual(ident.sequence, 1)
        self.assertEqual(ident.experiment_id, "exp-aes256gcm16-video")
        self.assertEqual(ident.attempt_number, 1)
        self.assertEqual(ident.window_index, 123)
        self.assertTrue(ident.is_window_level())

    def test_state_level_identity_allows_no_window(self):
        ident = CorrelationIdentity(
            dataset_run_id="run-20260920-001",
            sequence=2,
            experiment_id="exp-aes256gcm16-video",
            attempt_number=1,
        )
        self.assertTrue(ident.is_state_level())

    def test_empty_run_id_rejected(self):
        with self.assertRaises(ValueError):
            CorrelationIdentity(
                dataset_run_id="",
                sequence=1,
                experiment_id="exp",
                attempt_number=1,
            )

    def test_empty_experiment_id_rejected(self):
        with self.assertRaises(ValueError):
            CorrelationIdentity(
                dataset_run_id="run-1",
                sequence=1,
                experiment_id="   ",
                attempt_number=1,
            )

    def test_sequence_zero_rejected(self):
        with self.assertRaises(ValueError):
            CorrelationIdentity(
                dataset_run_id="run-1",
                sequence=0,
                experiment_id="exp",
                attempt_number=1,
            )

    def test_attempt_zero_rejected(self):
        with self.assertRaises(ValueError):
            CorrelationIdentity(
                dataset_run_id="run-1",
                sequence=1,
                experiment_id="exp",
                attempt_number=0,
            )

    def test_negative_window_start_rejected(self):
        with self.assertRaises(ValueError):
            CorrelationIdentity(
                dataset_run_id="run-1",
                sequence=1,
                experiment_id="exp",
                attempt_number=1,
                window_start_ns=-1,
                window_end_ns=0,
            )

    def test_window_end_before_start_rejected(self):
        with self.assertRaises(ValueError):
            CorrelationIdentity(
                dataset_run_id="run-1",
                sequence=1,
                experiment_id="exp",
                attempt_number=1,
                window_start_ns=100,
                window_end_ns=50,
            )

    def test_window_end_requires_start(self):
        with self.assertRaises(ValueError):
            CorrelationIdentity(
                dataset_run_id="run-1",
                sequence=1,
                experiment_id="exp",
                attempt_number=1,
                window_end_ns=50,
            )

    def test_identity_serialization_round_trip(self):
        ident = CorrelationIdentity(
            dataset_run_id="run-20260920-001",
            sequence=3,
            experiment_id="exp-aes256gcm16-video",
            attempt_number=2,
            window_index=7,
            window_start_ns=1000,
            window_end_ns=1100,
        )
        restored = CorrelationIdentity.from_json(ident.to_json())
        self.assertEqual(restored, ident)
        self.assertEqual(restored.to_dict(), ident.to_dict())


if __name__ == "__main__":
    unittest.main()