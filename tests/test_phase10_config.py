"""Phase 10 — central ProductionConfig tests (env-derived, no secrets)."""

import unittest

from correlation.config import CONFIG_SCHEMA_VERSION, ProductionConfig
from correlation.execution.settings import MODE_AUTHORIZED_TESTBED


class TestProductionConfig(unittest.TestCase):
    def test_defaults_safe(self):
        config = ProductionConfig()
        self.assertEqual(config.schema_version, CONFIG_SCHEMA_VERSION)
        self.assertFalse(config.execution.enable_production_execution)
        self.assertEqual(config.execution.mode, "DRY_RUN")
        self.assertEqual(config.streaming.transport, "memory")
        self.assertFalse(config.streaming.kafka_enabled)

    def test_from_env(self):
        env = {
            "SIHEXEC_MODE": "authorized_testbed",
            "SIHEXEC_ALLOWED_TESTBED_TARGETS": "192.0.2.0/24",
            "SIH_STREAM_WINDOW_MS": "250",
            "SIHAPI_PORT": "9001",
            "SIH_TRAFFIC_GENERATOR_MONITORED": "true",
        }
        config = ProductionConfig.from_env(env)
        self.assertEqual(config.execution.mode, MODE_AUTHORIZED_TESTBED)
        self.assertEqual(config.streaming.window_ms, 250)
        self.assertEqual(config.api_port, 9001)
        self.assertTrue(config.traffic_generator_monitored)

    def test_execution_production_flag_off_by_default(self):
        config = ProductionConfig.from_env({})
        self.assertFalse(config.execution.enable_production_execution)
        self.assertEqual(config.execution.allowed_testbed_targets, ())

    def test_to_dict(self):
        config = ProductionConfig()
        data = config.to_dict()
        self.assertEqual(data["schema_version"], CONFIG_SCHEMA_VERSION)
        self.assertEqual(data["execution"]["mode"], "DRY_RUN")
        self.assertEqual(data["streaming"]["window_ms"], 100)

    def test_no_secrets_in_output(self):
        # serialized config contains no secret-looking keys
        text = str(ProductionConfig().to_dict()).lower()
        for secret_key in ("password", "secret", "token", "api_key"):
            self.assertNotIn(secret_key, text)


if __name__ == "__main__":
    unittest.main()