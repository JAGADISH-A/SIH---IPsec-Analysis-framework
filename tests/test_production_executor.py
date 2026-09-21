"""Phase 10 — production execution base contract tests (statuses/targets)."""

import unittest

from correlation.execution.base import (
    EXECUTION_STATUSES,
    STATUS_DEPENDENCY_UNAVAILABLE,
    STATUS_SUCCESS,
    ExecutionOutcome,
    is_success,
    validate_execution_status,
)
from correlation.execution.host import MemoryHost, UnavailableHost
from correlation.execution.settings import (
    MODE_AUTHORIZED_TESTBED,
    MODE_DRY_RUN,
    MODE_PRODUCTION,
    ExecutionSettings,
)
from correlation.execution.targets import (
    ExecutionTarget,
    TargetAllowlist,
    parse_ip_version,
)


class TestExecutionStatuses(unittest.TestCase):
    def test_expected_vocabulary(self):
        required = {
            "SUCCEEDED", "FAILED", "DENIED", "EXPIRED", "CANCELLED",
            "ALREADY_APPLIED", "NOT_SUPPORTED", "TARGET_NOT_ALLOWED",
            "DEPENDENCY_UNAVAILABLE",
        }
        self.assertEqual(set(EXECUTION_STATUSES), required)

    def test_validate(self):
        self.assertEqual(validate_execution_status("SUCCEEDED"), "SUCCEEDED")
        with self.assertRaises(ValueError):
            validate_execution_status("MAGIC")
        self.assertTrue(is_success("SUCCEEDED"))
        self.assertFalse(is_success("FAILED"))


class TestExecutionTarget(unittest.TestCase):
    def test_auto_ip_version(self):
        target = ExecutionTarget(destination="198.51.100.9")
        self.assertEqual(target.ip_version, "ipv4")
        target6 = ExecutionTarget(destination="2001:db8::1")
        self.assertEqual(target6.ip_version, "ipv6")

    def test_explicit_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            ExecutionTarget(destination="198.51.100.9", ip_version="ipv6")

    def test_invalid_destination_rejected(self):
        with self.assertRaises(ValueError):
            ExecutionTarget(destination="not-an-ip")

    def test_port_protocol_bounds(self):
        with self.assertRaises(ValueError):
            ExecutionTarget(destination="198.51.100.9", destination_port=70000)
        with self.assertRaises(ValueError):
            ExecutionTarget(destination="198.51.100.9", protocol=999)

    def test_key(self):
        t = ExecutionTarget(destination="198.51.100.9", protocol=17, destination_port=4500)
        self.assertEqual(t.key(), "198.51.100.9|17|4500")

    def test_to_from_dict(self):
        t = ExecutionTarget(destination="198.51.100.9", protocol=17,
                            destination_port=4500)
        self.assertEqual(ExecutionTarget.from_dict(t.to_dict()), t)

    def test_parse_ip_version(self):
        self.assertEqual(parse_ip_version("198.51.100.9"), "ipv4")
        self.assertEqual(parse_ip_version("2001:db8::1"), "ipv6")
        self.assertEqual(parse_ip_version("garbage"), "UNKNOWN")


class TestTargetAllowlist(unittest.TestCase):
    def test_empty_allows_nothing(self):
        allowlist = TargetAllowlist()
        self.assertFalse(allowlist.allows("198.51.100.9"))

    def test_exact_host_and_cidr(self):
        allowlist = TargetAllowlist(networks=("192.0.2.0/24", "198.51.100.7"))
        self.assertTrue(allowlist.allows("192.0.2.5"))
        self.assertFalse(allowlist.allows("203.0.113.5"))
        self.assertTrue(allowlist.allows("198.51.100.7"))
        self.assertFalse(allowlist.allows("garbage"))

    def test_invalid_network_rejected(self):
        with self.assertRaises(ValueError):
            TargetAllowlist(networks=("999.999.999.999",))

    def test_allows_target(self):
        allowlist = TargetAllowlist(networks=("192.0.2.0/24",))
        target = ExecutionTarget(destination="192.0.2.8")
        self.assertTrue(allowlist.allows_target(target))
        self.assertTrue(allowlist.allows_target(target.to_dict()))


class TestSettings(unittest.TestCase):
    def test_defaults_dry_run_and_off(self):
        settings = ExecutionSettings()
        self.assertEqual(settings.mode, MODE_DRY_RUN)
        self.assertFalse(settings.enable_production_execution)

    def test_production_requires_enable_flag(self):
        with self.assertRaises(ValueError):
            ExecutionSettings(mode=MODE_PRODUCTION)
        ExecutionSettings(mode=MODE_PRODUCTION, enable_production_execution=True,
                          allowed_testbed_targets=("127.0.0.1/32",))

    def test_testbed_requires_allowlist(self):
        with self.assertRaises(ValueError):
            ExecutionSettings(mode=MODE_AUTHORIZED_TESTBED)

    def test_effective_mode(self):
        self.assertFalse(ExecutionSettings().effective_mode.network_effect_allowed)
        self.assertTrue(
            ExecutionSettings(mode=MODE_AUTHORIZED_TESTBED,
                              allowed_testbed_targets=("127.0.0.1/32",)
                              ).effective_mode.network_effect_allowed
        )

    def test_from_env(self):
        env = {
            "SIHEXEC_MODE": "authorized_testbed",
            "SIHEXEC_ENABLE_PRODUCTION_EXECUTION": "false",
            "SIHEXEC_ALLOWED_TESTBED_TARGETS": "192.0.2.0/24, 198.51.100.7",
        }
        settings = ExecutionSettings.from_env(env)
        self.assertEqual(settings.mode, "AUTHORIZED_TESTBED")
        self.assertEqual(settings.allowed_testbed_targets,
                         ("192.0.2.0/24", "198.51.100.7"))
        to_dict = settings.to_dict()
        self.assertEqual(to_dict["mode"], "AUTHORIZED_TESTBED")


class TestOutcome(unittest.TestCase):
    def test_roundtrip(self):
        outcome = ExecutionOutcome(
            execution_id="exec-1",
            recommendation_id="rec-1",
            action="BLOCK_FLOW",
            executor_type="xdp",
            status=STATUS_DEPENDENCY_UNAVAILABLE,
            success=False,
            network_effect=False,
            reason="no host",
            operation={"op": "xdp.block_flow"},
            started_at=1,
            completed_at=2,
        )
        restored = ExecutionOutcome.from_dict(outcome.to_dict())
        self.assertEqual(restored, outcome)

    def test_validation(self):
        with self.assertRaises(ValueError):
            ExecutionOutcome(
                execution_id="x", recommendation_id="r", action="BLOCK_FLOW",
                executor_type="xdp", status="FAKE", success=False,
                network_effect=False, reason="",
            )


class TestHosts(unittest.TestCase):
    def test_unavailable_host_is_honest(self):
        host = UnavailableHost()
        self.assertFalse(host.is_available())
        result = host.apply({"op": "x"})
        self.assertFalse(result["applied"])
        self.assertEqual(result["status"], STATUS_DEPENDENCY_UNAVAILABLE)

    def test_memory_host_records(self):
        host = MemoryHost()
        self.assertTrue(host.is_available())
        result = host.apply({"op": "firewall.block_flow", "target": {"destination": "192.0.2.1"}})
        self.assertTrue(result["applied"])
        self.assertEqual(result["status"], STATUS_SUCCESS)
        self.assertEqual(len(host.operations), 1)
        host.reset()
        self.assertEqual(len(host.operations), 0)

    def test_memory_host_unavailable(self):
        host = MemoryHost(available=False)
        self.assertFalse(host.is_available())
        self.assertFalse(host.apply({"op": "x"})["applied"])


if __name__ == "__main__":
    unittest.main()