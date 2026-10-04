"""Focused tests for the dataset sample planner (Module 2).

Run either as:

    .venv/bin/python -m controller.test_dataset_planner

or:

    .venv/bin/python -m unittest controller.test_dataset_planner

Uses a temporary directory for the persistence test; never touches the
production results directory.  No experiment is executed.
"""

import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from controller.dataset_planner import (
    ADDRESS_FAMILIES,
    DH_GROUPS,
    ESP_CIPHERS,
    MODES,
    PLAN_FILENAME,
    POSTURE_ORDER,
    build_catalogue,
    build_sample_plan,
    configuration_id,
    enumerate_candidates,
    posture_of_config,
    profile_sequence,
    traffic_quota,
    validate_traffic_profile,
    write_sample_plan,
)
from controller.dataset_run import create_dataset_run
from controller.validate import validate_config

TARGETS = (6, 10, 50, 100)

GCM_CIPHERS = {"aes128gcm16", "aes256gcm16"}
CBC_CIPHERS = {"aes128cbc", "aes256cbc"}
ESP_INTEGRITIES = {"sha256", "sha384", "sha512"}


def plan_samples(plan):
    return plan["samples"]


def plan_configs(plan):
    return [s["ipsec_configuration"] for s in plan_samples(plan)]


class TestCatalogue(unittest.TestCase):
    # 192 direct configurations (tunnel/transport x ipv4/ipv6 x crypto) plus
    # the 48 transport/ipv4 NAT-T cells.  NAT is a separate axis, not a new
    # mode, so the direct 192 are unchanged.
    DIRECT_ACCEPTED = 192
    NAT_ACCEPTED = 48

    def test_catalogue_counts(self):
        catalogue = build_catalogue()
        self.assertEqual(len(catalogue["accepted"]), self.DIRECT_ACCEPTED + self.NAT_ACCEPTED)
        self.assertEqual(len(catalogue["rejected"]), self.DIRECT_ACCEPTED + self.NAT_ACCEPTED)

    def test_nat_axis_is_transport_ipv4_only(self):
        """NAT may only be enumerated where a translator is provisioned."""
        catalogue = build_catalogue()
        nat_entries = [e for e in catalogue["accepted"] if e["config"].get("nat")]
        self.assertEqual(len(nat_entries), self.NAT_ACCEPTED)
        for entry in nat_entries:
            with self.subTest(configuration_id=entry["configuration_id"]):
                self.assertEqual(entry["config"]["mode"], "transport")
                self.assertEqual(entry["config"]["address_family"], "ipv4")

    def test_nat_configuration_ids_are_distinct(self):
        """A NAT-T cell must never collide with its direct counterpart."""
        catalogue = build_catalogue()
        ids = [e["configuration_id"] for e in catalogue["accepted"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_catalogue_per_posture_counts(self):
        catalogue = build_catalogue()
        counts = Counter(e["security_posture"] for e in catalogue["accepted"])
        # 240 accepted = the original 192 direct cells plus the 48 NAT-T cells.
        self.assertEqual(sum(counts.values()), self.DIRECT_ACCEPTED + self.NAT_ACCEPTED)
        self.assertEqual(
            dict(counts),
            {"STRONG": 15, "GOOD": 55, "MEDIUM": 65, "WEAK": 60, "WORST": 45},
        )

    def test_accepted_configurations_all_valid(self):
        catalogue = build_catalogue()
        for entry in catalogue["accepted"]:
            with self.subTest(configuration_id=entry["configuration_id"]):
                self.assertTrue(validate_config(entry["config"]))

    def test_rejected_configurations_are_invalid(self):
        catalogue = build_catalogue()
        self.assertTrue(all("reason" in e for e in catalogue["rejected"]))
        for entry in catalogue["rejected"]:
            with self.subTest(configuration_id=entry["configuration_id"]):
                with self.assertRaises(ValueError):
                    validate_config(entry["config"])

    def test_rejections_have_validator_reasons(self):
        catalogue = build_catalogue()
        reasons = {e["reason"] for e in catalogue["rejected"]}
        self.assertEqual(
            reasons,
            {
                "CBC ESP requires an integrity algorithm",
                "GCM ESP must not specify a separate integrity algorithm",
            },
        )

    def test_configuration_ids_unique(self):
        catalogue = build_catalogue()
        ids = [e["configuration_id"] for e in catalogue["accepted"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_catalogue_covers_all_shape_axes(self):
        catalogue = build_catalogue()
        modes = {e["config"]["mode"] for e in catalogue["accepted"]}
        families = {e["config"]["address_family"] for e in catalogue["accepted"]}
        ciphers = {e["config"]["esp"]["encryption"] for e in catalogue["accepted"]}
        dhs = {e["config"]["esp"]["dh_group"] for e in catalogue["accepted"]}
        pfs_values = {e["config"]["esp"]["pfs"] for e in catalogue["accepted"]}

        self.assertEqual(modes, set(MODES))
        self.assertEqual(families, set(ADDRESS_FAMILIES))
        self.assertEqual(ciphers, set(ESP_CIPHERS))
        self.assertEqual(dhs, set(DH_GROUPS))
        self.assertEqual(pfs_values, {True, False})

    def test_configuration_id_encoding(self):
        config = {
            "mode": "tunnel",
            "address_family": "ipv4",
            "ike": {},
            "esp": {
                "encryption": "aes256gcm16",
                "integrity": None,
                "dh_group": "modp3072",
                "pfs": True,
            },
        }
        self.assertEqual(
            configuration_id(config),
            "tunnel-ipv4-aes256gcm16-none-modp3072-true",
        )


class TestPostureScoring(unittest.TestCase):
    def base_config(self, encryption, dh_group, pfs, integrity):
        return {
            "mode": "tunnel",
            "address_family": "ipv4",
            "ike": {
                "version": 2,
                "encryption": "aes256",
                "integrity": "sha256",
                "dh_group": "modp2048",
            },
            "esp": {
                "encryption": encryption,
                "integrity": integrity,
                "dh_group": dh_group,
                "pfs": pfs,
            },
        }

    def test_strong_band(self):
        config = self.base_config("aes256gcm16", "modp4096", True, None)
        self.assertEqual(posture_of_config(config), ("STRONG", 12))

    def test_good_band_boundary(self):
        borderline = self.base_config("aes128gcm16", "modp3072", True, None)
        self.assertEqual(posture_of_config(borderline), ("GOOD", 10))
        strong_low = self.base_config("aes128gcm16", "modp4096", True, None)
        self.assertEqual(posture_of_config(strong_low), ("STRONG", 11))

    def test_medium_band(self):
        config = self.base_config("aes128cbc", "modp2048", True, "sha256")
        self.assertEqual(posture_of_config(config), ("MEDIUM", 6))

    def test_weak_band(self):
        config = self.base_config("aes256cbc", "modp2048", False, "sha256")
        self.assertEqual(posture_of_config(config), ("WEAK", 4))

    def test_worst_band_is_weakest_but_valid(self):
        config = self.base_config("aes128cbc", "modp2048", False, "sha256")
        self.assertTrue(validate_config(config))
        self.assertEqual(posture_of_config(config), ("WORST", 3))


class TestTrafficBalance(unittest.TestCase):
    def test_quotas_differ_by_at_most_one(self):
        for target in TARGETS + (1, 7, 119):
            quota = traffic_quota(target)
            counts = list(quota.values())
            self.assertEqual(len(quota), 6)
            self.assertEqual(sum(counts), target)
            self.assertLessEqual(max(counts) - min(counts), 1)

    def test_exact_quota_shapes(self):
        self.assertEqual(
            traffic_quota(6),
            {"voip": 1, "video": 1, "messaging": 1, "email": 1, "web": 1, "icmp": 1},
        )
        self.assertEqual(
            traffic_quota(10),
            {"voip": 2, "video": 2, "messaging": 2, "email": 2, "web": 1, "icmp": 1},
        )
        self.assertEqual(
            traffic_quota(50),
            {"voip": 9, "video": 9, "messaging": 8, "email": 8, "web": 8, "icmp": 8},
        )
        self.assertEqual(
            traffic_quota(100),
            {"voip": 17, "video": 17, "messaging": 17, "email": 17, "web": 16, "icmp": 16},
        )

    def test_profile_sequence_length_and_quotas(self):
        for target in TARGETS:
            sequence = profile_sequence(target)
            self.assertEqual(len(sequence), target)
            self.assertEqual(Counter(sequence), traffic_quota(target))

    def test_profile_sequence_is_round_robin(self):
        self.assertEqual(
            profile_sequence(10),
            ["voip", "video", "messaging", "email", "web", "icmp",
             "voip", "video", "messaging", "email"],
        )

    def test_validate_traffic_profile(self):
        for profile in ("voip", "video", "messaging", "email", "web", "icmp"):
            validate_traffic_profile(profile)
        with self.assertRaises(ValueError):
            validate_traffic_profile("bogus")
        with self.assertRaises(ValueError):
            validate_traffic_profile("")

    def test_invalid_targets_rejected(self):
        for bad in (0, -3, True, "10", 10.0, None, [6]):
            with self.assertRaises(ValueError):
                traffic_quota(bad)
            with self.assertRaises(ValueError):
                build_sample_plan(bad)


class TestSamplePlan(unittest.TestCase):
    def test_exact_sample_counts(self):
        for target in TARGETS:
            plan = build_sample_plan(target)
            self.assertEqual(len(plan_samples(plan)), target)
            self.assertEqual(plan["target_samples"], target)
            sequences = [s["sequence"] for s in plan_samples(plan)]
            self.assertEqual(sequences, list(range(1, target + 1)))

    def test_traffic_quotas_matched(self):
        for target in TARGETS:
            plan = build_sample_plan(target)
            profile_counts = Counter(s["traffic_profile"] for s in plan_samples(plan))
            self.assertEqual(dict(profile_counts), plan["traffic_quota"])
            self.assertEqual(dict(profile_counts), traffic_quota(target))

    def test_all_plan_configs_valid(self):
        for target in TARGETS:
            plan = build_sample_plan(target)
            for sample in plan_samples(plan):
                with self.subTest(target=target, sequence=sample["sequence"]):
                    self.assertTrue(validate_config(sample["ipsec_configuration"]))

    def test_gcm_has_no_hmac_cbc_has_hmac(self):
        plan = build_sample_plan(50)
        for sample in plan_samples(plan):
            esp = sample["ipsec_configuration"]["esp"]
            if esp["encryption"] in GCM_CIPHERS:
                self.assertIsNone(esp["integrity"])
            else:
                self.assertIn(esp["encryption"], CBC_CIPHERS)
                self.assertIn(esp["integrity"], ESP_INTEGRITIES)

    def test_all_postures_present(self):
        plan = build_sample_plan(50)
        postures = {s["security_posture"] for s in plan_samples(plan)}
        self.assertEqual(postures, set(POSTURE_ORDER))

    def test_posture_sequence_is_round_robin(self):
        plan = build_sample_plan(10)
        postures = [s["security_posture"] for s in plan_samples(plan)]
        self.assertEqual(postures, list(POSTURE_ORDER) * 2)

    def test_configuration_variety(self):
        plan = build_sample_plan(50)
        config_ids = {s["configuration_id"] for s in plan_samples(plan)}
        self.assertGreaterEqual(len(config_ids), 25)

    def test_per_posture_config_variety(self):
        plan = build_sample_plan(50)
        for posture in POSTURE_ORDER:
            ids = {
                s["configuration_id"]
                for s in plan_samples(plan)
                if s["security_posture"] == posture
            }
            self.assertGreater(len(ids), 1, msg=f"posture {posture} too uniform")

    def test_posture_planned_counts(self):
        plan = build_sample_plan(50)
        expected = {p: 10 for p in POSTURE_ORDER}
        self.assertEqual(plan["posture_planned"], expected)

    def test_unique_and_reuse_counts(self):
        plan = build_sample_plan(50)
        for posture in POSTURE_ORDER:
            self.assertEqual(
                plan["posture_unique_configuration_count"][posture],
                plan["posture_planned"][posture]
                - plan["posture_configuration_reuses"][posture],
            )

    def test_deterministic_plan(self):
        for target in TARGETS:
            with self.subTest(target=target):
                first = json.dumps(build_sample_plan(target), sort_keys=True)
                second = json.dumps(build_sample_plan(target), sort_keys=True)
                self.assertEqual(first, second)

    def test_full_axis_coverage_at_scale(self):
        plan = build_sample_plan(100)
        modes = set()
        families = set()
        ciphers = set()
        dhs = set()
        pfs_values = set()
        for sample in plan_configs(plan):
            modes.add(sample["mode"])
            families.add(sample["address_family"])
            ciphers.add(sample["esp"]["encryption"])
            dhs.add(sample["esp"]["dh_group"])
            pfs_values.add(sample["esp"]["pfs"])

        self.assertEqual(modes, set(MODES))
        self.assertEqual(families, set(ADDRESS_FAMILIES))
        self.assertEqual(ciphers, set(ESP_CIPHERS))
        self.assertEqual(dhs, set(DH_GROUPS))
        self.assertEqual(pfs_values, {True, False})

    def test_never_inserts_unsupported_config(self):
        plan = build_sample_plan(100)
        for sample in plan_configs(plan):
            esp = sample["esp"]
            if esp["encryption"] in GCM_CIPHERS:
                self.assertIsNone(esp["integrity"])
            else:
                self.assertIn(esp["integrity"], ESP_INTEGRITIES)

    def test_plan_metadata_present(self):
        plan = build_sample_plan(10)
        self.assertIn("planner_version", plan)
        self.assertIn("dataset_schema_version", plan)
        self.assertIn("catalogue", plan)
        self.assertEqual(plan["catalogue"]["accepted"], 240)
        self.assertEqual(plan["catalogue"]["rejected"], 240)


class TestPlanPersistence(unittest.TestCase):
    def test_write_and_read_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=10)
            plan = build_sample_plan(10)
            path = write_sample_plan(tmp, run.id, plan)

            self.assertEqual(path, Path(run.directory) / "staging" / PLAN_FILENAME)
            self.assertTrue(path.is_file())
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), plan)

    def test_write_to_missing_run_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = build_sample_plan(10)
            with self.assertRaises(FileNotFoundError):
                write_sample_plan(tmp, "dataset-does-not-exist", plan)


if __name__ == "__main__":
    unittest.main(verbosity=2)