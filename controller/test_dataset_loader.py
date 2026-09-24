"""Tests for controller.dataset_loader (schema validation + ML matrix build)."""

import itertools
import shutil
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

from controller import dataset_loader as dl
from controller.dataset_artifacts import FEATURE_COLUMNS, FLOAT_FEATURES, INT_FEATURES

CONFIGS = (
    "tunnel-ipv4-aes128cbc-sha256-modp2048-false",
    "tunnel-ipv4-aes256gcm16-none-modp4096-true",
    "transport-ipv6-aes256gcm16-none-modp3072-true",
)
POSTURES = ("STRONG", "GOOD", "MEDIUM", "WEAK", "WORST")


def feature_values(column, n):
    base = np.arange(1, n + 1, dtype=np.float64)
    if column in INT_FEATURES:
        return (base * 3).astype(np.int32)
    return base * 1.25


def build_table(n, run_id="run-a", float_inf_column=None, int_as_float_column=None,
                unknown_target=False):
    profile_iter = itertools.cycle(dl.TARGET_CLASSES)
    posture_iter = itertools.cycle(POSTURES)
    config_iter = itertools.cycle(CONFIGS)
    profiles = [next(profile_iter) for _ in range(n)]
    if unknown_target:
        profiles[0] = "alien-app"
    data = {
        "dataset_run_id": [run_id] * n,
        "sequence": np.arange(1, n + 1, dtype=np.int32),
        "experiment_id": [f"{run_id}-exp-{i:04d}-attempt-01" for i in range(1, n + 1)],
        "attempt_number": np.ones(n, dtype=np.int32),
        "traffic_profile": profiles,
        "security_posture": [next(posture_iter) for _ in range(n)],
        "configuration_id": [next(config_iter) for _ in range(n)],
        "captured_at": ["2026-09-23T16:45:42.493861+00:00"] * n,
        "pcap_path": [f"{run_id}/captures/{i}.pcap" for i in range(1, n + 1)],
        "feature_schema_version": ["v2"] * n,
    }
    for column in FEATURE_COLUMNS:
        values = feature_values(column, n)
        pa_type = pa.int32() if column in INT_FEATURES else pa.float64()
        if column == float_inf_column:
            values = np.array(values, dtype=np.float64)
            values[3] = float("inf")
        if column == int_as_float_column:
            pa_type = pa.float64()
        data[column] = pa.array(values, type=pa_type)
    return pa.table(data)


def write_run(dirpath, n, run_id="run-a", **kwargs):
    table = build_table(n, run_id=run_id, **kwargs)
    run_dir = dirpath / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, run_dir / "features.parquet")
    return run_dir


class LoaderSchemaTest(unittest.TestCase):
    def test_valid_table_passes(self):
        dl.validate_table(build_table(5), "run-a")

    def test_missing_columns_rejected(self):
        table = build_table(5).drop(["packet_count", "total_bytes"])
        with self.assertRaises(ValueError):
            dl.validate_table(table, "run-a")

    def test_unexpected_columns_rejected(self):
        table = build_table(5)
        table = table.append_column(pa.field("application_name", pa.string()),
                                    pa.array(["x"] * 5))
        with self.assertRaises(ValueError):
            dl.validate_table(table, "run-a")

    def test_wrong_schema_version_rejected(self):
        table = build_table(5)
        table = table.set_column(
            table.schema.get_field_index("feature_schema_version"),
            "feature_schema_version", pa.array(["v1"] * 5),
        )
        with self.assertRaises(ValueError):
            dl.validate_table(table, "run-a")

    def test_null_detection(self):
        table = build_table(5)
        values = list(table.column("packet_count").to_pylist())
        values[2] = None
        table = table.set_column(
            table.schema.get_field_index("packet_count"), "packet_count",
            pa.array(values, type=pa.int32()),
        )
        with self.assertRaises(ValueError):
            dl.validate_table(table, "run-a")

    def test_non_finite_detection(self):
        table = build_table(5, float_inf_column="mean_packet_size")
        with self.assertRaises(ValueError):
            dl.validate_table(table, "run-a")

    def test_type_mismatch_rejected(self):
        table = build_table(5, int_as_float_column="packet_count")
        with self.assertRaises(TypeError):
            dl.validate_table(table, "run-a")


class LoaderMatrixTest(unittest.TestCase):
    def test_feature_ordering_and_constant_removal(self):
        names = dl.feature_names()
        self.assertEqual(len(names), 59 - 2)
        self.assertNotIn("burst_packet_ratio", names)
        self.assertNotIn("ike_packet_count", names)
        self.assertEqual(names[:3], ["packet_count", "total_bytes", "mean_packet_size"])
        self.assertEqual(names, [c for c in FEATURE_COLUMNS if c not in dl.CONSTANT_FEATURES])

    def test_leakage_columns_excluded(self):
        names = dl.feature_names()
        for c in dl.LEAKAGE_COLUMNS:
            self.assertNotIn(c, names)
        self.assertNotIn("traffic_profile", names)
        self.assertNotIn("security_posture", names)
        self.assertNotIn("configuration_id", names)

    def test_unknown_target_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_run(Path(tmp), 5, run_id="run-a", unknown_target=True)
            with self.assertRaises(ValueError):
                dl.load_dataset(run_ids=("run-a",), datasets_dir=Path(tmp))


class LoaderCombineTest(unittest.TestCase):
    def _load_two(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        write_run(Path(self.tmp), 8, run_id="run-a")
        write_run(Path(self.tmp), 12, run_id="run-b")
        return dl.load_dataset(run_ids=("run-a", "run-b"), datasets_dir=Path(self.tmp))

    def test_combined_matrix(self):
        x, y, features, groups, meta = self._load_two()
        self.assertEqual(x.shape, (20, 57))
        self.assertEqual(len(y), 20)
        self.assertEqual(len(groups), 20)
        self.assertEqual(meta["dataset_run_ids"], ["run-a", "run-b"])
        self.assertEqual(meta["sample_counts"], {"run-a": 8, "run-b": 12})

    def test_provenance_preserved(self):
        x, y, features, groups, meta = self._load_two()
        self.assertEqual(set(meta["dataset_run_id"]), {"run-a", "run-b"})
        self.assertEqual(len(meta["experiment_id"]), 20)

    def test_groups_are_configuration_ids(self):
        x, y, features, groups, meta = self._load_two()
        self.assertTrue(any("transport" in g or "tunnel" in g for g in groups))

    def test_real_combined_sample_count_300(self):
        base = dl.DEFAULT_DATASETS_DIR
        if not (base / "dataset-20260923-221430" / "features.parquet").exists():
            self.skipTest("protected datasets not present")
        if not (base / "dataset-20260924-003710" / "features.parquet").exists():
            self.skipTest("protected datasets not present")
        x, y, features, groups, meta = dl.load_dataset()
        self.assertEqual(x.shape, (300, 57))
        self.assertEqual(meta["sample_counts"], {
            "dataset-20260923-221430": 200,
            "dataset-20260924-003710": 100,
        })
        self.assertEqual(len(y), 300)


if __name__ == "__main__":
    unittest.main()