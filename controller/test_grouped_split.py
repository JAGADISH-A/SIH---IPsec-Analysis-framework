"""Tests for controller.grouped_split (grouped stratified greedy split)."""

import tempfile
import unittest
from pathlib import Path

from controller.grouped_split import (
    SPLIT_SEED,
    assign_groups,
    build_sample_records,
    build_split_json,
    load_split,
    verify_split,
)


def records_for(groups: dict, targets=None) -> list:
    records = []
    for gid, members in groups.items():
        for i in range(members):
            records.append(
                {
                    "experiment_id": f"{gid}-exp-{i:03d}",
                    "dataset_run_id": "run-a",
                    "sequence": int(i + 1),
                    "configuration_id": gid,
                    "target": targets[len(records) % len(targets)],
                }
            )
    return records


TARGETS = ("voip", "video", "messaging", "email", "web", "icmp")


class AssignGroupsTest(unittest.TestCase):
    def _records(self):
        groups = {f"config-{i:02d}": 10 for i in range(12)}
        return records_for(groups, targets=TARGETS)

    def test_every_sample_assigned_once(self):
        records = self._records()
        assignment, seed, counts, target, total = assign_groups(records, seed=SPLIT_SEED)
        self.assertEqual(set(assignment), {r["experiment_id"] for r in records})
        report = verify_split(assignment, records)
        self.assertTrue(report["every_sample_once"])

    def test_group_isolation_holds(self):
        records = self._records()
        assignment, _, counts, _, _ = assign_groups(records, seed=SPLIT_SEED)
        report = verify_split(assignment, records)
        self.assertTrue(report["group_isolation_ok"])
        self.assertEqual(report["groups_spanning_splits"], [])
        self.assertFalse(any(report["pair_overlap"].values()))

    def test_deterministic(self):
        records = self._records()
        a1, _, c1, _, _ = assign_groups(records, seed=SPLIT_SEED)
        a2, _, c2, _, _ = assign_groups(records, seed=SPLIT_SEED)
        self.assertEqual(a1, a2)
        self.assertEqual(c1, c2)

    def test_counts_sum_to_total(self):
        records = self._records()
        assignment, _, counts, _, _ = assign_groups(records, seed=SPLIT_SEED)
        self.assertEqual(
            sum(sum(counts[s].values()) for s in counts), len(records)
        )

    def test_single_group_stays_together(self):
        records = records_for({"single-config": 50}, targets=TARGETS)
        assignment, _, counts, _, _ = assign_groups(records, seed=SPLIT_SEED)
        report = verify_split(assignment, records)
        self.assertTrue(report["group_isolation_ok"])
        self.assertEqual({a for a in assignment.values()}, {"train"})


class AssemblePersistenceTest(unittest.TestCase):
    def _loader_inputs(self):
        records = records_for({f"cfg-{i:02d}": 10 for i in range(12)}, targets=TARGETS)
        import numpy as np

        x = np.zeros((len(records), 1), dtype=np.float64)
        y = np.array([r["target"] for r in records])
        groups = np.array([r["configuration_id"] for r in records])
        metadata = {
            "dataset_run_id": ["run-a"] * len(records),
            "experiment_id": [r["experiment_id"] for r in records],
            "sequence": np.arange(1, len(records) + 1),
            "input_fingerprints": {"run-a": "abc"},
        }
        return records, x, y, groups, metadata

    def test_build_split_json_writes_verified_document(self):
        records, x, y, groups, metadata = self._loader_inputs()
        with tempfile.TemporaryDirectory() as tmp:
            path = build_split_json(x, y, groups, metadata,
                                    seed=SPLIT_SEED, split_path=Path(tmp) / "split.json")
            doc = load_split(path)
            self.assertEqual(len(doc["samples"]), len(records))
            self.assertTrue(doc["verification"]["group_isolation_ok"])
            self.assertTrue(doc["verification"]["every_sample_once"])
            self.assertTrue(doc["split_hash"])
            self.assertEqual(sum(doc["split_counts"].values()), len(records))

    def test_real_split_verification(self):
        from controller.dataset_loader import DEFAULT_DATASETS_DIR, load_dataset

        if not (DEFAULT_DATASETS_DIR / "dataset-20260923-221430" / "features.parquet").exists():
            self.skipTest("protected datasets not present")
        x, y, _, groups, metadata = load_dataset()
        with tempfile.TemporaryDirectory() as tmp:
            path = build_split_json(x, y, groups, metadata,
                                    seed=SPLIT_SEED, split_path=Path(tmp) / "split.json")
            doc = load_split(path)
            self.assertTrue(doc["verification"]["group_isolation_ok"])
            self.assertTrue(doc["verification"]["every_sample_once"])
            self.assertEqual(sum(doc["split_counts"].values()), 300)
            self.assertEqual(len(doc["samples"]), 300)
            self.assertTrue(doc["split_hash"])
            self.assertEqual(
                doc["split_hash"],
                "fbf04c326bb68d3579c4792dea76fb0baf68fcbd4f384f04487d92ccc2b233d4",
            )


class BuildSampleRecordsTest(unittest.TestCase):
    def test_build_sample_records(self):
        records = build_sample_records(
            y=["voip", "web"],
            groups=["cfg-1", "cfg-2"],
            dataset_run_id=["run-a", "run-a"],
            experiment_id=["e1", "e2"],
            sequence=[3, 8],
        )
        self.assertEqual(records[0]["configuration_id"], "cfg-1")
        self.assertEqual(records[1]["target"], "web")


if __name__ == "__main__":
    unittest.main()