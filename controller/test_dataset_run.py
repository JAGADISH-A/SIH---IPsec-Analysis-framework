"""Focused tests for the Dataset Run state/storage layer (Module 1).

Run either as:

    .venv/bin/python -m controller.test_dataset_run

or:

    .venv/bin/python -m unittest controller.test_dataset_run

Uses a temporary directory; never touches the production results directory.
No experiment is executed.
"""

import json
import os
import re
import tempfile
import unittest
from pathlib import Path

from controller.dataset_run import (
    SCHEMA_VERSION,
    STATUS_CREATED,
    SUB_DIRECTORIES,
    STATE_FILENAME,
    MANIFEST_FILENAME,
    _atomic_write_json,
    create_dataset_run,
    default_state,
    generate_dataset_run_id,
    load_dataset_run,
    validate_state,
)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


class TestDatasetRunCreate(unittest.TestCase):
    def test_create_with_target_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=3)

            self.assertTrue(run.directory.is_dir())
            self.assertTrue((run.directory / STATE_FILENAME).is_file())
            self.assertTrue((run.directory / MANIFEST_FILENAME).is_file())

            state = read_json(run.state_path)
            manifest = read_json(run.manifest_path)

            self.assertEqual(state["target_samples"], 3)
            self.assertEqual(
                manifest["dataset_schema_version"], SCHEMA_VERSION
            )

    def test_initial_counters_are_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=3)
            self.assertEqual(run.attempted_runs, 0)
            self.assertEqual(run.successful_samples, 0)
            self.assertEqual(run.failed_samples, 0)
            self.assertEqual(run.interrupted_samples, 0)
            self.assertEqual(run.status, STATUS_CREATED)
            self.assertEqual(run.data["committed_run_ids"], [])

            state = read_json(run.state_path)
            self.assertEqual(state["attempted_runs"], 0)

    def test_subdirectories_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=3)
            for sub in SUB_DIRECTORIES:
                self.assertTrue(
                    (run.directory / sub).is_dir(),
                    msg=f"missing subdirectory {sub}",
                )

    def test_manifest_fields_present(self):
        expected = {
            "dataset_run_id", "created_at", "updated_at", "target_samples",
            "attempted_runs", "successful_samples", "failed_samples",
            "interrupted_samples", "status", "dataset_schema_version",
        }
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=3)
            manifest = read_json(run.manifest_path)
            self.assertEqual(set(manifest), expected)

    def test_reserved_state_fields_present(self):
        reserved = {
            "current_experiment", "current_configuration",
            "current_traffic_profile", "traffic_allocation_progress",
            "configuration_selection_progress", "committed_run_ids",
        }
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=3)
            self.assertTrue(reserved.issubset(set(run.data)))

    def test_run_id_format(self):
        for _ in range(5):
            run_id = generate_dataset_run_id()
            self.assertRegex(run_id, r"^dataset-\d{8}-\d{6}$")

    def test_explicit_run_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=3, dataset_run_id="dataset-20260101-000001")
            self.assertEqual(run.id, "dataset-20260101-000001")
            self.assertEqual(run.directory.name, run.id)

    def test_duplicate_run_id_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            create_dataset_run(tmp, target_samples=3, dataset_run_id="dataset-20260101-000001")
            with self.assertRaises(ValueError):
                create_dataset_run(tmp, target_samples=3, dataset_run_id="dataset-20260101-000001")


class TestUpdateAndReload(unittest.TestCase):
    def test_update_survives_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=3)
            run.record_attempt()
            run.record_success()
            run.commit_run("quality-01-exp-0001")

            reloaded = load_dataset_run(tmp, run.id)
            self.assertEqual(reloaded.attempted_runs, 1)
            self.assertEqual(reloaded.successful_samples, 1)
            self.assertEqual(reloaded.failed_samples, 0)
            self.assertEqual(reloaded.interrupted_samples, 0)
            self.assertEqual(reloaded.data["committed_run_ids"], ["quality-01-exp-0001"])

    def test_committed_run_ids_persist_multiple(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=3)
            run.commit_run("exp-1")
            run.commit_run("exp-2")
            reloaded = load_dataset_run(tmp, run.id)
            self.assertEqual(
                reloaded.data["committed_run_ids"], ["exp-1", "exp-2"]
            )

    def test_manifest_tracks_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=5)
            run.record_attempt()
            run.record_success()
            manifest = read_json(run.manifest_path)
            self.assertEqual(manifest["attempted_runs"], 1)
            self.assertEqual(manifest["successful_samples"], 1)

    def test_update_immutable_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=3)
            with self.assertRaises(ValueError):
                run.update(target_samples=99)
            with self.assertRaises(ValueError):
                run.update(dataset_run_id="other-id")

    def test_unknown_field_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=3)
            with self.assertRaises(ValueError):
                run.update(not_a_real_field=1)

    def test_load_missing_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                load_dataset_run(tmp, "dataset-does-not-exist")


class TestValidation(unittest.TestCase):
    def test_target_samples_must_be_positive(self):
        for bad in (0, -1, -50):
            with self.subTest(value=bad, kind="create"):
                with tempfile.TemporaryDirectory() as tmp:
                    with self.assertRaises(ValueError):
                        create_dataset_run(tmp, target_samples=bad)

        with self.subTest(kind="state"):
            bad_state = default_state("dataset-x", 0, "now")
            with self.assertRaises(ValueError):
                validate_state(bad_state)

    def test_target_samples_must_be_int(self):
        for bad in ("5", 5.0, None, True, [3]):
            with self.subTest(value=bad):
                with tempfile.TemporaryDirectory() as tmp:
                    with self.assertRaises(ValueError):
                        create_dataset_run(tmp, target_samples=bad)

    def test_negative_counters_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=5)
            for field in (
                "attempted_runs", "successful_samples",
                "failed_samples", "interrupted_samples",
            ):
                with self.subTest(field=field):
                    with self.assertRaises(ValueError):
                        run.update(**{field: -1})

    def test_success_le_attempted(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=5)
            run.record_attempt()  # 1 attempt, 0 success
            with self.assertRaises(ValueError):
                run.update(successful_samples=2)  # > attempted

            run.record_success()
            self.assertEqual(run.successful_samples, 1)

    def test_failed_plus_interrupted_le_attempted(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=5)
            with self.assertRaises(ValueError):
                run.update(failed_samples=1, interrupted_samples=1)

            run.record_attempt()
            run.record_failure()
            run.record_attempt()
            run.record_interruption()
            self.assertEqual(run.failed_samples, 1)
            self.assertEqual(run.interrupted_samples, 1)
            self.assertEqual(run.attempted_runs, 2)

    def test_invalid_status_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=5)
            with self.assertRaises(ValueError):
                run.update(status="NOT-A-STATUS")

    def test_duplicate_commit_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=5)
            run.commit_run("exp-1")
            with self.assertRaises(ValueError):
                run.commit_run("exp-1")


class TestAtomicWrite(unittest.TestCase):
    def test_write_is_atomic_and_leaves_no_temp(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "state.json"
            data = {"hello": "world", "n": 42}

            _atomic_write_json(target, data)

            self.assertEqual(read_json(target), data)
            self.assertFalse(Path(str(target) + ".tmp").exists())

            # Subsequent writes replace cleanly.
            data2 = {"hello": "mutated", "n": 43}
            _atomic_write_json(target, data2)
            self.assertEqual(read_json(target), data2)
            self.assertFalse(Path(str(target) + ".tmp").exists())

    def test_uses_temporary_file_then_replace(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "state.json"
            data = {"a": 1}
            before = set(os.listdir(tmp))

            _atomic_write_json(target, data)
            after = set(os.listdir(tmp))

            # Only the destination remains; the temp was swapped away.
            self.assertEqual(after, before | {target.name})

    def test_atomic_write_survives_corrupt_temp(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "state.json"
            tmp_file = Path(str(target) + ".tmp")
            tmp_file.write_text("{ definitely not json")

            _atomic_write_json(target, {"ok": True})

            self.assertEqual(read_json(target), {"ok": True})
            self.assertFalse(tmp_file.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)