"""Module 5 artifact-contract tests.

Run either as:

    .venv/bin/python -m controller.test_dataset_artifacts

or:

    .venv/bin/python -m unittest controller.test_dataset_artifacts

Uses a temporary directory; never touches the production results directory.
The real testbed pipeline is replaced with fakes via dependency injection, so
no Containerlab/StrongSwan is required and no experiment is executed.

Synthetic feature records used here are generated from the live extractor
(``reference_feature_record``) and then overridden with test values; they are
clearly test fixtures and are never written into any production code path.
"""

import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

import pyarrow.parquet as pq

from controller.dataset_artifacts import (
    CAPTURES_SUBDIR,
    EXPORT_ARTIFACT_FILENAMES,
    FEATURES_PARQUET_FILENAME,
    FEATURE_COLUMNS,
    FEATURE_KEYS,
    FINALIZATION_FILENAME,
    METADATA_FILENAME,
    ORPHAN_STAGING_FILENAME,
    RUN_README_FILENAME,
    SCHEMA_VERSION,
    STAGING_SUBDIR,
    SUCCESSFUL_SAMPLES_FILENAME,
    build_dataset_zip,
    build_successful_record,
    collect_successful_sample,
    export_artifact_paths,
    finalize_dataset,
    normalize_feature_record,
    read_staging,
    reference_feature_record,
)
from controller.dataset_executor import (
    OUTCOME_FAILED,
    OUTCOME_INTERRUPTED,
    OUTCOME_SUCCESS,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PAUSED,
    execute_dataset_run,
    experiment_id_for,
    parse_experiment_id,
)
from controller.dataset_planner import (
    build_sample_plan,
    traffic_quota,
    write_sample_plan,
)
from controller.dataset_run import create_dataset_run, load_dataset_run


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def synthetic_features(packet_count=100, **overrides):
    """Full-schema synthetic feature record (based on the real extractor)."""
    feats = reference_feature_record()
    feats["packet_count"] = packet_count
    feats["total_bytes"] = packet_count * 120
    feats["outbound_packet_count"] = packet_count
    feats["outbound_bytes"] = packet_count * 120
    feats["outbound_packet_ratio"] = 1.0
    feats["outbound_byte_ratio"] = 1.0
    feats["flow_duration"] = 30.0
    feats["packets_per_second"] = round(packet_count / 30.0, 3)
    feats["bytes_per_second"] = round(packet_count * 120 / 30.0, 3)
    feats.update(overrides)
    return feats


class SyntheticRunner:
    """Scripted attempt runner returning full-schema successful outcomes."""

    PCAP_BYTES = b"\xd4\xc3\xb2\xa1" + b"\x00" * 48

    def __init__(self, script=None, default=OUTCOME_SUCCESS):
        self.script = script or {}
        self.default = default
        self.calls = []

    def __call__(self, experiment_id, sample, tmp_dir, results_root,
                 run_id=None, log=None, reuse=None):
        parsed = parse_experiment_id(experiment_id)
        seq, attempt = parsed[1], parsed[2]
        self.calls.append((seq, attempt, experiment_id))
        kind = self.script.get((seq, attempt), self.default)
        tmp = Path(tmp_dir)
        tmp.mkdir(parents=True, exist_ok=True)
        if kind == "KeyboardInterrupt":
            raise KeyboardInterrupt()
        if kind == OUTCOME_FAILED:
            (tmp / "partial.log").write_text("partial capture", encoding="utf-8")
            return {
                "status": OUTCOME_FAILED,
                "experiment_id": experiment_id,
                "reason": "SyntheticError",
                "error": "synthetic failure",
            }
        if kind == OUTCOME_INTERRUPTED:
            return {
                "status": OUTCOME_INTERRUPTED,
                "experiment_id": experiment_id,
                "reason": "SyntheticInterrupt",
                "error": "synthetic interrupt",
            }
        pcap = tmp / "capture.pcap"
        pcap.write_bytes(self.PCAP_BYTES)
        return {
            "status": OUTCOME_SUCCESS,
            "experiment_id": experiment_id,
            "metadata": {"experiment_id": experiment_id, "status": "PASS"},
            "features": synthetic_features(packet_count=100 + seq),
            "traffic_log": f"STATS profile={sample['traffic_profile']}\n",
            "pcap_path": str(pcap),
            "connectivity": {"status": "PASS"},
            "ipsec": {"ike_sa": "ESTABLISHED", "child_sa": "INSTALLED"},
        }


class FakeCleanup:
    def __init__(self):
        self.calls = []

    def __call__(self, experiment_id, sample, tmp_dir, runtime_ctx=None,
                         skip_destroy=False):
        self.calls.append((experiment_id, sample["sequence"]))
        if tmp_dir is not None:
            import shutil
            shutil.rmtree(Path(tmp_dir), ignore_errors=True)


def make_run_and_plan(tmp, target=3):
    run = create_dataset_run(tmp, target_samples=target)
    plan = build_sample_plan(target)
    write_sample_plan(tmp, run.id, plan)
    return run, plan


def run_with_collector(tmp, run, script=None, default=OUTCOME_SUCCESS,
                       max_attempts=5):
    runner = SyntheticRunner(script, default=default)
    executed = execute_dataset_run(
        tmp, run.id,
        run_attempt_fn=runner,
        cleanup_fn=FakeCleanup(),
        max_attempts_per_sequence=max_attempts,
        collector_fn=collect_successful_sample,
    )
    return executed, runner


def staging_path(run):
    return run.directory / STAGING_SUBDIR / SUCCESSFUL_SAMPLES_FILENAME


def read_lines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def rewrite_staging(run, records):
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
    staging_path(run).write_text(text, encoding="utf-8")


def finalization_state(tmp, run):
    path = run.directory / FINALIZATION_FILENAME
    return json.loads(path.read_text()) if path.exists() else None


def outcome_with_pcap(experiment_id, tmpdir):
    pcap = Path(tmpdir) / "src.pcap"
    pcap.write_bytes(SyntheticRunner.PCAP_BYTES)
    return {
        "status": OUTCOME_SUCCESS,
        "experiment_id": experiment_id,
        "metadata": {"experiment_id": experiment_id, "status": "PASS"},
        "features": synthetic_features(),
        "pcap_path": str(pcap),
    }


# ---------------------------------------------------------------------------
# Basic collection
# ---------------------------------------------------------------------------

class TestBasicCollection(unittest.TestCase):
    def test_one_successful_sample_produces_one_staged_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            executed, _ = run_with_collector(tmp, run)
            self.assertEqual(executed.status, STATUS_COMPLETED)
            staged = read_staging(run)
            self.assertEqual(len(staged), 1)
            self.assertEqual(staged[0]["sequence"], 1)
            self.assertEqual(staged[0]["experiment_id"],
                             experiment_id_for(run.id, 1, 1))
            self.assertEqual(staged[0]["status"], "SUCCESS")

    def test_failed_sample_is_not_staged(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            executed, _ = run_with_collector(
                tmp, run, script={(1, 1): OUTCOME_FAILED, (1, 2): OUTCOME_FAILED},
                max_attempts=2,
            )
            self.assertEqual(executed.status, STATUS_FAILED)
            self.assertEqual(read_staging(run), [])

    def test_interrupted_sample_is_not_staged(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            executed, _ = run_with_collector(
                tmp, run, script={(1, 1): OUTCOME_INTERRUPTED},
            )
            self.assertEqual(executed.status, STATUS_COMPLETED)
            self.assertEqual(executed.interrupted_samples, 1)
            staged = read_staging(run)
            self.assertEqual(len(staged), 1)
            self.assertEqual(staged[0]["attempt_number"], 2)

    def test_successful_retry_produces_exactly_one_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            executed, _ = run_with_collector(
                tmp, run, script={(1, 1): OUTCOME_FAILED},
            )
            self.assertEqual(executed.status, STATUS_COMPLETED)
            self.assertEqual(executed.failed_samples, 1)
            staged = read_staging(run)
            self.assertEqual(len(staged), 1)
            self.assertEqual(staged[0]["sequence"], 1)
            self.assertEqual(staged[0]["attempt_number"], 2)
            # the failed attempt exists only under failures/
            failed_exp = experiment_id_for(run.id, 1, 1)
            self.assertTrue(
                (run.directory / "failures" / failed_exp / "failure.json").is_file()
            )
            self.assertNotIn(failed_exp,
                             [r["experiment_id"] for r in staged])

    def test_duplicate_sequence_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=1)
            executed, _ = run_with_collector(tmp, run)
            self.assertEqual(executed.status, STATUS_COMPLETED)
            self.assertEqual(len(read_staging(run)), 1)
            run = load_dataset_run(tmp, run.id)  # reload committed state
            sample = plan["samples"][0]

            # idempotent re-collection of the same committed attempt
            out = outcome_with_pcap(experiment_id_for(run.id, 1, 1), tmp)
            again = collect_successful_sample(
                run, experiment_id_for(run.id, 1, 1), 1, sample, out
            )
            self.assertEqual(again["experiment_id"],
                             experiment_id_for(run.id, 1, 1))
            self.assertEqual(len(read_staging(run)), 1)

            # a *different* experiment id for an already-committed sequence
            with self.assertRaises(ValueError):
                collect_successful_sample(
                    run, experiment_id_for(run.id, 1, 2), 2, sample,
                    outcome_with_pcap(experiment_id_for(run.id, 1, 2), tmp),
                )

    def test_metadata_contains_security_posture(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=1)
            run_with_collector(tmp, run)
            record = read_staging(run)[0]
            self.assertEqual(record["security_posture"],
                             plan["samples"][0]["security_posture"])

    def test_metadata_contains_traffic_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=1)
            run_with_collector(tmp, run)
            record = read_staging(run)[0]
            self.assertEqual(record["traffic_profile"],
                             plan["samples"][0]["traffic_profile"])

    def test_metadata_contains_full_ipsec_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=1)
            run_with_collector(tmp, run)
            record = read_staging(run)[0]
            expected = plan["samples"][0]["ipsec_configuration"]
            self.assertEqual(record["ipsec_configuration"], expected)
            self.assertEqual(record["mode"], expected["mode"])
            self.assertEqual(record["address_family"],
                             expected["address_family"])
            self.assertEqual(record["ike_version"], expected["ike"]["version"])
            self.assertEqual(record["ike_encryption"],
                             expected["ike"]["encryption"])
            self.assertEqual(record["ike_integrity"],
                             expected["ike"]["integrity"])
            self.assertEqual(record["ike_dh_group"],
                             expected["ike"]["dh_group"])
            self.assertEqual(record["esp_encryption"],
                             expected["esp"]["encryption"])
            self.assertEqual(record["esp_integrity"],
                             expected["esp"]["integrity"])
            self.assertEqual(record["esp_dh_group"],
                             expected["esp"]["dh_group"])
            self.assertEqual(record["pfs"], expected["esp"]["pfs"])

    def test_posture_matches_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=3)
            run_with_collector(tmp, run)
            for record in read_staging(run):
                sample = plan["samples"][record["sequence"] - 1]
                self.assertEqual(record["security_posture"],
                                 sample["security_posture"])

    def test_traffic_profile_matches_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=3)
            run_with_collector(tmp, run)
            for record in read_staging(run):
                sample = plan["samples"][record["sequence"] - 1]
                self.assertEqual(record["traffic_profile"],
                                 sample["traffic_profile"])

    def test_configuration_matches_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=3)
            run_with_collector(tmp, run)
            for record in read_staging(run):
                sample = plan["samples"][record["sequence"] - 1]
                self.assertEqual(record["configuration_id"],
                                 sample["configuration_id"])
                self.assertEqual(record["ipsec_configuration"],
                                 sample["ipsec_configuration"])

    def test_pcap_reference_points_to_successful_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            runner = SyntheticRunner()
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
                collector_fn=collect_successful_sample,
            )
            record = read_staging(run)[0]
            exp = experiment_id_for(run.id, 1, 1)
            self.assertEqual(record["pcap_path"],
                             f"{CAPTURES_SUBDIR}/0001/{exp}.pcap")
            pcap = run.directory / record["pcap_path"]
            self.assertTrue(pcap.is_file())
            self.assertEqual(pcap.read_bytes(), SyntheticRunner.PCAP_BYTES)

    def test_failed_pcap_is_not_referenced(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            run_with_collector(tmp, run, script={(1, 1): OUTCOME_FAILED})
            failed_exp = experiment_id_for(run.id, 1, 1)
            self.assertTrue(
                (run.directory / "failures" / failed_exp / "failure.json").is_file()
            )
            staged = read_staging(run)
            self.assertEqual(len(staged), 1)
            self.assertNotEqual(staged[0]["experiment_id"], failed_exp)
            for record in staged:
                pcap = run.directory / record["pcap_path"]
                self.assertTrue(pcap.is_file())
                self.assertNotIn(
                    failed_exp, str(pcap.relative_to(run.directory))
                )

    def test_jsonl_contains_exactly_one_record_per_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            run_with_collector(tmp, run)
            staged = read_staging(run)
            self.assertEqual(len(staged), 3)
            self.assertEqual(sorted(r["sequence"] for r in staged),
                             [1, 2, 3])

    def test_jsonl_lines_are_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            run_with_collector(tmp, run)
            for line in staging_path(run).read_text().splitlines():
                if line.strip():
                    parsed = json.loads(line)
                    self.assertIsInstance(parsed, dict)


# ---------------------------------------------------------------------------
# Feature schema / normalization
# ---------------------------------------------------------------------------

class TestFeatureSchema(unittest.TestCase):
    def test_feature_schema_is_consistent(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            run_with_collector(tmp, run)
            for record in read_staging(run):
                normalized = normalize_feature_record(record["features"])
                self.assertEqual(list(normalized), FEATURE_COLUMNS)
            # extractor output agrees with the declared schema
            self.assertEqual(
                FEATURE_KEYS, set(reference_feature_record().keys())
            )

    def test_mixed_type_corruption_is_rejected(self):
        base = synthetic_features()
        cases = [
            {"packet_count": "100"},           # str in an int column
            {"packet_count": 100.5},           # non-integral float in int column
            {"burst_count": "3"},              # str in an int column
            {"mean_packet_size": "abc"},       # str in a float column
            {"flow_duration": float("nan")},   # non-finite float
            {"bytes_per_second": float("inf")},
        ]
        for overrides in cases:
            corrupted = dict(base)
            corrupted.update(overrides)
            with self.assertRaises(ValueError):
                normalize_feature_record(corrupted)

    def test_missing_or_extra_feature_is_rejected(self):
        base = synthetic_features()
        missing = dict(base)
        missing.pop("flow_duration")
        with self.assertRaises(ValueError):
            normalize_feature_record(missing)
        extra = dict(base)
        extra["fabricated_feature"] = 1.0
        with self.assertRaises(ValueError):
            normalize_feature_record(extra)

    def test_minimum_validity_requirement_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=1)
            sample = plan["samples"][0]
            out = outcome_with_pcap(experiment_id_for(run.id, 1, 1), tmp)
            out["features"]["packet_count"] = 0
            with self.assertRaises(ValueError):
                collect_successful_sample(
                    run, experiment_id_for(run.id, 1, 1), 1, sample, out
                )


# ---------------------------------------------------------------------------
# Materialization
# ---------------------------------------------------------------------------

class TestMaterialization(unittest.TestCase):
    def test_parquet_contains_exactly_successful_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            run_with_collector(tmp, run)
            finalize_dataset(tmp, run.id)
            table = pq.read_table(run.directory / FEATURES_PARQUET_FILENAME)
            self.assertEqual(table.num_rows, 3)
            self.assertEqual(sorted(r["sequence"] for r in table.to_pylist()),
                             [1, 2, 3])

    def test_parquet_materialization_is_atomic(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            run_with_collector(tmp, run)
            finalize_dataset(tmp, run.id)
            parquet = run.directory / FEATURES_PARQUET_FILENAME
            self.assertTrue(parquet.is_file())
            self.assertFalse(parquet.with_suffix(parquet.suffix + ".tmp").exists())
            # re-finalization is idempotent and leaves no tmp files
            finalize_dataset(tmp, run.id)
            self.assertEqual(pq.read_table(parquet).num_rows, 3)
            self.assertFalse(list(run.directory.glob("*.tmp")))

    def test_failed_parquet_materialization_does_not_mark_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            run_with_collector(tmp, run)
            with mock.patch(
                "pyarrow.parquet.write_table",
                side_effect=RuntimeError("disk full"),
            ):
                with self.assertRaises(RuntimeError):
                    finalize_dataset(tmp, run.id)
            state = finalization_state(tmp, run)
            self.assertEqual(state["status"], "FAILED")
            parquet = run.directory / FEATURES_PARQUET_FILENAME
            self.assertFalse(parquet.exists())
            self.assertFalse(parquet.with_suffix(parquet.suffix + ".tmp").exists())

    def test_metadata_materialization_is_atomic(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            run_with_collector(tmp, run)
            finalize_dataset(tmp, run.id)
            meta_path = run.directory / METADATA_FILENAME
            self.assertTrue(meta_path.is_file())
            self.assertFalse(meta_path.with_suffix(meta_path.suffix + ".tmp").exists())
            metadata = read_lines(meta_path)
            staged = read_staging(run)
            self.assertEqual(len(metadata), len(staged))
            for record in metadata:
                self.assertEqual(record["status"], "SUCCESS")

    def test_count_mismatch_prevents_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            run_with_collector(tmp, run)
            staged = read_staging(run)
            rewrite_staging(run, staged[:-1])  # drop one successful record
            with self.assertRaises(ValueError):
                finalize_dataset(tmp, run.id)
            self.assertEqual(finalization_state(tmp, run)["status"], "FAILED")

    def test_duplicate_sequence_prevents_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            run_with_collector(tmp, run)
            staged = read_staging(run)
            rewrite_staging(run, staged + [staged[1]])  # duplicate seq 2
            with self.assertRaises(ValueError):
                finalize_dataset(tmp, run.id)
            self.assertEqual(finalization_state(tmp, run)["status"], "FAILED")


# ---------------------------------------------------------------------------
# Consistency validation
# ---------------------------------------------------------------------------

class TestConsistencyValidation(unittest.TestCase):
    def _completed_run(self, tmp, target=1):
        run, _ = make_run_and_plan(tmp, target=target)
        run_with_collector(tmp, run)
        return run

    def test_missing_posture_prevents_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self._completed_run(tmp, 3)
            staged = read_staging(run)
            staged[0] = {k: v for k, v in staged[0].items()
                         if k != "security_posture"}
            rewrite_staging(run, staged)
            with self.assertRaises(ValueError):
                finalize_dataset(tmp, run.id)

    def test_missing_traffic_profile_prevents_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self._completed_run(tmp, 3)
            staged = read_staging(run)
            staged[0] = {k: v for k, v in staged[0].items()
                         if k != "traffic_profile"}
            rewrite_staging(run, staged)
            with self.assertRaises(ValueError):
                finalize_dataset(tmp, run.id)

    def test_missing_configuration_prevents_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self._completed_run(tmp, 3)
            staged = read_staging(run)
            staged[0] = {k: v for k, v in staged[0].items()
                         if k != "ipsec_configuration"}
            rewrite_staging(run, staged)
            with self.assertRaises(ValueError):
                finalize_dataset(tmp, run.id)

    def test_plan_mismatch_prevents_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            run_with_collector(tmp, run)
            staged = read_staging(run)
            staged[0]["esp_encryption"] = "aes256cbc"  # does not match plan
            rewrite_staging(run, staged)
            with self.assertRaises(ValueError):
                finalize_dataset(tmp, run.id)

    def test_plan_fingerprint_mismatch_prevents_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=3)
            run_with_collector(tmp, run)
            modified = build_sample_plan(3)
            modified["samples"][0]["traffic_profile"], modified["samples"][1]["traffic_profile"] = (
                modified["samples"][1]["traffic_profile"],
                modified["samples"][0]["traffic_profile"],
            )
            write_sample_plan(tmp, run.id, modified)  # plan regenerated on disk
            with self.assertRaises(ValueError):
                finalize_dataset(tmp, run.id)
            self.assertEqual(finalization_state(tmp, run)["status"], "FAILED")


# ---------------------------------------------------------------------------
# End-to-end
# ---------------------------------------------------------------------------

class TestEndToEnd(unittest.TestCase):
    def test_target3_produces_exactly_3_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            run_with_collector(tmp, run)
            finalize_dataset(tmp, run.id)
            staged = read_staging(run)
            metadata = read_lines(run.directory / METADATA_FILENAME)
            table = pq.read_table(run.directory / FEATURES_PARQUET_FILENAME)
            self.assertEqual(len(staged), 3)
            self.assertEqual(len(metadata), 3)
            self.assertEqual(table.num_rows, 3)

    def test_target3_with_failed_attempts_produces_3_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            script = {(s, 1): OUTCOME_FAILED for s in (1, 2, 3)}
            executed, _ = run_with_collector(tmp, run, script=script)
            self.assertEqual(executed.status, STATUS_COMPLETED)
            self.assertEqual(executed.failed_samples, 3)
            staged = read_staging(run)
            self.assertEqual(len(staged), 3)
            self.assertTrue(all(r["attempt_number"] == 2 for r in staged))
            finalize_dataset(tmp, run.id)
            table = pq.read_table(run.directory / FEATURES_PARQUET_FILENAME)
            self.assertEqual(table.num_rows, 3)

    def test_failed_attempts_remain_isolated(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            script = {(s, 1): OUTCOME_FAILED for s in (1, 2, 3)}
            run_with_collector(tmp, run, script=script)
            finalize_dataset(tmp, run.id)
            successful_ids = {r["experiment_id"] for r in read_staging(run)}
            metadata_ids = {
                r["experiment_id"]
                for r in read_lines(run.directory / METADATA_FILENAME)
            }
            feature_ids = {
                r["experiment_id"]
                for r in pq.read_table(
                    run.directory / FEATURES_PARQUET_FILENAME
                ).to_pylist()
            }
            for seq in (1, 2, 3):
                failed_exp = experiment_id_for(run.id, seq, 1)
                self.assertTrue(
                    (run.directory / "failures" / failed_exp / "failure.json").is_file()
                )
                self.assertNotIn(failed_exp, successful_ids)
                self.assertNotIn(failed_exp, metadata_ids)
                self.assertNotIn(failed_exp, feature_ids)

    def test_successful_rows_preserve_traffic_distribution(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=6)
            run_with_collector(tmp, run)
            records = read_staging(run)
            observed = Counter(r["traffic_profile"] for r in records)
            planned = traffic_quota(6)
            self.assertEqual(dict(observed), dict(planned))
            finalize_dataset(tmp, run.id)

    def test_successful_rows_preserve_posture_distribution(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=6)
            run_with_collector(tmp, run)
            records = read_staging(run)
            observed = Counter(r["security_posture"] for r in records)
            planned = Counter(s["security_posture"] for s in plan["samples"])
            self.assertEqual(dict(observed), dict(planned))
            finalize_dataset(tmp, run.id)

    def test_all_rows_preserve_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=3)
            run_with_collector(tmp, run)
            for record in read_staging(run):
                sample = plan["samples"][record["sequence"] - 1]
                self.assertEqual(record["configuration_id"],
                                 sample["configuration_id"])
                self.assertEqual(record["ipsec_configuration"],
                                 sample["ipsec_configuration"])
                self.assertEqual(record["esp_encryption"],
                                 sample["ipsec_configuration"]["esp"]["encryption"])
                self.assertEqual(record["esp_integrity"],
                                 sample["ipsec_configuration"]["esp"]["integrity"])
                self.assertEqual(record["esp_dh_group"],
                                 sample["ipsec_configuration"]["esp"]["dh_group"])
                self.assertEqual(record["pfs"],
                                 sample["ipsec_configuration"]["esp"]["pfs"])

    def test_empty_dataset_cannot_be_marked_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)  # created, never executed
            with self.assertRaises(ValueError):
                finalize_dataset(tmp, run.id)
            self.assertEqual(finalization_state(tmp, run)["status"], "FAILED")

    def test_incomplete_dataset_cannot_be_marked_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            executed, _ = run_with_collector(
                tmp, run, script={(2, 1): "KeyboardInterrupt"},
            )
            self.assertEqual(executed.status, STATUS_PAUSED)
            with self.assertRaises(ValueError):
                finalize_dataset(tmp, run.id)
            self.assertEqual(finalization_state(tmp, run)["status"], "FAILED")

    def test_complete_dataset_passes_all_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=3)
            run_with_collector(tmp, run)
            state = finalize_dataset(tmp, run.id)
            self.assertEqual(state["status"], "COMPLETED")
            self.assertEqual(state["parquet_rows"], 3)
            self.assertEqual(state["metadata_records"], 3)

    def test_dataset_schema_version_is_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            run_with_collector(tmp, run)
            record = read_staging(run)[0]
            self.assertEqual(record["dataset_schema_version"], "v1")
            self.assertEqual(record["feature_schema_version"], "v1")
            finalize_dataset(tmp, run.id)
            row = pq.read_table(
                run.directory / FEATURES_PARQUET_FILENAME
            ).to_pylist()[0]
            self.assertEqual(row["feature_schema_version"], "v1")
            manifest = json.loads(
                (run.directory / "manifest.json").read_text()
            )
            self.assertEqual(manifest["dataset_schema_version"], "v1")

    def test_readme_is_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            run_with_collector(tmp, run)
            finalize_dataset(tmp, run.id)
            readme = run.directory / RUN_README_FILENAME
            self.assertTrue(readme.is_file())
            text = readme.read_text()
            self.assertIn(run.id, text)
            self.assertIn("dataset_schema_version: v1", text)
            self.assertIn("features.parquet", text)
            self.assertIn("metadata.jsonl", text)
            self.assertIn("captures/<sequence>/<experiment_id>.pcap", text)
            self.assertIn("security_posture", text)
            self.assertIn("traffic", text)
            self.assertIn("STRONG", text)
            self.assertIn("does NOT compute the future", text)


# ---------------------------------------------------------------------------
# Artifact-failure and recovery semantics
# ---------------------------------------------------------------------------

class TestArtifactFailure(unittest.TestCase):
    def test_artifact_failure_means_sample_not_committed(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)

            def failing_collector(run, experiment_id, attempt, sample, outcome,
                                  log=None):
                raise RuntimeError("captures full")

            executed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=SyntheticRunner(),
                cleanup_fn=FakeCleanup(),
                collector_fn=failing_collector,
            )
            self.assertEqual(executed.status, STATUS_FAILED)
            self.assertEqual(executed.successful_samples, 0)
            self.assertEqual(executed.failed_samples, 5)
            self.assertEqual(read_staging(run), [])
            failure = json.loads(
                (run.directory / "failures"
                 / experiment_id_for(run.id, 1, 1) / "failure.json").read_text()
            )
            self.assertEqual(failure["reason"], "ArtifactError")

    def test_artifact_failure_recovers_on_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)

            def flaky_collector(run, experiment_id, attempt, sample, outcome,
                                log=None):
                if experiment_id == experiment_id_for(run.id, 1, 1):
                    raise RuntimeError("transient artifact failure")
                return collect_successful_sample(
                    run, experiment_id, attempt, sample, outcome, log=log
                )

            executed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=SyntheticRunner(),
                cleanup_fn=FakeCleanup(), collector_fn=flaky_collector,
            )
            self.assertEqual(executed.status, STATUS_COMPLETED)
            self.assertEqual(executed.failed_samples, 1)
            self.assertEqual(executed.successful_samples, 1)
            staged = read_staging(run)
            self.assertEqual(len(staged), 1)
            self.assertEqual(staged[0]["attempt_number"], 2)
            self.assertNotEqual(staged[0]["experiment_id"],
                                experiment_id_for(run.id, 1, 1))

    def test_orphan_staged_record_is_not_treated_as_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=1)
            sample = plan["samples"][0]
            # simulate a crash between staging and commit: an orphan record
            # whose attempt never committed
            orphan_exp = experiment_id_for(run.id, 1, 99)
            orphan = build_successful_record(
                run, sample, orphan_exp, 99,
                {"features": synthetic_features()},
                f"{CAPTURES_SUBDIR}/0001/{orphan_exp}.pcap",
            )
            staging_path(run).write_text(json.dumps(orphan) + "\n")

            executed, _ = run_with_collector(tmp, run)
            self.assertEqual(executed.status, STATUS_COMPLETED)
            self.assertEqual(executed.successful_samples, 1)

            staged = read_staging(run)
            self.assertEqual(len(staged), 1)
            self.assertEqual(staged[0]["experiment_id"],
                             experiment_id_for(run.id, 1, 1))
            # orphan is reported, not silently accepted as the sample
            orphan_lines = read_lines(
                run.directory / STAGING_SUBDIR / ORPHAN_STAGING_FILENAME
            )
            self.assertEqual(len(orphan_lines), 1)
            self.assertEqual(orphan_lines[0]["experiment_id"], orphan_exp)

    def test_resume_does_not_duplicate_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            executed, _ = run_with_collector(
                tmp, run, script={(2, 1): "KeyboardInterrupt"},
            )
            self.assertEqual(executed.status, STATUS_PAUSED)
            self.assertEqual(len(read_staging(run)), 1)  # seq 1 only
            # resume
            completed, _ = run_with_collector(tmp, run)
            self.assertEqual(completed.status, STATUS_COMPLETED)
            staged = read_staging(run)
            self.assertEqual(len(staged), 3)
            self.assertEqual(sorted(r["sequence"] for r in staged), [1, 2, 3])
            # seq 2 was retried, so it is attempt 2 -- not duplicated
            seq2 = [r for r in staged if r["sequence"] == 2][0]
            self.assertEqual(seq2["attempt_number"], 2)
            finalize_dataset(tmp, run.id)
            table = pq.read_table(run.directory / FEATURES_PARQUET_FILENAME)
            self.assertEqual(table.num_rows, 3)


# ---------------------------------------------------------------------------
# Dataset download / export bundle
# ---------------------------------------------------------------------------

class TestDatasetExport(unittest.TestCase):
    def _finalized_run(self, target=2):
        tmp = tempfile.TemporaryDirectory()
        try:
            run, _ = make_run_and_plan(tmp.name, target=target)
            run_with_collector(tmp.name, run)
            finalize_dataset(tmp.name, run.id)
            return tmp, run
        except Exception:
            tmp.cleanup()
            raise

    def test_export_artifact_paths_are_the_four_final_files(self):
        tmp, run = self._finalized_run()
        try:
            paths = export_artifact_paths(run)
            self.assertEqual(
                [p.name for p in paths],
                [*EXPORT_ARTIFACT_FILENAMES],
            )
            for path in paths:
                self.assertTrue(path.is_file())
                self.assertTrue(path.is_relative_to(run.directory.resolve()))
        finally:
            tmp.cleanup()

    def test_zip_contains_exactly_the_final_artifacts(self):
        tmp, run = self._finalized_run()
        import io
        import zipfile
        try:
            destination = Path(tmp.name) / "bundle.zip"
            build_dataset_zip(run, destination)
            with zipfile.ZipFile(destination) as zf:
                names = zf.namelist()
                self.assertEqual(sorted(names), sorted(EXPORT_ARTIFACT_FILENAMES))
                for name in names:
                    self.assertNotIn("/", name)  # archive-root basenames only
                    self.assertNotIn("..", name)
            # Evidence / provenance directories never enter the bundle.
            for forbidden in ("captures", "experiments", "failures",
                              "staging", "logs", "tmp", "state.json",
                              "finalization.json"):
                for name in names:
                    self.assertNotIn(forbidden, name)
        finally:
            tmp.cleanup()

    def test_zip_members_match_source_bytes_and_sources_unchanged(self):
        tmp, run = self._finalized_run()
        import io
        import zipfile
        try:
            before = {
                name: (run.directory / name).read_bytes()
                for name in EXPORT_ARTIFACT_FILENAMES
            }
            destination = Path(tmp.name) / "bundle.zip"
            build_dataset_zip(run, destination)
            with zipfile.ZipFile(destination) as zf:
                for name, payload in before.items():
                    self.assertEqual(zf.read(name), payload)
            after = {
                name: (run.directory / name).read_bytes()
                for name in EXPORT_ARTIFACT_FILENAMES
            }
            self.assertEqual(after, before)
        finally:
            tmp.cleanup()

    def test_build_dataset_zip_returns_member_paths(self):
        tmp, run = self._finalized_run()
        import io
        import zipfile
        try:
            destination = Path(tmp.name) / "bundle.zip"
            members = build_dataset_zip(run, destination)
            self.assertEqual([p.name for p in members],
                             list(EXPORT_ARTIFACT_FILENAMES))
            with zipfile.ZipFile(destination) as zf:
                self.assertEqual(sorted(zf.namelist()),
                                 sorted(EXPORT_ARTIFACT_FILENAMES))
        finally:
            tmp.cleanup()

    def test_missing_artifact_is_rejected(self):
        tmp, run = self._finalized_run()
        try:
            (run.directory / RUN_README_FILENAME).unlink()
            with self.assertRaisesRegex(ValueError, "READM"):
                export_artifact_paths(run)
            with self.assertRaisesRegex(ValueError, "READM"):
                build_dataset_zip(run, Path(tmp.name) / "bundle.zip")
        finally:
            tmp.cleanup()

    def test_path_traversal_artifact_is_rejected(self):
        tmp, run = self._finalized_run()
        try:
            outside = Path(tmp.name) / "outside-secret.txt"
            outside.write_text("secret\n", encoding="utf-8")
            readme = run.directory / RUN_README_FILENAME
            readme.unlink()
            readme.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "escapes"):
                export_artifact_paths(run)
            with self.assertRaisesRegex(ValueError, "escapes"):
                build_dataset_zip(run, Path(tmp.name) / "bundle.zip")
        finally:
            tmp.cleanup()

    def test_directory_in_place_of_artifact_is_rejected(self):
        tmp, run = self._finalized_run()
        try:
            metadata = run.directory / METADATA_FILENAME
            metadata.unlink()
            metadata.mkdir()
            with self.assertRaisesRegex(ValueError, "missing"):
                export_artifact_paths(run)
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()