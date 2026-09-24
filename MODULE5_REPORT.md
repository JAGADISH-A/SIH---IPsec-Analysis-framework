# Module 5: Dataset Artifacts — Final Report

**Status:** Complete | **Tests:** 45 Module 5 tests | **Total suite:** 181 tests, 0 failures

## Required Items

### 1. One staging record per committed successful sample
`collect_successful_sample()` stages exactly one JSON record per committed
successful sample, written to `staging/successful_samples.jsonl` (append +
fsync). Only samples the engine has committed may enter the staging log.

### 2. Failed / partial / abandoned samples never staged
The collector is only invoked on the Module 3/4 success outcome. Failed and
interrupted attempts are recorded under `failures/` and never appear in staging,
metadata, or the Parquet file (tested: `test_failed_sample_is_not_staged`,
`test_failed_attempts_remain_isolated`).

### 3. Successful retry produces exactly one record
When a sequence fails on attempt 1 and succeeds on attempt 2, staging contains a
single record for that sequence with `attempt_number == 2`. The failed attempt's
success is never recorded (tested: `test_successful_retry_produces_exactly_one_record`).

### 4. Duplicate sequence protection
A logical sequence may contribute at most one staged record. Re-collecting the
same `experiment_id` is idempotent (dedupe). A *different* experiment id for an
already-committed sequence raises `ValueError` (tested:
`test_duplicate_sequence_is_rejected`, `test_duplicate_sequence_prevents_completion`).

### 5. Metadata includes security posture
Each record carries `security_posture`, taken from the Module 2 plan sample
(`sample["security_posture"]` filtering). Never recalculated from traffic.

### 6. Metadata includes traffic profile
Each record carries `traffic_profile`, taken from the plan sample.

### 7. Metadata includes full IPsec configuration
Each record carries the flattened config fields `mode`, `address_family`,
`ike_version`, `ike_encryption`, `ike_integrity`, `ike_dh_group`,
`esp_encryption`, `esp_integrity`, `esp_dh_group`, `pfs`, plus the full nested
`ipsec_configuration` object, all copied verbatim from the plan sample.

### 8. Posture in staging must match the plan
`validate_final_dataset` rejects any record whose posture differs from its plan
sample, and verifies the overall posture distribution matches `posture_planned`
(test: `test_missing_posture_prevents_completion`).

### 9. Traffic profile in staging must match the plan
Same enforcement for traffic: per-record match plus `traffic_quota` distribution
match. Quota entries with count 0 are handled correctly (smoke run caught this
during development).

### 10. Configuration in staging must match the plan
`configuration_id` and the full `ipsec_configuration` (plus all flattened keys)
must equal the plan sample (tests: `test_configuration_matches_plan`,
`test_plan_mismatch_prevents_completion`).

### 11. PCAP reference points to successful evidence
The record's `pcap_path` is `captures/<sequence>/<experiment_id>.pcap`; the
collector physically copies the evidence from the attempt tmp dir. A missing
PCAP file fails finalization (test: `test_pcap_reference_points_to_successful_evidence`).

### 12. Failed-attempt PCAP never referenced
Staged/metadata/Parquet records only reference committed attempts; failed
attempt dirs live under `failures/<experiment_id>/` and are excluded from all
dataset artifacts.

### 13. JSONL: one record per line
`successful_samples.jsonl` and `metadata.jsonl` are strict JSONL. Every line is
valid JSON; corrupt lines raise `ValueError` in `read_staging` (test:
`test_jsonl_lines_are_valid_json`).

### 14. Feature schema consistency
The 54-column feature schema is declared explicitly (`FEATURE_COLUMNS` +
`INT_FEATURES`/`FLOAT_FEATURES`) and cross-checked against the live extractor
via `reference_feature_record()`/`assert_feature_keys()`. All feature types
normalized; mixed-type records are rejected (tests: `test_feature_schema_is_consistent`,
`test_mixed_type_corruption_is_rejected`).

### 15. Parquet contains exactly the successful rows
`features.parquet` is a 64-column table (10 linkage/ground-truth + 54 features),
one row per successful sample, written atomically at finalization (tmp + fsync +
rename `os.replace`). `pq.read_table` round-trips exactly.

### 16. Atomic materialization (no partial artifacts)
A failed Parquet write never leaves a `.tmp` or half-written final file and never
marks finalization COMPLETED; `finalization.json` records FAILED and the previous
valid artifacts survive (test: `test_failed_parquet_materialization_does_not_mark_complete`,
`test_metadata_materialization_is_atomic`).

### 17. Empty/incomplete dataset cannot be finalized
`finalize_dataset` refuses when `successful_samples != target_samples`, staged
count differs, sequences don't cover `1..target`, or the run is not COMPLETED
(tests: `test_empty_dataset_cannot_be_marked_complete`,
`test_incomplete_dataset_cannot_be_marked_complete`, `test_count_mismatch_prevents_completion`).

### 18. Distribution preservation (traffic + posture, target=3..6)
`test_successful_rows_preserve_traffic_distribution` and `test_successful_rows_preserve_posture_distribution`
verify exact profile/posture counts on target=6 plans.

### 19. Resumed run does not duplicate staging
A PAUSED run (interrupt) resumed with the same collector appends only newly
committed sequences; already committed sequences are skipped (test:
`test_resume_does_not_duplicate_staging`).

### 20. Schema version recorded
Records, Parquet rows, and `manifest.json` all carry
`feature_schema_version = "v1"` / `dataset_schema_version = "v1"` (test:
`test_dataset_schema_version_is_present`).

### 21. README and human-readable artifacts
`finalize_dataset` writes `README.txt` (target, successful count, artifact
paths, posture categories, traffic profiles, ground-truth semantics,
inspection commands). See `test_readme_is_generated`.

### 22. Zero-quota profiles handled in distribution checks (bug found by smoke test)
The Module 2 plan's `traffic_quota` includes all six profiles with `0` counts for
unused ones. The distribution check now compares per-profile observed vs
expected (defaulting missing to 0) instead of raw dict equality, so a run that
uses only three profiles finalizes correctly.

### 23. Artifact failure maps to a FAILED attempt
`_run_sequence` wraps `persist_successful_sample` + collector in try/except. An
artifact persistence failure converts the attempt to FAILED with reason
`"ArtifactError"` (recorded in `failures/<exp_id>/failure.json`); the sequence is
never committed and never staged (test: `test_artifact_failure_means_sample_not_committed`).

### 24. Artifact failure recovers on a later attempt
Degraded persistence (fail once, succeed on retry) is handled by the attempt
budget: staging ends with the successful retry's record only (test:
`test_artifact_failure_recovers_on_retry`).

### 25. Orphan staging records are archived, reported, not accepted
A staged record whose attempt was never committed (e.g. crash between staging and
commit) is moved to `staging/staging-orphans.jsonl` and never counted as the
sample's success (test: `test_orphan_staged_record_is_not_treated_as_success`).

### 26. Plan fingerprint guard at finalization
`finalize_dataset` reloads the plan and verifies it matches the stored
`plan_fingerprint` before any consistency check; a regenerated/different plan is
rejected (`test_plan_fingerprint_mismatch_prevents_completion`).

## Files Modified
- `controller/dataset_artifacts.py` — NEW module: schemas, staging, normalization, collection, finalization, materialization
- `controller/dataset_executor.py` — `collector_fn` param threaded through `execute_dataset_run` / `_run_sequence`; ArtifactError semantics; CLI wiring

## Files Added
- `controller/test_dataset_artifacts.py` — 45 tests covering all items above
- `SCHEMA.md` — full v1 dataset/feature schema documentation

## Verification Notes
- `pyarrow 25.0.1` installed in the project venv (no Parquet writer existed before).
- Full suite: `python -m unittest discover -s controller -p "test_*.py"` → 181 tests OK.
- End-to-end smoke run (target=3, synthetic runner): run COMPLETED, 3 staged records,
  3 Parquet rows, 3 metadata records, PCAP evidence under `captures/`, `README.txt`
  present, `finalization.json` COMPLETED, no `.tmp` leftovers.