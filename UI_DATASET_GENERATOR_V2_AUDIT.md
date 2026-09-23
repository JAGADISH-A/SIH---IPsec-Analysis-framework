# UI Dataset Generator — V2 Compatibility Audit

Date: 2026-09-23 · Branch `feature/testbed` @ `a3740c9` · **Audit only.** No
production code was modified, no new generator was written, no experiment was
run, no frontend/backend was changed, and nothing was committed. The only new
file is this report.

Device under test: the **backend dataset generator** the UI calls via
`POST /dataset-runs` (the "Automated Experiment Run" card). The UI caller is
not the device under test (as per the audit brief).

Status vocabulary: `V2-COMPATIBLE`, `V1-ERA` (historical, pre-migration
persisted artifact only; no active path produces v1 features), `OUT OF SCOPE`.

---

## 1. Verdict

| Item | Status | Justification |
|---|---|---|
| UI dataset generator (backend `/dataset-runs` path) | `V2-COMPATIBLE` | The UI invokes the exact same `execute_dataset_run` engine as the CLI; every step of that engine produces the **v2 / 59-column** feature record, hard-enforced at commit/finalization. Ground-truth run re-verified offline==live==persisted (exit 0). See §3–§8. |

The canonical dataset `results/datasets/dataset-20260916-231246` was produced
by the dataset-run **CLI/executor** path; that path is the **same code path the
UI invokes** (proven in §4, §5). There is no separate UI-specific generator to
audit for v2 drift.

---

## 2. Scope & method

- Read: `frontend/app.js`, `controller/api.py`, `controller/dataset_api.py`,
  `controller/dataset_executor.py`, `controller/experiment_runner.py`,
  `controller/campaign.py`, `controller/features.py`,
  `controller/live_features.py`, `controller/dataset_artifacts.py`,
  `controller/dataset_run.py`, `controller/dataset_rebuild.py`,
  `controller/quality.py`, `controller/dataset.py`.
- Inspected real persisted artifacts under `results/datasets/*` and the legacy
  `results/dataset/` aggregate (pyarrow + metadata.jsonl + state/manifest).
- Ran the safe non-lab test suite (241 tests) and the canonical-run parity
  verification (exit 0) — §12, §13.
- Did NOT run a live generation (each sample redeploys the shared lab topology
  and holds `TESTBED_LOCK`); the completed run `dataset-20260916-231246` is
  the ground truth, consistent with `DATASET_GENERATE_AUDIT_REPORT.md:33`.

---

## 3. User path (UI → API)

`frontend/index.html` card "Automated Experiment Run" + target input, driven by
`frontend/app.js`:

- `app.js:8` `DATASETS_URL = "/dataset-runs"`; `app.js:9` settings URL.
- `app.js:1127,1157` read the ceiling from `GET /dataset-runs/settings`
  (`maximum_target_samples`), bounding the input.
- `app.js:1164` `startDatasetRun()`; `app.js:1180-1183` `POST DATASETS_URL`
  with body `{"target_samples": <int>}`.
- `app.js:1259` polls `GET /dataset-runs/{id}` every 2500 ms; `app.js:1240`
  fetches results; `app.js:1371` resume POST; `app.js:1416` download link;
  `app.js:1430` binds `#datasetGenerateBtn` → `startDatasetRun`.

The frontend only ever POSTs a target integer and polls; all sample creation,
capture, feature extraction, staging and finalization are backend.

---

## 4. Backend entry point (the generator the UI drives)

`controller/api.py:43-49` mounts the dataset router on the same FastAPI app:

```
app.include_router(
    create_dataset_router(
        results_root="results",
        max_target_samples=DEFAULT_MAX_TARGET_SAMPLES,
        lock=TESTBED_LOCK,
    )
)
```

`controller/dataset_api.py`:

- `dataset_api.py:384` `create_dataset_router(...)`. In production
  (`run_attempt_fn/cleanup_fn/collector_fn` all `None`) the worker falls back
  to the **real** Module 3/4/5 implementations —
  `dataset_api.py:292` `executor_mod.run_attempt`,
  `dataset_api.py:293` `executor_mod.cleanup_attempt`,
  `dataset_api.py:296` `collector = artifacts_mod.collect_successful_sample`.
- `dataset_api.py:441` `POST /dataset-runs` → `create_dataset_run`:
  validates target ≤ ceiling (422) and `lock.try_reserve(TESTBED_LOCK)` (409),
  then `dataset_api.py:477` `dataset_run_mod.create_dataset_run(...)` +
  `dataset_api.py:480-483` `planner_mod.build_sample_plan` / `write_sample_plan`,
  then `dataset_api.py:494` `_spawn(dataset_run_id)`.
- `dataset_api.py:412-425` `_spawn` runs `_run_dataset_worker` on a background
  thread with the production defaults above.
- `dataset_api.py:283` `_run_dataset_worker` → `dataset_api.py:298-304`
  `executor_mod.execute_dataset_run(...)` and, on COMPLETED,
  `dataset_api.py:306` `artifacts_mod.finalize_dataset(...)`; testbed released
  in `finally` (`dataset_api.py:323`).

So the UI's generator = `execute_dataset_run` + `collect_successful_sample` +
`finalize_dataset`.

---

## 5. Same code path as the CLI (proven)

The canonical run was produced through the executor path; the UI and the CLI
invoke the **identical function**:

| | CLI | UI (production worker) |
|---|---|---|
| entry | `dataset_executor.py:293` `main()` (`python -m controller.dataset_executor <run_id> ...`) | `dataset_api.py:283` `_run_dataset_worker` |
| engine call | `dataset_executor.py:340-345` `execute_dataset_run(..., collector_fn=collect_successful_sample, ...)` | `dataset_api.py:298-304` `execute_dataset_run(..., collector_fn=artifacts_mod.collect_successful_sample, ...)` |
| run-attempt | default `run_attempt` (defined at `dataset_executor.py:152`, default arg at `dataset_executor.py:242`) | `dataset_api.py:292` `executor_mod.run_attempt` |
| finalize | CLI user must call `finalize_dataset` (or the generic engine's collector) | `dataset_api.py:306` `artifacts_mod.finalize_dataset` |

The only UI/CLI difference is run-id creation: the CLI requires an existing run
directory (`dataset_executor.py:299` takes a run id), which is **created by the
same `dataset_run_mod.create_dataset_run` + `planner_mod.build_sample_plan`**
that the UI calls in-band (`dataset_api.py:477-483`). The occupied-downstream
code is 100% shared.

---

## 6. Feature extraction on the UI path — v2 / 59 columns

Per-sample pipeline (`dataset_executor.py:152` `run_attempt`):

- `dataset_executor.py:185` `campaign_mod.execute_trial_pipeline(...)`.
- `campaign.py:239-241` `features_mod.extract_features(pcap_path, capture_ip=cap_wan_ip, nominal_duration=duration)`.
- `features.py:469` `extract_features` — thin PCAP-reading wrapper over
  `features.py:374` `summarize_capture`, "the **59-feature** record ... the
  single computation shared by the training pipeline and the live bridge"
  (`features.py:376,385-387`).

v2 column set is enforced structurally:

- `dataset_artifacts.py:84` `FEATURE_SCHEMA_VERSION = "v2"`.
- `dataset_artifacts.py:115-175` `FEATURE_COLUMNS` — exactly **59** columns
  (18 int + 41 float, per `INT_FEATURES` at `dataset_artifacts.py:182-191`);
  `dataset_artifacts.py:194` `FEATURE_KEYS = frozenset(FEATURE_COLUMNS)`.
- `dataset_artifacts.py:238` `assert_feature_keys` raises if a record's key set
  ≠ `FEATURE_KEYS`; `dataset_artifacts.py:391` `normalize_feature_record`
  normalizes and enforces int/float typing per column.
- `dataset_artifacts.py:449` `build_successful_record` stamps
  `"feature_schema_version": FEATURE_SCHEMA_VERSION` on every committed record.
- `dataset_artifacts.py:478` `collect_successful_sample` is the UI-path
  collector; a sample only commits after `collect_successful_sample` stages a
  v2-valid record (`dataset_executor.py:254-258`).
- `dataset_artifacts.py:611` `validate_final_dataset` (called by
  `finalize_dataset`, `dataset_artifacts.py:821`) rejects any non-v2 record —
  `dataset_artifacts.py:684-687` "version … must match the enforced
  FEATURE_SCHEMA_VERSION".

v1-only IKE-exchange columns are deliberately absent from v2
(`dataset_artifacts.py:177-180` comment; `features.py:526` docstring): they
cannot be reproduced by the live XDP feed, so v2 removed them. `_ike_summary`
(`features.py:514`) emits only IKE size/count fields that ARE in v2.

---

## 7. Live-parity (the audit's v2 reference path)

`controller/live_features.py` instantiates the same shared computation:

- `live_features.py:90` `LIVE_METADATA_KEYS = ("feature_schema_version",
  "window_start_ns", "window_end_ns")`.
- `live_features.py:233` emits `"feature_schema_version": FEATURE_SCHEMA_VERSION`
  with `features = {...}` 59 keys.
- Docstring `live_features.py:11` documents the emitted record shape.

The canonical-run parity check feeds the preserved PCAPs through both the
offline `extract_features` path and the live `LiveFeatureExtractor` path and
requires byte-identical rows (§8).

---

## 8. Ground-truth run — persisted v2

`results/datasets/dataset-20260916-231246` (created 2026-09-16T17:42:46Z, 5/5
samples, one per posture band; finalization re-run during the 09-23 v2
migration):

- `state.json` / `manifest.json`: `dataset_schema_version: "v1"` —
  this is the **run-state/artifact schema axis** (kept by design), NOT the
  feature schema; see `V1_DATASET_CLEANUP_REPORT.md:140-141`.
- `staging/successful_samples.jsonl`: 5 records, each `feature_schema_version:
  "v2"`, `features` = exactly 59 columns.
- `metadata.jsonl`: 5 records, all `feature_schema_version = "v2"`.
- `features.parquet`: 5 rows × 69 columns = 10 linkage
  (`PARQUET_ID_COLUMNS`, `dataset_artifacts.py:201-...`) + 59 features;
  `feature_schema_version` linkage column = `v2` for all rows.
- `finalization.json`: `status COMPLETED`, `parquet_rows 5`,
  `metadata_records 5`, `updated_at 2026-09-23T08:01:55Z`.
- Verification command (exit 0):

```
.venv/bin/python -m controller.dataset_rebuild --run-id dataset-20260916-231246 --verify-only
OK: 5/5 records match the live v2 feature path
```

This is documented in `DATASET_V2_REGEN_VALIDATION_REPORT.md` and
`V1_DATASET_CLEANUP_REPORT.md:11-23`.

---

## 9. Schema-version inventory of persisted data

| Artifact | Feature-schema status | Notes |
|---|---|---|
| `results/datasets/dataset-20260916-231246` (canonical) | **v2 / 59** (metadata, parquet, staging) | Ground truth; per-experiment `features.json` dumps are v1-era provenance snapshots (§10). |
| `results/datasets/acc-eng-01`, `acc-eng-02` | **v1-era** (64 cols: 59 + `ike_sa_init_count`, `ike_auth_count`, `ike_create_child_sa_count`, `ike_informational_count`, `ike_version`; parquet 74 cols, finalized 09-15) | Acceptance-run artifacts, pre-migration. Distinct run ids, retained ("other valid datasets" per `V1_DATASET_CLEANUP_REPORT.md:80-85`). |
| `results/datasets/dataset-20260913-235839`, `dataset-20260914-202956`, `dataset-20260914-225751`, `dataset-20260914-235105`, `dataset-20260915-113002` | **v1-era** (54-feature flat schema; parquet 64 cols = 10 ID + 54 features, no IKE columns) | Pre-IKE-extractor era runs, finalized 09-14/09-15. No longer reproduced by any current code. |
| `results/datasets/dataset-20260916-122639` | stale: staging v1 / 64 cols | COMPLETED but never finalized (no parquet/metadata/finalization.json) — see `DATASET_GENERATE_AUDIT_REPORT.md:122` (named 122612 there). Pre-migration, never re-migrated. |
| `results/dataset/` (singular) — `features.csv` + `metadata.jsonl` | Legacy Module-1 flat aggregate (54 col CSV header), last written 09-15 | Produced by `quality.py:360` → `dataset.py:124,128` `append_aggregate` over legacy `*-exp-*` dirs. Separate pre-schema-version format, not the v1 feature schema and not on the UI path (`V1_DATASET_CLEANUP_REPORT.md:62,75-79`). |

All v1-era rows are historical artifacts of the pre-2026-09-23 code; **no active
code path emits them** (see §11).

---

## 10. v1-era features.json inside the canonical run (not consumed)

`results/datasets/dataset-20260916-231246/experiments/*/features.json` contain
64-key v1-era dumps (e.g. `ike_sa_init_count`, `ike_auth_count`, ...) with no
`feature_schema_version` key. They were written at execution time by the
pre-migration code path (`experiment_runner.py:386`
`persist_successful_sample` writing `outcome["features"]`). Today `outcome
["features"]` is the v2/59 dict (campaign → `extract_features`), so a *new* run
(via UI or CLI) would write v2 here too. The pipeline does not consume these
dumps — the consumed artifacts are `staging` → `metadata.jsonl` →
`features.parquet`, all v2
(`V1_DATASET_CLEANUP_REPORT.md:86-91`). They are retained as evidence.

---

## 11. v1 references: active vs historical

Per the full inventory in `V1_DATASET_CLEANUP_REPORT.md:33-98`:

- **No ACTIVE code or test presents the v1/64-column feature schema as
  current.** `ike_sa_init_count` etc. appear only in docstrings (v2 removal
  rationale), no-reintroduction tests, and the migration tool.
- `dataset_artifacts.py:83` `SCHEMA_VERSION = "v1"` is the **run-state artifact
  schema** axis (like `dataset_run.py:30` `SCHEMA_VERSION`, `planner` v1) — an
  intentionally separate, kept axis, distinct from `FEATURE_SCHEMA_VERSION
  = "v2"` (`dataset_artifacts.py:84`).
- The legacy flat `results/dataset/` aggregate is produced by the Module-1
  quality workflow (`quality.py:346-360` still calls
  `features.extract_features` for its own CSV rows), not by the dataset-run
  generator.

---

## 12. Tests

Safe, non-lab suite (identical to the batches used by
`DATASET_V2_REGEN_VALIDATION_REPORT.md:160-170` and
`V1_DATASET_CLEANUP_REPORT.md:116-125`; `controller.test_dataset_executor`
excluded — one test drives real `reset_and_deploy`/`destroy`, needing the
lab/sudo):

```
.venv/bin/python -m unittest controller.test_features controller.test_live_features controller.test_dataset_artifacts ebpf.test_window_aggregator ebpf.test_state_builder controller.test_dataset_planner controller.test_dataset_run controller.test_dataset_reuse controller.test_dataset_reuse_decision controller.test_generator controller.test_dataset_timing controller.test_ipsec_events controller.test_audit controller.test_config

Ran 241 tests in 2.752s

OK
```

Re-ran (runs during this audit):

```
.venv/bin/python -m controller.dataset_rebuild --run-id dataset-20260916-231246 --verify-only
OK: 5/5 records match the live v2 feature path   (exit 0)
```

---

## 13. Findings

1. **UI generator is v2.** `POST /dataset-runs` → background worker → the
   exact `execute_dataset_run` engine used by the CLI; features computed by
   `campaign.execute_trial_pipeline` → `features.extract_features` →
   `summarize_capture` (`features.py:374`, "the 59-feature record"), committed
   only after v2 enforcement (`assert_feature_keys` /
   `normalize_feature_record` / `validate_final_dataset`).
2. **CLI and UI share the device under test.** No separate UI generator exists;
   the canonical run is valid ground truth for the UI path (§5).
3. **No live v1 generator exists.** v1/64 artifacts on disk predate the v2
   migration (per-experiment `features.json`, `acc-eng-*`, and the 09-13..09-16
   dataset runs). The current engine writes v2 everywhere.
4. **Dataset schema v1 ≠ feature schema v1.** `dataset_schema_version: "v1"` on
   the canonical run is the run-state axis and is expected, not evidence of a
   v1 feature generator.

## 14. Limitations

- No live UI-triggered generation was executed (lab redeploy + `TESTBED_LOCK`;
   consistent with `DATASET_GENERATE_AUDIT_REPORT.md:225-231`). Conclusion is
   by code-path identity (§5) plus persisted ground truth (§8), not by a fresh
   UI-originated lab run.
- `acc-eng-*` and the 09-* runs were produced by pre-migration code and retain
   v1 features; a consumer must not mix them with the canonical v2 dataset
   (retained as evidence per `V1_DATASET_CLEANUP_REPORT.md`).

---

## 15. Verdict line

```
UI DATASET GENERATOR: V2-COMPATIBLE
```

Nothing was committed.