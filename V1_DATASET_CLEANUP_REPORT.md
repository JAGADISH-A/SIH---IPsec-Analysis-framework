# V1 Dataset Cleanup Report

- Date: 2026-09-23
- Scope: Phase 2b cleanup only. Remove obsolete v1 references/artifacts now that
  the canonical dataset `results/datasets/dataset-20260916-231246` is
  exclusively v2 (verified). No ML, no synthetic data, no feature/schema
  changes, no unrelated cleanup. Nothing was committed.

## 1. Migration-state confirmation

`results/datasets/dataset-20260916-231246` is exclusively v2:

- `metadata.jsonl`: 5 records, all `feature_schema_version="v2"`, feature
  dicts exactly 59 columns each, no v1 IKE-exchange columns present.
- `features.parquet`: 5 rows x 69 columns (10 linkage + 59 features);
  `feature_schema_version` column `v2` for all rows.
- `staging/successful_samples.jsonl`: v2, 59 columns.
- Live/offline/persisted parity verified:

```
.venv/bin/python -m controller.dataset_rebuild --run-id dataset-20260916-231246 --verify-only
OK: 5/5 records match the live v2 feature path   (exit 0)
```

Active code already enforces v2/59 everywhere:
`controller/features.py`, `controller/live_features.py`,
`controller/dataset_artifacts.py` (`FEATURE_SCHEMA_VERSION="v2"`,
`normalize_feature_record`, `assert_feature_keys`), `controller/dataset_rebuild.py`,
`controller/test_features.py`, `controller/test_live_features.py`,
`controller/test_dataset_artifacts.py` (incl. the no-reintroduction test for the
five removed IKE-exchange columns).

## 2. V1 reference inventory and classification

Every remaining v1 / 64-column / IKE-exchange-column mention was classified by reading
the code and docs, not by guessing.

### Historical / reporting (retained as-is)

| Reference | Why retained |
|---|---|
| `DATASET_V2_REGEN_VALIDATION_REPORT.md` | Migration evidence / validation report (required to keep). |
| `ML_LAYER_AUDIT.md` | Phase-1 audit deliverable; documents pre-migration state (required to keep). |
| `DATASET_GENERATOR_ML_PIPELINE_REPORT.md` | Documents the v1->v2 decision and 64/64 v1 reproducibility evidence. |
| `DATASET_GENERATE_AUDIT_REPORT.md` | Audit findings re the former 64-key extractor / 54-col doc drift. |
| `MODULE5_REPORT.md` | Module-5 delivery report (feature_schema_version was "v1" at delivery). |
| `ACCEPTANCE_REPORT.md` | Acceptance notes on 54-vs-64 column history. |
| `E2E_VERIFICATION_REPORT.md` | "schema v1" here refers to `audit_schema_version` (audit events), a different, still-current axis; not the feature schema. |
| `SCHEMA.md` | Active data contract, but already fully v2 (title "Dataset artifact schema (v2)"; its v1/64 section is labelled a "Feature-schema history" note; `feature_schema_version="v2"` throughout). |
| `LIVE_V2_FEATURE_PIPELINE_REPORT.md` | Reports the v2 record shape and the v1 removed-column list. |
| `ML_CORRELATION_BOUNDARY.md`, `MODULE9_DESIGN.md`, `MODULE10_LIVE_VALIDATION_REPORT.md`, `STATE_CONSTRUCTION_REPORT.md`, `INSTALLATION_AUDIT.md`, `FRONTEND_RELABEL_REPORT.md`, `MODULE4_REPORT.md`, `MODULE6_REPORT.md`, `MODULE7_REPORT.md`, `MODULE8_REPORT.md`, `README.md` | No feature-schema-v1 / 64-column references; ML/correlation architecture docs retained. |

### Active / runtime (v2-aligned; all retained, none point at v1 as current)

| Reference | Assessment |
|---|---|
| `controller/features.py` | v2 extractor. Docstring (`features.py:522-531`) explains why the five v1 columns are excluded (feature-schema v2). Keep. |
| `controller/dataset_artifacts.py` | v2 schema; `normalize_feature_record` is the intentional v1->v2 normalization. Docstring/comment (# NOTE: feature_schema_version v1 also carried ...) explains the removal. Keep. |
| `controller/dataset_rebuild.py` | v2 rebuild + live-parity tool; docstring references v1->v2 as migration history. Keep. |
| `controller/test_features.py` / `controller/test_live_features.py` | v2-enforcing; assert the removed columns are absent (no-reintroduction test). Keep. |
| `controller/test_dataset_artifacts.py` | Asserts `feature_schema_version=="v2"` and `dataset_schema_version=="v1"` (a separate, intentionally kept axis). `ike_version` there is the configured metadata field, not an ML feature. Keep. |
| `controller/dataset.py` | Legacy Module-1 flat aggregate (`results/dataset/{features.csv,metadata.jsonl}`), a separate pre-schema-version format, not the v1 feature schema. Still used by `campaign.py`/`quality.py`/`experiment_runner.py` via `append_aggregate`/`build_metadata`. Not in scope. Keep. |

## 3. Obsolete v1 dataset copy / archive

No separate obsolete v1 copy/archive of the canonical dataset exists. There are
no `*.bak`, `.orig`, `*.tar*`/`*.zip`, backup or archive directories, and no
stale `staging-orphans.jsonl` or leftover `.tmp` files anywhere, including
`results/`. The canonical dataset dir contains only its v2 artifacts and its
evidence.

Distinct things that are NOT an obsolete v1 copy of the canonical run and were
therefore left untouched:

- `results/dataset/` (singular) - legacy Module-1 aggregate (`features.csv` +
  `metadata.jsonl`) actively appended to by `controller/dataset.py`
  `append_aggregate` (wired via `campaign.py` / `quality.py`); it is not
  "genuinely unused", is not a feature-schema artifact, and is not a copy of
  the canonical dataset.
- Other `results/datasets/*` runs (`acc-eng-01`, `acc-eng-02`,
  `dataset-20260913-235839`, `dataset-20260914-202956`,
  `dataset-20260914-225751`, `dataset-20260914-235105`,
  `dataset-20260915-113002`, `dataset-20260916-122639`) - separate, distinct
  v1-era dataset runs with their own run ids and evidence. They are "other
  valid datasets" (hard constraint: do not delete).
- `results/datasets/dataset-20260916-231246/experiments/*/features.json` -
  v1-era (64-col) per-experiment provenance dumps inside the canonical run.
  The pipeline does not consume them (staging -> metadata.jsonl ->
  features.parquet are the consumed artifacts and are v2); they are evidence
  and part of the canonical run directory, so they are retained. The v2
  migration report itself did not rewrite them.

## 4. References edited / files created

No active references were edited: the reference scan found no code, test,
config, or doc that presents the 64-column / v1 feature schema as current.
All v1 mentions that remain are historical evidence/docs or the intentional
v1->v2 normalization/enforcement code.

File created:

- `V1_DATASET_CLEANUP_REPORT.md` (this report).

## 5. Reference-scan result (before / after)

- Before: v1 / 64-column references present in 9 docs (all historical/reporting)
  plus intentional v1->v2 code/docstrings and enforcement tests. No ACTIVE
  reference pointed at a v1 feature schema as current.
- After: unchanged - all retained references are historical evidence/docs or
  the intentional `normalize_feature_record` v1->v2 normalization and the
  removed-column no-reintroduction tests. No remaining ACTIVE reference would
  cause future ML training/inference or pipeline runs to consume v1 features.

## 6. Tests

Safe, non-lab suite (as specified; `controller.test_dataset_executor` excluded -
lab/sudo-bound):

```
.venv/bin/python -m unittest controller.test_features controller.test_live_features controller.test_dataset_artifacts ebpf.test_window_aggregator ebpf.test_state_builder controller.test_dataset_planner controller.test_dataset_run controller.test_dataset_reuse controller.test_dataset_reuse_decision controller.test_generator controller.test_dataset_timing controller.test_ipsec_events controller.test_audit controller.test_config

Ran 241 tests in 2.808s

OK
```

Dataset verification re-run after cleanup:

```
.venv/bin/python -m controller.dataset_rebuild --run-id dataset-20260916-231246 --verify-only
OK: 5/5 records match the live v2 feature path   (exit 0)
```

## 7. Final canonical dataset / schema

- Single canonical ML dataset: `results/datasets/dataset-20260916-231246`
  (dataset id unchanged).
- Final feature schema: v2 / 59 features (metadata 5 x v2, `features.parquet`
  5 x 69 cols, staging v2).
- `dataset_schema_version` remains `v1` and `planner_version` remains `v1` -
  these are separate, unchanged version axes (kept by design).
- Historical migration evidence remains auditable
  (`DATASET_V2_REGEN_VALIDATION_REPORT.md`, `DATASET_GENERATOR_ML_PIPELINE_REPORT.md`,
  `ML_LAYER_AUDIT.md`, `DATASET_GENERATE_AUDIT_REPORT.md`, `MODULE5_REPORT.md`).

Nothing was committed.