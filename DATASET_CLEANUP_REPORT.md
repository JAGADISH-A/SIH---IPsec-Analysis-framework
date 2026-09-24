# Dataset Cleanup Report

- Date: 2026-09-24
- Scope: Remove confirmed failed/aborted dataset generation runs. Preserve the two
  protected datasets and every dataset referenced by code, tests, or docs. No ML.
  Nothing committed (`results/` is git-ignored and untracked).

## PHASE 0 — DATASET INVENTORY

Observed: All dataset run directories live under `results/datasets/` (13 remaining
after cleanup; 22 before). Verified protected datasets exist. `results/dataset/`
(singular) is a legacy Module-1 aggregate. `results/*-exp-*` are legacy campaign
experiment outputs; `results/e2e-verification/`, `results/audit/` are non-dataset
artifacts.

Actions: Full inventory of results/ and reference scan (code, tests, config, docs)
for every dataset run id.

Protected datasets: `results/datasets/dataset-20260923-221430`,
`results/datasets/dataset-20260924-003710`.

## PHASE 1 — DATASET CLASSIFICATION

| Dataset | Class |
|---|---|
| `dataset-20260923-221430` | KEEP - PROTECTED (200 samples) |
| `dataset-20260924-003710` | KEEP - PROTECTED (100 samples) |
| `dataset-20260916-231246` | KEEP - REQUIRED FOR VERIFICATION (tests, dataset_rebuild.py, docs) |
| `acc-eng-01`, `acc-eng-02`, `dataset-20260913-235839`, `dataset-20260914-202956`, `dataset-20260914-225751`, `dataset-20260914-235105`, `dataset-20260915-113002`, `dataset-20260916-122639` | KEEP - RETAINED AS EVIDENCE (`V1_DATASET_CLEANUP_REPORT.md`, hard constraint: do not delete) |
| `results/dataset/` (singular) | KEEP - ACTIVE LEGACY AGGREGATE (`controller/dataset.py` `append_aggregate`) |
| `dataset-20260923-185633` | UNKNOWN - REQUIRES REVIEW (failed; referenced as evidence in `UI_TESTBED_INTEGRATION_FIX_REPORT.md`) |
| `dataset-20260923-214502` | UNKNOWN - REQUIRES REVIEW (COMPLETED 3-sample run, unused) |
| `dataset-20260923-193806`, `194108`, `202750`, `202956`, `203424`, `203457`, `203853` | REMOVE - STALE / FAILED GENERATION (0 samples, zero references) |

## PHASE 2 — VERIFICATION OF PROTECTED DATASETS

Verified `dataset-20260923-221430`: 200/200 metadata records, 200 parquet rows
(69 cols), status COMPLETED, `feature_schema_version=v2`, 5 postures x 6 profiles,
seq 1-200, finalization `parquet_rows=200`, `metadata_records=200`.
Verified `dataset-20260924-003710`: 100/100 records, 100 parquet rows (69 cols),
COMPLETED (state `failed 1` = failed attempt kept in `failures/`), v2 features,
5 postures x 6 profiles, seq 1-100.

## PHASE 3 — DUPLICATION ANALYSIS

The two protected datasets are **independent, non-duplicate** runs: distinct run
ids, distinct experiment ids, distinct staging plans, sequence spaces 1-200 vs
1-100 with no record sharing either id. Neither is a backup, regeneration, or
extension of the other. Neither duplicates `dataset-20260916-231246` (5 samples).
No duplicates found across any retained dataset. No action.

## PHASE 4 — STALE, TEMPORARY, TEST, AND UNNECESSARY DATASETS

Candidates (7) = failed/aborted generation runs with 0 successful samples, no
`features.parquet`/`metadata.jsonl`/`.pcap`, no references in code/tests/config/docs;
failure cause `sudo: interactive authentication is required` (environment, not data).
Excluded from cleanup: doc-referenced failed run `185633`, completed unused run
`214502` (UNKNOWN - require review), evidence-retained v1 runs, legacy aggregate,
campaign experiment dirs (out of dataset scope).

## PHASE 5 — CLEANUP PLAN

Created `DATASET_CLEANUP_PLAN.md` listing the 7 exact deletion paths (no wildcards),
explicit rm commands, the not-deleted list with reasons, and post-cleanup
verification steps.

## PHASE 6 — DELETE CONFIRMED DATASET DIRECTORIES

Deleted (explicit paths):
`results/datasets/dataset-20260923-193806`,
`...-194108`, `...-202750`, `...-202956`, `...-203424`, `...-203457`,
`...-203853`. Exit 0.

## PHASE 7 — VERIFICATION

- `test -d` protected dirs: 221430 OK, 003710 OK, plus 231246 OK.
- sha256sum of `features.parquet`, `metadata.jsonl`, `manifest.json`,
  `finalization.json`, `README.txt`, `state.json` for both protected datasets
  identical to pre-cleanup baseline.
- Row counts unchanged: 221430 = 200 metadata / 200 parquet; 003710 = 100 / 100.
- Dataset inventory re-run: 13 dirs remain; only the 7 planned were removed.
- `git status --short`: clean (only new untracked `DATASET_CLEANUP_PLAN.md`;
  `results/` remains git-ignored and untracked).

## PHASE 8 — NO ML WORK

## Files affected

- Deleted: 7 directories under `results/datasets/` (see PHASE 6).
- Created: `DATASET_CLEANUP_PLAN.md`, `DATASET_CLEANUP_REPORT.md`.
- Modified: none (data and tracked files untouched). Nothing committed.

## References

- `V1_DATASET_CLEANUP_REPORT.md` (prior cleanup: evidence retention)
- `UI_DATASET_GENERATOR_V2_AUDIT.md` (v1 runs retained as evidence)
- `controller/test_live_features.py`, `controller/dataset_rebuild.py` (verify path)

---

## DATASET CLEANUP COMPLETE

Checklist:
- [x] PHASE 0: Dataset inventory complete (results/, all dirs inventoried).
- [x] PHASE 1: All datasets classified; UNKNOWN - REQUIRES REVIEW items NOT deleted.
- [x] PHASE 2: Both protected datasets verified (221430: 200/200; 003710: 100/100).
- [x] PHASE 3: No duplicate datasets found; protected pair confirmed independent.
- [x] PHASE 4: Stale/temporary/test candidates identified; safe set confirmed.
- [x] PHASE 5: `DATASET_CLEANUP_PLAN.md` created with explicit paths only.
- [x] PHASE 6: 7 confirmed failed/aborted runs deleted (no wildcards).
- [x] PHASE 7: Protected datasets intact (checksums + counts match), repo clean.
- [x] PHASE 8: No ML work performed; stop when complete.