# Dataset Cleanup Plan

- Date: 2026-09-24
- Scope: Remove confirmed failed/aborted dataset generation runs only. Preserve the
  two protected datasets and everything referenced by code, tests, or documentation.
  No ML work. Nothing is committed.

## Deletion candidates (exact paths, no wildcards)

Each candidate is a generation run that produced **0 successful samples**, contains
**no** `features.parquet`, `metadata.jsonl`, or `.pcap` captures, and is **referenced
nowhere** (code, tests, config, docs). All failed with the environment error
`sudo: interactive authentication is required` (not a data issue).

| # | Path | state.json status | attempted / failed | Reason |
|---|---|---|---|---|
| 1 | `results/datasets/dataset-20260923-193806` | RUNNING | 0 / 0 | aborted run; only manifest/plan/state, no attempts |
| 2 | `results/datasets/dataset-20260923-194108` | FAILED | 1 / 1 | failed generation, no samples |
| 3 | `results/datasets/dataset-20260923-202750` | FAILED | 1 / 1 | failed generation, no samples |
| 4 | `results/datasets/dataset-20260923-202956` | FAILED | 1 / 1 | failed generation, no samples |
| 5 | `results/datasets/dataset-20260923-203424` | FAILED | 1 / 1 | failed generation, no samples |
| 6 | `results/datasets/dataset-20260923-203457` | FAILED | 1 / 1 | failed generation, no samples |
| 7 | `results/datasets/dataset-20260923-203853` | FAILED | 1 / 1 | failed generation, no samples |

Commands (explicit paths only):

```
rm -rf \
  results/datasets/dataset-20260923-193806 \
  results/datasets/dataset-20260923-194108 \
  results/datasets/dataset-20260923-202750 \
  results/datasets/dataset-20260923-202956 \
  results/datasets/dataset-20260923-203424 \
  results/datasets/dataset-20260923-203457 \
  results/datasets/dataset-20260923-203853
```

## Recognized but NOT deleted (with reason)

| Path | Why kept |
|---|---|
| `results/datasets/dataset-20260923-221430` | **Protected dataset #1** (200 samples, FINALIZED, v2 features). Never modify/delete. |
| `results/datasets/dataset-20260924-003710` | **Protected dataset #2** (100 samples, FINALIZED, v2 features). Never modify/delete. |
| `results/datasets/dataset-20260916-231246` | Canonical v2 dataset; required by `controller/test_live_features.py`, `controller/test_features.py`, `controller/dataset_rebuild.py`, and 12+ reports. |
| `results/datasets/dataset-20260923-185633` | Failed run but referenced by `UI_TESTBED_INTEGRATION_FIX_REPORT.md` as diagnostic evidence. UNKNOWN - REQUIRES REVIEW. |
| `results/datasets/dataset-20260923-214502` | COMPLETED 3-sample run with valid final artifacts; unused but not stale. UNKNOWN - REQUIRES REVIEW. |
| `results/datasets/acc-eng-01`, `acc-eng-02`, `dataset-20260913-235839`, `dataset-20260914-202956`, `dataset-20260914-225751`, `dataset-20260914-235105`, `dataset-20260915-113002`, `dataset-20260916-122639` | Retained as evidence per `V1_DATASET_CLEANUP_REPORT.md` ("other valid datasets", hard constraint: do not delete). |
| `results/dataset/` (singular) | Legacy Module-1 aggregate, actively appended by `controller/dataset.py::append_aggregate` (wired via `campaign.py`/`quality.py`/`experiment_runner.py`). |
| `results/*-exp-*` campaign dirs | Legacy campaign experiment outputs referenced by `campaign-*.json` configs and `ACCEPTANCE_REPORT.md`/`E2E_VERIFICATION_REPORT.md`. Out of dataset scope; leave alone. |
| `results/e2e-verification/`, `results/audit/`, `results/observed-state/` | Non-dataset artifacts; out of scope. |

## Post-cleanup verification

1. `test -e` both protected dataset dirs.
2. Re-run `sha256sum` on protected dataset artifacts and compare to pre-cleanup
   baseline (recorded 2026-09-24).
3. Verify `metadata.jsonl` count (200 / 100) and `features.parquet` row count
   (200 / 100) unchanged.
4. Re-run dataset inventory listing `results/datasets`.
5. Confirm `git status --short` clean (git ignores `results/`).