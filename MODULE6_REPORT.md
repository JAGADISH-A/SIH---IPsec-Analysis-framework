# Module 6: Dataset Run API — Final Report

**Status:** Complete | **Tests:** 39 Module 6 tests | **Total suite:** 220 tests, 0 failures

## Required Items

### 1. HTTP endpoints
| Method | Path | Purpose |
|---|---|---|
| `POST`   | `/dataset-runs`                      | Create and start a dataset run with the user-supplied target |
| `GET`    | `/dataset-runs/settings`             | Return the configured safety maximum target |
| `GET`    | `/dataset-runs/{dataset_run_id}`     | Persisted state + success-based progress |
| `POST`   | `/dataset-runs/{dataset_run_id}/resume` | Resume a PAUSED run; COMPLETED is a no-op |
| `GET`    | `/dataset-runs/{dataset_run_id}/results` | Lightweight results summary (never the full feature table) |

All routes are registered by `create_dataset_router()` and included in the main
`controller.api` app (`openapi()` exposes all five).

### 2. Request schema — the exact target is the contract
`DatasetTargetRequest` is a strict pydantic model (`ConfigDict(strict=True)`):
- `target_samples: int` with `gt=0`.
- Booleans, floats (`1.5`), and strings (`"500"`) are **rejected** with HTTP 422
  (strict mode + an explicit boolean validator).
- The number flows **unchanged** through the stack: `DatasetRun(target_samples=N)`
  → plan with exactly N logical samples → execution until N successful samples →
  finalization with N feature rows. There is **no default, clamp, rounding or
  reinterpretation** anywhere in the module.

Proof of end-to-end preservation (test suite):
- `test_exact_two_successful_samples` — target=2 yields exactly 2 committed
  samples, 2 staged records, 2 Parquet rows, `committed_samples == 2`.
- `test_target500_flow_unchanged` — target=500: `state["target_samples"] == 500`,
  `plan["target_samples"] == 500`, `len(plan["samples"]) == 500`, the Module 2
  traffic quota is preserved (`voip == 84`).
- `test_requested_target_is_preserved_exactly` / `test_plan_length_equals_requested_target`
  — 137 in → 137 plan slots, 137 successes, `successful_samples == 137`.

### 3. Safety maximum — reject, never shrink
- `maximum_target_samples` comes from `DATASET_MAX_TARGET_SAMPLES` (default `1000`).
- Requests **above** the maximum → HTTP 422 with a detail mentioning the ceiling;
  requests at the boundary are accepted; the stored target always equals the
  request.
- `GET /dataset-runs/settings` returns `{"maximum_target_samples": N}` so a
  frontend can validate before posting.

### 4. Background architecture (HTTP never blocks)
- `POST /dataset-runs` validates, reserves the testbed, persists the run + plan,
  then returns `201` with the initial status **immediately**; execution runs on a
  dedicated worker thread in the same process (matching the manual experiment
  API). `resume` spawns a worker the same way.
- The worker runs Module 3/4 `execute_dataset_run(...)` (with the Module 5
  `collector_fn`), then Module 5 `finalize_dataset` when the run completed.
  Progress is therefore observable while the run executes.

### 5. Single active run + no overlap with the manual experiment API
- A shared reservation registry (`controller/testbed_lock.py`, `TestbedLock`)
  with kinds `EXPERIMENT` / `DATASET` and the module singleton `TESTBED_LOCK` is
  used by **both** this runner and the manual experiment API
  (`controller/api.py`).
- A dataset run holds the lock from creation until the worker has fully finished
  (including finalization); all other dataset/experiment requests get **409**
  while it is active (`test_dataset_run_conflicts_with_another_active_dataset_run`,
  `test_dataset_blocked_while_manual_experiment_active`,
  `test_manual_experiment_blocked_while_dataset_active`).
- The lock is always released in a `finally` even when the worker raises.

### 6. Rapid duplicate POSTs → 409, never 500
- Run ids come from Module 1's `generate_dataset_run_id()` (format
  `dataset-%Y%m%d-%H%M%S`). That generator has **one-second resolution**, so two
  posts in the same second would produce the same id. Testing caught this: the
  original allocator looped forever on the identical string and raised 500.
- `_allocate_dataset_run_id` now walks backwards through distinct seconds, so the
  second POST collides at the **lock reservation**, which is taken *before* any
  run directory is created → deterministic `409` with a single on-disk run
  (`test_duplicate_start_requests_are_prevented`).

### 7. Resume semantics
- `COMPLETED` → `200` informational no-op with the existing final state; no new
  worker, no re-execution (`test_resume_complete_run_does_not_duplicate_execution`).
- `RUNNING` → `409` "already running", no second worker (`test_resume_running_run_does_not_start_second_worker`).
- `FAILED` → `409` mentioning the terminal status (`test_resume_failed_run_is_rejected`).
- `PAUSED`/`CREATED` → the stored `plan_fingerprint` is compared with the current
  `staging/plan.json`; a missing or altered plan → `400`
  (`test_resume_validates_plan_fingerprint`). Otherwise the lock is reserved and a
  new worker is spawned.

### 8. Progress is success-based only
`progress_percentage = successful_samples / target_samples * 100` (2 decimals),
where `successful_samples` is the count of **committed** successful samples.
Failed and interrupted attempts do not move progress and are surfaced as counts:
- `test_progress_is_success_based_not_attempt_based` — 1 attempt started, 0
  successes → `0.0%`.
- `test_progress_125_of_500_is_25_percent` / `test_progress_25_percent_at_125_of_500`
  — 124 and 125 successes → `24.8%` and `25.0%`.
- `test_failed_attempts_do_not_increase_progress` /
  `test_interrupted_attempts_do_not_increase_progress` — progress stays at 50%
  after a failed/interrupted attempt.

### 9. Traffic / posture handling — delegation, not reimplementation
- Per-record `traffic_profile` / `security_posture` and `ipsec_configuration`
  are carried in from the Module 2 plan by the DatasetRun; classification and
  allocation logic live in Modules 1/2; retry/cleanup in Modules 3/4;
  normalization/staging/finalization in Module 5. `dataset_api` delegates via
  module-attribute lookup, has no planner/executor/artifact logic of its own, and
  the delegation is pinned by tests
  (`test_api_does_not_reimplement_planner_logic`,
  `test_api_delegates_execution_to_the_executor`,
  `test_api_delegates_artifacts_to_dataset_artifacts`).
- `GET .../results` returns `traffic_distribution` and
  `security_posture_distribution` derived from Module 2 plan quotas (including
  zero-quota profiles), the `feature_row_count` from
  `pyarrow.parquet.read_metadata` (**never** `read_table`/full load), artifact
  paths, and finalization state
  (`test_results_exposes_traffic_distribution`,
  `test_results_exposes_posture_distribution`,
  `test_results_does_not_read_the_full_parquet`).

### 10. Persistence — file-backed, restart-safe
- State is persisted continuously to `state.json`; every read endpoint derives
  its payload from the persisted DatasetRun, never fabricated values
  (`test_get_existing_dataset_run_returns_persisted_state`,
  `test_dataset_run_target_samples_equals_request`).
- Unknown ids → `404`; unreadable/corrupt state → `500` and is never auto-repaired
  (`test_unknown_dataset_run_404`).
- No in-memory database; restart simply reads the existing run directories.

### 11. Concurrency notes found by the test suite
- Same-second duplicate posts (see §6) and worker/teardown races were both caught
  by tests: after observation of a terminal state, tests wait for the worker to
  fully finalize before removing a results root.
- Worker threads are joined/observed through the persisted state via polling
  helpers; the lock guarantees a single active execution even under interleaved
  gated runners (`HoldGate`).

### 12. Test suite and results
- `controller/test_dataset_api.py` — 39 new tests covering all items above.
- Modules 1–5 remain complete at 181 tests (dataset run, planner, executor/retry,
  controller API, dataset artifacts).
- Full suite: `python -m unittest discover -s controller -p "test_*.py"` →
  **220 tests, 0 failures**.

## Files Added / Modified
- `controller/dataset_api.py` — NEW: request/response models, `create_dataset_router`,
  worker, `_allocate_dataset_run_id`, status/results/settings payload builders.
- `controller/testbed_lock.py` — NEW: `TestbedLock` + `TESTBED_LOCK` singleton
  shared with the manual experiment API.
- `controller/api.py` — MODIFIED: includes the dataset router; manual experiment
  creation now reserves `TESTBED_LOCK` (409 on conflict) and releases in `finally`
  — existing manual API behaviour otherwise unchanged.
- `controller/test_dataset_api.py` — NEW: 39 Module 6 tests.

## Verification Notes
- No planner, executor, artifacts, posture-classification, or config-generation
  code was duplicated; the real Module 1–5 implementations were exercised through
  the API with a synthetic attempt/cleanup runner for deterministic outcomes.
- A live real-testbed run was **not** performed in this environment (no testbed
  reachable); end-to-end correctness is proven via the delegated real
  planner/executor/artifacts under deterministic synthetic execution,
  including target=2→2 (2 successes, 2 rows, 2 staged records) and
  target=500→500 (500 plan slots, 500 committed samples, preserved traffic
  quota).

## Limitations
- Workers are bound to the process that received the request (matching the manual
  experiment API); a multi-worker deployment would need the lock to become
  inter-process (e.g. file lock). Extra-run storage (captures/evidence on disk)
  remains on the control host as in Modules 1–5.
- The safety ceiling is enforced at the API layer only; a client on the same
  process could bypass it (not a threat model for this testbed).