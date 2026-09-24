# Module 4: Dataset Execution Hardening — Final Report

**Status:** Complete | **Tests:** 36 Module 4 tests | **Total suite:** 136 tests, 0 failures

## Required Items

### 1. Orphaned in-progress marker recovery
`_recover_orphaned_attempt()` detects `attempt_in_progress[seq] != 0` at sequence
entry (set from prior SIGKILL). The orphaned attempt number is consumed (budget
slots lost), its experiment directory preserved in `failures/`, and the marker is
cleared before the next fresh attempt begins. Attempt numbers are never reused.

### 2. Stale guard before attempt start
`_stale_guard()` checks `run.data["stale_sequence"]` / `stale_experiment` before
each new attempt. If set, it runs `_cleanup_attempt` on the stale experiment. If
re-cleanup fails → `PAUSED` with `"stale environment"` error. If it succeeds →
stale fields are cleared and execution proceeds normally.

### 3. Cleanup failure policy
`_cleanup_attempt()` wraps the cleanup function call. On exception: the cleanup
error is logged to `failures/<exp_id>/cleanup_error.log`, `stale_sequence` and
`stale_experiment` are recorded on the run, but the sample's outcome is never
changed. A failed cleanup does NOT mark the sample as failed; only the runner
outcome determines that.

### 4. Plan fingerprint (immutability)
`plan_fingerprint()` computes `sha256(json(plan, sort_keys=True))` of the staging
plan. On first RUNNING transition the fingerprint is persisted. On resume,
`execute_dataset_run` re-computes and compares; a mismatch, missing plan, or
corrupted JSON raises `ValueError` and the run is not touched.

### 5. Runtime state consistency validation
`validate_runtime_state()` is called at load time and before the COMPLETED
update. It enforces:
- `len(committed_run_ids) == successful_samples`
- Every committed ID parses as `<run_id>-exp-<seq>-attempt-<N>` with this run's
  experiment id
- Committed IDs are unique
- Committed sequence numbers are within `1..target_samples`

### 6. Attempt budget exhaustion handling
`max_attempts_per_sequence` is TOTAL per logical sequence, cumulative across
restarts, consumed at attempt start in `attempts_per_sequence[seq]`. Every
started attempt (FAILED, INTERRUPTED-outcome, KeyboardInterrupt/PAUSED, orphan)
consumes one slot. When exhausted the loop breaks immediately with
`"giving up after N attempts -> run FAILED"`.

### 7. Paused-resume semantics
When a run is PAUSED (cleanup failure, KeyboardInterrupt/SIGKILL, budget
exhaustion via interrupt), resume calls `execute_dataset_run` again. The loaded
state preserves all counters, committed ids, and stale markers. Sequences
already COMPLETED are skipped. Sequences with stale markers hit the stale guard.

### 8. Corrupted / missing plan handling
Missing plan → `ValueError`. Invalid JSON → `json.JSONDecodeError` (subclass of
`ValueError` raised by plan fingerprint check). Valid JSON with changed content
→ `ValueError` with `"plan has changed"` message. None of these touch run state.

### 9. Attempt-in-progress marker lifecycle
`_record_attempt_start()` sets `attempt_in_progress[seq] = attempt` BEFORE any
runner call. `_run_sequence` clears it to `0` after outcome recording. The
`_recover_orphaned_attempt()` function checks this marker at sequence entry and
cleans up if non-zero (orphaned SIGKILL case). This ensures a crashed attempt
is detectable on next load.

### 10. Monotonic attempt numbering
Attempt numbers are derived from `max(attempts_per_sequence.get(seq, 0)) + 1`
at each attempt start. They are never reused or decremented across restarts.
`attempts_per_sequence` is stored as JSON-safe string keys (`"1"`, `"2"`, ...)
and accessed via `str(seq)`.

### 11. Budget exhaustion recovery path
To continue a FAILED run after budget exhaustion, the operator must explicitly
pass a larger `max_attempts_per_sequence` value to `execute_dataset_run`. There
is no automatic escalation.

### 12. State consistency constraints
`validate_state()` enforces invariants at every `run.update()`:
- `successful_samples <= attempted_runs`
- `successful_samples <= target_samples`
- `failed_samples + interrupted_samples <= attempted_runs`
- Each counter is a non-negative integer
- `attempt_in_progress` is `None | dict{str: int}`
- `plan_fingerprint` is `None | str`
- `stale_sequence` is `None | int`
- `stale_experiment` is `None | str`

The execution engine components (`COUNTER_INCREMENTS` in `dataset_executor.py`)
maintain the exact partition `successful + failed + interrupted == attempted`
at every update, guaranteed by a unit test matrix covering all three outcomes.

### 13. cleanup_error.log artifact
On cleanup failure, `failures/<exp_id>/cleanup_error.log` is created with the
exception message and traceback. This exists independently of the main
`failure.log` written for runner-level failures.

### 14. Stale tracking fields on DatasetRun
`default_state` includes `stale_sequence` (`None`), `stale_experiment` (`None`),
`plan_fingerprint` (`None`). These are set by `_mark_stale()` (on cleanup
failure) and `execute_dataset_run()` (fingerprint persistence). They do not
alter the state machine beyond enabling the stale guard on resume.

### 15. Signal-interrupt handling
KeyboardInterrupt is caught inside the attempt loop. The runner outcome is set
to INTERRUPTED (`"interrupted"` status), the run is marked PAUSED, and the
attempt budget is consumed. On SIGKILL, the `attempt_in_progress` marker
detects the orphan on next load.

### 16. Stale environment blocks blind continuation
When stale is set and the stale guard's re-cleanup fails, the run is immediately
PAUSED and `_run_sequence` returns `False`. No new attempt is started. The
operator must manually intervene (clean up, adjust config) before resuming.

### 17. Fingerprint comparison at resume entry
`execute_dataset_run` recomputes the plan fingerprint at every call (not just
first RUNNING). After a prior RUNNING transition, any subsequent call validates
the plan matches the stored fingerprint before touching any counters or starting
any attempts.

## Files Modified
- `controller/dataset_run.py` — additive state fields + stronger `validate_state`
- `controller/dataset_executor.py` — `_run_sequence` / `execute_dataset_run` rewrite

## Files Added
- `controller/test_dataset_hardening.py` — 36 tests covering all 17 items
