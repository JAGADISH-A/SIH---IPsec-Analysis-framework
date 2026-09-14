# MODULE10_FIX_PLAN.md

Module 10 — NEW live run `dataset-20260914-155715` (5/5 attempts, `TypeError`) — diagnosis + smallest wiring fix (REPORT ONLY, NOT APPLIED; no commit/push).

## 1. Existing fresh deployment function (REAL, authoritative — controller/executor.py)
```python
def reset_and_deploy(self, mode):        # executor.py — the one true fresh deploy
```
- campaign.py imports it — authoritatively:
  - `campaign.py:30` `from .executor import ( ..., reset_and_deploy, ... )`
- It is the ONLY real fresh-deploy provider this project owns (StrongSwan/Containerlab live path).

## 2. How campaign invokes it today (REAL)
- campaign.py:30 imports `reset_and_deploy` (bare name bound from `.executor`).
- The historical module-9 fresh path calls `reset_and_deploy(mode)` — same call the executor tests exercise (41/41 green).
- New module-10 campaign reaches **campaign.py:147**:
  ```python
  reuse_mod.reset_and_deploy_or_reuse(mode, address_family)
  ```
  which does NOT pass the seam any provider.

## 3. Why `fresh_fn` is None (REAL, reuse.py seam body lines 144–172)
```python
144 def reset_and_deploy_or_reuse(mode, address_family, *, mode_mod=None,
145                             fresh_fn=None, recorder=None, log=None):
...
156     if mode_mod is None or fresh_fn is None:
157         fresh_fn(mode)          # <-- fresh_fn IS None → TypeError: 'NoneType' object is not callable
158         return {"reused": False, "identity": topology_identity(mode, address_family)}
```
- Seam default `fresh_fn=None`; campaign call passes nothing → `fresh_fn(mode)` = `None(mode)` → the exact 5-identical TypeError.
- Root cause is **integration wiring**: the seam's fresh fallback is never given the real existing fresh deployment (`executor.reset_and_deploy`).

## 4. Smallest correct production fix (wiring — does NOT touch reuse logic, does NOT weaken reuse, does NOT mocks, does NOT touch planner/traffic/dataset/featurization/capture)
At campaign.py:147, hand the seam its already-imported fresh deploy provider:
```python
reuse_mod.reset_and_deploy_or_reuse(
    mode, address_family, mode_mod=mode_mod, fresh_fn=reset_and_deploy,
)
```
(replace `147` bare-call with the seam call that binds `fresh_fn=reset_and_deploy` — the exact function campaign already imports at line 30 and already uses for fresh deploys; `mode_mod` remains the reuse-fresh module for the REUSE path.)

## 5. Files that would change (exact)
- `controller/campaign.py` — line 147 only (the seam call): pass `fresh_fn=reset_and_deploy`.

NOT changed: `controller/reuse.py`, `controller/executor.py`, `controller/campaign.py` other lines, executor/planner/dataset/traffic/capture/features/frontend/api/tests, retry budgets, traffic duration (30s), dataset semantics. NOT committed, NOT pushed.

## 6. Verification planned after authorization (NOT run)
- `controller/test_dataset_reuse_decision` (5 tests) + `controller/test_dataset_executor` (41) → expect green.
- One live `dataset-*` run target=2 → expect `successful_samples:2, failed_samples:0, status:COMPLETE`.

## 7. Status
**STOPPED after diagnosis; no code change, no restart, no rerun, no commit, no push.** Awaiting go-ahead.
