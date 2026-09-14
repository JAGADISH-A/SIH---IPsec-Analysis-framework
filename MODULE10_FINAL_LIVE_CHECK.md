# MODULE10_FINAL_LIVE_CHECK.md

**Module 10 — live dataset failure diagnosis (REAL evidence; production code NOT modified, no restart, no rerun, no commit/push)**

## 1. Source code — verified real (4 independent greps, identical)
`controller/campaign.py:147`:
```python
reuse_mod.reset_and_deploy_or_reuse(mode, address_family)
```
Qualified seam call is present and correct — the OLD bare `NameError` (`reset_and_deploy_or_reuse` not defined) is **confirmed gone** from source. `grep -Rni "reset_and_deploy_or_reuse" controller/` → only the qualified call.

Current process freshness (STEP 4):
- uvicorn server started `Mon Sep 14 15:56:53 2026`.
- `controller/campaign.py` mtime `15:36:16` , `controller/reuse.py` mtime `13:48:34` — **both before server start** ⇒ the running worker is NOT stale; it loaded the fixed `campaign.py:147`.

## 2. Dataset run inspected (real on-disk evidence)
`results/datasets/dataset-20260914-155715/`
- `state.json`: `target_samples:2`, `successful_samples:0`, `failed_samples:5`, `interrupted_samples:0`, `status:"FAILED"`, `attempts_per_sequence:{1:5}`.
- 5 attempt dirs `attempt-01…05`, each with `failure.json` + `error.log`.

## 3. Exact failures (attempts 01–05, all identical)
| Attempt | reason | error | stage |
|---|---|---|---|
| 01 | TypeError | `'NoneType' object is not callable` | 1. topology deploy/reuse (seam) |
| 02 | TypeError | `'NoneType' object is not callable` | 1 |
| 03 | TypeError | `'NoneType' object is not callable` | 1 |
| 04 | TypeError | `'NoneType' object is not callable` | 1 |
| 05 | TypeError | `'NoneType' object is not callable` | 1 |

`failure.json` (attempt-01, full): `status FAILED`, `reason "TypeError"`, `error "'NoneType' object is not callable"`, `ipsec_configuration` = tunnel/ipv4, IKE aes256/sha256/modp2048, ESP aes128gcm16/modp4096 PFS true, `traffic_profile voip`, `security_posture STRONG`.

## 4. First failing stage
**Stage 1 — topology deploy/reuse decision** (`controller/reuse.py` `reset_and_deploy_or_reuse`, invoked at campaign.py:147). Nothing after it runs: no topology deploy, no config, no StrongSwan, no IKE/CHILD_SA, no ESP, no connectivity, no traffic, no capture, no features, no persistence.

## 5. Root cause (exact, real)
The seam `reset_and_deploy_or_reuse(..., mode_mod=None, fresh_fn=None, fresh_fn/mode_mod not supplied)` reaches its **fresh fallback branch** and executes `fresh_fn(mode)` where the supplied `fresh_fn` is **`None`** → `TypeError: 'NoneType' object is not callable`.

I.e. the Module-10 seam in `controller/reuse.py` does **not** default to the real fresh deploy (`mode_mod.reset_and_deploy`), it tries to call a `None` fallback callable. This is a **production-code defect in the reuse seam**, independent of the (now-fixed) `campaign.py:147` seam-call defect.

## 6. Classification
- **Production-code bug** (controller/reuse.py fresh-fallback path) — NOT testbed, NOT StrongSwan/IPsec/CONNECTIONS, NOT topology, NOT traffic/capture/features, NOT retry budget, NOT dataset semantics/timing, NOT stale process, NOT artifact persistence.
- Same root cause for **all 5 attempts** (identical TypeError).

## 7. Smallest justified fix (REPORT ONLY — NOT applied, per instruction)
In `controller/reuse.py`, the fresh fallback when `fresh_fn`/`mode_mod` absent must delegate to the real modal fresh deployment instead of `None(mode)` — e.g. require `mode_mod` and call `mode_mod.reset_and_deploy(mode)` (or raise a clear `RuntimeError` listing the missing provider). Exact seam body must be re-read before fixing; **not implemented here** to respect "diagnose only — do not modify".

## 8. Status
**FAIL** (live dataset-20260914-155715: 0/2; diagnosis complete; stop per instruction; no commit/push).
