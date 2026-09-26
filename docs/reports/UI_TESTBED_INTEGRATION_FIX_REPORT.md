# UI Testbed Integration Fix Report

- Date: 2026-09-23
- Scope: integration fix so the existing UI dataset-generation workflow
  (`POST /dataset-runs`) reliably reaches the real IPsec testbed, plus error
  propagation so a failed deployment is never reported as success.  No ML, no
  new generator, no observation-layer change, no feature/schema change.

## 1. Root cause of the `br-wan` failure

The tunnel topology (`topology/tunnel/ipsec.clab.yml:56-87`) declares `br-wan`
as a `kind: bridge` node.  Containerlab does **not** create externally-managed
root-namespace bridges (it only enslaves endpoints to them) and refuses to
recreate them on reconcile.  The project's authoritative lifecycle
(`scripts/deploy-ipsec.sh`, invoked by `scripts/run.sh`) is explicit about
this (deploy-ipsec.sh:9-38): `br-wan` must exist in the root netns *before*
`containerlab deploy`, and the wrapper creates it deterministically
(`ensure_bridge`, deploy-ipsec.sh:51-58) and removes it only once it has no
remaining members (deploy-ipsec.sh:96-111).

The backend dataset path **bypassed that lifecycle**: `controller/executor.py`
`deploy()`/`destroy()` called `sudo containerlab deploy/destroy` directly on
the topology file (old executor.py:70-92).  The raw `containerlab deploy` then
failed with:

```
ERROR
Bridge "br-wan" referenced in topology but does not exist
```

`run.sh`/manual deployment worked beforehand only because the wrapper created
`br-wan`; the UI/API path never went through it.

### Existing intended bridge/topology lifecycle (unchanged by this fix)

| Concern | Where the project defines it |
|---|---|
| `br-wan` is externally managed, must pre-exist | `scripts/deploy-ipsec.sh:9-38`, `README.md:31-37,53` |
| Create bridge deterministically/idempotently | `ensure_bridge`, `scripts/deploy-ipsec.sh:51-58` |
| Deploy with `--reconfigure` (containerlab >= 0.79) | `scripts/deploy-ipsec.sh:23-37,64` |
| GW-A observation health-check after deploy | `scripts/deploy-ipsec.sh:65-84` |
| Transport topology has no external bridge | `topology/transport/ipsec.clab.yml` (direct veth links) |
| Cleanup removes bridge only when memberless | `scripts/deploy-ipsec.sh:96-111` |
| Observation point (GW-A eth2 mirror -> audit-tap0 + eth3 -> sensor) | `topology/tunnel/ipsec.clab.yml:15-38,59-65,89-92`, `scripts/gw-entrypoint.sh`, `scripts/audit-tap-setup.sh` |

## 2. Files changed

- `controller/executor.py`
  - Added `FatalTopologyError(RuntimeError)` (non-retryable infrastructure failure).
  - `deploy(mode)` and `destroy(mode)` now route **tunnel** through the
    authoritative lifecycle wrapper
    (`sudo bash scripts/deploy-ipsec.sh deploy|destroy`), which ensures
    `br-wan` before deploy.  **transport** keeps the raw containerlab calls
    (no external bridge).
  - `deploy()` failure is re-raised as `FatalTopologyError` with the real
    diagnostic.
  - `run()` now includes the captured stderr (tail) in the raised `RuntimeError`,
    so the actual failure surfaces instead of the generic
    "Command failed with exit code 1".
- `controller/dataset_executor.py`
  - `run_attempt` maps `FatalTopologyError` to a FAILED outcome marked
    `"fatal": True` with the actual error.
- `controller/experiment_runner.py`
  - `_run_sequence` honors a fatal outcome: it marks the run FAILED with the
    actual error and returns immediately ("EXHAUSTED") instead of burning the
    remaining per-sequence attempt budget on the same doomed deployment.
- `controller/test_executor.py` (new) — mocked unit tests for the lifecycle
  routing, stderr-in-error, and fatal mapping.
- `controller/test_experiment_runner.py` — added `test_fatal_outcome_stops_run_after_one_attempt`.
- No frontend change was required: `frontend/app.js:993-1000` already renders
  the backend `error` on FAILED runs; the UI never treats `201` as success.

### Observation architecture preserved (verified unchanged)

- eBPF/XDP tap and observation point: not moved; GW-A remains the
  authoritative observation point (`deploy-ipsec.sh` even health-checks the
  eth2 mirred filters after deploy).
- GW-A/GW-B semantics, transport topology, PCAP evidence path, and the
  v2 / 59-feature pipeline: untouched.

## 3. Exact execution path after the fix

```
Browser UI
  -> POST /dataset-runs {"target_samples": N}            (frontend/app.js:8; controller/dataset_api.py:441)
  -> background worker _run_dataset_worker               (dataset_api.py:283)
  -> execute_dataset_run                                 (dataset_executor.py:241; experiment_runner.execute_repeated_run)
  -> per sample: campaign_mod.execute_trial_pipeline     (campaign.py:109)
       -> reuse_mod.reset_and_deploy_or_reuse            (reuse.py)
       -> fresh path: reset_and_deploy(mode)             (executor.py)
            tunnel: destroy via deploy-ipsec.sh destroy  (executor.py destroy)
            tunnel: deploy via deploy-ipsec.sh deploy    (executor.py deploy)
                     -> ensure_bridge  (creates br-wan if absent, idempotent)
                     -> containerlab deploy --reconfigure -t topology/tunnel/ipsec.clab.yml
                     -> GW-A observation health-check
  -> swanctl load/initiate/verify (IKE ESTABLISHED, CHILD INSTALLED)
  -> connectivity probe -> trafficgen -> capture (IKE+ESP pcap in gw-a)
  -> features.extract_features -> summarize_capture -> v2/59 feature record
  -> collector stages sample -> finalize_dataset          (dataset_artifacts.py)
```

## 4. Privileged-command handling

- The privileged model is unchanged: `sudo` is prepended to each host command
  (executor.py), matching the project's documented sudo-based deploy model
  (`scripts/run.sh:73`, `scripts/install.sh`).  The backend is **not** expected
  to run as root.
- containerlab 0.79.0 and `scripts/deploy-ipsec.sh` (executable, `bash -n`
  clean) are present on the host.
- Exit codes are checked in `run()` (returncode != 0 -> raise).  Errors from
  privileged commands now propagate with their stderr, so `sudo` failures /
  a non-interactive-sudo hang would surface as a FAILED run rather than a
  silent/bogus success.
- `deploy-ipsec.sh` uses `set -euo pipefail`, so a bridge-creation failure
  (e.g. missing CAP_NET_ADMIN) aborts before containerlab and the run records
  the actual reason.

## 5. Error / retry behavior

Before (observed on `dataset-20260923-185633`): the run created a plan,
then burned all **5 attempts for sequence 1** on the same doomed deploy
(`attempted_runs=5`, `failed_samples=5`, `status=FAILED`), and the persisted
error was the generic `Command failed with exit code 1` — the real
"Bridge br-wan ..." diagnostic never reached the run error, the UI, or the
failure logs.

After: a deployment failure is a `FatalTopologyError`; `run_attempt` returns a
fatal FAILED outcome; `_run_sequence` records it, marks the run FAILED with the
actual diagnostic, and stops — exactly one attempt for the sequence, no
retries.  The failure is persisted (`failures/<exp>/failure.json` + `error.log`),
surfaced via `GET /dataset-runs/{id}` (status + `error`), and rendered by the
UI banner (`frontend/app.js:993-1000`).  A `201 Created` on POST means "run
accepted"; the run's final status always reflects the deployment outcome.

## 6. Regression results

- `controller.test_executor` (new): OK
- `controller.test_experiment_runner`: includes new fatal-outcome test — OK
- 277 fast-safe tests (baseline 241 + new): `Ran 277 tests in 1.270s OK`
- `controller.test_dataset_api`: `Ran 51 tests in 115.731s OK`
- `controller.test_traffic` + `controller.test_zeek`: `Ran 45 tests in 1.138s OK`

(`controller.test_dataset_executor` remains lab/sudo-bound and is excluded by
design, as in prior reports.)

## 7. Verification of the single run (operator step)

The fix is code-verified and regression-tested, but this shell cannot execute
privileged lab commands (`sudo` is interactive-only here).  The mandated
end-to-end **single test run** must be performed by the operator:

```
# 1) ensure the FastAPI app is running (as the operator, with a sudo-capable
#    session that can run the lab):
cd /home/jagan/ipsec-testbed && .venv/bin/python -m uvicorn controller.api:app --host 0.0.0.0 --port 8000

# 2) one small run:
curl -s -X POST http://127.0.0.1:8000/dataset-runs -H 'Content-Type: application/json' \
     -d '{"target_samples": 1}'

# 3) poll until terminal state:
curl -s http://127.0.0.1:8000/dataset-runs/<dataset_run_id>

# 4) verify artifacts (v2 / 59 features, live parity):
.venv/bin/python -m controller.dataset_rebuild --run-id <dataset_run_id> --verify-only
```

Expected on success: deploy succeeds (br-wan present), GW-A/GW-B up,
GW-A observation mirror health-check passes, traffic generated, capture/PCAP
evidence produced, features v2/59 with 100-ms aligned window bounds,
finalization COMPLETED, UI badge shows the actual final state.

Expected on infra failure (e.g. sudo/lab genuinely unavailable): FAILED after
one attempt with the real diagnostic, no retries, UI shows it.

## 8. Command for the subsequent 12-sample collection

Run only after the single test run above passes end-to-end:

```
# Run 1 (12 samples)   -- wait for status=COMPLETED AND finalization COMPLETED
curl -s -X POST http://127.0.0.1:8000/dataset-runs -H 'Content-Type: application/json' \
     -d '{"target_samples": 12}'
# Run 2 (12 samples)   -- separate run id, executes after Run 1 completes
curl -s -X POST http://127.0.0.1:8000/dataset-runs -H 'Content-Type: application/json' \
     -d '{"target_samples": 12}'
# Validate each run
.venv/bin/python -m controller.dataset_rebuild --run-id <run_1_id> --verify-only
.venv/bin/python -m controller.dataset_rebuild --run-id <run_2_id> --verify-only
```

## 9. Evidence paths

- Per run: `results/datasets/<run>/captures/NNNN/<experiment_id>.pcap`
- Per committed sample: `results/datasets/<run>/experiments/<experiment_id>/{metadata.json, features.json, traffic.log, capture.pcap}`
- Per failure: `results/datasets/<run>/failures/<experiment_id>/{failure.json, error.log, partial/}`
- Final artifacts: `features.parquet`, `metadata.jsonl`, `staging/successful_samples.jsonl`, `finalization.json`

## 10. Constraints respected

- No second topology, second dataset generator, or alternate observation path.
- No ML, no feature/schema change, no correlation/risk/XAI/audit/policy change.
- Nothing committed.