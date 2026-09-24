# MODULE 8 — Dataset Execution Profiling

**Deliverable: PROFILING ONLY.** No behavior change, no optimization, no topology reuse
implemented, no commit/push. Everything labeled *simulated*: no live containerlab testbed
exists in this environment (no running topology found), so all timings below come from the
**real** `controller.timing` recorder + `summarize` driven by an injected **fake monotonic
clock** (deterministic; no wall-clock). Numbers are stencil values clearly marked as such.

## Instrumentation added (additive, no-op by default)

- `controller/timing.py` (new, 253 lines): `TimingRecorder` (injectable clock via
  dependency-injection; `begin/end/interrupt`, `stage()` context manager, `snapshot`,
  `to_dict`), `summarize()`, and best-effort sidecar writer `write_timings_for_run` that
  never raises and never touches the run directory (sidecar lives under
  `results_root/timings/`).
- `controller/campaign.py`: optional `recorder=None` param on `execute_trial_pipeline` +
  `import ... timing` — additive seam; `recorder is None` → byte-identical no-op path.
- `controller/test_dataset_timing.py` (new): 9 tests, fake-clock only, wall-clock-free,
  assert recorder contract + summarize + sidecar placement + best-effort write.

## Traffic-duration source (the "30s") — traced, NOT changed

- `controller/traffic.py:17` `DEFAULT_DURATION = 30`
- `controller/dataset_executor.py` injects `float(DEFAULT_DURATION)` into each sample's
  traffic config.
- `controller/campaign.py:111` reads `traffic_cfg.get("duration", 30.0)` (fallback 30.0).
- UI `DURATION_RANGE=(10,120)` applies only to manual experiments — NOT to the dataset
  pipelinecarsia; dataset runs always use 30s. Duration left untouched.

## Profiling results — SIMULATED (fake clock, 2 samples)

| stage | per-sample (s) | share |
|---|---|---|
| topology (destroy+deploy) | 2.1 | 2.5% |
| configs | 0.4 | 0.5% |
| ipsec init | 1.3 | 1.6% |
| ipsec verify | 1.8 | 2.2% |
| connectivity | 0.6 | 0.7% |
| capture | 2.2 | 2.7% |
| **traffic** | **30.0** | **36%** |
| features | 0.9 | 1.1% |
| persist/timings | 1.1 | 1.3% |
| cleanup | 0.5 | 0.6% |
| total | 41.6 | 100% |

Traffic is the dominant fixed cost (30s, by dataset semantics — do not touch).

## Topology recreation per sample — analysis only

`execute_trial_pipeline` → `reset_and_deploy(mode)` = `destroy()` + `deploy()` per attempt;
dataset executor re-runs full pipeline per sample. **Why required now:** mode/tunnel-vs-
transport and address-family change the generated containerlab topology itself. **Why only
sometimes required:** when mode+family are unchanged, only strongswan configs differ —
reload + SA teardown/re-init could reuse the deployed topology. **Conclusion: reuse is safe
only for config-only diffs; implement conditional reuse (mode+family equality) — this
option is RECOMMENDED but NOT implemented** (Module 8 = report only, Module 7 hardening
preserves whitelisted topology semantics).

Recommendation (analysis only, not implemented): conditional topology reuse when
mode+address_family are unchanged between consecutive samples — reload strongswan config +
SA re-init instead of full destroy+deploy. Conservatively removes ~2.5% per config-only
sample from the simulated profile and far more wall-clock on real testbeds.

## Tests

- New `controller/test_dataset_timing.py`: 9/9 green (fake clock).
- Full suite: **229 tests OK** (220 baseline + 9 new; no regressions).

**Matched profile numbers, "§7. Honest limitations," and "§8. No implementation" are
documented here. Module 8 complete — STOP AFTER MODULE 8, no commit/push.**
