# ML Data Collection Report — Phase 3C

Date: 2026-09-23 · Branch `feature/testbed` · **Audit/preparation only.** No
production code/module was modified, no feature pipeline or schema was touched,
no new generator was written, no ML library was installed, no experiment was
run, and nothing was committed. The only new file is this report. No
`sudo`/containerlab/network command was attempted (interactive sudo required).

Context: `UI_DATASET_GENERATOR_V2_AUDIT.md` established that the UI dataset
generator is V2-COMPATIBLE (no separate legacy UI generator). This report
prepares the smallest legitimate real-traffic experiment matrix for the ML
phase, states exactly what an operator must run, and reports what currently
exists on disk.

---

## 1. Verdict summary

| Item | Status |
|---|---|
| Decoupled profile↔posture expressible by the existing planner? | **YES** for `target_samples >= 7` (emergent from two independent round-robins, not from any hard-coded shackling); **NO** for `n=5` (perfect 1:1 confounding in the canonical set). See §5. |
| Existing real data satisfying v2 + diversity? | **NO.** Only the canonical `dataset-20260916-231246` is v2 (n=5, perfectly confounded, 1 sample/class on both axes). All other `results/datasets/*` runs are v1-era (64- or 54-col feature vectors) and are not usable for v2 training. See §7. |
| New v2 runs required? | **YES** — require a human operator (sudo/lab). See §6 and the OPERATIONAL BLOCKER. |
| Planned matrix | 2 dataset runs × `target_samples=12` = **24 real captured samples**, 6 traffic classes × 5 posture bands, 12 (profile × posture) cells each observed in 2 independent runs. See §6. |

---

## 2. Scope & method

- Read: `controller/dataset_planner.py`, `controller/dataset_executor.py`,
  `controller/dataset_run.py`, `controller/campaign.py`, `controller/traffic.py`,
  `controller/dataset_api.py`, `controller/experiment_runner.py`,
  `controller/dataset_artifacts.py`, `controller/dataset_rebuild.py`,
  `controller/features.py`, `controller/live_features.py`, `controller/capture.py`,
  `controller/executor.py`, `SCHEMA.md`, `ML_IMPLEMENTATION_AUDIT.md`,
  `UI_DATASET_GENERATOR_V2_AUDIT.md`, `V1_DATASET_CLEANUP_REPORT.md`.
- Ran the safe 241-test suite (lab/sudo-bound `controller.test_dataset_executor`
  excluded) and the read-only canonical parity check — §9.
- Empirically enumerated the plan/pairing surface with the real planner
  (`build_sample_plan(n)` for `n` in {5,6,7,10,12,30}) — §5.
- Did **not** run any generation (each sample redeploys/reuses the shared
  containerlab topology and requires `sudo`: `controller/executor.py:70-108`,
  `controller/capture.py:60-145`, `controller/traffic.py:361-505`).

---

## 3. What the testbed can legitimately generate

### 3.1 Traffic classes

`controller/traffic.py:39` — six profiles, three of which the live XDP/WAN-side
feature path expresses through packet geometry (rate/size/burst), and one of
which is TCP payload DNA:

| Profile | Model (builtin, `traffic.py:138-161`) | ESP-layer signature |
|---|---|---|
| `voip` | udp, 50 pps, 160 B, constant | CBR small frames |
| `video` | udp, 250 pps, 1200 B, constant | CBR large frames |
| `messaging` | udp, 50 pps, 110 B, bursty (on1s/off3s) | bursty small |
| `email` | tcp, 2.5 pps, 8192 B, bursty (on1s/off1s), nagle off | bursty large TCP |
| `web` | tcp, 2.0 pps, 320 B, constant, nagle off | sparse TCP |
| `icmp` | `ping` 5 pps 32 B (`traffic.py:272-283`) | sparse ICMP → ESP/IPComp |

Duration range `(10, 120)` s (`traffic.py:41`), canonical `DEFAULT_DURATION=30`
(`traffic.py:40`), default port 20000 (`traffic.py:37`). Both `builtin`
(`scripts/trafficgen.py`) and `ditg` backends reproduce the same six profiles
(`traffic.py:56-134`); ICMP always uses `ping`.

### 3.2 IPsec configurations / posture bands

`controller/dataset_planner.py:119-170` enumerates 384 shape-compatible
candidates; `validate_config` accepts **192** (`accepted`) across the five
deterministic posture bands (`posture_of_config`, `dataset_planner.py:85-105`):

| Band | Score rule | Accepted configs (verified) |
|---|---|---|
| STRONG | >= 11 | 12 |
| GOOD   | 9–10  | 44 |
| MEDIUM | 6–8   | 52 |
| WEAK   | 4–5   | 48 |
| WORST  | == 3  | 36 |

Configuration axes: mode tunnel/transport, family ipv4/ipv6, ESP
aes128/256gcm16 + aes128/256cbc, integrity (GCM→none; CBC→sha256/384/512), DH
modp2048/3072/4096, PFS on/off (`dataset_planner.py:50-57`). IKE phase is a
fixed baseline (`dataset_planner.py:59-65`).

### 3.3 Labels

Ground truth labels are **not** derived from traffic. Each plan sample carries
`traffic_profile` and `security_posture` labels assigned by the planner
(`dataset_artifacts.py:431-466` `build_successful_record`); the finalization
validator cross-checks every staged record against the plan
(`dataset_artifacts.py:689-716`). So the class space the system can emit is
exactly: `{voip, video, messaging, email, web, icmp}` ×
`{STRONG, GOOD, MEDIUM, WEAK, WORST}` plus the fine-grained
`configuration_id`. Nothing else is inventable by the existing mechanism.

---

## 4. Existing dataset configuration (canonical run, inspected)

`results/datasets/dataset-20260916-231246` (the only v2 run):

- experiments: 5 (`target_samples=5`); state COMPLETED, 5/5 success, `attempt-01`
  each; `committed_run_ids` `/state.json`.
- plan (`staging/plan.json`): quota 1/profile for voip,video,messaging,email,web
  (icmp 0); `posture_planned` 1/band; `plan_fingerprint` pinned
  (state `0e2194f6…`).
- traffic per experiment: 30 s nominal (`traffic_model.duration` in metadata),
  port 20000, capture filter `udp port 500 or udp port 4500 or esp or ah`
  (`capture.py:33`) — the run-level defaults applied when `run_options=None`
  (`dataset_executor.py:241-288`, `experiment_runner.py:463-473`).
- output location: `results/datasets/<run_id>/` with `captures/000N/
  <experiment_id>.pcap`, `experiments/<id>/`, `staging/`, `features.parquet`,
  `metadata.jsonl`, `manifest.json`, `finalization.json`, `README.txt`.
- expected label per experiment = the plan sample's `traffic_profile` +
  `security_posture` (verified 5/5 in metadata + parity check §9).

---

## 5. Profile ↔ posture confounding — can the existing system decouple?

### 5.1 How plans are built (file:line evidence)

- `traffic_quota(target)` (`dataset_planner.py:173-180`) balances profiles to
  within 1; `profile_sequence` (`dataset_planner.py:183-196`) round-robins the
  profile sequence starting at index 0.
- Posture selection round-robins the non-empty posture bands, also starting at
  index 0 (`dataset_planner.py:222-225`); within a band the configuration
  cycles deterministically over that band's accepted catalogue
  (`dataset_planner.py:227-229`).
- There is **no explicit cross-item constraint** in `build_sample_plan`
  (`dataset_planner.py:199-272`) and no hard-coded binding of a profile to a
  posture. The observed pairing is purely the emergent result of two
  independent round-robin sequences with different periods (5 posture bands vs
  up-to-6 profiles) both starting at index 0. The README explicitly claims the
  axes are independent (`dataset_artifacts.py:779-791`), and the planner
  docstring states both axes are "independently varied" (`dataset_planner.py:7-10`).

### 5.2 Empirical pairing (run with the real planner, read-only)

`profile → postures` for increasing `target_samples`:

| target | voip | video | messaging | email | web | icmp | Fully decoupled? |
|---|---|---|---|---|---|---|---|
| 5 | STRONG | GOOD | MEDIUM | WEAK | WORST | — | **No — 1:1 confound** |
| 6 | STRONG | GOOD | MEDIUM | WEAK | WORST | STRONG | Partial |
| 7 | STRONG,GOOD | GOOD | MEDIUM | WEAK | WORST | STRONG | Partial (voip decoupled) |
| 10 | STRONG,GOOD | GOOD,MEDIUM | MEDIUM,WEAK | WEAK,WORST | WORST | STRONG | Partial (web/icmp single) |
| 12 | STRONG,GOOD | GOOD,MEDIUM | MEDIUM,WEAK | WEAK,WORST | STRONG,WORST | STRONG,GOOD | **Every profile ≥2 postures; every posture ≥2 profiles** |
| 30 | all 5 | all 5 | all 5 | all 5 | all 5 | all 5 | Full 6×5 crossing (1 obs/cell) |

So the existing system **can legitimately express "traffic A + posture X" and
"traffic A + posture Y" with the same profile** (and vice versa) — the smallest
target with full per-class decoupling on both axes is **12**. The n=5 confound
in the canonical set is an artifact of the small target, not a system
limitation.

### 5.3 Plan-authoring constraints (honest caveats)

- The only **supported** plan creators call `build_sample_plan(target)` and
  `write_sample_plan(...)` (`dataset_api.py:477-483` for the UI/API; no CLI
  exporter exists in `dataset_planner`/`dataset_run`). `build_sample_plan` is
  deterministic, so a given target always yields the *same* pair sequence.
- `validate_plan` (`dataset_executor.py:80-136`) is structural — it checks
  profile/posture/config validity, quota consistency and contiguous sequences,
  but **not** planner provenance; in principle a hand-written cross-product
  `plan.json` would pass. However, no supported entry point writes a
  non-planner plan, and the run is pinned to its plan by fingerprint on resume
  (`experiment_runner.py:96-110`, `dataset_api.py:550-567`). This report
  therefore designs around planner-derived plans only (no hand-crafted plan).
- Planner cannot express an arbitrary subset (e.g. "only STRONG×voip"): the
  plan is a deterministic function of `target_samples`. Its smallest decoupled
  size is 12.

---

## 6. Smallest legitimate experiment matrix (for the operator)

Rationale: (a) keep the canonical 30 s/sample, port 20000, default capture
filter; (b) use the planner-native route so no plan/measurement is hand-crafted;
(c) cover all 6 traffic classes and all 5 posture bands; (d) give every
profile ≥2 postures and every posture ≥2 profiles; (e) repeat the same 12
cells across **two independent runs** (independent run ids + experiment ids) so
a model cannot memorize an experiment id and each (profile × posture) cell has
2 real observations.

### 6.1 Matrix — posture × profile → # captures (2 runs × target 12)

| | voip | video | messaging | email | web | icmp | Σ |
|---|---|---|---|---|---|---|---|
| **STRONG** | 2 | — | — | — | 2 | 2 | 6 |
| **GOOD** | 2 | 2 | — | — | — | 2 | 6 |
| **MEDIUM** | — | 2 | 2 | — | — | — | 4 |
| **WEAK** | — | — | 2 | 2 | — | — | 4 |
| **WORST** | — | — | — | 2 | 2 | — | 4 |
| **Σ** | 4 | 4 | 4 | 4 | 4 | 4 | **24** |

Per-run pair sequence (deterministic planner output, `build_sample_plan(12)`):
`voip/STRONG, video/GOOD, messaging/MEDIUM, email/WEAK, web/WORST,
icmp/STRONG, voip/GOOD, video/MEDIUM, messaging/WEAK, email/WORST,
web/STRONG, icmp/GOOD`. Within each band the configuration cycles over that
band's accepted catalogue (12–52 configs/band), so same-band samples in one run
carry distinct `configuration_id`s. Each of the 12 cells is observed twice (one
per run), with different dataset_run_id / experiment_id / captured_at.

### 6.2 Run mode

Run mode **dataset-run** via the existing `execute_dataset_run` engine
(`dataset_executor.py:241-288`), the exact engine the 09-16 canonical run used.
Duration 30 s/sample (canonical default), port 20000, capture filter default
`udp port 500 or udp port 4500 or esp or ah` (`capture.py:33`). The API worker
additionally finalizes on COMPLETED (`dataset_api.py:298-306`); per-sample
evidence is preserved as in the canonical run (§8).

### 6.3 Exact operator commands

**Route A — UI/API (recommended; creates run + plan, executes, finalizes).**
While the FastAPI app (`controller.api:app`, mounted via
`controller/api.py:43-49`) is running, POST twice **sequentially** (the shared
`TESTBED_LOCK` forbids concurrency — `dataset_api.py:64-69,461-474`):

```bash
curl -s -X POST http://127.0.0.1:8000/dataset-runs \
     -H 'Content-Type: application/json' -d '{"target_samples": 12}'
# -> {"dataset_run_id": "dataset-<TS1>", ...}   (poll GET /dataset-runs/<id> until
#    status=COMPLETED and finalization.status=COMPLETED, then POST a second,
#    identical request for run 2)
curl -s -X POST http://127.0.0.1:8000/dataset-runs \
     -H 'Content-Type: application/json' -d '{"target_samples": 12}'
```

(`target=12 <= DATASET_MAX_TARGET_SAMPLES=1000` ceiling, `dataset_api.py:67-69,453-462`.)

**Route B — CLI (same engine; run dir + plan must be pre-created; finalization
is NOT automatic for the CLI per `UI_DATASET_GENERATOR_V2_AUDIT.md` §5):**

```bash
.venv/bin/python -c "from controller import dataset_run as d, dataset_planner as p; \
r=d.create_dataset_run('results',12); p.write_sample_plan('results',r.id,p.build_sample_plan(12)); print(r.id)"
.venv/bin/python -m controller.dataset_executor <dataset_run_id>
.venv/bin/python -c "from controller import dataset_artifacts as a; a.finalize_dataset('results','<dataset_run_id>')"
```

Repeat for the second run (new id). **Neither route can be executed from this
shell** — both deploy/reuse the containerlab topology and run privileged
traffic/capture (§2, OPERATIONAL BLOCKER).

Timing estimate: the canonical 5-sample run spanned ~3.4 min ≈ 41 s/sample
(`captured_at` deltas in `metadata.jsonl`); 12 samples ≈ 8–9 min, so the two
runs ≈ 17–18 min plus the first sample's fresh deploy.

---

## 7. Existing real data inventory (as-is)

| Artifact | Feature schema | Rows | Usable for v2 training? |
|---|---|---|---|
| `results/datasets/dataset-20260916-231246` (canonical) | **v2 / 59** | 5 | Only existing real v2 data — **not sufficient** (perfect profile↔posture confound, 1 sample/class, no split possible; `ML_IMPLEMENTATION_AUDIT.md:195-201`) |
| `results/datasets/acc-eng-01` | v1 / 64 | 6 | No (v1-era) |
| `results/datasets/acc-eng-02` | v1 / 64 | 2 | No (v1-era) |
| `results/datasets/dataset-20260913-235839` | v1 / 54 | 2 | No (v1-era) |
| `results/datasets/dataset-20260914-202956` | v1 / 54 | 2 | No (v1-era) |
| `results/datasets/dataset-20260914-225751` | v1 / 54 | 2 | No (v1-era) |
| `results/datasets/dataset-20260914-235105` | v1 / 54 | 2 | No (v1-era) |
| `results/datasets/dataset-20260915-113002` | v1 / 54 | 2 | No (v1-era) |
| `results/datasets/dataset-20260916-122639` | v1 / 64, **stale**, never finalized | 2 | No (v1-era + no parquet/metadata/finalization) |
| `results/dataset/` (legacy Module-1 aggregate) | pre-schema flat CSV, 70 cols = 16 ID/metadata + **54** features; no `feature_schema_version` | 40 | No (not a v2 artifact; see `V1_DATASET_CLEANUP_REPORT.md:62,75-79`) |

Verified column counts and `feature_schema_version` per run by reading each
run's `metadata.jsonl`/`staging/successful_samples.jsonl` (read-only). No
current code path emits v1 features (`UI_DATASET_GENERATOR_V2_AUDIT.md` §9-11).

Canonical class distribution (reproduced from `metadata.jsonl`): traffic
`{voip:1, video:1, messaging:1, email:1, web:1}` (icmp:0), posture
`{STRONG:1, GOOD:1, MEDIUM:1, WEAK:1, WORST:1}`; pairs are the diagonal
voip/STRONG … web/WORST — **confirming the 1-profile-per-posture confound**.
All samples tunnel/ipv4, IKEv2, 30 s, single capture point
`192.168.100.1`/gw-a (`ML_IMPLEMENTATION_AUDIT.md:202-206`).

**Conclusion: existing real v2 data is the n=5 canonical set only — new
v2 runs are required, and they require the operator (sudo/lab).**

---

## 8. Preservation / evidence expectations (per run)

What the executor preserves for each new run (mirrors the canonical run):

- **Experiment identity & commit**: `<run>/state.json` —
  `dataset_run_id`, per-sequence counters, `committed_run_ids`
  (`<run>-exp-<NNNN>-attempt-<NN>`), `plan_fingerprint`, timestamps
  (`experiment_runner.py:81-110,610-627`; `dataset_run.py:46-83`).
- **PCAP evidence**: `<run>/captures/<seq>/<experiment_id>.pcap` — copied at the
  commit boundary by the Module-5 collector (`dataset_artifacts.py:478-542`,
  path at `:517-522`); referenced by `pcap_path` in every metadata record.
- **Per-experiment provenance**: `<run>/experiments/<experiment_id>/` with
  `metadata.json`, `features.json`, `traffic.log`, `capture.pcap`
  (`experiment_runner.py:381-391`).
- **Campaign/plan identity**: `<run>/staging/plan.json` (planner version,
  quota, posture_planned, per-sample profile/posture/config) + pinned
  fingerprint.
- **Classified labels + metadata**: `metadata.jsonl` (per record:
  `feature_schema_version=v2`, 59 `features`, `traffic_profile`,
  `security_posture`, `configuration_id`, flattened+nested ipsec config,
  `traffic_model`, `captured_at`, `pcap_path`) — `dataset_artifacts.py:431-466`.
- **Materialized dataset**: `features.parquet` (10 linkage + 59 feature cols),
  `finalization.json`, `README.txt`, `manifest.json`
  (`dataset_artifacts.py:563-588,591-604,757-802,821-878`).
- **Failures**: `<run>/failures/<experiment_id>/` including partial captures
  (`experiment_runner.py:394-445`) — failed/interrupted attempts never enter the
  dataset (`validate_runtime_state`, `dataset_artifacts.py:9-18,611-750`).

---

## 9. Validate-run checklist (for the operator, AFTER generation)

The operator should run each of these after the two runs complete; this shell
will not run them against new data (nothing new exists yet).

```
# per run (exit 0 for both):
.venv/bin/python -m controller.dataset_rebuild --run-id <dataset_run_id> --verify-only
#   -> "OK: N/N records match the live v2 feature path"
# then confirm on-disk invariants (they are enforced by
# controller/dataset_artifacts.py validate_final_dataset :611-750 and
# controller/test_dataset_artifacts.py :413-459):
#   - metadata.jsonl: every record feature_schema_version == "v2"
#   - features: exactly 59 keys == FEATURE_COLUMNS; no NaN/Inf
#     (normalize_feature_record rejects non-finite, :377-408)
#   - finalization.json status COMPLETED, parquet_rows == metadata_records == 24
#   - staging/plan.json <-> state.json plan_fingerprint match; committed_run_ids
#     cover sequences 1..12 in both runs
#   - per-record posture/profile/config == plan sample (validate_final_dataset
#     cross-checks), pcap_path file exists under captures/000N/
#   - class counts: traffic 4/profile, posture STRONG6 GOOD6 MEDIUM4 WEAK4 WORST4
#     per the matrix in §6.1
```

---

## 10. Windowing — as implemented (reported, not changed)

Current artifacts emit **ONE 59-feature record per epoch/sample**, with the
statistics restricted to the densest `nominal_duration`-sized window
(`features.py:319-341` `_densest_window`, applied at `features.py:399-403`),
and carry 100 ms-aligned `window_start_ns`/`window_end_ns` geometry as
observation bounds (`live_features.py:205-216,232-237`; `SCHEMA.md:114-139`).
The architecture's per-100-ms-window row feed (sparse, mostly all-zero rows —
one v2 record per 100 ms window) is an **open policy item**, not an
implementation gap (`ML_IMPLEMENTATION_AUDIT.md` §11 ambiguity 2, :514-520;
`ML_LAYER_AUDIT.md:95-99`). This report does not change the windowing.

---

## 11. Limitations / ambiguities

- No new runs were executed (lab/sudo-bound). Everything about the planned runs
  is derived from the shared code path plus the canonical persisted ground
  truth; the two planned runs are not yet on disk (executed = 0 pending
  operator).
- Planner determinism: two runs with the same target produce the *same*
  (profile, posture, configuration_id) plan sequence; cross-run variation is the
  run/experiment ids + real capture timestamps/traffic, not the plan. Each cell
  is captured twice with the same configuration_id per sequence. To vary the
  paired configuration per repeat an operator would run a different target (e.g.
  12 + 13), not modeled here — marked as a design choice, not a defect.
- No supported CLI exists to create a run directory + plan (only the API does
  it in-band, `dataset_api.py:477-483`); the CLI route above therefore uses a
  one-liner calling the same Module 1/2 functions.
- A hand-written (non-planner) `plan.json` would pass `validate_plan`, but no
  supported entry point writes one and resumes are fingerprint-pinned; the
  smallest-legitimate design deliberately avoids hand-authored plans.
- No ML libraries present in `.venv` (no numpy/scipy/scikit-learn); none were
  installed. The dataset itself needs no ML dependency.

---

## 12. Tests

Safe, non-lab suite (as specified; `controller.test_dataset_executor` excluded —
one test drives real `reset_and_deploy`/`destroy`):

```
.venv/bin/python -m unittest controller.test_features controller.test_live_features controller.test_dataset_artifacts ebpf.test_window_aggregator ebpf.test_state_builder controller.test_dataset_planner controller.test_dataset_run controller.test_dataset_reuse controller.test_dataset_reuse_decision controller.test_generator controller.test_dataset_timing controller.test_ipsec_events controller.test_audit controller.test_config

Ran 241 tests in 2.968s

OK
```

Read-only canonical verification re-run during this audit:

```
.venv/bin/python -m controller.dataset_rebuild --run-id dataset-20260916-231246 --verify-only
OK: 5/5 records match the live v2 feature path   (exit 0)
```

---

## OPERATIONAL BLOCKER

```
THIS SHELL CANNOT PERFORM PRIVILEGED LAB EXECUTION (sudo -n fails: "interactive
authentication is required"); generating the 24 real v2 samples requires a human
operator with sudo/lab access to run the prepared commands (§6.3):
POST /dataset-runs {"target_samples": 12} twice, sequentially, then the §9
verify-report checks.
```

The single precondition that unblocks generation is a **human operator with
privileged access** executing the §6.3 route A (or B) — the machine otherwise
lacks the containerlab/network-namespace/capture privileges (`sudo`) required
by `controller/executor.py:70-108`, `controller/capture.py:60-145`, and
`controller/traffic.py:361-505`. Until then, executed new v2 samples = 0; the
planned matrix and evidence paths above are ready for that operator verbatim.