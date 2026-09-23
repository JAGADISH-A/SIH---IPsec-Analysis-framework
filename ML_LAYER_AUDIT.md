# ML / AI Layer Audit — Phase 1

Date: 2026-09-23 · Branch `feature/testbed` @ `a3740c9` · Analysis only.

Scope of this phase: **audit only**. No code was modified, no model was
trained, no dependency was added and no design change was made. This document
states, for every ML-layer capability in the reference architecture, what
exists today in this repository run, backed by file/line evidence, and what
remains. It deliberately does not invent ML functionality that does not exist.

Classification labels used throughout: `IMPLEMENTED`, `PARTIALLY IMPLEMENTED`,
`MISSING`, `NOT REQUIRED`, `ENVIRONMENT-BLOCKED`.

---

## 1. Current ML architecture (as it actually exists)

The quoted authoritative `architecture.txt` does **not exist** in this
repository (`find . -name 'architecture*'` returns nothing). The de-facto
architecture must therefore be read from the code and the accepted boundary
documents, primarily `ML_CORRELATION_BOUNDARY.md`. What exists today:

```
gw-a WAN mirror (passive TAP, copy-only)
   |
   v  ebpf/xdp_monitor.c / xdp_monitor.bpf.c      (XDP classifier + ring buffer)
   |      per-packet event: {ts, type, src, dst, proto, len, spi, seq | sport, dport}
   |
   +--> ebpf/xdp_window_aggregator.py     100 ms windows  (monitoring geometry)
   |       window_aggr.jsonl
   +--> controller/live_features.py       LiveFeatureExtractor -> v2 59-col record
   |       windows.jsonl / features_record.jsonl   (inference-time feature bridge)
   +--> ebpf/ipsec_state_builder.py       observed-state (auditor input)
   |       state_events.jsonl / state_windows.jsonl
   |
   +--> (training side) controller/features.py  extract_features on stored PCAP
            -> dataset run finalization ->
            features.parquet + metadata.jsonl + captures/<seq>/*.pcap
```

The reference architecture's remaining stages — **ML/AI engine (traffic
classification + anomaly detection), scores, expected-vs-observed correlation,
risk, XAI** — are **not implemented on this branch**. Correlation is
implemented on the separate `feature/ai-classifier` / `feature/security-assessment`
branches and is explicitly out of scope for this repository run
(`ML_CORRELATION_BOUNDARY.md`; `E2E_VERIFICATION_REPORT.md` §3.12, §3.18.6).

The architectural principle that **ML output must never silently become
authoritative evidence** (correlation must rely on independent evidence) is
codified in `ML_CORRELATION_BOUNDARY.md` and reinforced by the state builder's
terminology discipline (`ebpf/ipsec_state_builder.py:14`).

## 2. What is already implemented (foundations, in scope on this branch)

| Capability | Status | Evidence |
|---|---|---|
| Passive WAN-side observation point (TAP/mirror) | `IMPLEMENTED` | topology + sensor image; `STATE_CONSTRUCTION_REPORT.md` §12 |
| XDP ingress classifier (protocol-level) | `IMPLEMENTED` | `ebpf/xdp_monitor.bpf.c`, `ebpf/xdp_monitor_common.h`, `ebpf/test_xdp_classifier.py` |
| 100 ms window aggregation | `IMPLEMENTED` | `ebpf/xdp_window_aggregator.py` |
| v2 feature extraction authority (59 cols) | `IMPLEMENTED` | `controller/features.py:374 summarize_capture`, `:469 extract_features` |
| Live (inference-time) v2 feature bridge | `IMPLEMENTED` | `controller/live_features.py:141 LiveFeatureExtractor` |
| Observed-IPsec-state construction | `IMPLEMENTED` | `ebpf/ipsec_state_builder.py` |
| Labeled dataset generator (training-data producer) | `IMPLEMENTED` | `controller/dataset_planner.py`, `dataset_executor.py`, `dataset_artifacts.py` |
| Dataset quality / aggregate reporting | `IMPLEMENTED` | `controller/quality.py` |
| Audit record engine (observations only) | `IMPLEMENTED` | `controller/audit.py`, `controller/ipsec_events.py` |

None of the above performs ML. Each module explicitly disclaims it
(`ebpf/xdp_window_aggregator.py:8-10`, `ebpf/ipsec_state_builder.py:14`,
`LIVE_V2_FEATURE_PIPELINE_REPORT.md` §1, `controller/dataset_artifacts.py` README
wording §"no ML").

## 3. Input contract (event → window → feature)

### 3.1 Per-packet XDP event (official input)
Schema: `ts` (kernel `bpf_ktime_get_ns`, monotonic, integer ns), `type` ∈
`IKE / IKE-NAT-T / ESP / AH / OTHER`, `src`/`dst` (outer IPv4), `proto`,
`len` (**L2** frame length `data_end - data`), `spi`/`seq` for ESP/AH,
`sport`/`dport` for UDP-class.
- Defined in `ebpf/xdp_monitor_common.h`/`xdp_monitor.bpf.c`; parsed by
  `ebpf/xdp_window_aggregator.py:167 PacketEvent` (+ `from_dict:182`), which also
  accepts numeric counter and alias encodings and degrades unknown types to
  `OTHER` (`normalize_event_type:131`).
- Real feed evidence: `results/observed-state/live_events_wan_side_new.jsonl`
  (212 events), `.../lab-verify-20260919-143813/lab_events.jsonl` (30 events).

### 3.2 100 ms windows
`window_index = ts // window_ns`; `WINDOW_SIZE_MS = 100`
(`xdp_window_aggregator.py:44-46,93`). Bounded-late reordering (`WINDOW_LOOKBACK`,
`events_dropped_late` counter) and explicit empty-window emission for silence
detection (`:48-61`). Real evidence: 205 / 199 / 1911 windows on the three
ground-truth captures; 171 windows on the live lab run; 2064 windows in the
recorded-feed smoke test.

### 3.3 v2 feature record (what ML would consume)
One 59-column record per epoch (or per windowed batch), `feature_schema_version
= "v2"`. Column names/types imported from `controller/dataset_artifacts.py`
(`FEATURE_COLUMNS:115`, `INT_FEATURES:182`); `assert_feature_keys` called on
every emitted record (`live_features.py:231`). Geometry fields
`window_start_ns`/`window_end_ns` are observation bounds, not features.
- All size features are **L3** (`ip_total`); live side converts `l3 = len - 14`
  (`live_features.py:87 ETHERNET_HEADER_BYTES = 14`; conversion at `:183`).
- Direction anchored to the capture point (`src == capture_ip` ⇒ outbound).
- IKE = UDP 500 + 4500 merged; AH/OTHER contribute to no feature column.
- No label, posture, provenance or plaintext inside `features`
  (`SCHEMA.md` §Live v2; `LIVE_V2_FEATURE_PIPELINE_REPORT.md` §10).

Status: `IMPLEMENTED` (epoch granularity with a `--emit-every` hook for
periodic batches; windowed/batched emission across seconds-to-minutes epochs is
the not-yet-deployed consumption policy).

## 4. Classification

Two distinct meanings, both audited:

- **Protocol-level classification** (what kind of packet was observed) —
  `IMPLEMENTED` by the XDP classifier + `PacketEvent.type` labels
  (`xdp_window_aggregator.py:107`). Caveat: classifier keys on outer **IPv4**
  only; IPv6-outer frames fall to `OTHER` (`E2E_VERIFICATION_REPORT.md` §3.13,
  §3.15). This is deterministic, not ML.
- **ML classification layer** (feature-vector → traffic class / posture /
  expected outcome) — `MISSING`. No model artifact, no training, no scoring,
  no inference call exists anywhere (`grep` for model/classifier/anomaly/
  inference across `controller/ ebpf/ scripts/ frontend/` finds only doc prose
  and non-ML uses such as the traffic-`model` profile and XDP-`classifier`).
- **Security-posture "bands"** (STRONG/GOOD/MEDIUM/WEAK/WORST) are produced by a
  **deterministic, config-only rule** (`dataset_planner.posture_of_config`), not
  by a learned classifier. They are the *labels* used to build training data,
  never a runtime verdict. Status for the layer "posture from traffic": `MISSING`;
  for the label generator: `IMPLEMENTED` (`DATASET_GENERATOR_ML_PIPELINE_REPORT.md`
  §8).

## 5. Anomaly detection

`MISSING`. Nothing computes an anomaly score, a deviation, a threshold breach or
a detection verdict. The state builder's `active`/`INACTIVE` (§7 of
`STATE_CONSTRUCTION_REPORT.md`) is descriptive observation with a configurable
timeout — explicitly **no alert, no detection**. The rekey SPI change is
recorded as an observed transition, not labelled anomalous
(`STATE_CONSTRUCTION_REPORT.md` §10). `quality.py` checks the *training dataset*
(NaN, negatives, frame mix, label agreement), not live traffic.

## 6. Dataset / training pipeline

### 6.1 Data production (ground truth)
`IMPLEMENTED`. Module 1-6: deterministic posture-aware plan
(`dataset_planner.py`), run state machine (`dataset_run.py`), execution with
attempt/failure semantics (`dataset_executor.py`), staging + finalization
(`dataset_artifacts.py`). Final artifacts: `features.parquet` (10 linkage + 59
feature cols = 69), `metadata.jsonl`, per-sequence PCAP evidence, `manifest.json`,
`finalization.json`. Ground-truth labels come from the Module 2 plan sample,
never recalculated from traffic (no leakage; `SCHEMA.md` §metadata; `dataset_
artifacts.py:411 build_successful_record`).

Completed real runs under `results/datasets/`: 9 datasets. The canonical
ground-truth run is `dataset-20260916-231246` (5/5 samples, all five posture
bands, voip/video/messaging/email/web) and `acc-eng-02` (2, transport/ipv6,
GOOD). Feature rows are deterministic and byte-reproducible from their PCAPs
(`DATASET_GENERATOR_ML_PIPELINE_REPORT.md` §9 — re-extraction reproduces
64/64 v1 keys exactly on all 5 stored samples).

### 6.2 Schema versioning drift (audit finding)
The stored completed artifact `dataset-20260916-231246` was finalized at
`feature_schema_version = "v1"` (64 columns, includes the five IKE
exchange/version columns). The current code contract is **v2 = 59 columns**
(`dataset_artifacts.py:84,115`; `features.py` emits no v1 IKE-exchange fields).
Code and docs are aligned on v2; the on-disk ground-truth data predates the
migration. `assert_feature_keys()` and the finalization validator
(`dataset_artifacts.py:238,672`) now *enforce* v2, so a new run (or a
`--rebuild` of the aggregate via `quality.py:315`) is required before the
training set carries the v2 rows the live bridge produces. A v2 end-to-end
synthetic finalize was already proven (69-column parquet, no removed columns —
`DATASET_GENERATOR_ML_PIPELINE_REPORT.md` §6). Status: `PARTIALLY IMPLEMENTED`
(schema migrated in code+tests; stored dataset not yet regenerated in v2).

### 6.3 Model training
`MISSING`. Zero model fitting, selection, hyper-parameter, evaluation or
checkpointing exists. `LIVE_V2_FEATURE_PIPELINE_REPORT.md` §1 explicitly: "No
ML: zero model training, selection or scoring."

## 7. Runtime inference

`MISSING` (for a model). The **feature-side** of inference-time is in place:
`LiveFeatureExtractor` turns the live XDP event stream into the exact v2 record
the training extractor would produce (`summarize_capture` is the single shared
implementation of the math — `features.py:374`, `live_features.py:220`).
However, no model is loaded, scored or serialized, and there is no inference
endpoint or daemon. Real-feed smoke evidence exists
(`LIVE_V2_FEATURE_PIPELINE_REPORT.md` §14: 212 events → 196 feature frames,
192 ESP + 4 IKE-NAT-T → one valid v2 record).

## 8. ML output / MLL record

No MLL record format exists (no score, verdict, confidence, explanation or
classification outputs and hence no schema for them). The only "outputs" today
that a future ML layer will consume are:
- `features_record.jsonl` (v2 feature input; `SCHEMA.md` §Live v2),
- observed-state snapshots (`ipsec_state_builder.snapshot`, §7 states).

Both are **inputs/observations**, not verdicts. Status: `MISSING` for the MLL
layer; `IMPLEMENTED` for its input documents.

## 9. ML → correlation boundary

Documented authoritatively in `ML_CORRELATION_BOUNDARY.md`:
- The 100-ms window layer is observable-only (no ESP payload decode) and
  contains no policy, no detection and no verdicts.
- Correlation ("expected plan + observed → reconcile") is implemented on a
  **separate branch** and is out of scope for this repository run
  (`E2E_VERIFICATION_REPORT.md` §3.12/§3.18.6).
- Rule preserved: ML output is non-authoritative; correlation uses independent
  evidence (the observed-state builder is documented as "the input to a future
  expected-vs-observed layer" — `ipsec_state_builder.py:14`, `STATE_CONSTRUCTION_
  REPORT.md` §4).

On this branch the correlation layer is `MISSING` by explicit scope; the
boundary contract is `IMPLEMENTED`. The wiring from a future MLL output into
the correlation layer has no placeholder beyond the documented input contract.

## 10. Tests / evidence

All evidence reproduced and green during this audit:

| Suite | Tests | Status |
|---|---:|---|
| `ebpf.test_window_aggregator` | 19 | OK |
| `ebpf.test_state_builder` | 25 | OK |
| `controller.test_features` | 8 | OK |
| `controller.test_live_features` | 15 | OK |
| `controller.test_dataset_artifacts` | 52 | OK |
| **Subtotal (feature/window/state core)** | **119** | **OK** |
| dataset-generator regression (planner/run/reuse/generator/timing/ipsec_events/audit/config/… ) | 98 | OK |

- Offline/live parity is pinned by `controller/test_live_features.py`: events
  reconstructed from the real 8-frame fixture and from **all five real captures
  of the completed run**, asserting exact equality across all 59 features.
- No ML-model tests exist and none can exist: there is no model or inference
  code to test. Test coverage therefore ends at the feature/state boundary —
  exactly as intended on this branch.
- Real-lab runtime evidence: `results/observed-state/` (live events/windows/
  state, pre-rekey/full/wan-side), `lab-verify-20260919-143813/` (30-event live
  run incl. rekey: 22 ESP, 4 IKE-NAT-T, 4 OTHER; state snapshot lists 4 SPIs),
  `results/e2e-verification/` (transport v4/v6).
- Full `unittest discover` stalls on lab-bound modules (pre-existing harness
  limitation); suites are run by module. `ENVIRONMENT-BLOCKED` for the discover
  harness, not for the target code.

## 11. ML dependencies

`requirements.txt` (runtime, Python 3.14.4 venv):
`fastapi==0.141.1`, `pydantic==2.13.5`, `pyarrow==25.0.1`, `uvicorn==0.52.4`.

- `pyarrow` is present for parquet materialization of *datasets* (not ML).
- Verified `.venv/bin/pip freeze`: **no** numpy, pandas, scikit-learn, torch,
  tensorflow, joblib, onnx or any model runtime.
- Consequence: even a trivial model (e.g. scikit-learn) cannot be imported
  today. The reference architecture's ML engine is therefore
  `ENVIRONMENT-BLOCKED` (and, independently, `MISSING` in code) — adding ML
  packages is a deliberate, separately-approved dependency decision, out of
  scope for this audit phase.

## 12. Dashboard / downstream consumers

- Frontend (`frontend/index.html`, `frontend/app.js`, 1,484 lines) consumes
  exactly two API groups: manual experiments (`/experiments`...) and dataset
  runs (`/datasets-runs`...). `grep` of all `fetch(`/URLs in `app.js`: only
  `EXPERIMENTS_URL`, `CONFIGS_URL`, `DATASETS_URL`, `DATASET_SETTINGS_URL`,
  `HEALTH_URL`. There are **no** endpoints, cards or calls for windows, feature
  records, observed state, scores, classifications or anomalies.
- `classifyError()` at `app.js:535` is HTTP-error classification, not ML.
- Backend API (`controller/api.py`, `dataset_api.py`) exposes manual experiment
  orchestration and dataset-run CRUD/progress/results/download only. No ML/cor
  relation endpoint. `NOT REQUIRED` today; `MISSING` for any future ML surface.

## 13. Gap matrix

| Layer / capability | Status (this branch) | Evidence |
|---|---|---|
| Passive WAN mirror + XDP observer | `IMPLEMENTED` | topology, `xdp_monitor.*`, observed-state evidence |
| Protocol classification (ESP/IKE/AH/OTHER, IPv4-outer) | `IMPLEMENTED` | `xdp_monitor.bpf.c`, `PacketEvent` |
| IPv6-outer classification | `PARTIALLY IMPLEMENTED` | IPv6 → `OTHER` (`E2E` §3.13); offline parser v6 fixed (§3.18.1) |
| 100 ms window aggregation | `IMPLEMENTED` | `xdp_window_aggregator.py`, 3 captures + live |
| 59-col v2 feature authority | `IMPLEMENTED` | `features.py:summarize_capture`, tests |
| Live v2 feature bridge | `IMPLEMENTED` | `live_features.py`, lab-verify evidence |
| Windowed/periodic batch emission policy | `PARTIALLY IMPLEMENTED` | epoch mode + `--emit-every`; no deployed consumer |
| Observed-state construction | `IMPLEMENTED` | `ipsec_state_builder.py` |
| Dataset generator (training-data producer) | `IMPLEMENTED` | planner/executor/artifacts + 9 runs |
| v2 training dataset on disk | `PARTIALLY IMPLEMENTED` | stored ground-truth run is v1 (64-col); v2 synthetic finalize proven |
| Traffic/posture ML classification | `MISSING` | no model/inference anywhere |
| Anomaly detection | `MISSING` | no score/rule/detector |
| Risk / security scoring (runtime) | `MISSING` | only deterministic config posture labels exist |
| Expected-vs-observed correlation | `MISSING` (separate branch) | `ML_CORRELATION_BOUNDARY.md`; excluded by scope |
| XAI / explanations | `MISSING` | `state_builder.py:14` disclaims |
| MLL output schema | `MISSING` | no verdict/output record exists |
| ML dependencies | `ENVIRONMENT-BLOCKED` | reqs = fastapi/pydantic/pyarrow/uvicorn only |
| ML model tests / evaluation | `MISSING` | no model to test |
| Dashboard ML surface | `MISSING` | frontend consumes experiments + dataset-runs only |
| `architecture.txt` mentioned by reference | `MISSING` | file absent; de-facto arch = `ML_CORRELATION_BOUNDARY.md` |

## 14. Exact remaining work (next milestones)

1. **Regenerate the v2 training set.** Re-run dataset generation (or
   `quality.py --rebuild`) so `features.parquet`/`metadata.jsonl` are at
   `feature_schema_version = v2` (59 cols) and match the live bridge schema
   column-for-column. Target ≥ 25 samples for per-posture class balance
   (`DATASET_GENERATOR_ML_PIPELINE_REPORT.md` §13).
2. **Deploy the live consumer policy.** Choose epoch/windowed batch emission for
   the live `LiveFeatureExtractor` (e.g. aligned to generator runs via
   `--emit-every`) so feature records are produced continuously, not only on a
   single epoch (open item in `LIVE_V2_FEATURE_PIPELINE_REPORT.md` §15).
3. **Define the MLL record contract** (score/verdict + confidence + evidence
   provenance) before writing any model, so the output never claims authority
   over independent audit evidence.
4. **Add the ML engine** (approved dependency + training/eval on the v2 set +
   inference over the live feature bridge). Only then can classification /
   anomaly detection exist.
5. **Correlation**: on its separate branch already; merge/integrate under the
   boundary contract with observed-state and MLL as inputs (never MLL as sole
   authority).
6. **XAI / explanations and dashboard surfaces** for whatever the ML layer
   emits.

## 15. Recommended implementation order

Phase boundaries should preserve the "observable first, verdict last, evidence
independent" rule:

1. v2 training-dataset regeneration (unblocks data quality) — dataset layer.
2. Live feature-batch emission policy — bridge layer.
3. MLL output contract (schema + non-authoritativeness) — design doc/contract.
4. ML engine (deps + training + scoring on live bridge) —
   classification/anomaly.
5. Correlation layer merge from separate branch — reconciles MLL + state.
6. Risk + XAI + dashboard — presentation/explanation layer.

---

### Phase-1 summary

This repository run today delivers the entire *observation-to-input* stack for a
future ML layer — XDP events, 100 ms windows, 59-column v2 features (offline and
live, structural parity), observed state, and a labeled dataset generator — all
deterministic, all tested, none of it ML. The ML engine, anomaly detection,
runtime risk scoring, correlation (on a separate branch), XAI and any ML
dashboard surface are `MISSING`; ML dependencies are `ENVIRONMENT-BLOCKED`.
Phase 1 ends here with no repository changes.