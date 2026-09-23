# ML Implementation Audit — Phase 2 (implementation-readiness)

Date: 2026-09-23 · Branch `feature/testbed` @ `a3740c9` · **Audit only.** No code
was modified (one new file: this report), no model was trained, no synthetic
data was created, no feature/schema change was made, no CI/lab run was
executed, and nothing was committed.

Scope: the **ML / AI ENGINE only** as defined by the authoritative
architecture — i.e. **Traffic Type Classification** and **Anomaly Detection**
fed by the 100-ms-window feature boundary. Correlation is implemented on a
separate branch and is out of scope; Risk Engine, XAI, Audit, Response/Policy,
Analyst Approval, XDP Action and Dashboard are downstream and out of scope.

Status vocabulary used in this report: `IMPLEMENTED`, `PARTIALLY IMPLEMENTED`,
`MISSING`, `BLOCKED`, `OUT OF SCOPE` (as required by the audit brief).

---

## 1. Architecture mapping table

| Architecture component | Repository status |
|---|---|
| 100-ms Windows → ML input | `PARTIALLY IMPLEMENTED` |
| Traffic Type Classification | `MISSING` |
| Anomaly Detection | `MISSING` |
| ML output contract | `MISSING` |
| ML → Correlation boundary | `IMPLEMENTED` (contract) / `MISSING` (ML-output wiring) |

### Justifications (one line each)

| Component | Status | Justification |
|---|---|---|
| 100-ms Windows → ML input | `PARTIALLY IMPLEMENTED` | The exact 59-feature v2 input record exists, is produced deterministically by a single shared computation from both the offline and the live XDP path, and is parity-verified (structural parity); what is missing is the *deployed* per-100-ms-window feed policy that hands a window to the ML engine (epoch granularity with 100 ms-aligned geometry today) — see §2, §3. |
| Traffic Type Classification | `MISSING` | No classifier, classes, training, serialization, inference code, configuration or tests exist; the only "classification" is deterministic and non-ML (XDP packet-type labels; posture "bands" from a config rule) — see §4. |
| Anomaly Detection | `MISSING` | No detector, score, threshold, training, persistence or tests; "active/INACTIVE" in the state builder is a descriptive observation, explicitly not a detection — see §5. |
| ML output contract | `MISSING` | No MLL/output record schema exists anywhere (no score, verdict, confidence, predicted class, anomaly status, model version); only the *input* documents exist — see §6, §8. |
| ML → Correlation boundary | `IMPLEMENTED` (contract) / `MISSING` (wiring) | The hand-off contract is documented and enforced as "observable-only, non-authoritative, independent evidence" (`ML_CORRELATION_BOUNDARY.md`); the concrete ML-output→correlation wiring has no placeholder — see §9. |

### File/name mapping note

The brief references `ebpf/window_aggregator.py` and `ebpf/state_builder.py`;
the actual modules are `ebpf/xdp_window_aggregator.py` and
`ebpf/ipsec_state_builder.py` (same responsibilities; citations below use the
real names).

---

## 2. Section findings

### 1) ML input boundary — `PARTIALLY IMPLEMENTED`

Trace: IPsec state engine is **out of scope** for features (no v2 feature
depends on SPI/seq/state; `controller/live_features.py:43-49`) → parser/feature
engine → 100-ms windows → ML input.

- Window geometry: `WINDOW_SIZE_MS = 100`, `window_index = ts // window_ns`
  (`ebpf/xdp_window_aggregator.py:40-46,93`). Window records carry
  `window_start_ns` / `window_end_ns` / `window_duration_ms` and raw counts
  (`ebpf/xdp_window_aggregator.py:297-321`) — this is *monitoring geometry*, not
  the ML feature vector.
- The ML input record is the **v2 59-feature record** produced by
  `controller/live_features.py` (`snapshot()` at :228-237) and by the training
  pipeline `controller/features.py::extract_features` (:469-511). Both call the
  **single shared computation** `summarize_capture` (`controller/features.py:
  374-466`; single-source-of-truth documented at `controller/live_features.py:
  17-23`).
- Schema authority: `controller/dataset_artifacts.py` — `FEATURE_COLUMNS`
  (59, ordered; :115-175), `INT_FEATURES` (17; :182-191), `FLOAT_FEATURES` (42;
  :193), `FEATURE_KEYS` (:194), `FEATURE_SCHEMA_VERSION = "v2"` (:84),
  `PARQUET_ID_COLUMNS` (10 linkage; :201-212), `PARQUET_SCHEMA` (10 + 59 = 69
  columns; :214-218).
- Enforced on every emitted live record by `assert_feature_keys`
  (`controller/live_features.py:231`; impl `controller/dataset_artifacts.py:
  238-247`) and by `normalize_feature_record` at finalization (:391-408).
- Exact input object the ML engine would receive (per 100 ms-aligned epoch):

  ```json
  {"feature_schema_version":"v2","window_start_ns":<int>,"window_end_ns":<int>,
   "features":{<59 columns, 17 int + 42 float>}}
  ```
  (`SCHEMA.md:114-155`; `controller/live_features.py:228-237`).

- Feature ordering: the **contractual ordering is `FEATURE_COLUMNS`** — it is
  the parquet column order (`controller/dataset_artifacts.py:214-218`; verified
  against the canonical `features.parquet`). The live `features` dict is built
  in `summarize_capture` insertion order (`controller/features.py:434-466`),
  and `metadata.jsonl` keys are JSON-sorted (`sort_keys=True`,
  `controller/dataset_artifacts.py:313`, :595). Runtime validation is
  set-based (`assert_feature_keys`), so ordering is guaranteed only at the
  parquet boundary; an ML consumer must key by column name, never by position
  (ambiguity noted in §11).
- Types: int32 for 17 features, float64 for 42 (`controller/dataset_artifacts.
  py:214-217`), enforced by `_require_int`/`_require_float` (:365-388).
- Timestamp semantics: live `ts` is kernel `bpf_ktime_get_ns` monotonic ns
  (`ebpf/xdp_window_aggregator.py:29-30`); windows expose aligned `window_start_
  ns`/`window_end_ns` boundaries (`controller/live_features.py:205-216`);
  offline PCAP timestamps are epoch seconds converted to ns in the parity
  harness (`controller/live_features.py:116-138`). The shared math consumes
  `(ts_s, incl_len, l3_len, src, dst)` — numerical parity is exact at emitted
  precision (`LIVE_V2_FEATURE_PIPELINE_REPORT.md:217-241`).
- L2→L3 conversion (`len − 14`) at the live boundary
  (`controller/live_features.py:87,178-190`).
- **Train/inference representation parity: yes** — same `summarize_capture`
  on both sides; verified byte-exact for all 5 canonical captures by
  `controller/dataset_rebuild.py::verify_live_parity` (:170-229) and by
  `controller/test_live_features.py` (:204-232).
- **Gap**: the task calls for "100-ms WINDOWS → ML input", but the feature
  record is emitted per *epoch* (one record spanning the epoch's aligned 100 ms
  boundaries; `--emit-every N` at event-count granularity,
  `controller/live_features.py:275-302`). A guarantee that every 100 ms window
  produces *exactly one* ML-input record is not implemented or tested
  (`LIVE_V2_FEATURE_PIPELINE_REPORT.md:172-184`; `ML_LAYER_AUDIT.md:284-285`).
  This is the "PARTIALLY IMPLEMENTED" component of this row.

### 2) Traffic Type Classification — `MISSING`

No classifier exists. Grep of `controller/`, `ebpf/`, `scripts/`,
`frontend/` for `classif|model|anomaly|predict|score` returns only:

- XDP **protocol**-type labels (ESP/IKE/AH/OTHER) — deterministic, non-ML
  (`ebpf/xdp_window_aggregator.py:107-145`; `ebpf/test_xdp_classifier.py`).
- Security-posture "bands" = deterministic config rule `posture_of_config`
  (`controller/dataset_planner.py:86-105`), used only as **training labels**
  (`ML_LAYER_AUDIT.md:125-130`).
- `traffic_model` in `controller/traffic.py` — the D-ITG/builtin generator
  *model description*, not an ML model (`controller/traffic.py:20-22,260-297`).
- `frontend/app.js:535 classifyError` — HTTP error classification.

No classifier implementation, no label/class set for the ML job, no training
code, no model serialization, no inference call, no classifier configuration,
no classifier tests. See also `ML_LAYER_AUDIT.md:113-130` (""feature-vector →
traffic class" — `MISSING`") and §10 (no model tests exist).

### 3) Anomaly Detection — `MISSING`

No detector exists. Nothing computes an anomaly score, a deviation, a
threshold breach or a detection verdict. The state builder's `active` /
`INACTIVE` is a descriptive observation with a configurable timeout, explicitly
not an alert or detection (`ebpf/ipsec_state_builder.py:14,78-85,328-333`;
`STATE_CONSTRUCTION_REPORT.md:114-119`); the rekey SPI change is recorded as an
observed transition, not labelled anomalous
(`STATE_CONSTRUCTION_REPORT.md:189-191`). `controller/quality.py` validates the
*training dataset*, not live traffic (`ML_LAYER_AUDIT.md:139-140`). No detector
implementation, methodology, score semantics, threshold configuration, model
persistence or tests. See also `ML_LAYER_AUDIT.md:132-140`.

### 4) ML output boundary — `MISSING` (see §8 for the field-by-field contract)

No ML output/MLL record exists. The only "outputs" a future ML layer can
consume are its *inputs*: `features_record.jsonl` (v2) and the observed-state
snapshots — both observations, never verdicts (`ML_LAYER_AUDIT.md:191-200`).
`controller/api.py` / `controller/dataset_api.py` expose no ML endpoint
(`ML_LAYER_AUDIT.md:270-272`). Minimum required outputs derived from the
architecture and existing contracts are enumerated in §8.

### 5) ML → Correlation boundary — contract `IMPLEMENTED`, ML-output wiring `MISSING`

`ML_CORRELATION_BOUNDARY.md:1-52` is the authoritative contract: the window /
feature layer is observable-only (no ESP payload decode, no policy, no
verdicts); correlation (expected plan + observed → reconcile) lives on a
**separate branch**; ML output must never become authoritative evidence — the
correlation layer consumes independent evidence (the observed-state builder is
"the input to a future expected-vs-observed layer",
`ebpf/ipsec_state_builder.py:5,14`). What the ML engine must expose so an
external correlation layer can consume it (retain, do not duplicate) is given
in §9. No ML engine exists to expose it, and no placeholder field exists in any
contract for the ML-output→correlation join (only the documented input
contract).

### 6) Training dataset (audit of the canonical run only)

Canonical: `results/datasets/dataset-20260916-231246` (re-finalized at v2;
`DATASET_V2_REGEN_VALIDATION_REPORT.md`).

- Rows: **5** (`features.parquet` 5×69; `metadata.jsonl` 5 records;
  `finalization.json` `parquet_rows=5`). Sequences 1..5, all `attempt-01`.
- Labels: `traffic_profile` voip/video/messaging/email/web (quota 1 each,
  `traffic_quota`; `staging/plan.json`); `security_posture`
  STRONG/GOOD/MEDIUM/WEAK/WORST (1 each, `posture_planned`). Both label axes
  have exactly **1 sample per class**.
- Feature schema: v2, 59 features; 17 int32 + 42 float64; all rows carry
  `feature_schema_version="v2"`; `feature_schema_version` linkage column all
  v2 (verified).
- Metadata: `dataset_schema_version=v1` (kept as a separate axis), full
  flattened + nested `ipsec_configuration`, `traffic_model`, `captured_at`
  ISO-8601, `pcap_path`, ground-truth labels (`SCHEMA.md:162-203`;
  `controller/dataset_artifacts.py:431-466`).
- Provenance: plan `planner_version=v1`, catalogue 384 candidates → 192
  accepted, `plan_fingerprint=0e2194f6…` pinned in `state.json`; every row
  has PCAP evidence under `captures/NNNN/` and is re-derivable from it
  (`controller/dataset_rebuild.py:66-83`).
- Leakage: labels come **only** from the Module 2 plan, never from traffic
  (`controller/dataset_artifacts.py:435-465`; `validate_final_dataset`
  posture/profile/config cross-checks :689-716). No label derives from the
  feature vector. **Confound:** each posture band is paired 1:1 with a distinct
  traffic profile (STRONG=voip … WORST=web), so at n=5 posture and profile are
  perfectly correlated — a model trained on these 5 rows cannot separate the
  two target axes.
- Train/validation/test suitability: **not suitable** — n=5 with 1 sample per
  class for both target axes; no usable split, no held-out set possible, no
  class diversity within a band.
- Real-data coverage: all 5 samples are tunnel/ipv4, IKEv2, single capture
  point (gw-a WAN `192.168.100.1`), single lab run (2026-09-16), all profiles
  at 30.0 s nominal duration. No transport/ipv6 in the canonical set (2
  transport/ipv6 samples exist in `acc-eng-02`, a separate v1-era run;
  `ML_LAYER_AUDIT.md:154-159`).

### 7) Determinism and reproducibility

- Deterministic **extraction**: single deterministic stdlib-only computation
  (`controller/features.py`, no numpy/random); offline↔live parity is exact at
  emitted precision (`LIVE_V2_FEATURE_PIPELINE_REPORT.md:217-241`); byte-
  reproducible v2 re-generation of all 5 rows from PCAPs
  (`controller/dataset_rebuild.py`; `DATASET_V2_REGEN_VALIDATION_REPORT.md:180-181`).
- Deterministic **plan/traffic generation**: planner is deliberately
  random-free (`controller/dataset_planner.py:14-15`;
  `controller/test_dataset_planner.py:303`); builtin/D-ITG traffic models carry
  fixed seeds and are deterministic (`controller/traffic.py:84-88,165-168`).
- **Dependency pinning exists for the current runtime** (`requirements.txt`:
  exact pins `fastapi==0.141.1`, `pydantic==2.13.5`, `pyarrow==25.0.1`,
  `uvicorn==0.52.4`), but **no ML dependency is present**.
- **Missing**: deterministic training (no seeded RNG / parameter-init policy),
  deterministic inference (no inference code), model versioning/identifier,
  serialized-model schema compatibility, and reproducibility of a training run
  (no training run exists). Noted in `ML_LAYER_AUDIT.md:175-178,247-259` and in
  the brief (LIVE report shows extraction determinism; training determinism
  would additionally require seeded RNG and pinned ML deps).

### 8) XAI boundary

XAI sits behind Risk Engine downstream of correlation — out of scope to
implement here. Audit conclusion: the current input contracts **already retain
everything a downstream XAI layer needs for attribution** — the full 59
per-feature values, `feature_schema_version`, and the 100 ms-aligned
`window_start_ns`/`window_end_ns` identity are materialized in every feature
record (`controller/live_features.py:228-237`) and training row
(`controller/dataset_artifacts.py:214-218`). A future ML output record must
therefore preserve/echo the input window identity and feature vector so an XAI
layer can attribute verdicts to features; nothing more is required of the ML
engine by the existing contracts (`ebpf/ipsec_state_builder.py:14` disclaims
XAI).

### 9) Dependencies

`requirements.txt` (runtime, Python 3.14.4): `fastapi==0.141.1`,
`pydantic==2.13.5`, `pyarrow==25.0.1`, `uvicorn==0.52.4` (`requirements.txt:1-6`).
`.venv/bin/pip freeze` confirms exactly these plus their transitive runtime
deps (starlette, anyio, h11, httpcore, httpx, pydantic_core, typing_extensions,
idna, click, certifi, typing-inspection, annotated-doc, annotated-types) —
**no numpy, pandas, scipy, scikit-learn, joblib, statsmodels, torch or any
model runtime**. Missing for the two ML functions (not installed; see §7 of the
deliverable for the list and §6).

### 10) Tests

Existing (all green, re-run this audit — 241 tests OK, see Verification):

- v2/59-feature input validation: `controller/test_dataset_artifacts.py:413`
  (`test_feature_schema_is_consistent`), `:425` (`test_mixed_type_corruption_is_
  rejected` — includes NaN and Inf), `:441` (`test_missing_or_extra_feature_is_
  rejected`), `:731` (`test_dataset_schema_version_is_present`),
  `controller/test_live_features.py:80-251` (schema, type citizenship, no-label
  leak, empty-epoch zero record, L2→L3, direction, parity, CLI),
  `controller/test_features.py:92` (v1 IKE-exchange columns are not ML features).
- Malformed windows/events: `ebpf/test_window_aggregator.py:271`
  (`test_iter_jsonl_events` — malformed/non-JSON lines skipped), window
  boundary and ordering tests (:148-257). Richer window-side edge cases exist in
  `ebpf/test_state_builder.py` (25 tests).
- Missing/wrong-schema handling at finalization: `controller/test_dataset_
  artifacts.py:553-603,704-746`.
- Deterministic plan/traffic: `controller/test_dataset_planner.py:303`,
  `controller/test_traffic.py:165`.

Missing (no code exists for them): classifier tests, anomaly detector tests,
deterministic-inference tests, ML input-record-per-100ms-window tests,
model/version-mismatch tests, ML output-contract tests, training-reproducibility
tests. (Consistent with `ML_LAYER_AUDIT.md:233-238`: "No ML-model tests exist
and none can exist: there is no model or inference code to test.")

---

## 3. ML input boundary (the exact representation training and inference share)

After a 100 ms-aligned observation period, the object an ML engine consumes is
one JSON record (per `controller/live_features.py:228-237`, `SCHEMA.md:114-155`):

```
{
  "feature_schema_version": "v2",          # dataset_artifacts.py:84
  "window_start_ns":  <int>,               # aligned (ts_first//100ms)*100ms
  "window_end_ns":    <int>,               # aligned ((ts_last//100ms)+1)*100ms
  "features": { <exactly the 59 FEATURE_COLUMNS in order dataset_artifacts.py:115-175> }
}
```

- **The 59 features** (17 int32 + 42 float64; `dataset_artifacts.py:182-193`),
  all L3-size-based ESP statistics plus a separate IKE block, produced by the
  one shared function `summarize_capture` (`features.py:374-466`), so offline
  training and live inference are **structurally identical**; byte-exact parity
  on all five canonical captures is pinned by `test_live_features.py:219` and
  `dataset_rebuild.py:170-229`.
- **Ordering**: contract order = `FEATURE_COLUMNS` (parquet order,
  `dataset_artifacts.py:214-218`); serialized JSON ordering varies (live dict
  insertion order, metadata keys JSON-sorted) — an ML consumer must address by
  column name.
- **Types**: int32 for the 17 `INT_FEATURES`, float64 for the 42 others;
  non-finite floats and mixed types are rejected at finalization
  (`normalize_feature_record`, `dataset_artifacts.py:365-408`).
- **Window identity**: `window_start_ns`/`window_end_ns` (100 ms-aligned
  geometry, both 0 for an empty epoch). No separate `window_id`/`window_index`
  field is emitted by any component (the aggregator computes an index internally
  only, `xdp_window_aggregator.py:40-41`).
- **Timestamp semantics**: kernel monotonic ns for live events, era PCAP
  seconds→ns for the offline path; only the 59 numeric features plus the integer
  geometry boundary are materialized — no wall-clock time inside the record.
- **Metadata accompanying a window**: only `feature_schema_version`,
  `window_start_ns`, `window_end_ns` (`LIVE_METADATA_KEYS`,
  `live_features.py:90`). Labels (posture/profile), config, `captured_at` and
  provenance exist only in the training artifacts (`PARQUET_ID_COLUMNS`,
  `metadata.jsonl`) and are never inside `features` (`SCHEMA.md:133-139`).
- **Train/inference parity**: yes — identical record by construction;
  parameter policy (e.g. `nominal_duration` densest-window, capture-IP
  direction anchor) must be carried identically at inference
  (`LIVE_V2_FEATURE_PIPELINE_REPORT.md:131,172-184`).

---

## 4. ML output contract (only what the contracts already imply; missing ones listed)

Classified per the audit brief (explicitly defined / implemented / implied /
missing). **No ML output record exists today** (`ML_LAYER_AUDIT.md:191-200`).

**Explicitly defined + implemented (input-side fields the ML output may echo):**

| Field | Status | Evidence |
|---|---|---|
| `feature_schema_version` | IMPLEMENTED | `dataset_artifacts.py:84`; emitted in live records `live_features.py:233` |
| `window_start_ns` / `window_end_ns` | IMPLEMENTED | `live_features.py:205-216,232-237`; window aggregator `xdp_window_aggregator.py:297-321` |
| 59 features (names + types) | IMPLEMENTED | `dataset_artifacts.py:115-193` |
| `captured_at` (wall-clock ISO) | IMPLEMENTED (dataset side only) | `dataset_artifacts.py:460` (`build_successful_record`) — not part of the live input record |
| ground-truth `traffic_profile` / `security_posture` | IMPLEMENTED (dataset labels only) | `PARQUET_ID_COLUMNS` `dataset_artifacts.py:206-207`; metadata `build_successful_record` |

**Implied by existing contracts (retained requirement; not yet a field):**

- **Echo of the window identity + schema version in every ML output** so an
  external correlator can join the verdict to the exact 100 ms window and to the
  observed-state record (boundary contract: the correlator consumes window
  records + features; `ML_CORRELATION_BOUNDARY.md:8-21,38-44`).
- **Non-authoritative ML output**: the architecture and the boundary contract
  require that ML output be usable by correlation as one independent input, not
  as authoritative IPsec state (`ML_CORRELATION_BOUNDARY.md:33-44`;
  `ML_LAYER_AUDIT.md:48-51,204-213`).

**Missing (required by the ML engine per the architecture, absent from the repo):**

| Field | Status | Why required |
|---|---|---|
| predicted traffic type / class | MISSING | architecture: ML = Traffic Type Classification (§4) |
| classification confidence / probability | MISSING | no contract defines it; only recommended in `ML_LAYER_AUDIT.md:310` (score/verdict + confidence). Classify as **missing**, not implied |
| anomaly status (normal/anomalous) | MISSING | architecture: ML = Anomaly Detection (§5) |
| anomaly score | MISSING | no score semantics defined anywhere; only recommended (`ML_LAYER_AUDIT.md:310`) — **missing** |
| anomaly threshold & detector config | MISSING | no threshold/parameter surface exists |
| model / version identifier | MISSING | no model, no version axis; reproducibility requires it (§7) |
| ML output schema version | MISSING | no MLL schema exists (`ML_LAYER_AUDIT.md:293`) |
| ML output record format (per-window verdict JSON) | MISSING | no format/serialization defined; only the input JSONL exists |
| window ID beyond geometry bounds | MISSING | no `window_id` field anywhere (aggregator index is internal only, `xdp_window_aggregator.py:40-41`) — treat `window_start_ns` as the de-facto identity (implied by contract) |

Edge classification decisions (see §11 ambiguities): the confidence and anomaly-
score fields are judged **missing** (only a report recommendation mentions them,
`ML_LAYER_AUDIT.md:310`), while *echoing window identity and features* is
**implied by contract** (the correlator must be able to join), and *predicted
class + anomaly status* are **implied by the architecture** (they are the two
ML outputs) but unimplemented.

---

## 5. ML → Correlation boundary (what the external correlator needs from ML; retained, not duplicated)

The correlation layer is on a separate branch (out of scope here). The ML
engine must expose, without becoming the source of truth for IPsec state:

1. **Window identity** that the verdict applies to: `window_start_ns` /
   `window_end_ns` (+ `feature_schema_version`) — required to join the ML
   verdict to the window and to the independently-constructed observed-state
   snapshot (`ipsec_state_builder.snapshot`, `ebpf/ipsec_state_builder.py:
   335-385`; contract at `ML_CORRELATION_BOUNDARY.md:8-21`).
2. **The two engine outputs as enumerated in (§4):** predicted traffic type
   and anomaly status/score, keyed to the window identity.
3. **Non-authoritative framing**: ML output is one input to correlation;
   IPsec-state facts come only from the observed-state builder (which "never
   infers SA/crypto", `ebpf/ipsec_state_builder.py:20-25`). The ML layer must
   not infer or over-ride observed state, must not perform expected-vs-observed
   reconciliation (that is correlation's job, separate branch), and must not
   become the sole evidence for any downstream decision
   (`ML_LAYER_AUDIT.md:204-213`).
4. **Nothing duplicated**: the ML engine should retain its input feature
   vector + identity in its output record only to the extent needed for
   attribution/XAI and the join; it must not reproduce the observed-state
   builder's counters or transitions (those remain the auditor's independent
   evidence path).

No code implements any of these four points today (wiring `MISSING`), but the
contract boundary itself is documented and `IMPLEMENTED`.

---

## 6. Missing-dependency list (not installed — do not install)

From `requirements.txt` and `.venv/bin/pip freeze` (§9 finding), for the two ML
functions:

- `numpy` — fundamental array math for any classifier/detector (pyarrow can
  read parquet without it, but no numeric model runtime exists).
- `scikit-learn` — the practical class-aware/ensemble classifier (e.g.
  RandomForest/GradientBoosting for traffic-type classification) **and** the
  anomaly-detector + isotonic baseline (IsolationForest / OneClassSVM /
  `sklearn.isotonic.IsotonicRegression`). Brings transitively:
- `scipy` and `joblib` (scikit-learn hard dependencies; joblib also gives model
  persistence/serialization).
- `pandas` — optional convenience for parquet→array loading (pyarrow is already
  present); not strictly required.
- `statsmodels` — *optional* if a dedicated statistical boundary/EWMA baseline
  is preferred over scikit-learn's isotonic/isolation primitives; not required
  if scikit-learn is used.

Nothing below exists in the venv; adding these is a deliberate, separately-
approved dependency decision (out of scope for this audit;
`ML_LAYER_AUDIT.md:247-259` → `ENVIRONMENT-BLOCKED`).

---

## 7. Minimal dependency-ordered implementation plan (ML / AI ENGINE only)

Each step is tagged with its blocker chain. Nothing downstream of the ML engine
(correlation, Risk, XAI, Audit, Response, Analyst, XDP Action, Dashboard)
appears.

1. **Approve + add ML dependencies** (`numpy`, `scikit-learn`; `scipy`/`joblib`
   come transitively) with exact pinned versions in `requirements.txt`.
   → `BLOCKED` on the dependency decision (an ML import fails today).
2. **Consumption policy for the ML input**: decide and implement per-100-ms-
   window emission of the v2 record (currently epoch-granularity with aligned
   bounds; `--emit-every N` is event-count, not time-based) so ML receives
   exactly one record per 100 ms window.
   → `BLOCKED` on nothing; open design item (`LIVE_V2_FEATURE_PIPELINE_REPORT.md:362-366`).
3. **ML output contract**: define the MLL record (fields from §4 — predicted
   class, confidence, anomaly status/score, threshold, model version, echoed
   window identity + `feature_schema_version`, non-authoritative marker) and its
   schema-version axis, as a design contract *before* any model.
   → `BLOCKED` on step 2 (record identity) and on the design decision
   (`ML_LAYER_AUDIT.md:310`).
4. **Training data adequacy**: expand the v2 training set beyond n=5 (one
   sample per class on both label axes, plus the profile↔posture confound) using
   the existing dataset generator at v2.
   → `BLOCKED` on nothing (generator is `IMPLEMENTED`); prerequisite for
   meaningful classification/anomaly (§6 finding).
5. **Traffic Type Classification**: train classifier on v2 features (features
   only, labels from plan only — no leakage); implement inference over the live
   bridge; serialize model + version.
   → `BLOCKED` on steps 1, 3, 4.
6. **Anomaly Detection**: statistical baseline (isotonic/EWMA per-feature over
   the v2 distribution; or IsolationForest) with explicit score semantics and
   a configurable threshold; detector persistence + version.
   → `BLOCKED` on steps 1, 3, 4.
7. **Determinism / reproducibility**: seed RNG + parameter init, pin ML
   dependency versions, embed model + feature-schema version in every output,
   guard inference with `assert_feature_keys` + schema-version check.
   → `BLOCKED` on steps 1, 5, 6.
8. **Tests** (blocked items from §10): ML-input-per-window validation,
   classifier, anomaly detector, deterministic inference, malformed windows,
   missing features, NaN/Inf, wrong schema version, model/version mismatch,
   output contract, training reproducibility.
   → `BLOCKED` on steps 1–7.

Every step stays inside the ML engine; correlation/XAI/risk/audit/response/
dashboard wiring is explicitly out of scope and must be delivered after this
plan, under the boundary contract in §5.

---

## Verification performed (read-only / safe)

```
$ .venv/bin/python -m unittest controller.test_features controller.test_live_features \
    controller.test_dataset_artifacts ebpf.test_window_aggregator ebpf.test_state_builder \
    controller.test_dataset_planner controller.test_dataset_run controller.test_dataset_reuse \
    controller.test_dataset_reuse_decision controller.test_generator \
    controller.test_dataset_timing controller.test_ipsec_events \
    controller.test_audit controller.test_config
Ran 241 tests in 2.651s
OK
```

(Exit 0. `controller.test_dataset_executor` excluded — lab/sudo-bound by design,
per `DATASET_V2_REGEN_VALIDATION_REPORT.md:168-170`.)

Canonical dataset re-confirmed (read-only): `features.parquet` 5 rows × 69 cols
(10 linkage + 59 features; all rows `feature_schema_version=v2`, parquet feature
column order == `FEATURE_COLUMNS`); `metadata.jsonl` 5 records (v2, 59 feature
keys each); `staging/plan.json` (traffic quota 1/profile, posture 1/band,
planner v1); `finalization.json` `COMPLETED`. No lab/sudo command was run; no
file was modified other than creating this audit file.

---

## 11. Ambiguities / judgement calls

1. **`window_id` vs geometry**: no output field named `window_id` or
   `window_index` exists anywhere (index is computed internally and dropped,
   `ebpf/xdp_window_aggregator.py:40-41,297-321`). I classify "window identity =
   `window_start_ns`/`window_end_ns`" as **implied by contract** (both the
   aggregator and the live feature record emit only the bounds), and any
   separate integer window-id field for the ML output as **missing**.
2. **Per-100-ms-window granularity**: the architecture says "100-ms WINDOWS →
   ML input", but the repo's ML-ready record is one per *epoch* with 100 ms-
   aligned bounds (plus an event-count `--emit-every` hook). Whether ML consumes
   one 59-feature record per 100 ms window (sparse, mostly all-zero) or per
   epoch/generator-aligned batch is **not resolved by any contract** — a genuine
   open policy item, not an implementation gap (`LIVE_V2_FEATURE_PIPELINE_REPORT.
   md:172-184,362-366`; `ML_LAYER_AUDIT.md:284-285`).
3. **Confidence / anomaly-score fields**: only `ML_LAYER_AUDIT.md:310` (a report
   recommendation: "score/verdict + confidence + evidence provenance") hints at
   them. No code or schema references them. I classify both as **missing**
   (report prose ≠ contract), noting the report as the source of the hint.
   `predicted traffic type` and `anomaly status` are **implied by the
   architecture** (they are the two specified ML outputs) but still **missing**
   as fields.
4. **`dataset_schema_version=v1` alongside `feature_schema_version=v2`**: the
   canonical run intentionally keeps `dataset_schema_version`/`planner_version`
   at v1 (a separate, unchanged axis; `SCHEMA.md:7-11`;
   `V1_DATASET_CLEANUP_REPORT.md:140-141`). Not an ML-schema inconsistency.
5. **Feature ordering in JSON vs parquet**: contract order = `FEATURE_COLUMNS`;
   `metadata.jsonl` keys are alphabetized (`sort_keys=True`,
   `dataset_artifacts.py:313,595`) and live-dict order is insertion order
   (`features.py:434-466`) — order is set-checked, never positional. An ML
   consumer must key by column name; an inference wrapper taking a *positional*
   vector would silently break. Noted as a latent contract nuance.
6. **Module paths in the brief** (`ebpf/window_aggregator.py`,
   `ebpf/state_builder.py`) do not exist verbatim; the real modules are
   `ebpf/xdp_window_aggregator.py` / `ebpf/ipsec_state_builder.py`. Citations
   use the real names.

---

### Summary

The repository delivers the entire *observation-to-input* stack for the ML
engine — 100 ms windows, the exact v2 59-feature record via a single shared
computation (offline and live, byte-exact parity), the observed-state layer, and
a small labeled v2 dataset (5 rows, one per profile and one per posture) — all
deterministic and tested, none of it ML. **Traffic Type Classification and
Anomaly Detection are both `MISSING`**, the ML output contract is `MISSING`
(only input documents and implied requirements exist), and ML dependencies are
absent (`ENVIRONMENT-BLOCKED`). The ML → correlation boundary contract is
`IMPLEMENTED`; the concrete ML-output→correlation wiring is `MISSING` by
explicit scope. No active reference to a classifier, model or anomaly detector
exists in the codebase.