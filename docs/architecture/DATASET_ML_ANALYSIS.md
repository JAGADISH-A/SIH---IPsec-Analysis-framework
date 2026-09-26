# DATASET_ML_ANALYSIS.md

- Date: 2026-09-24
- Scope: READ-ONLY dataset analysis and ML design for the two protected datasets.
  No dataset modified, nothing deleted, no ML code written. Git commit `28beb6d`.
- Authoritative sources: `controller/dataset_artifacts.py` (`FEATURE_COLUMNS`,
  `FEATURE_SCHEMA_VERSION="v2"`), `controller/features.py` (`summarize_capture`),
  `controller/live_features.py`, `controller/dataset_planner.py`
  (`posture_of_config`), `ML_IMPLEMENTATION_AUDIT.md`, `ML_LAYER_AUDIT.md`,
  `DATASET_GENERATOR_ML_PIPELINE_REPORT.md`, `ML_DATA_COLLECTION_REPORT.md`,
  `ML_CORRELATION_BOUNDARY.md`, `SCHEMA.md`.

---

## 1. Dataset inventory

| | `dataset-20260923-221430` | `dataset-20260924-003710` |
|---|---|---|
| Rows (`features.parquet`) | 200 | 100 |
| Columns (`features.parquet`) | 69 (10 linkage + 59 features) | 69 (10 linkage + 59 features) |
| `metadata.jsonl` records | 200 | 100 |
| Manifest status | COMPLETED, `dataset_schema_version=v1` | COMPLETED, `dataset_schema_version=v1` |
| Finalization | `parquet_rows=200`, `metadata_records=200` | `parquet_rows=100`, `metadata_records=100` |
| State | target 200 / ok 200 / failed 0 | target 100 / ok 100 / failed 1 |
| `feature_schema_version` | v2 | v2 |
| Capture time range (UTC) | 16:45:42 → 19:05:38 | 19:08:09 → 20:11:08 |
| Sequence range | 1–200 (unique) | 1–100 (unique) |
| Unique `experiment_id` | 200/200 | 100/100 |
| Unique `pcap_path` | 200/200 | 100/100 |
| Nulls | 0 | 0 |
| Duplicate full rows | 0 | 0 |
| Duplicate 59-feature rows | 0 | 0 |
| Constant (zero-variance) columns | `dataset_run_id`, `attempt_number`, `feature_schema_version`, `burst_packet_ratio`, `ike_packet_count` | `dataset_run_id`, `feature_schema_version`, `burst_packet_ratio`, `ike_packet_count` |

Both datasets are finalized canonical artifacts produced by the same v2 engine
(`execute_dataset_run` → `execute_trial_pipeline` → `summarize_capture`), staged
atomically, record-validated (`min packet_count >= 1`), and finalized with
`features.parquet` + `metadata.jsonl` + `manifest.json` + `README.txt` +
`finalization.json` + per-sample captures.

```json
{
  "inventory": [
    {"dataset_run_id": "dataset-20260923-221430", "samples": 200, "features_parquet": 200, "metadata_records": 200, "feature_schema_version": "v2", "dataset_schema_version": "v1", "parquet_columns": 69, "feature_columns": 59, "nulls": 0, "duplicate_rows": 0, "constant_columns": ["burst_packet_ratio","ike_packet_count"]},
    {"dataset_run_id": "dataset-20260924-003710", "samples": 100, "features_parquet": 100, "metadata_records": 100, "feature_schema_version": "v2", "dataset_schema_version": "v1", "parquet_columns": 69, "feature_columns": 59, "nulls": 0, "duplicate_rows": 0, "constant_columns": ["burst_packet_ratio","ike_packet_count"]}
  ]
}
```

## 2. Dataset comparison

| Criterion | Result |
|---|---|
| Schemas identical | **Yes** — parquet schemas compare equal (same 69 columns, same Arrow types, same order). |
| Feature names identical | **Yes** — the trailing 59 columns are the same `FEATURE_COLUMNS` list. |
| Feature meanings identical | **Yes** — both produced by the same `summarize_capture` / `normalize_feature_record`; semantics documented in `dataset_artifacts.py:115-175`. |
| Units identical | **Yes** — bytes (L3 `ip_total`), seconds, frames/s, bytes/s, ratios 0..1, Shannon bits. |
| Schema versions identical | **Yes** — `feature_schema_version=v2`, `dataset_schema_version=v1` in both. |
| Preprocessing conventions identical | **Yes** — L3 sizes (`incl_len−14`), ratio rounding to 3 decimals, `normalize_feature_record` coercion, min-validity check. |
| Label representation identical | **Yes** — same string enums: 6 `traffic_profile` values, 5 `security_posture` values. |
| Duplicate samples between datasets | **No** — 0 overlapping 59-feature tuples; no identical rows. |
| Duplicate experiment IDs | **No** — `experiment_id` sets disjoint; 300 unique across the pair. |
| Duplicate logical sequence IDs | **No collision** — sequences are per-run indices 1..N; both runs start at 1 but are namespaced by `dataset_run_id` (no shared namespace). |
| Captures reused | **No** — `pcap_path` sets disjoint; 200 + 100 unique captures. |
| `captured_at` overlap | **No** — timestamps disjoint; sequential same-session collection (16:45→20:11 UTC). |
| Configuration coverage | 221430: 168 unique `configuration_id` of 200 samples; 003710: 92 unique of 100. Both draw from the same planner catalogue. |
| Attempt retries | 221430: all `attempt_number=1`; 003710: 99×1 + 1×2 (one retried sample, status SUCCESS). |
| Independent collection vs extension/regeneration | **Independent collection** — distinct run ids, distinct plans, distinct captures, no shared ids, no shared feature vectors; it is a second run of the same generator, not an extension (independent sequence namespace) and not a regeneration of the other. |

```json
{
  "comparison": {
    "schemas_identical": true, "feature_names_identical": true, "feature_meanings_identical": true,
    "units_identical": true, "schema_versions_identical": true, "preprocessing_identical": true,
    "labels_identical": true, "duplicate_samples_between": 0, "duplicate_experiment_ids": 0,
    "sequence_collision": false, "capture_reuse": 0, "relation": "INDEPENDENT_COLLECTION"
  }
}
```

## 3. Label distributions

Verified from the actual `metadata.jsonl` labels (not assumed). Six traffic
classes and five posture bands both confirmed present.

### dataset-20260923-221430 (n=200)

| Class | Count | % |
|---|---|---|
| traffic_profile = voip | 34 | 17.0 |
| traffic_profile = video | 34 | 17.0 |
| traffic_profile = messaging | 33 | 16.5 |
| traffic_profile = email | 33 | 16.5 |
| traffic_profile = web | 33 | 16.5 |
| traffic_profile = icmp | 33 | 16.5 |
| security_posture = STRONG | 40 | 20.0 |
| security_posture = GOOD | 40 | 20.0 |
| security_posture = MEDIUM | 40 | 20.0 |
| security_posture = WEAK | 40 | 20.0 |
| security_posture = WORST | 40 | 20.0 |

### dataset-20260924-003710 (n=100)

| Class | Count | % |
|---|---|---|
| traffic_profile = voip | 17 | 17.0 |
| traffic_profile = video | 17 | 17.0 |
| traffic_profile = messaging | 17 | 17.0 |
| traffic_profile = email | 17 | 17.0 |
| traffic_profile = web | 16 | 16.0 |
| traffic_profile = icmp | 16 | 16.0 |
| security_posture = STRONG | 20 | 20.0 |
| security_posture = GOOD | 20 | 20.0 |
| security_posture = MEDIUM | 20 | 20.0 |
| security_posture = WEAK | 20 | 20.0 |
| security_posture = WORST | 20 | 20.0 |

### Combined (n=300) — diagnostic only

| Class | Count | % |
|---|---|---|
| voip | 51 | 17.0 |
| video | 51 | 17.0 |
| messaging | 50 | 16.7 |
| email | 50 | 16.7 |
| web | 49 | 16.3 |
| icmp | 49 | 16.3 |
| STRONG / GOOD / MEDIUM / WEAK / WORST | 60 each | 20.0 each |

Cross-tab (per dataset): all 30 (profile × posture) cells present in each run
(6–7 per cell in 221430, 3–4 per cell in 003710). Profile and posture are
decoupled by the planner as designed.

```json
{
  "distributions": {
    "dataset-20260923-221430": {"traffic_profile": {"voip":34,"video":34,"messaging":33,"email":33,"web":33,"icmp":33}, "security_posture": {"STRONG":40,"GOOD":40,"MEDIUM":40,"WEAK":40,"WORST":40}},
    "dataset-20260924-003710": {"traffic_profile": {"voip":17,"video":17,"messaging":17,"email":17,"web":16,"icmp":16}, "security_posture": {"STRONG":20,"GOOD":20,"MEDIUM":20,"WEAK":20,"WORST":20}},
    "combined": {"traffic_profile": {"voip":51,"video":51,"messaging":50,"email":50,"web":49,"icmp":49}, "security_posture": {"STRONG":60,"GOOD":60,"MEDIUM":60,"WEAK":60,"WORST":60}}
  }
}
```

## 4. ML target

Evidence from the architecture:

- `ML_IMPLEMENTATION_AUDIT.md:9` — the defined architecture is **Traffic Type
  Classification** and **Anomaly Detection**.
- `ML_IMPLEMENTATION_AUDIT.md:358` — "predicted traffic type / class …
  architecture: ML = Traffic Type Classification (§4)".
- `ML_LAYER_AUDIT.md:125-130` — security-posture "bands" are produced by the
  **deterministic, config-only rule** `posture_of_config`
  (`controller/dataset_planner.py:85-105`), used only as **training labels**,
  never a runtime verdict.
- `DATASET_GENERATOR_ML_PIPELINE_REPORT.md §5` — "Ground-truth label =
  `security_posture` + `traffic_profile` resolved from the Module-2 plan
  sample, never recomputed from traffic."

**Decision: candidate target = `traffic_profile`** (6 classes: voip, video,
messaging, email, web, icmp). This is the architecturally defined ML
classification task.

`security_posture` is **not** the ML target: it is a deterministic function of
`ipsec_configuration` (`posture_of_config` score: GCM family 4 / CBC 2, aes256 2
/ aes128 1, PFS 2/0, DH points; STRONG≥11, GOOD≥9, MEDIUM≥6, WEAK≥4, WORST=3).
It is a label generator, not something a traffic-feature classifier is designed
to predict. The two labels are orthogonal (all 30 profile×posture cells
present) and MUST NOT be merged.

Ambiguity note: `ML_LAYER_AUDIT.md:121` lists "feature-vector → traffic class /
posture / expected outcome" as one corrupt/`MISSING` bucket, so posture
classification from traffic is an undefined, ambiguous task in the current
architecture. Per the strict rule, we do not guess: the defined target is
`traffic_profile`; posture prediction is recorded as an open question, not
designed.

```json
{
  "ml_target": {"column": "traffic_profile", "classes": ["voip","video","messaging","email","web","icmp"], "architecture": "Traffic Type Classification", "decision": "traffic_profile", "security_posture_role": "config-derived label generator, NOT an ML target", "labels_merged": false}
}
```

## 5. Feature schema

`features.parquet` = 10 linkage/ground-truth columns + 59 feature columns.

Linkage / non-feature columns (`PARQUET_ID_COLUMNS`):

| Column | Role |
|---|---|
| `dataset_run_id` | dataset identifier (provenance; drop) |
| `sequence` | per-run sample index (identifier; drop) |
| `experiment_id` | per-sample experiment identifier (identifier; drop) |
| `attempt_number` | capture attempt index (identifier/retry; drop) |
| `traffic_profile` | **label 1** (target candidate) |
| `security_posture` | **label 2** (config-derived; drop for target=traffic_profile) |
| `configuration_id` | config identity (metadata; leakage-prone; drop) |
| `captured_at` | collection timestamp (timestamp; leakage-prone; drop) |
| `pcap_path` | capture path (identifier; leakage-prone; drop) |
| `feature_schema_version` | schema version (dataset metadata; drop) |

The 59 feature columns (authoritative meanings from
`controller/dataset_artifacts.py:115-175`, computed by
`controller/features.summarize_capture` over the outer ESP+IKE stream only):

`packet_count` (int, ESP frames), `total_bytes` (int, sum of outer-IP lengths),
`mean_packet_size`, `packet_size_std`, `min_packet_size`, `max_packet_size`,
`packet_size_p10/p50/p90/p95/p99` (bytes), `unique_packet_size_count`,
`packet_size_entropy` (bits), `small_packet_ratio` (≤300 B threshold,
`features.py:47`), `large_packet_ratio` (>1400 B, `features.py:48`),
`mean_inter_arrival_time`, `inter_arrival_time_std`, `min_inter_arrival_time`,
`max_inter_arrival_time` (s), `packets_per_second`, `bytes_per_second`,
`flow_duration` (s, 21.96–30.00 observed), `outbound_packet_count`,
`inbound_packet_count`, `outbound_bytes`, `inbound_bytes`,
`outbound_packet_ratio`, `inbound_packet_ratio`, `outbound_byte_ratio`,
`inbound_byte_ratio`, `outbound_mean_packet_size`, `inbound_mean_packet_size`,
`outbound_packets_per_second`, `inbound_packets_per_second`,
`outbound_packet_size_p10/p50/p90/p95/p99`, `inbound_packet_size_p10/p50/p90/p95/p99`,
`burst_count`, `mean_burst_packets`, `mean_burst_duration`,
`burst_packet_ratio`, `burst_count_10ms`, `mean_burst_packets_10ms`,
`burst_count_50ms`, `mean_burst_packets_50ms`, `burst_count_200ms`,
`mean_burst_packets_200ms`, `ike_packet_count`, `ike_datagram_bytes`,
`ike_min_packet_size`, `ike_max_packet_size`, `ike_mean_packet_size`.

Types: 17 int32 + 42 double (declared `INT_FEATURES`/`FLOAT_FEATURES` in
`dataset_artifacts.py:182-193`), no nulls in either run.

Constant / zero-variance features on the combined 300 rows (drop, no ML value):

- `burst_packet_ratio` = 1.0 for all 300 (all frames fall inside bursts).
- `ike_packet_count` = 4 for all 300 (exactly 2 SA_INIT + 2 AUTH observed in
  every capture, matching `DATASET_GENERATOR_ML_PIPELINE_REPORT.md §3`).

Low-variance features to note (usable, not dropped): `unique_packet_size_count`
(4 distinct values), `large_packet_ratio` (8), `small_packet_ratio` (17),
`ike_*` (2–6 distinct values).

Classification summary:

- **ML features** = the 57 non-constant columns of the 59-feature set.
- **Labels** = `traffic_profile` (target), `security_posture` (secondary label).
- **Identifiers** = `dataset_run_id`, `sequence`, `experiment_id`,
  `attempt_number`, `pcap_path`.
- **Timestamps** = `captured_at`.
- **Experiment/dataset metadata** = `feature_schema_version`,
  `configuration_id`, and (metadata.jsonl-only) flattened + nested
  `ipsec_configuration` (`mode`, `address_family`, `ike_version`,
  `ike_encryption`, `ike_integrity`, `ike_dh_group`, `esp_encryption`,
  `esp_integrity`, `esp_dh_group`, `pfs`), `traffic_model`.
- **Leakage-prone** = `configuration_id` + all `ipsec_configuration` fields
  (exact input to `posture_of_config`), `traffic_model` (contains the generator
  parameters — `profile`, `packet_rate`, `packet_size`, `protocol` — that were
  used to create the traffic), `captured_at`, `pcap_path`.

```json
{
  "feature_schema": {
    "version": "v2", "feature_columns": 59, "linkage_columns": 10, "total_constant_features": ["burst_packet_ratio", "ike_packet_count"],
    "features_for_ml": 57, "labels": ["traffic_profile", "security_posture"],
    "identifiers": ["dataset_run_id","sequence","experiment_id","attempt_number","pcap_path"],
    "timestamps": ["captured_at"], "dataset_metadata": ["feature_schema_version","configuration_id"]
  }
}
```

## 6. Live/offline compatibility

- One feature implementation: `summarize_capture` in `controller/features.py`.
  Both the offline extractor (`extract_features`, pcap) and the live bridge
  (`controller/live_features.py`, XDP event feed) call it — no duplicated
  statistics (`live_features.py:17-22`).
- Live/offline representation parity verified byte-exact over the five canonical
  captures by `controller/dataset_rebuild.py::verify_live_parity` and
  `controller/test_live_features.py` (`ML_IMPLEMENTATION_AUDIT.md §1`).
- Direction: the 6 outbound/inbound columns are anchored to the **known WAN
  address of the capture point** (`features.py:480`), which is fixed at deploy
  time and available at inference (live events carry src/dst).
- L2→L3 normalization: the XDP event `len` is L2; the live extractor converts
  with `len − 14` so live features match the L3 training features
  (`live_features.py:87,178-190`).
- Per-feature: every candidate feature is (a) computable offline from stored
  PCAPs, (b) computable live from the XDP feed, (c) deterministic (fixed
  formulas, fixed thresholds/burst defaults `DEFAULT_BURST_WINDOW_S=0.050`),
  (d) independent of ground-truth labels, (e) independent of information
  unavailable at inference. No feature depends on ESP SPI, sequence numbers or
  decrypted content (`live_features.py:45`).
- Live records add provenance keys `window_start_ns`/`window_end_ns`
  (100 ms-aligned; `LIVE_METADATA_KEYS`), which are not ML features.

No compatibility hack is required for the dataset side. The only open live-path
item is deploy-time (not dataset): the guarantee that every 100 ms window emits
exactly one ML-input record is `PARTIALLY IMPLEMENTED`
(`ML_IMPLEMENTATION_AUDIT.md §1`, `LIVE_V2_FEATURE_PIPELINE_REPORT.md:172-184`).

## 7. Data leakage analysis

Suspected sources, all documented (none silently dropped):

1. **`traffic_model` (metadata.jsonl only)** — contains the generator's fixed
   `profile`, `packet_rate`, `packet_size`, `protocol`, `burst` schedule. If
   ever used as a feature it is a perfect cipher for `traffic_profile`. It is
   NOT present in `features.parquet`; loader must never read it into features.
2. **`configuration_id` + `ipsec_configuration` (mode, address_family, ike*,
   esp_*, pfs)** — `security_posture` is a pure deterministic function of these
   (`posture_of_config`). Using them as features would embed the posture label.
   Dropped; they stay in metadata as provenance.
3. **`traffic_profile` / `security_posture`** — the labels themselves. Both are
   dropped from the feature matrix (the non-target label is dropped too so it
   can never leak into training).
4. **Identifiers** — `experiment_id`, `sequence`, `attempt_number`,
   `dataset_run_id`, `pcap_path` — unique per row; if used, the model could
   memorize split membership. Dropped.
5. **`captured_at`** — absolute collection timestamps differ across runs and
   correlate with run/session, not traffic class; dropped (timestamps are not
   inference-stable and leak session identity).
6. **Application names / filenames / directory names** — no application/process
   names appear in the feature or linkage schema; capture filenames embed
   `experiment_id` but exist only in the evidence path (`captures/<seq>/`).
7. **Known destination / inner payload** — none available: features derive from
   the outer ESP+IKE stream; inner IPs and plaintext are never decoded
   (`ML_CORRELATION_BOUNDARY.md` boundary contract; `features.py:44-47`).
8. **Label provenance** — labels come from the Module-2 plan sample, never
   recomputed from traffic (`dataset_artifacts.py:411-446`); no label-to-feature
   feedback loop exists.
9. **Feature-content caveat** — for the chosen task (traffic classification) the
   59 outer-stream features are the intended predictors, not leakage. If someone
   instead tried to predict `security_posture`, ESP-overhead size/rate differences
   across configurations would be an indirect, fragile proxy; that task is not
   defined (see §4) and is not designed.

## 8. Combination decision

**Conclusion: COMBINE.**

Justification:
- Identical schema, feature names, meanings, units, schema versions,
  preprocessing and label enumerations (§2) — **no normalization required**.
- Independent, non-overlapping collections (§2): disjoint experiment ids, pcap
  paths, feature tuples, and timestamps; same testbed/generator/session
  (16:45→20:11 UTC), so domain consistency holds.
- Complementary balanced coverage: 200 + 100 → 300 rows with 6 balanced profiles
  and 5 balanced postures (§3).
- Combination = row concatenation of `features.parquet` preserving
  `dataset_run_id` as provenance; the shared run session makes the two runs
  directly comparable.

Caveats (not blockers):
- Both runs used the deterministic generated traffic (fixed rates/sizes per
  profile), so separation is near-perfect and 300-sample derived metrics will be
  optimistic relative to real-world traffic.
- `burst_packet_ratio` and `ike_packet_count` remain constant across the
  combined set (verified); drop them after combining.
- The single `attempt_number=2` sample in 003710 is a valid SUCCESS capture with
  unique experiment id — keep it.

## 9. Train/validation/test split design

Correlation analysis:
- **Per-capture independence:** every row is a distinct capture (unique pcap,
  fresh traffic run); no capture spans multiple rows — no leakage by capture.
- **Configuration correlation:** samples sharing `configuration_id` share
  topology identity (`mode`), crypto overhead shapes and, for the same profile,
  near-identical deterministic features (e.g. 4 samples
  `tunnel-ipv4-aes128gcm16-none-modp4096-true` in 221430). This is the dominant
  correlation group for repeated-feature risk.
- **Profile correlation:** samples of the same `traffic_profile` share fixed
  generator parameters — this is the *signal*, not a leakage group.
- **Run/session correlation:** two same-session runs; topology was
  destroyed+redeployed per sample (`MODULE9_DESIGN.md §1`), but time adjacency
  is mild. Sequence indices are per-run and carry no information.

Recommended split (reproducible, grouped, stratified):

1. **Grouping key = `configuration_id`** — keep every sample of one
   configuration together in exactly one split.
2. **Stratification = `traffic_profile`** (target; 6 classes, ~17% each),
   secondarily balanced on `security_posture` and `mode`.
3. **Ratio = 70 / 15 / 15** ≈ 210 / 45 / 45 rows with per-class stratification
   and whole-group placement (group members follow their largest-requirement
   split).
4. **Deterministic assignment:** fixed seed recorded in the split artifact;
   assignment computed offline and persisted as
   `results/ml/split_v1.json` (`{key(experiment_id): "train|val|test"}`),
   shipped with SHA-256 of input parquet so it can be reproduced exactly.
   Same-config groups assigned en bloc algorithmically, not through iteration
   that depends on load order.
5. **Model selection / hyper-parameter CV** = `StratifiedGroupKFold(n_splits=5)`
   over the training portion only, `groups=configuration_id` — no validation
   sample leaks into tuning.
6. **Hold-out discipline:** `test` never used for tuning or feature selection;
   feature-selection statistics (constant-column detection, any thresholding)
   computed on the training split only.

## 10. RF + SHAP design (design only — not implemented)

Proposed files: `controller/dataset_loader.py`, `controller/train_random_forest.py`,
`controller/evaluate_model.py`, `controller/shap_analysis.py`. Sketches below are
specifications, not code.

### dataset_loader.py
- **Input dataset:** `results/datasets/dataset-20260923-221430/features.parquet`
  + `results/datasets/dataset-20260924-003710/features.parquet` (read-only).
- **Target column:** `traffic_profile` (6 classes, label-encoded 0–5 with a
  stored ordered class list `["voip","video","messaging","email","web","icmp"]`).
- **Feature columns:** the 59 `FEATURE_COLUMNS` minus the two constant columns
  (`burst_packet_ratio`, `ike_packet_count`) = **57 features**; assert schema
  against `FEATURE_COLUMNS` and reject null/non-finite values (none exist today,
  assertion is a guard).
- **Excluded (never loaded into X):** `dataset_run_id`, `sequence`,
  `experiment_id`, `attempt_number`, `traffic_profile` (target), `security_posture`,
  `configuration_id` (grouping key only), `captured_at`, `pcap_path`,
  `feature_schema_version` (see §5, §7).
- **Preprocessing:** none for RF (trees need no scaling/imputation); dtype
  validated against the declared `INT_FEATURES`/`FLOAT_FEATURES` sets;
  label-encoder with persisted mapping; output numpy arrays + metadata dict.

### train_random_forest.py
- **Preprocessing:** loaders above; no config columns, no metadata, no
  `traffic_model` anywhere in the matrix.
- **Split strategy:** §9 (grouped by `configuration_id`, stratified by target,
  70/15/15, seed + `split_v1.json` artifact).
- **Model:** `RandomForestClassifier` with `n_estimators=500`,
  `max_features="sqrt"`, `min_samples_leaf=2`, `max_depth=None`,
  `class_weight="balanced_subsample"`, `oob_score=True`, `random_state=<seed>`,
  `n_jobs<=cores`. Hyper-parameters tuned only via
  `StratifiedGroupKFold(n_splits=5, groups=configuration_id)` on train.
- **Class imbalance strategy:** dataset is balanced by design (§3); stratified
  split preserves balance; `class_weight="balanced_subsample"` is a guard, not
  a necessity. Report raw counts with every run.
- **Outputs:** `results/ml/model_traffic_rf_v1.joblib`,
  `results/ml/train_report.json`, per-fold CV scores, OOB score.

### evaluate_model.py
- **Metrics:** accuracy; macro / weighted / per-class precision, recall, F1;
  confusion matrix (as table + PNG); OOB score; 5-fold CV mean±std.
- **Hold-out:** evaluation on the 15% `test` split only; `test` never seen
  during training or tuning.
- **Outputs:** `results/ml/eval_report.json`, `results/ml/confusion_matrix.png`,
  per-class report rows.

### shap_analysis.py
- **Method:** `shap.TreeExplainer(model)` over the trained RF; used for
  **explanation only** — never a classifier and never part of inference.
- **Outputs (results/ml/shap/):**
  - global mean |SHAP| bar (`shap_importance_bar.png` + `shap_importances.json`);
  - beeswarm/summary plot per class; SHAP summary for the 6-class output
    (probability space);
  - top-feature dependency plots (top-3 by mean |SHAP|);
  - 2–3 force plots per class from the test split;
  - raw `shap_values.npz` persisted for re-plotting.
- **Interpretation note:** with deterministic generated traffic the RF will be
  near-perfect and SHAP importances will mirror the fixed generator parameters
  (rate/size per profile) — report them as descriptions of this synthetic
  domain, not generalizable network fingerprints.

### Model artifact format
`results/ml/model_traffic_rf_v1.joblib` = dict:
`{estimator, feature_names[57], feature_schema_version="v2",
target_classes=["voip","video","messaging","email","web","icmp"],
label_encoder, split_artifact="split_v1.json", split_hash, input_fingerprints,
meta{git_commit, created_at, seed, library_versions, dataset_run_ids,
sample_counts}}`.

### Feature-schema artifact
`results/ml/feature_schema_v2.json` generated from
`controller.dataset_artifacts.FEATURE_COLUMNS` + `INT_FEATURES` +
`FLOAT_FEATURES` + `FEATURE_SCHEMA_VERSION`, listing all 59 columns, the 2
dropped constant columns and why, and the 57 used.

### Reproducibility metadata
SHA-256 fingerprints of both input `features.parquet`, run ids, sample counts,
seed, split JSON hash, library versions, git commit, date — persisted in the
train report and the model `meta`.

## 11. Open questions / blockers

1. **Dependencies missing in `.venv`:** `numpy`, `scikit-learn`, `joblib`,
   `shap`, `matplotlib` (and optionally `pandas`) are NOT installed. Design
   assumes loader uses pyarrow (available) for reading. No packages were
   installed.
2. **Live inference windowing gap:** "every 100 ms window → exactly one ML-input
   record" is a `PARTIALLY IMPLEMENTED` live-path item
   (`ML_IMPLEMENTATION_AUDIT.md §1`). Affects live deployment, not training
   design.
3. **Anomaly Detection** — the second defined ML job has no labels in these
   datasets (no anomaly-labeled samples). Blocked until anomaly labels exist.
4. **`security_posture` prediction from traffic is architecturally ambiguous**
   (config-derived label, not an inference task). Not designed; flagged, not
   guessed.
5. **Small-n, deterministic domain:** 300 samples from one synthetic generator —
   accuracy will be close to perfect and generalizability outside the fixed
   generator parameters is unproven.
6. **Configuration-group sizes:** many configuration_ids have a single sample;
   group-split needs a documented rule for groups with `size < split
   requirement` (place whole group in the split with the largest target-class
   need) to remain deterministic.

---

## DATASET ANALYSIS STATUS

```
200-sample dataset inspected:            YES
100-sample dataset inspected:            YES
Schemas compared:                        YES
Labels verified:                         YES
Overlap checked:                         YES
Leakage checked:                         YES
Live/offline compatibility checked:      YES
ML target established:                   YES (traffic_profile)
Dataset combination established:         YES (COMBINE)
Split strategy established:              YES (grouped+stratified, 70/15/15)
RF design ready:                         YES (design only)
SHAP design ready:                       YES (design only)
```

**ML implementation: NOT STARTED**

No dataset was modified. Nothing was deleted. No ML code was written. No
packages were installed. Nothing was committed.