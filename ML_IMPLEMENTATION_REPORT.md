# Traffic Classification ML Layer — Implementation Report

Status: `ML = Traffic Type Classification` implemented and verified.

## Scope

Implemented the traffic-profile classification layer designed in
`DATASET_ML_ANALYSIS.md` on the 300 protected samples (200 from
`dataset-20260923-221430`, 100 from `dataset-20260924-003710`). The layer
reads the two feature v2 parquets, builds a 57-feature matrix, applies a
deterministic grouped/stratified split, trains a scikit-learn
`RandomForestClassifier`, evaluates strictly on the untouched test
partition, and produces observational SHAP explanations.

## Architecture verification

- Random forest is the traffic-classifier (`traffic_profile`), per the
  audited architecture (`ML_IMPLEMENTATION_AUDIT.md`).
- SHAP is explainability only: it never predicts, never overrides, never
  mutates the model. Verified at runtime: `predictions_equal: true`,
  `probabilities_equal: true`. SHAP output representation is detected and
  recorded verbatim (`ndarray (n_samples, n_features, n_classes)`, shap
  0.52.0).
- `security_posture` is a configuration-derived label
  (`posture_of_config`), not an ML target — no posture classifier, no
  label merging.
- Anomaly detection is NOT implemented (no anomaly labels exist; out of scope).
- Live/run-time inference IS implemented via the adapter
  (`controller/ml_inference.py`, see "Live 100-ms inference adapter" below);
  the live path (`live_features.py`) remains unchanged.
- The two protected datasets were only read, never written.

## Dataset and features

- Feature schema v2, 59 declared features minus 2 verified constants
  (`burst_packet_ratio` = 1.0, `ike_packet_count` = 4) = 57 used features.
- `X` is strictly the 57 features; `groups` = `configuration_id`; labels
  stay separate. Leakage columns (posture, configuration, identifiers,
  timestamps, schema version) are never in `X`.
- No nulls, no non-finite rows, declared int32/double types validated.
- `feature_schema_v2.json` persists the used-feature list for
  reproducibility.

## Split

- Strategy: `grouped_stratified_greedy_by_configuration_id`, greedy and
  fully deterministic (seed 7, no shuffling). A configuration group never
  spans splits.
- Actual split: train 212 / validation 42 / test 46 (ratios 70/15/15).
- Verification persisted in `split_v1.json`: `group_isolation_ok: true`,
  `every_sample_once: true`, no spanning groups. All 6 classes present in
  every partition (train e.g. voip 35, video 38, ..., icmp 35).
- `split_hash` (
  `fbf04c326bb68d3579c4792dea76fb0baf68fcbd4f384f04487d92ccc2b233d4`) is
  embedded in the model artifact and cross-checked at evaluation.

## Model and hyperparameters

`RandomForestClassifier(n_estimators=500, max_features="sqrt",
min_samples_leaf=2, max_depth=None, class_weight="balanced_subsample",
oob_score=True, random_state=7, n_jobs=-1)`. Model selection used
`StratifiedGroupKFold(5)` on the train partition only; validation and
test were never touched during selection (Tabular default controls).

## Results (test partition, 46 samples)

- accuracy: 1.0000, macro P/R/F1: 1.0000 / 1.0000 / 1.0000,
  weighted P/R/F1: 1.0000 / 1.0000 / 1.0000.
- Per class (precision/recall/f1 all 1.0000): voip (7), video (7),
  messaging (7), email (10), web (8), icmp (7).
- OOB (train): 1.0. Train-only CV (5 folds): accuracy mean 1.0 (std 0.0),
  macro-F1 mean 1.0 (std 0.0).

## SHAP explainability

- Global top features (mean |SHAP|): `packets_per_second`, `packet_size_p99`,
  `packet_count`, `outbound_packets_per_second`, `outbound_packet_size_p95` —
  rate and size distribution, consistent with the model's separation of
  traffic profiles.
- Per-class and per-sample (`top 10 contributions`) importance recorded in
  `shap_importances.json`; plots under `results/ml/shap/`.

## Reproducibility

- Commit: `28beb6d245534cc14d96e8013c15053e96d8ba96`
- Python 3.14.4; numpy 2.5.3, scikit-learn 1.9.1, joblib 1.6.0, shap
  0.52.0, matplotlib 3.11.2 (pinned in `requirements.txt`).
- Input fingerprints (`features.parquet` sha256) recorded in
  `split_v1.json`, the model artifact, `train_report.json`,
  `eval_report.json`, and `shap_importances.json`.
- Pipeline order: `controller.dataset_loader` -> `controller.grouped_split`
  -> `controller.train_random_forest` -> `controller.evaluate_model` ->
  `controller.shap_analysis`.

## Verification

- 38 offline ML-layer tests pass
  (`controller/test_dataset_loader.py`, `test_grouped_split.py`,
  `test_ml_model.py`, `test_shap.py`; SHAP non-interference and
  representation handling covered).
- 37 adapter tests pass (`controller/test_ml_inference.py`: strict 57-feature
  schema rejection, ML result contract, offline==live parity at the 57-vector
  boundary, `predict_many` batch == sequential, SHAP non-interference,
  100-ms window grouping, CLI). Combined ML suite: **75 passed**.
- Full `pytest -q`: **549 passed, 15 skipped, 0 failed**
  (576 subtests). No unrelated test changed; the pre-existing
  `test_dataset_api.py` acceptance/timing flake is unchanged and unmodified.
- Dataset integrity re-verified: protected datasets unchanged
  (`features.parquet` sha256 `6d4df9c8...878a`, `aaee80ff...eef3`).

## 2026-09-24 — live 100-ms inference adapter

`controller/ml_inference.py` connects the live v2 feature producer
(`controller/live_features.py`) to the trained Random Forest without touching
either side.

- **Input** (`predict`): a live v2 record
  `{feature_schema_version, window_start_ns, window_end_ns, features{59}}` or a
  bare 57-feature mapping. Live records are checked against the full 59-column
  v2 schema, then the two verified constants (`burst_packet_ratio`=1.0,
  `ike_packet_count`=4, single-valued across all 300 samples) are dropped.
- **Feature vector**: exactly 57 features, ordered by
  `results/ml/feature_schema_v2.json`; `feature_order()` asserts the schema
  file agrees with `dataset_loader.feature_names()` and the artifact
  `feature_names`. Validation is strict and repairs nothing: 57 count, exact
  names (missing/extra/unknown rejected), duplicates rejected, and every value
  must be a finite number (NaN/inf/bool/non-numeric rejected, `ValueError`).
- **Output contract**: `{model_version, feature_schema_version, window_id,
  timestamp, traffic_profile, probabilities{6}}` — the six-class prediction
  plus confidence, echoing the window identity; no risk score, no security
  decision, no policy action.
- **SHAP**: on demand only (`--explain` / `explain()`), observational; every
  explanation carries a non-interference check.
- **Throughput**: the estimator was trained with `n_jobs=-1` (frozen), so a
  single-sample `predict_proba` pays joblib's full pool spawn/teardown
  (~283 ms). `predict_many` batch-scores N windows in one `predict_proba`
  call with identical results (1.55 ms/window) and is used by the CLI
  `--events` path.
- **CLI**: `python -m controller.ml_inference --events <events.jsonl> --output -`
  buckets the event stream into real 100-ms windows and emits one ML result
  per window; `--records` consumes pre-windowed v2 records; `--explain`
  attaches on-demand SHAP.

### Testbed rehearsal (six profiles → 100-ms windows → ML)

The privileged lab (`sudo -n` over Containerlab/XDP/tcpdump) is unavailable in
this environment, so every held-out TEST-split capture (46 samples, all six
profiles, never used in training) was replayed read-only through the real
observation path — events → `LiveFeatureExtractor` → v2 record → adapter → RF:

- **30-s aggregate path** (mirrors the offline eval): accuracy **1.0** across
  all 46 held-out samples; the live v2 record reproduces the stored training
  57-vector byte-exact on 45/46 (the single deviation is one 3-decimal field,
  `bytes_per_second` ±0.003, from the documented ns→s timestamp
  sub-rounding; prediction unaffected). Evidence: `results/ml/live_bridge/`.
- **Real 100-ms window path** per profile (correct fraction across windows):
  icmp 1.000, voip 0.984, video 0.980, email 0.915, web 0.896, messaging
  0.462. Confidence rises with window packet count (for 20+ packets/window:
  video/web 1.0, voip 0.997, email 0.5(→ larger windows better), messaging
  0.504). **Messaging is genuinely equivocal at 100-ms granularity** and is
  flagged rather than hidden — at the 30-s aggregate the same captures
  classify 7/7, so the aggregation window is what disambiguates it. Two known
  limitations, reported honestly: the held-out split contains tunnel-mode
  captures only (no transport-mode test samples), and the RF was trained on
  30-s aggregates, so sparse 100-ms windows are sparse-feature windows, not
  confident verdicts.

## 2026-09-24 limitation — synthetic data

The dataset is generated by a deterministic traffic generator, so every
partition is trivially separable: all scores are 1.0. These numbers
demonstrate the pipeline end-to-end but do **NOT** establish that
generalization to real, noisy, live traffic holds. Before any production
use the model must be re-trained and validated on real captured traffic
and held-out data; these artifacts are the baseline scaffold, not a
production classifier.

## Excluded (explicitly out of scope)

- security-posture classification, anomaly detection, hyperparameter search,
  a live correlation/response engine, and any modification of the two
  protected datasets or the live capture path. Live 100-ms inference itself
  IS implemented (adapter above); an always-on scoring daemon and the
  ML→correlation wiring are deployment/downstream phases, not part of this
  ML layer.