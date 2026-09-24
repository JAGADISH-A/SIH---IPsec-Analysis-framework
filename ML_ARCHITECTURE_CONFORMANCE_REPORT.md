# ML Architecture Conformance Report

Date: 2026-09-24 · Audit-only. Scope: **the currently implemented ML layer
only** (dataset loader → grouped split → Random Forest → evaluation → SHAP)
plus its ML-facing boundaries. No retraining, no dataset modification, no
anomaly detector created, no unrelated architecture audited, nothing
committed.

Note on `architecture.txt`: the file named in the brief **does not exist** in
the repository (independently confirmed at `ML_LAYER_AUDIT.md:18-19,297`); the
architectural ML scope quoted in the brief was corroborated against
`ML_IMPLEMENTATION_AUDIT.md`, `ML_CORRELATION_BOUNDARY.md` and `SCHEMA.md`,
which reproduce the same flow. Evidence below is cited from actual code,
artifacts and tests, not from documentation alone.

---

## Final matrix

| Component | Status | Evidence | Gap |
| ---------------------- | ------ | -------- | --- |
| ML input contract | IMPLEMENTED | Offline contract verified from code+parquet: `controller/dataset_loader.py:146-229` builds X (300,57) float64; parquet feature-column order == `FEATURE_COLUMNS` (59) for both runs; Arrow types 17 int32 + 42 double match `INT_FEATURES`/`FLOAT_FEATURES`; 0 nulls; NaN/Inf rejected (`validate_table`, `dataset_loader.py:91-132`); schema version pinned to `"v2"` (`dataset_loader.py:93-103`). Live record = 59-feature v2 + `feature_schema_version` + `window_start_ns/end_ns` (`live_features.py:228-237`). | Live→model adapter absent (separate row below); consumption of one-record-per-100-ms-window still an open live-path policy item. |
| 57-feature schema | IMPLEMENTED | `feature_names()` == `FEATURE_COLUMNS` minus exactly `{burst_packet_ratio, ike_packet_count}` with order preserved (`dataset_loader.py:35,146-148`); both constants verified single-valued ({1.0}, {4}) across both runs; `feature_schema_v2.json` lists the same 57; artifact `feature_names` identical to loader (verified programmatically). | None. |
| Dataset loader | IMPLEMENTED | All 12 required checks verified programmatically: loads only the 2 protected runs (`PROTECTED_DATASET_RUN_IDS`, `dataset_loader.py:28`); validates v2; uses `FEATURE_COLUMNS`; removes only the 2 constants; produces exactly 57; target `traffic_profile`; excludes `security_posture`, identifiers, `configuration_id`, `captured_at`, `feature_schema_version` (`LEAKAGE_COLUMNS`, `dataset_loader.py:50-60`); no `traffic_model` anywhere in code; rejects null/non-finite/wrong-type/unknown-label; deterministic ordering. `security_posture` can only enter X if it were in `FEATURE_COLUMNS` — it is not, and `columns` selection in `load_dataset` (`dataset_loader.py:170-171`) takes only the 57 named features. | None. |
| Grouped split | IMPLEMENTED | `results/ml/split_v1.json`: counts 212/42/46, `ratios` 70/15/15, `seed` 7, `strategy` grouped_stratified_greedy_by_configuration_id, `verification.group_isolation_ok: true`, `every_sample_once: true`, 0 spanning groups, all 6 classes in each partition; `split_hash` fbf04c32… embedded in artifact and cross-checked at evaluation (`evaluate_model.py:95-98`); CV runs on `x_train` only (`train_random_forest.py:125-135`); test used only in `run_evaluate`/`run_shap` (`evaluate_model.py:101`, `shap_analysis.py:51`). | None. |
| Random Forest | IMPLEMENTED | `RandomForestClassifier` with exactly: n_estimators=500, max_features="sqrt", min_samples_leaf=2, max_depth=None, class_weight="balanced_subsample", oob_score=True, random_state=7, n_jobs=-1 — verified from the saved artifact's `metadata.hyperparameters`, not from docs (`train_random_forest.py:69-79`). | None (offline training/serialization only; live scoring is the 100-ms integration row). |
| Traffic classification | IMPLEMENTED | Semantics verified: features → predicted `traffic_profile` with the 6 documented classes (`artifact.target_classes == ["voip","video","messaging","email","web","icmp"]`, `label_encoder` 0–5 ordered). No code path predicts `security_posture`, risk or policy action (grep: `predict|RandomForest` only in `train/evaluate/shap` ML modules). Architecture question — correct classification function — answered: yes. | Model quality is benchmark-only on synthetic data (accuracy 1.0 retained; see limitation). |
| Model artifact | IMPLEMENTED | `results/ml/model_traffic_rf_v1.joblib` contains `estimator, feature_names, feature_schema_version, target_classes, label_encoder, split_artifact, split_hash, input_fingerprints, metadata{git_commit, created_at, seed, library_versions, dataset_run_ids, sample_counts, hyperparameters, oob_score, cv, class_mapping}`. Load→predict contract tested: reload → same 57-feature vector → recomputed accuracy/macro-F1/confusion-matrix byte-equal to `eval_report.json`; `predict_proba` deterministic across calls; `test_ml_model.py::ArtifactContractTest` covers round-trip, missing-key rejection and real-artifact contract. | None. |
| Evaluation | IMPLEMENTED | `results/ml/eval_report.json` + `eval_report.md` + `confusion_matrix.png` from the untouched 46-sample test partition only; accuracy 1.0 / macro F1 1.0 / per-class 1.0 (supports 7/7/7/10/8/7); OOB and CV reported from train metadata, never recomputed on test (`evaluate_model.py:126-130`); split-hash mismatch raises (`evaluate_model.py:95-98`). Metric value preserved unchanged as required. | Interpreted only as synthetic-deterministic benchmark. |
| SHAP/XAI | IMPLEMENTED | `shap.TreeExplainer(model)` on the trained RF (`shap_analysis.py:122-123`) with the same 57 `feature_names`; global + per-class + individual explanations produced (`shap_importances.json`: `global_importance` top-20, `per_class_importance` top-15 × 6 classes, `individual_explanations` × 6 + 6 PNGs); class order preserved (`shap_values.npz` keys ordered voip…icmp; `target_classes` identical); representation recorded (`ndarray(46,57,6)`, shap 0.52.0); observational only — never predicts or overrides. | None. |
| SHAP non-interference | IMPLEMENTED | Runtime flags in `shap_importances.json`: `predictions_equal: true`, `probabilities_equal: true` (`shap_analysis.py:135-139`); dedicated test `test_shap.py::test_shap_does_not_change_model_outputs` asserts `predict_proba` and `predict` byte-equal before/after `shap_values`; both pass. | None. |
| Anomaly detection | BLOCKED / MISSING | No anomaly detector exists anywhere: grep `anomaly` across all `.py` → only the disclaimer `ebpf/ipsec_state_builder.py:14` ("no ML, anomaly detection, classification, risk scoring or XAI"). No anomaly model, training data, inference, score, threshold, evaluation or tests; the datasets carry no anomaly labels. RF classification is NOT anomaly detection; low RF confidence and SHAP magnitude are NOT used as anomaly scores. | Requires an anomaly-labelled dataset + detector design — out of scope for this audit and explicitly not implemented. |
| 100-ms ML integration | NOT YET INTEGRATED | The 100-ms producer exists and is contract-correct: `LiveFeatureExtractor.snapshot()` emits `{feature_schema_version, window_start_ns, window_end_ns, features{59}}` from the shared `summarize_capture` (`live_features.py:218-237`), byte-exact parity with training (`test_live_features.py`, `dataset_rebuild.py`). But: no code anywhere references the model outside the offline ML files (grep `model_traffic|predict|inference` → only `train/evaluate/shap` + tests); no adapter converts a live 59-feature record into the 57-column vector; no inference call; no per-window-one-record guarantee (epoch-granularity emission, `live_features.py:254-302`). ML model implemented ≠ ML model connected to live 100-ms inference — the latter does not exist. | Adapter (live record → 57-col vector → `estimator.predict`), per-window emission policy, and a test are all absent. |
| ML output contract | PARTIALLY IMPLEMENTED | Offline machine-readable outputs exist and are internally consistent: `train_report.json` (params, OOB/CV, class mapping, split counts, model sha), `eval_report.json` (metrics, confusion matrix, reproducibility incl. split_hash), `shap_importances.json` (representation, importances, non-interference, model sha) — all with stable JSON keys, cross-verified equal for split hash / fingerprints / git commit / library versions. What does NOT exist: a per-window verdict record (`predicted traffic_profile` + confidence + `model_version` + echoed `window_start_ns/window_end_ns` + non-authoritative marker), i.e. the schema a downstream correlator would consume. | Output record format and window-identity join fields undefined/unimplemented; offline reports are evaluations, not the runtime output contract. |
| Reproducibility | IMPLEMENTED | Chain verified end-to-end programmatically: on-disk `features.parquet` sha256 == fingerprints recorded in `split_v1.json` == artifact == `train_report` == `eval_report` (both runs); split_hash consistent across split doc/artifact/train/eval/SHAP; `train_report.model_artifact.sha256` == file sha == `shap_importances.model_artifact.sha256`; git commit `28beb6d…` and library versions (Python 3.14.4, numpy 2.5.3, scikit-learn 1.9.1, joblib 1.6.0, shap 0.52.0, matplotlib 3.11.2) equal in artifact and reports; seed 7 in split + artifact + train_report; deps pinned in `requirements.txt`. | None. |

---

## Per-phase verification detail (Phases 2–14)

- **Phase 2 (input contract):** verified from parquet, not docs — 69 columns
  (10 linkage + 59 features) in declared order in both runs; types 17×int32 /
  42×double; `feature_schema_version=v2` on every row; 0 nulls; X
  `(300, 57)` float64; no NaN/Inf; model input shape accepted by the saved
  estimator (57 features, artifact `feature_names` identical). Preprocessing:
  none (RF requires no scaling/imputation); validation = type/null/finiteness
  checks that fail closed. **Live/offline schema equality:** the *feature
  computation* is identical (single `summarize_capture`, byte-exact parity),
  so canonical live schema == training schema == model schema at the feature
  level; the live→model **connection** is `NOT YET INTEGRATED` (future phase,
  not a defect).
- **Phase 3 (loader):** 12/12 checks OK (see matrix row); `security_posture`
  membership test: not in `FEATURE_COLUMNS`, not in the loader's selected
  `columns`, listed in `LEAKAGE_COLUMNS`, asserted absent from
  `feature_names()` by `test_dataset_loader.py::test_leakage_columns_excluded`.
- **Phase 4 (RF):** 8/8 hyperparameters verified from artifact metadata;
  target is `traffic_profile` with the 6-class mapping verified (voip→0 …
  icmp→5); OOB computed by sklearn with `oob_score=True` (1.0). Judgment on
  the architecture question: the RF performs the intended traffic
  classification function correctly regardless of the synthetic 1.0 score.
- **Phase 5 (split):** 212/42/46 confirmed from `split_v1.json` (not
  recreated); group isolation, disjointness (partition masks sum to 300 with
  no overlap by construction of one label per experiment_id), test-untouched
  (CV indexed into `x_train` only), seed 7, persisted artifact + hash,
  all-six-classes per split — all verified.
- **Phase 6 (artifact contract):** required keys present; reload→predict
  reproduces exactly the reported test metrics (accuracy, macro F1,
  confusion matrix all byte-equal to `eval_report.json`); `predict_proba`
  deterministic; feature vector used is the same 57-column ordered vector.
- **Phase 7 (semantics):** output vocabulary is exactly the 6
  `traffic_profile` classes; no posture/risk/policy predictor exists;
  `ML_IMPLEMENTATION_REPORT.md` claims only classification + explainability
  and lists posture classification, anomaly detection and live inference as
  explicitly excluded.
- **Phase 8/9 (SHAP):** non-interference true at runtime + covered by
  dedicated test; representation recorded; class order preserved; no
  "causal / ground truth / second classifier / security decision / risk
  score" wording anywhere in `shap_analysis.py`, `shap_importances.json`,
  `ML_IMPLEMENTATION_REPORT.md` or `ML_ARCHITECTURE_CONFORMANCE.md` (grep
  clean); `shap_importances.json.limitation` states SHAP reflects this fixed
  generator's characteristics, not universal fingerprints; accuracy 1.0 kept
  verbatim and documented as synthetic-deterministic benchmark only
  (`ML_IMPLEMENTATION_REPORT.md` "limitation — synthetic data"). Metric not
  altered.
- **Phase 10 (anomaly):**
  `Anomaly Detection: BLOCKED / MISSING` — *Reason: no anomaly-labelled
  dataset/model/inference implementation is currently available.* Confirmed
  by repo-wide search (only a disclaimer matches). No RF-confidence or
  SHAP-based anomaly proxy exists or was invented.
- **Phase 11 (100-ms):** object = live v2 record (59 features, deterministic
  insertion order from `summarize_capture`); model requires the 57-column
  subset in `FEATURE_COLUMNS` order; **no adapter exists** between them and
  **no test** covers a live→RF path. `ML model implemented` and `ML model
  connected to live 100-ms inference` are distinguished: the former yes, the
  latter `NOT YET INTEGRATED`.
- **Phase 12 (ML→XAI→correlation):** ML currently exports offline
  JSON artifacts (metrics, feature list, class list, model sha, SHAP
  references) with stable keys; XAI consumes the same artifact/model
  (in-process, `ML → XAI: IMPLEMENTED`). No per-window prediction/confidence/
  model-version record keyed to `window_start_ns` exists, so the
  correlator-facing interface is `NOT YET INTEGRATED` (not `BROKEN`);
  downstream correlation engine untouched.
- **Phase 13 (tests):** ML-only suite: `pytest -q controller/test_dataset_loader.py
  controller/test_grouped_split.py controller/test_ml_model.py controller/test_shap.py`
  → **38 passed** (5.9 s). Full suite `pytest -q` → **512 passed, 15 skipped,
  576 subtests passed, 0 failed** (221 s). Known pre-existing flaky tests:
  `controller/test_dataset_api.py` acceptance/timing tests
  (`test_failed_attempts_do_not_increase_progress`,
  `test_post_target_500_accepted_if_below_maximum`) have failed
  intermittently in earlier runs but pass in isolation and passed in this
  full run — unrelated to the ML layer, unmodified by it. No unrelated test
  was changed.
- **Phase 14 (reproducibility):** every chain link verified equal
  (datasets → loader fingerprints → `split_v1.json` → artifact →
  `train_report.json` → `eval_report.json` → `shap_importances.json` → model
  file sha → git commit → library versions → seed 7); protected datasets
  unmodified.

---

## Final status block

```text
ML ARCHITECTURE STATUS

Traffic Classification:
IMPLEMENTED

Random Forest:
IMPLEMENTED

SHAP:
IMPLEMENTED

Anomaly Detection:
BLOCKED / MISSING

Reason:
No anomaly-labelled dataset/model/inference implementation is currently available.

100-ms → ML integration:
NOT YET INTEGRATED

ML → XAI:
IMPLEMENTED

ML → Correlation interface:
NOT YET INTEGRATED
```

## Constraint compliance

Audit-only: no code, dataset, feature-extraction or metric was modified;
accuracy 1.0 preserved as the synthetic benchmark; `security_posture` never
treated as an ML prediction; SHAP not treated as a classifier; anomaly
detection not implemented; live inference and correlation integration not
claimed; two new report files created (`ML_ARCHITECTURE_CONFORMANCE.md`,
`ML_ARCHITECTURE_CONFORMANCE_REPORT.md`); nothing committed.
