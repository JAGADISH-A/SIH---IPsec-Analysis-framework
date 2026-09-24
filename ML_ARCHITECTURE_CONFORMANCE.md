# ML Architecture Conformance — Mapping

Date: 2026-09-24 · Audit of the **currently implemented ML layer only**
(classifier + split + artifact + SHAP). No unrelated architecture audited, no
code modified, no model retrained, datasets untouched.

Source architecture (Phase 0): the file `architecture.txt` named in the audit
brief **does not exist in the repository** (confirmed by
`ML_LAYER_AUDIT.md:18-19,297` — `find . -name 'architecture*'` empty). The
architectural ML scope quoted in the brief is therefore corroborated by the
existing boundary/audit documents (`ML_IMPLEMENTATION_AUDIT.md`,
`ML_CORRELATION_BOUNDARY.md`, `SCHEMA.md`) which reproduce the same flow:
Parser/Feature Engine → 100-ms windows → **ML/AI Engine {Traffic Type
Classification, Anomaly Detection}** → expected-vs-observed → XAI.

Implementation inspected: `controller/dataset_loader.py`,
`controller/grouped_split.py`, `controller/train_random_forest.py`,
`controller/evaluate_model.py`, `controller/shap_analysis.py`, tests
(`test_dataset_loader.py`, `test_grouped_split.py`, `test_ml_model.py`,
`test_shap.py`), artifacts under `results/ml/`, plus the ML-facing live
boundary in `controller/live_features.py` (read-only).

Status vocabulary (only these five are used):
`IMPLEMENTED`, `PARTIALLY IMPLEMENTED`, `MISSING`, `BLOCKED`,
`NOT YET INTEGRATED`.

## 1. Architecture → actual component matrix

| Architectural ML component | Required | Actual implementation | Status |
| --- | --- | --- | --- |
| ML / AI Engine | ML execution layer | Offline pipeline present: `dataset_loader → grouped_split → train_random_forest → evaluate_model → shap_analysis` producing `results/ml/{model_traffic_rf_v1.joblib, split_v1.json, train_report.json, eval_report.json, shap/*}`. No runtime/live inference entry point (no scoring daemon/endpoint). | PARTIALLY IMPLEMENTED (offline engine only; no runtime engine) |
| Traffic Type Classification | Required | 6-class classifier over `traffic_profile` (voip/video/messaging/email/web/icmp) trained from the two protected datasets (300 samples → X=(300,57)); semantics verified: features → predicted `traffic_profile` only (Phase 7). | IMPLEMENTED |
| Random Forest classifier | Implementation choice | `RandomForestClassifier(n_estimators=500, max_features="sqrt", min_samples_leaf=2, max_depth=None, class_weight="balanced_subsample", oob_score=True, random_state=7, n_jobs=-1)` verified from the saved artifact (`controller/train_random_forest.py:69-79`). | IMPLEMENTED |
| Anomaly Detection | Required architectural branch | Zero anomaly code: grep for `anomaly|score|threshold|detector` across `controller/ebpf/scripts/frontend` finds only explicit disclaimers (`ebpf/ipsec_state_builder.py:14`). No anomaly labels in the datasets, no detector, no score, no threshold, no tests. | BLOCKED / MISSING (Phase 10) |
| XAI | Required downstream explainability | `controller/shap_analysis.py` produces global/per-class/individual explanations on the trained RF; observational only. | IMPLEMENTED |
| SHAP | XAI implementation | `shap.TreeExplainer(model)` over the RF with the same 57 feature names; representation recorded (`ndarray(46,57,6)`, shap 0.52.0); non-interference verified (`predictions_equal: true`, `probabilities_equal: true`). | IMPLEMENTED |
| 100-ms input contract | Required input | Live producer emits the exact v2 59-feature record (`controller/live_features.py:228-237`) with structural/byte-exact parity to training (`summarize_capture` single source). No adapter feeds 100-ms windows into the RF; no inference call exists (Phase 11). | NOT YET INTEGRATED (live→model); the training-side 57-feature contract itself is IMPLEMENTED |

## 2. Boundary notes carried into the report

- `security_posture` remains a config-derived label generator
  (`posture_of_config`), never an ML target; not merged with `traffic_profile`.
- `accuracy = 1.0` is retained verbatim as the synthetic-deterministic
  benchmark; it is interpreted only as performance on this generated dataset.
- Anomaly Detection must not be inferred from RF confidence or SHAP magnitude.
- Live inference and downstream correlation wiring are integration phases, not
  defects of the offline ML engine — marked `NOT YET INTEGRATED`, not `MISSING`.

Full evidence matrix, per-phase findings and the final status block are in
`ML_ARCHITECTURE_CONFORMANCE_REPORT.md`.
