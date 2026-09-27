# Documentation

All project documentation lives here. `README.md` in the repository root remains the
entry point for the testbed itself (deploy, verify, tear down).

## `verification/` — what was checked, and what the result was

| Document | What it is |
|----------|------------|
| **[FINAL_VERIFICATION_REPORT.md](verification/FINAL_VERIFICATION_REPORT.md)** | **Start here.** Current scope, architecture, verified path, evidence chain, findings, limitations, and reproduction commands. |
| [IMPLEMENTATION_STATUS_AUDIT.md](verification/IMPLEMENTATION_STATUS_AUDIT.md) | Historical engineering audit log. Records how each finding was found, reproduced and fixed. Kept for provenance; superseded by the final report for current status. |
| [E2E_VERIFICATION_REPORT.md](verification/E2E_VERIFICATION_REPORT.md) | Containerlab end-to-end run: deploy, XFRM/strongSwan state, traffic matrix. |
| [ACCEPTANCE_REPORT.md](verification/ACCEPTANCE_REPORT.md) | Campaign acceptance matrix across tunnel/transport and IPv4/IPv6. |
| [CORRELATION_LAYER_VERIFICATION_REPORT.md](verification/CORRELATION_LAYER_VERIFICATION_REPORT.md) | Correlation layer contract verification. |
| [LIVE_V2_FEATURE_PIPELINE_REPORT.md](verification/LIVE_V2_FEATURE_PIPELINE_REPORT.md) | 100 ms live feature pipeline and 59-column v2 schema verification. |
| [MULTI_SA_VERIFICATION_REPORT.md](verification/MULTI_SA_VERIFICATION_REPORT.md) | Multi-SA / multi-tunnel correlation on a real shared-UDP/4500 gateway: per-SA resolution, windowing, ML results, ambiguity handling, and the audit-identity regression that was found and fixed. |
| [ML_ARCHITECTURE_CONFORMANCE_REPORT.md](verification/ML_ARCHITECTURE_CONFORMANCE_REPORT.md) | Model artifact contract, load→predict parity, SHAP non-interference. |
| [DATASET_V2_REGEN_VALIDATION_REPORT.md](verification/DATASET_V2_REGEN_VALIDATION_REPORT.md) | Dataset v2 regeneration validation. |
| [V1_DATASET_CLEANUP_REPORT.md](verification/V1_DATASET_CLEANUP_REPORT.md) | v1 dataset cleanup record. |
| [MODULE4_REPORT.md](verification/MODULE4_REPORT.md) … [MODULE10_LIVE_VALIDATION_REPORT.md](verification/MODULE10_LIVE_VALIDATION_REPORT.md) | Per-module implementation and validation reports (modules 4–8, 10). |
| [INSTALLATION_AUDIT.md](verification/INSTALLATION_AUDIT.md) | Installation-path audit. |
| [DOWNSTREAM_PIPELINE_AUDIT.md](verification/DOWNSTREAM_PIPELINE_AUDIT.md) | Downstream pipeline audit. |
| [ML_IMPLEMENTATION_AUDIT.md](verification/ML_IMPLEMENTATION_AUDIT.md), [ML_LAYER_AUDIT.md](verification/ML_LAYER_AUDIT.md) | ML layer audits. |
| [DATASET_GENERATE_AUDIT_REPORT.md](verification/DATASET_GENERATE_AUDIT_REPORT.md), [UI_DATASET_GENERATOR_V2_AUDIT.md](verification/UI_DATASET_GENERATOR_V2_AUDIT.md) | Dataset-generator audits. |

## `architecture/` — how the system is designed

| Document | What it is |
|----------|------------|
| [SCHEMA.md](architecture/SCHEMA.md) | Data contract for dataset/state/window/result schemas. |
| [MODULE9_DESIGN.md](architecture/MODULE9_DESIGN.md) | Topology-reuse decision table and dataset reuse design. |
| [ML_CORRELATION_BOUNDARY.md](architecture/ML_CORRELATION_BOUNDARY.md) | The ML ↔ correlation boundary contract. |
| [MULTI_SA_CORRELATION.md](architecture/MULTI_SA_CORRELATION.md) | Passive SA identity, the resolver, per-SA windowing and observed state, ambiguity handling, and the backward-compatibility rules. |
| [ML_ARCHITECTURE_CONFORMANCE.md](architecture/ML_ARCHITECTURE_CONFORMANCE.md) | Target ML architecture and the model-metadata contract. |
| [STATE_CONSTRUCTION.md](architecture/STATE_CONSTRUCTION.md) | How observed state is constructed from raw events. |
| [DATASET_ML_ANALYSIS.md](architecture/DATASET_ML_ANALYSIS.md) | Dataset analysis feeding the model. |

## `reports/` — implementation and change reports

Dataset generation/cleanup, ML data collection, ML implementation, frontend relabel,
and UI/testbed integration reports. These are chronological records of work done; for
current status see the final verification report.

## `development/` — how to work on this repository

Repository layout, environment setup, test commands, and cleanup conventions.
See [development/REPOSITORY_GUIDE.md](development/REPOSITORY_GUIDE.md).
