# Security Analysis Capability Table

**Scope.** This document reflects the **current backend analytical foundation** of
the IPsec testbed: the producers, the evidence they read, the states they emit,
the API routes that expose them, and the tests that pin them. Frontend work is
**intentionally out of scope** for this document; no capability below is claimed
on the basis of a UI.

**Status source.** Full suite run on the tree that contains this file:
`2109 passed, 11 skipped, 1 failed, 4515 subtests passed` (the single failure is
the pre-existing
`tests/test_ai_dotenv.py::TestRepositoryEnvFile::test_the_repo_env_file_has_no_populated_gemini_key`,
unrelated to analytical behaviour). Targeted run of the capability suite:
`tests/test_security_products.py` → `74 passed, 1257 subtests passed`.

**Invariants these capabilities share**

| Invariant | Enforced by |
|---|---|
| One producer per product; no parallel implementation | `correlation/analysis/` (one module per area), `correlation/api/store.py::build_analysis_products` |
| Every analytical value carries a `state`, a `source`, a `reason`, and `limitations` | `correlation/analysis/states.py::validate_state` |
| `UNKNOWN` / `NOT_AVAILABLE` / `NOT_APPLICABLE` never become a negative finding | `correlation/analysis/states.py::UNESTABLISHED_STATES`; risk engine is the only scorer |
| A sequence gap is never replay evidence | `correlation/analysis/replay.py`, `correlation/risk/rules.py::rule_replay_duplicate_sequence` |
| A configured value is never echoed back as a runtime value | `correlation/analysis/crypto_evidence.py` (`runtime_value` stays `null` while `state == UNKNOWN`) |
| Score is produced only by `correlation/risk/scoring.py` | contributions attached per finding by `correlation/risk/engine.py::_attach_scores` |
| Every analytical product carries `producer`, `state`, `reason` and `source` | `correlation/api/adapters.py::with_analytical_contract` + `PRODUCT_PRODUCERS`, applied to all 12 products in `correlation/api/store.py::build_analysis_products` |
| Every live route is documented and every documented route is routable | `correlation/api/openapi.py::openapi_document`; `tests/test_analytics_api.py::TestOpenApiDoesNotDrift`; `tests/test_mission_context.py::test_no_new_route_was_introduced` |

**State vocabulary** (`correlation/analysis/states.py`):
`OBSERVED`, `CONFIGURED`, `INFERRED`, `ASSESSED`, `UNKNOWN`, `NOT_AVAILABLE`,
`NOT_APPLICABLE`. Replay additionally uses the brief's own status vocabulary:
`OBSERVED`, `NO_EVIDENCE`, `INSUFFICIENT_DATA` (`correlation/analysis/replay.py`).

---

## 12-area capability table

| # | Capability | State / answer | Single-source producer | Evidence | API route | Tests |
|---|---|---|---|---|---|---|
| 1 | Security associations: establishment, direction, first/last packet, sequence progression, lifetime/rekey, age | `OBSERVED` (packets, direction, first/last, sequence), `INFERRED` (age), `NOT_AVAILABLE` (lifetime, rekey, SA identity — `sa_snapshot()` records none) | `correlation/analysis/sa.py::analyze_sa` (`correlation/analysis/sa.py:328`) | state-builder snapshot; per-association reason names `ebpf/ipsec_state_builder.py::sa_snapshot()` | `GET /api/assessments/{id}/sa` | `tests/test_security_products.py::TestArea1SecurityAssociations` (6) |
| 2 | Runtime cryptographic evidence: encryption, integrity, DH group, PFS, IKE version, tunnel/transport mode | Five wire-invisible properties: `configured_value` + `state=UNKNOWN` + `runtime_observable=false` + `evidence_source=configuration`; mode `OBSERVED` only when `ObservedState.mode` came from `swanctl --list-sas` | `correlation/analysis/crypto_evidence.py::analyze_crypto_evidence` (`:181`) | expected configuration vs recorded SA report | `GET /api/assessments/{id}/crypto-evidence` | `::TestArea2RuntimeCryptoEvidence` (4) |
| 3 | Replay analysis: status, duplicates, backward steps, gaps, evidence level, per-SPI detail | `OBSERVED` / `NO_EVIDENCE` / `INSUFFICIENT_DATA`; levels `PER_PACKET` / `AGGREGATE` / `ABSENT`; product `state` = least-established per-SPI state; gaps counted and never replay evidence | `correlation/analysis/replay.py::analyze_replay` (`:426`) | per-packet journal (exact) or state-builder aggregates (`duplicate_sequences=null`, not `0`, when exact counting is impossible) | `GET /api/assessments/{id}/replay` | `::TestArea3Replay` (8) |
| 3b | Replay finding + response | `replay.duplicate_sequence` / `RISK-REPLAY-DUPLICATE`, severity `LOW`, `score=6`, `state=OBSERVED`, `runtime_applicable=true`; fires only on `status=OBSERVED and duplicate_sequences>0`; response `RESP-REPLAY-009` → `REQUIRE_REVIEW`, approval required, never auto-executed | `correlation/risk/rules.py::rule_replay_duplicate_sequence` (`:492`), registered in `correlation/risk/policy.py::ALL_RULES`; `correlation/response/rules.py` + `correlation/response/policy.py::DEFAULT_RULE_OVERRIDES` | journal duplicate evidence passed to the engine as a mapping (`RiskEngine.assess(replay_evidence=...)`), never recomputed there (`metadata.replay_evidence.derived_by_this_engine=false`) | `GET /api/assessments/{id}/risk` | `::TestTheReplayRule` (10) |
| 4 | Metadata exposure: eleven observable dimensions + risk level | `OBSERVED`/`MEDIUM` when addresses + timing + volume are readable and payload is not; `NOT_AVAILABLE`/`NONE` with no observation; `NOT_AVAILABLE` (not recorded) kept distinct from `NOT_APPLICABLE` (does not apply); four-step documented ladder `HIGH`/`MEDIUM`/`LOW`/`NONE`; findings carry no severity and no score; two dimensions added here — `ike_esp_metadata` (presence only: protocol presence is observable, version/cipher/cookies are truthfully `NOT_AVAILABLE`) and `packet_direction` (per-SPI direction from the recorded SPI state) | `correlation/analysis/metadata.py::analyze_metadata_exposure` (`:246`) | state-builder fields, each dimension with its own evidence entry and reason | `GET /api/assessments/{id}/metadata-exposure` | `::TestArea4MetadataExposure` (5) |
| 5 | Correlation output enrichment | Every row exposes `verdict` (= `status`, the brief's name for it), `configured_value`, `state`, `runtime_observable`, `evidence_source` alongside the existing status; status→state mapping is fixed: `MATCH`/`MISMATCH`→`OBSERVED`, `UNKNOWN`→`UNKNOWN`, `NOT_APPLICABLE`→`NOT_APPLICABLE`; `observed_value is null` ⇒ `runtime_observable=false` | `correlation/api/adapters.py::_outcome_row` (`:188`) | Phase-4 outcomes + `evidence_refs` | `GET /api/assessments/{id}/correlation` | `::TestArea5CorrelationOutput` (4) |
| 6 | Finding contract | 22 keys always emitted, including `rule_id, category, severity, score, score_added, source, configured_value, state, runtime_applicable, evidence, reason, evidence_refs`; `to_dict()`/`from_dict()` round-trips exactly; `score_added` sums ≤ `overall_score` ≤ 100 | `correlation/risk/models.py::RiskFinding` (+ `correlation/risk/engine.py::_attach_scores`) | scorer contributions (`finding_id`-mapped; missing ⇒ `score_added=0`) | `GET /api/assessments/{id}/risk` | `::TestArea6FindingContract` (5) |
| 7 | Threat matrix | One row per risk finding plus one per metadata-exposure finding; categories `Cryptographic weakness`, `Configuration weakness`, `Protocol weakness`, `Traffic anomaly`, `Replay anomaly`, `Metadata exposure`, `Evidence gap`, `Unclassified threat`; severity copied verbatim and never recomputed; metadata rows have `severity: null` | `correlation/analysis/threat_matrix.py::build_threat_matrix` (`:282`) | finding evidence + `correlation/response/rules.py::RESPONSE_RULE_TRACEABILITY` for recommendations | `GET /api/assessments/{id}/threat-matrix` | `::TestArea7ThreatMatrix` (5) |
| 8 | Technical report | 14 numbered sections over the same products as the bundle; new §1 Executive summary (status, score, severity, finding count; no recomputation), new §13 Recommendations quoting every threat-matrix recommendation verbatim, §14 Evidence and provenance; `state=ASSESSED`; deterministic across rebuilds (byte-identical JSON) | `correlation/analysis/reports.py::build_technical_report` | bundle products + `sources` digests | `GET /api/assessments/{id}/report` | `::TestArea8TechnicalReport` (4) |
| 9 | Executive report | Five questions keyed by the brief's names, each `{question, state, statements, evidence, answered}`: `what_was_assessed`, `security_posture`, `major_risks`, `evidence_supporting_risks`, `what_should_be_fixed` | `correlation/analysis/reports.py::build_executive_report` | same products + response plan (`ResponsePlan`) | `GET /api/assessments/{id}/executive-report` | `::TestArea9ExecutiveReport` (4) |
| 10 | ML transparency | `present, model, model_version, predicted_class, classification_confidence, probabilities, classes, inference_status (NOT_EXECUTED / COMPLETED / INCOMPLETE), provenance, predicted_vs_policy (MATCH / MISMATCH / UNKNOWN / NOT_APPLICABLE / NOT_EVALUATED / PARTIAL)`; `classes` = the class names the probability vector is indexed by, emitted only when a full vector exists whose keys are exactly the six canonical traffic profiles (else `null`); `provenance.executed_by_this_backend=false` | `correlation/api/adapters.py::ml_to_view` (`:298`), `correlation/ml/controller_bridge.py::require_controller_result` | producer `extras` copied verbatim (`_ML_PROVENANCE_KEYS`) + `model_version` from `MLResult` | `GET /api/assessments/{id}/ml` | `::TestArea10MlTransparency` (5) |
| 11 | API consistency / front-end consumability | 15 sub-resources under one read-only family, each resolved to its bundle key through `SUB_RESOURCE_KEYS` (identity when absent), with a unique `operationId`, and a documented + routable OpenAPI path (48 paths / 48 operationIds, GET-only); unknown sub-resource → structured `unknown_resource` 404; every phase-8 200 now documents typed JSON component schemas — 41 schemas total, sub-resource responses narrow a shared `AssessmentSubResourceResponse` envelope to the named product, analytical products declare the Phase-1 contract keys as required, and the bundle route documents all 21 bundle keys | `correlation/api/routes.py` (`SUB_RESOURCES`, `SUB_RESOURCE_KEYS`), `correlation/api/openapi.py::openapi_document` | OpenAPI 3.1 served at `/api/v1/openapi.json` | all of the above | `::TestArea11ApiConsistency` (7), `tests/test_analytics_api.py::TestOpenApiDoesNotDrift`, `tests/test_mission_context.py::test_no_new_route_was_introduced` |
| 12 | Validation + traceability | This document; per-area tests, recorded-case invariants, determinism and route-count pins | `tests/test_security_products.py` (74 tests / 1257 subtests) | committed recorded artifacts only — no traffic generated, no testbed changes | — | see Validation status below |

### Sub-resource → bundle key map

| URL name | Bundle key | Product |
|---|---|---|
| `expected` | `expected` | configured state |
| `observed` | `observed` | recorded observation |
| `correlation` | `correlation` | Phase-4 comparison + enrichment |
| `risk` | `risk` | findings, score, metadata |
| `xai` | `xai` | explainability |
| `ml` | `ml` | ML transparency |
| `evidence` | `evidence` | evidence refs + sources |
| `ipsec-state` | `ipsec_state` | expected vs observed (alias of `observed`) |
| `sa` | `sa` | area 1 |
| `crypto-evidence` | `crypto_evidence` | area 2 |
| `replay` | `replay_assessment` | area 3 |
| `metadata-exposure` | `metadata_exposure` | area 4 |
| `threat-matrix` | `threat_matrix` | area 7 |
| `report` | `report` | area 8 |
| `executive-report` | `executive_report` | area 9 |

Bundle assembly: `correlation/api/store.py::build_analysis_products` (`:585`);
per-packet evidence selection: `sequence_journal_for` (`:554`) /
`ObservationEvidence` (`:530`) — a `.jsonl` capture is read as a journal, a
`.pcap` is not parsed, and the journal is added to `bundle["sources"]` only for
the assessment that actually read it (drift children rebuild from their own
current-state artifact and drop it).

---

## Recorded-case outcomes

Built from the committed artifacts through the normal store path
(`correlation/api/store.py::build_store()`); no traffic was generated.

| Case slot | Replay status | Evidence level | Duplicate sequences | SA state | Crypto state | Metadata | Findings | Score / band | Sources read |
|---|---|---|---|---|---|---|---|---|---|
| `band-strong` | `INSUFFICIENT_DATA` | `AGGREGATE` | `null` (not `0`) | `OBSERVED` | `UNKNOWN` | `OBSERVED` / `MEDIUM` | none | 0 / `INFO` | state + window |
| `band-good` | `INSUFFICIENT_DATA` | `AGGREGATE` | `null` | `OBSERVED` | `UNKNOWN` | `OBSERVED` / `MEDIUM` | none | 0 / `INFO` | state + window |
| `band-medium` | `INSUFFICIENT_DATA` | `AGGREGATE` | `null` | `OBSERVED` | `UNKNOWN` | `OBSERVED` / `MEDIUM` | `esp.dh_group.weak` | 6 / `LOW` | state + window |
| `band-weak` | `INSUFFICIENT_DATA` | `AGGREGATE` | `null` | `OBSERVED` | `UNKNOWN` | `OBSERVED` / `MEDIUM` | `esp.pfs.disabled` | 12 / `MEDIUM` | state + window |
| `band-worst` | `INSUFFICIENT_DATA` | `AGGREGATE` | `null` | `OBSERVED` | `UNKNOWN` | `OBSERVED` / `MEDIUM` | `esp.pfs.disabled`, `esp.encryption.cbc` | 24 / `HIGH` | state + window |
| `strong-clean` | `INSUFFICIENT_DATA` | `AGGREGATE` | `null` | `OBSERVED` | `UNKNOWN` | `OBSERVED` / `MEDIUM` | none | 0 / `INFO` | state + window |
| `pfs-weak` | `INSUFFICIENT_DATA` | `AGGREGATE` | `null` | `OBSERVED` | `UNKNOWN` | `OBSERVED` / `MEDIUM` | `esp.pfs.disabled` | 12 / `MEDIUM` | state + window |
| `tunnel-v4` | `INSUFFICIENT_DATA` | `AGGREGATE` | `null` | `OBSERVED` | `UNKNOWN` | `OBSERVED` / `MEDIUM` | none | 0 / `INFO` | state + window (pcap not parsed) |
| `tunnel-v6` | `INSUFFICIENT_DATA` | `AGGREGATE` | `null` | `OBSERVED` | `UNKNOWN` | `OBSERVED` / `MEDIUM` | `correlation.mismatch.address_family` | 12 / `MEDIUM` | state + window (pcap not parsed) |
| `transport-v6` | `NO_EVIDENCE` | `PER_PACKET` | `0` (clean, both SPIs monotonic) | `OBSERVED` | `UNKNOWN` | `OBSERVED` / `MEDIUM` | none | 0 / `INFO` | state + `events.jsonl` journal |
| `nat-t` | `OBSERVED` | `PER_PACKET` | `1` (SPI `0xcda30093`, seq 7 twice, separation `0.000193474` s) | `OBSERVED` | `UNKNOWN` | `OBSERVED` / `MEDIUM` | `replay.duplicate_sequence` | 6 / `LOW` | state + `live_events_full.jsonl` journal |
| `ml-mismatch` | `INSUFFICIENT_DATA` | — (no observation) | `null` | `NOT_AVAILABLE` | `UNKNOWN` | `NOT_AVAILABLE` / `NONE` | `esp.pfs.disabled`, `esp.encryption.cbc`, `ml.classification.disagreement` | 30 / `HIGH` | ML window only |
| `unknown` | `INSUFFICIENT_DATA` | — (no observation) | `null` | `NOT_AVAILABLE` | `UNKNOWN` | `NOT_AVAILABLE` / `NONE` | none (gap stays a gap) | 0 / `INFO` | none |

Invariants proven across every slot:

- `replay.duplicate_sequence` appears **iff** `replay_assessment.status == OBSERVED`
  and `duplicate_sequences > 0`; observed duplicates with no finding = failure.
- No finding is ever derived from an unrecorded SA lifetime/rekey/identity field.
- `risk.overall_score >= sum(finding.score_added)` and `<= 100`.
- Every product is present in every bundle with `producer`, `state`, `reason`,
  `source`, `limitations`, and every `state` is in the seven-state vocabulary.
- Two `build_store()` runs produce byte-identical `sa`, `crypto_evidence`,
  `replay_assessment`, `metadata_exposure`, `threat_matrix`, `report`,
  `executive_report`.

---

## Validation status

| Suite | Result |
|---|---|
| `tests/test_security_products.py` (capability suite, areas 1–12) | `74 passed, 1257 subtests passed` |
| Full suite: `timeout 2400 .venv/bin/python -m pytest tests/ -q` | **`2109 passed, 11 skipped, 1 failed, 4515 subtests passed`** |
| Pre-existing failure (unchanged by this work) | `tests/test_ai_dotenv.py::TestRepositoryEnvFile::test_the_repo_env_file_has_no_populated_gemini_key` |
| Lint / typecheck | none configured in this repository (no `ruff`, `flake8`, `mypy`, `pyproject.toml` tool table) |

Route and documentation pins: `tests/test_mission_context.py::test_no_new_route_was_introduced`
(base count 33 + 15 explicitly named read-only routes = 48),
`tests/test_analytics_api.py::test_every_documented_route_is_really_routable`,
`tests/test_analytics_api.py::test_every_live_route_is_documented`.
