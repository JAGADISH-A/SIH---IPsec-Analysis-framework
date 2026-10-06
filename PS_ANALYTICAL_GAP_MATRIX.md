# PS Analytical Gap Matrix

**Purpose.** Cross-reference the gaps found by the read-only PS → backend audit
(Phase 1) against what this pass implemented (Phase 2). For every item: whether
it is now *implemented*, *implemented and pinned by a test*, or *deliberately
deferred* — with the file, line and test that corroborates it. The source of
truth for "what PS demands" remains the brief (`/tmp/opencode/ps_brief.md` in
the audit session); nothing here re-states requirements from a changed source.

**Scope.** Backend analytical products and their API representation only.
Frontend work is out of scope (no frontend file was modified). No new scoring
path exists: `correlation/risk/scoring.py` remains the single scorer.

---

## Status legend

| Status | Meaning |
|---|---|
| `CLOSED` | Gap removed; behaviour implemented and pinned by at least one test. |
| `DEFERRED` | Known residual; kept explicitly, with reason and owner, rather than left silent. |

---

## P0 — remediated this pass

| Gap id | What PS asked for / what was missing | Status | Where implemented | How it is pinned |
|---|---|---|---|---|
| P0-1 | The delivered report is a data dump; PS's analyst document needs a report that leads with the assessment outcome and stays evidence-bound. Implemented: §1 *Executive summary* (status, score, severity, finding count, with an explicit no-recompute note) and §9 risk section which now carries *evidence* and *limitations* paragraphs (evidence policy, sorted unknown handling, non-runtime-applicable findings). | `CLOSED` | `correlation/analysis/reports.py` helpers `_executive_summary_paragraphs`, `_assessment_evidence_paragraph`, `_assessment_limitation_paragraphs`; section assembly in `build_technical_report` | `tests/test_security_products.py::TestArea8TechnicalReport` (heading pins for §1/§13/§14); `tests/test_api_routes.py::test_full_bundle_sections` |
| P0-2 | PS §9's five questionnaire items were not the keys the executive report used. Implemented: `EXECUTIVE_QUESTIONS` is now exactly `what_was_assessed, security_posture, major_risks, evidence_supporting_risks, what_should_be_fixed`; each answer carries `{question, state, statements, evidence, answered}`, and an unanswerable question is reported `answered: false` — never guessed. | `CLOSED` | `correlation/analysis/reports.py::EXECUTIVE_QUESTIONS`, `build_executive_report` | `tests/test_security_products.py::TestArea9ExecutiveReport` (all five keys asserted across every recorded bundle; old `what_action` key removed from all consumers) |
| P0-3 | When ML probabilities were exposed, the class names the vector is indexed by were not published. Implemented: `classes` is emitted for the full probability vector whose keys are exactly the six canonical traffic profiles and is `null` for every other ML result; `require_controller_result` records it in the normalized result too. | `CLOSED` | `correlation/ml/controller_bridge.py::require_controller_result`; `correlation/api/adapters.py::ml_to_view` | `tests/test_security_products.py::TestArea10MlTransparency::test_the_probability_vector_publishes_the_class_it_is_indexed_by` |

## P1 — remediated this pass

| Gap id | What PS asked for / what was missing | Status | Where implemented | How it is pinned |
|---|---|---|---|---|
| P1-1 | 17 phase-8 JSON routes documented their 200 with a bare `{"type": "object"}` or nothing; the API contract did not type its own payloads. Implemented: 26 new component schemas (41 total), the bundle route documents all 21 bundle keys, each of the 15 sub-resources narrows one shared `AssessmentSubResourceResponse` envelope to its named product, analytical products declare the Phase-1 contract keys as *required*, and `/api/health` answers with an `ApiHealth` schema. No route was added, removed or renamed. | `CLOSED` | `correlation/api/openapi.py` (schemas section; `_sub_resource_response`, `_product`, typed `_json_ok(schema=...)`) | 48 paths / 48 unique operationIds unchanged; `tests/test_security_products.py::TestArea11ApiConsistency` (typed-response, ref-resolution, product-schema↔payload, bundle-key↔schema); `tests/test_analytics_api.py::TestOpenApiDoesNotDrift` |
| P1-2 | Threat-matrix recommendations existed in the registry but never reached the analyst document. Implemented: new §13 *Recommendations (finding-specific remediation)* quotes every `threat_matrix.entries[].recommendation` verbatim and says so ("this report writes no remediation text of its own"); the placeholder path (`threat is None`) still emits a constructed paragraph so numbering never breaks. | `CLOSED` | `correlation/analysis/reports.py::_remediation_paragraphs` | `tests/test_security_products.py::TestArea8TechnicalReport::test_every_threat_matrix_recommendation_is_quoted_verbatim` |
| P1-3 | Metadata exposure covered 9 dimensions and said nothing about IKE/ESP header visibility or SPI-selected direction. Implemented: `ike_esp_metadata` (presence-only — protocol presence is `OBSERVED`, version/cipher/cookies/identity are truthfully `NOT_AVAILABLE`) and `packet_direction` (per-SPI direction from the recorded SPI state), total 11 dimensions. No new metadata findings: `nat-t` stays `risk_level MEDIUM` with 5 findings, so the threat matrix is unchanged. | `CLOSED` | `correlation/analysis/metadata.py` constants `IKE_ESP_METADATA`, `PACKET_DIRECTION` and their dimension builders | `tests/test_security_products.py::TestArea4MetadataExposure::test_eleven_dimensions_are_classified_for_a_recorded_capture` |
| P1-4 | Analytical products carried `state/reason/source` but not a single, explicit `producer`, and the contract keys were applied module-by-module instead of once. Implemented: `with_analytical_contract(view, *, product, state, reason, source)` stamps the four Phase-1 keys; `PRODUCT_PRODUCERS` names the 12 producers; the contract is applied in `assessment_bundle` (correlation, ml, risk, xai, evidence) and in `store.build_analysis_products` for the other 7 products; never overwrites a producer-recorded value. Sources were also sharpened per product. | `CLOSED` | `correlation/api/adapters.py::with_analytical_contract`, `PRODUCT_PRODUCERS`; `correlation/api/store.py::build_analysis_products`; `correlation/analysis/reports.py` imports cleaned | Verfied live: all 13 bundles × 12 products have non-empty `producer`, `state`, `reason`, `source` (0 missing). Pinned by `tests/test_security_products.py::TestArea11ApiConsistency::test_every_product_schema_matches_the_payload_it_documents` (contract keys are `required` in every analytical schema) |
| P1-5 | Correlation rows lacked PS's name for a row outcome. Implemented: `_outcome_row` adds `verdict` as the same canonical value as `status` — the same decision carried twice under both names, never a second verdict. | `CLOSED` | `correlation/api/adapters.py::_outcome_row` | `tests/test_security_products.py::TestArea5CorrelationOutput` (`verdict == status` asserted for every row of every bundle; `verdict` added to `REQUIRED_ROW_KEYS`) |

## P2 — deferred (explicit residuals)

| Gap id | Residual | Why deferred | Owner / fix path |
|---|---|---|---|
| P2-1 | Frontend route/prop/state cleanup (role strings, `path (None)` rendering in §12, danger-prefix ripple) | Out of PS backend scope; no frontend file was allowed to change this pass | Frontend follow-up; must not gate the backend contract |
| P2-2 | Threat-matrix precedence rationale documented (threat rows vs finding rows ordering) | Documentation-only; behaviour already deterministic and tested | `correlation/analysis/threat_matrix.py` docstring |
| P2-3 | A backward-sequencing recorded fixture | Test fixture gap, not a capability gap; the replay rule is implemented and unit-tested | Add a fixture under `tests/fixtures/` with a real backwards-sequence capture |
| P2-4 | A crypto-*observed* recorded fixture (an SA report that enables `mode == OBSERVED`) | Test fixture gap; producer path exists and is unit-tested | Add a recorded swanctl SA snapshot |
| P2-5 | `/api/v1/*` (phase-10) routes document only their error responses, no 200 schema | Those routes are a phase-10 surface disabled by default; typing them belongs to phase-10's own contract work | `correlation/api/openapi.py` phase-10 section |

---

## Residual-risk register (not gaps, honest boundaries)

These are boundaries the implementation states as data rather than hiding:

- A property the capture cannot observe reports its configured value next to a
  `NOT_AVAILABLE` state — never as if it had been seen
  (`correlation/analysis/crypto_evidence.py`).
- `ML` is model-derived inference (`state INFERRED` when present); it never
  overrides an observation and never reports a protocol fact
  (`correlation/api/adapters.py::ml_to_view`).
- A sequence gap is never replay evidence; `duplicate_sequences` is `null`
  (not `0`) when exact counting was impossible (`correlation/analysis/replay.py`).
- `risk_level` in metadata exposure is chosen by the published four-step ladder
  and carries no severity and no score — the risk engine is the only scorer.
- Executives: an absent answer is reported `answered: false`, never invented
  (`correlation/analysis/reports.py::build_executive_report`).

---

## Validation (this pass)

| Check | Result |
|---|---|
| OpenAPI document | 48 paths, 48 unique operationIds, 41 component schemas, 0 dangling `$ref`; every phase-8 200 typed |
| Route guards | 33 base + 15 named sub-resources = 48; unchanged from baseline |
| Capability suite | `tests/test_security_products.py` → `74 passed, 1257 subtests passed` (was 69 / 1179) |
| Full suite | `2109 passed, 11 skipped, 1 failed, 4515 subtests passed` (was 2104 / 4437); the single failure is the pre-existing `test_ai_dotenv.py` gemini-key check, unrelated |
| Determininism | Two `build_store()` runs produce byte-identical `report` and `executive_report` (still pinned) |
| Reports | `report.reason` auto-states "14 section(s)"; all five PS questions populated on `nat-t` |
| Files touched | `correlation/api/adapters.py`, `correlation/api/openapi.py`, `correlation/api/store.py`, `correlation/analysis/reports.py`, `correlation/analysis/metadata.py`, `correlation/ml/controller_bridge.py`, `tests/test_security_products.py` |

---

## Coverage statement

- **P0 + P1: 100% closed.** Every gap the audit elevated to P0 or P1 is
  implemented and pinned by a test in this pass.
- **P2 residuals are explicit, not silent**: each is listed above with a reason
  and an owner, and none of them is a missing analytical capability — they are
  frontend scope, documentation, or extra recorded fixtures.
- **The analytical contract claim is 100% within its own stated boundary**: the
  PS backend capability surface (products, states, evidence, single scorer,
  API representation, report and executive answers) is now implemented and
  described by typed, routable, drift-checked schemas.