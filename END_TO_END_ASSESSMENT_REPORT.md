# End-to-End Assessment Report

**Milestone:** end-to-end integration and acceptance of the completed Chain-of-Custody
Explainability, Lightweight Mission Context, and Drift-Aware Security Assessment
capabilities.

**Status:** accepted. 63 new tests, 0 failures. Full repository: **2163 passed,
22 skipped, 0 failed, 2454 subtests passed**.

**Scope:** integration only. No detection logic was invented, no existing engine was
replaced, no frontend was started, no dependency was added, and no ML/AnI component was
introduced.

---

## 1. What was actually wrong

The three previous milestones were each accepted on their own terms, and each was correct.
The problem was that they had never been required to work *together*.

Tracing the production path before writing any code found exactly one real gap.

`AssessmentStore` computed a genuine `DriftAssessment` and attached it to the plan-based
assessment as **context**. But `build_chain_of_custody` resolves a finding only from the
assessment that was registered:

```python
# correlation/api/store.py, before this milestone
drift = assess_drift(self.baselines.get(self.baseline_id), observed, ...)
self.drift_inputs[assessment_id] = drift
bundle["drift"] = drift.to_dict()          # context only
# ... and nothing registers drift.risk anywhere
```

So a drift finding was scored, real, and unreachable. Reproduced before the fix:

```
finding ids the store can explain: ['RISK-ADDRESS-FAMILY-MISMATCH', 'RISK-ML-CLASSIFICATION',
  'RISK-PFS-DISABLED', 'RISK-WEAK-DH-GROUP', 'RISK-WEAK-ESP-CRYPTO']
drift finding ids produced:       []
REACHABLE VIA CUSTODY: NONE  <-- integration gap
chain_of_custody -> KeyError '...:3:band-medium:RISK-DRIFT-ESP-PRESENCE'
```

The vertical slice was severed between "drift finding" and "chain of custody". Everything
downstream — evidence, integrity, mission context, the explanation endpoint — was already
built and tested, but none of it could ever be reached by a drift finding.

## 2. The path, traced before it was changed

| Stage | Component | Produces |
|---|---|---|
| Plan materialization | `correlation.adapters.ExpectedStateAdapter` | `ExpectedState`, `CorrelationIdentity` |
| Observation | `correlation.artifacts.load_observed_state` | `ObservedState`, `ArtifactRecord` |
| Baseline | `correlation.drift.validate_baseline` | `ValidatedBaseline` (state digest + seal) |
| Drift comparison | `correlation.drift.assess_drift` | `DriftAssessment` |
| Drift risk | existing `RiskEngine`/`RiskPolicy`/`score_findings` | `RiskAssessment`, `RiskFinding` |
| Explanation | `correlation.xai.ExplainabilityEngine` | `ExplainabilityResult` |
| Recommendation | `correlation.response.planner.plan` | `ResponseRecommendation` |
| Bundle / table row | `correlation.api.adapters` | `assessment_bundle`, `header_view` |
| Mission context | `correlation.mission.mission_context` | `MissionContext` |
| Custody | `correlation.custody.build_chain_of_custody` | `ChainOfCustody` |
| Evidence | `correlation.models.evidence.EvidenceRef` | digest-verified links |
| API | `correlation.api.custody_routes`, `drift_routes` | JSON payloads |

Two verifications were done first, before any change, to establish that the existing
components already accept a drift-origin assessment unchanged:

- `ExplainabilityEngine().explain(drift.risk, ...)` → OK
- `plan_response(PlanningContext(assessment=drift.risk, ...))` → OK, producing
  `RISK-DRIFT-ESP-PRESENCE` (HIGH) and `RISK-DRIFT-AH-PRESENCE` (MEDIUM)

So no new engine, adapter or abstraction was needed. The fix was composition.

## 3. The integration

**A drift finding is now registered as a first-class assessment**, the same way any other
assessment is, under a derived slot:

```
dataset-20260924-003710:3:band-medium          # plan-based, carries the drift as context
dataset-20260924-003710:3:band-medium-drift    # the drift comparison, as an assessment
```

The registration path was extracted into one shared `_register` method used by both, so
there is exactly one implementation of "an assessment becomes visible". The drift-origin
assessment therefore inherits the bundle, the table row, the custody chain, the evidence
verification, the mission context and both explanation routes — because it *is* an
ordinary assessment, not a special case.

It is registered **only when the comparison produces findings**. `no_drift`,
`not_configured` and `indeterminate` carry no `RiskAssessment`, so they add nothing to the
surface. A store built with no baseline behaves exactly as it did before drift existed.

The current observation is declared for one slot only, so the recorded capture remains the
observed state of the plan-based assessment. The pipeline was not rerouted.

## 4. The scenario

### 4.1 What is real

| | |
|---|---|
| Baseline source | `results/e2e-verification/parser/tunnel_v4/state.jsonl` |
| Its SHA-256 | `0cefd78120fa3e61ab98ea423a533d38da2471717d3099c43f10031011f5214a` |
| Baseline id | `baseline-e2e-tunnel-v4` |
| Validated by / at | `sec-ops@ipsec-testbed` / `2026-09-20T09:00:00Z` |
| Baseline state digest | `460f2b4b5f53982b3ca1ec583815cc1d27c700165ff15a28cc812f336105b7c3` |
| Baseline seal (first 16) | `7decc33d4c15d3e6` |

### 4.2 What is controlled, and is labelled

No recorded capture in this repository contains a security-state change. Every usable
recorded state artifact produces the **same** canonical state digest
`460f2b4b5f53982b3ca1ec583813cc1d27c700165ff15a28cc812f336105b7c3` — `tunnel_v4`,
`tunnel_v6inner`, and all six `results/observed-state/live_state_from_{events,windows}_*`
artifacts, 8 in total. (A ninth, `transport_live_reverify`, is not loadable at all: the
loader rejects it because `last_esp_timestamp_ns` postdates the snapshot it claims to
summarize. That is an integrity refusal, not a differing posture.) A drifted demonstration
therefore cannot be built from recorded data, and was not.

| | |
|---|---|
| Current state | `tests/fixtures/drift/ah_substitution_state.jsonl` |
| Its SHA-256 | `496ea12e91f1d16cea11de268ccc38e9a87b68120fceb06134f1a0d17deb2858` |
| Its provenance | `tests/fixtures/drift/ah_substitution_provenance.json` |
| Declared kind | `disclosed_derived_observation` |
| Derived from | `results/e2e-verification/parser/tunnel_v4/state.jsonl` |
| Current state digest | `ccaed704121592f35d0af7ca1f745cd2778316ee0d0425fbcd22990e00aa3b2a` |

Three separate mechanisms keep it from reading as a capture:

1. **A typed input.** `DriftCurrentObservation` is deliberately *not* a `RecordedObservation`.
   Whether the current state was captured or declared is carried in the type, not a flag.
2. **A structured declaration.** `DriftCurrentSource` publishes
   `kind: "declared_observation"`, `is_capture: false`, the producer's own
   `declared_kind`, and the producer's verbatim "this is NOT a packet capture" statement.
   The model refuses a source that claims to be a declared observation *and* a live capture.
3. **Exclusion from the capture evidence channel.** `evidence_ref_for` types an artifact by
   extension, so a `.jsonl` would be published as a live XDP state artifact. The fixture is
   deliberately **not** given an `EvidenceRef`; it appears only in the provenance list under
   role `controlled_drift_observation`. The two evidence references in the chain are both
   the real recorded capture.

Additionally, `DriftCurrentObservation.__post_init__` re-hashes the artifact and **refuses to
construct** if it no longer matches the digest attached to it. Nothing is silently repaired
or re-derived to make a mismatch disappear.

### 4.3 The comparison

| Variable | Baseline | Current | Severity | Finding |
|---|---|---|---|---|
| `esp.presence` | `true` | `false` | HIGH | `RISK-DRIFT-ESP-PRESENCE` |
| `ah.presence` | `false` | `true` | MEDIUM | `RISK-DRIFT-AH-PRESENCE` |
| `address_family` | `ipv4` | `ipv4` | — | unchanged |

Status `drift`, category `configuration_drift`, rule `drift.configuration`, technical score
**30 / HIGH** — scored by the existing risk engine under the existing policy. No drift
scoring scale was added.

## 5. Provenance: every field under the source that established it

| Claim | Filed as | Source |
|---|---|---|
| the validated baseline | `CONFIGURED` | `correlation.drift registry` |
| the current security state | `OBSERVED` | `correlation.drift canonicalization of ObservedState` |
| the changed fields | `DERIVED` | `correlation.drift (drift-model-v1)` |
| what kind of artifact the current state is | `CONFIGURED` | `correlation.drift (drift-model-v1)` |
| the expected plan values | `EXPECTED` | the materialized plan |
| the response action | `RECOMMENDED` | `ResponseRecommendation.action` |
| asset role / criticality / impact | `CONFIGURED` | `operator_supplied_asset_mission_profile` |
| the contextualized risk | `DERIVED` | `operator_supplied_asset_mission_profile via mission-context-v1` |

19 facts, each with a `value`, a `value_digest` and a `source`. Nothing is carried only as
prose.

**The ML/XAI boundary holds.** No drift fact is sourced from the model, and an assessment
carrying an ML result produces the same `finding_digest`, the same score and the same drift
status as one without — asserted directly, not inferred from the absence of a finding.

## 6. Integrity and tampering

Twelve integrity checks are published on that chain: **10 pass, 1 fails, 1 is
`unavailable`**. Neither exception is a pass:

```
pass  finding.record_digest                     evidence.artifact_digests
pass  observation.authoritative_value_present   provenance.artifact_digests
pass  xai.non_authoritative                     mission.context_declared
pass  mission.risk_preserves_technical         drift.baseline_explicit
pass  drift.fields_within_declared_scope        drift.current_source_declared_not_captured
fail  observation.expected_observed_coherent    <- DEFECT, see below
unavail audit.chain_linked                      <- no audit event supplied
```

`audit.chain_linked` is `unavailable` because this store is built without an
audit event, so the chain is not anchored in the tamper-evident journal. That is
an honest "cannot be checked", not a green tick.

`observation.expected_observed_coherent` **fails, and the failure is a real
defect in this milestone's integration, not a property of the drift claim.**
`correlation/api/store.py` registers the drift-origin assessment with
`observed=<the declared fixture>` but `correlation=<the plan comparison, built
from the recorded capture>` — two different observations. The custody layer
reads its OBSERVED facts from the correlation rows, so the same chain publishes

```
observed.esp_presence  True   [OBSERVED / authoritative_observation]
derived.drift_changed_fields  esp.presence: baseline=True -> current=False
```

i.e. it simultaneously asserts that ESP was observed present and that ESP
drifted from present to absent. The integrity check is right; the pairing is
wrong. Tracked in `NOVEL_FEATURE_ACCEPTANCE_REPORT.md`; not fixed here.

Verified behaviours:

- Both evidence references re-hash to their recorded digests
  (`artifact_sha256 == actual_sha256`, `verification_status: valid`).
- **Tampering is detected.** Replacing a finding's evidence digest with `0…0` makes that
  link `invalid`, the claimed digest is reported as claimed (never quietly corrected), the
  real digest is reported alongside it, `evidence.artifact_digests` becomes `fail`, and the
  ref's own `verify()` still returns `invalid`. Nothing is rewritten.
- **Skipping verification is not passing.** With `verify_evidence=False` the check does not
  report `pass` and no link reports `valid`.
- The comparison stayed inside its declared scope: only the three comparable fields are
  compared, and only two differ.

## 7. Two asset contexts, one technical reality

Both runs use the same baseline, the same declared current observation, the same evidence
and the same digests. Only the declared asset context differs.

| | `gw-a` (development) | `gw-b` (operational-communications) |
|---|---|---|
| criticality / mission impact | low / low | high / high |
| Technical risk | **30 HIGH** | **30 HIGH** |
| Contextualized risk | **30 HIGH** | **45 CRITICAL** |
| Multiplier | 10000 bp (neutral) | 15000 bp |
| `finding_digest` | `6d4225301e3ba8457957f88be9d9514a7e65f5ecf919f5bb169d89221ec2835d` | **identical** |
| `observed_state` | identical | identical |
| `baseline` | identical | identical |
| `drift` | identical | identical |
| `finding` | identical | identical |
| `technical_risk` | identical | identical |
| `evidence` | identical | identical |
| `sources` | identical | identical |

Byte-identical across the two assets: `drift`, `evidence`, `sources`, `finding_id`, `rule`,
`risk_score`, `risk_severity`, `severity`, `category`, `title`, `steps`, `identity`,
`audit_event_ids`, `audit_linkage_status`, `read_only`, and every component/version field.

Allowed to differ, and only these:

- the `mission_context` section,
- 5 of 19 facts — `asset.asset_id`, `asset.criticality`, `asset.mission_impact`,
  `asset.role`, `derived.contextualized_risk` — none of which is filed as `OBSERVED`,
- 1 of 8 limitations — the one that names the declared role, criticality and mission
  impact. The other 7 are shared verbatim.
- 2 of 12 integrity checks — `mission.context_declared` and
  `mission.risk_preserves_technical` — which correctly name the declared asset and the
  contextualized score, and which reach the same verdict.

The other **10** integrity checks are byte-identical, so the technical integrity result
cannot be moved by an operator's asset declaration.

An undeclared asset (`gw-undeclared`) reports `not_configured`, keeps the technical risk at
30, and produces the **same** `finding_digest` — the asset declaration is provably not part
of the technical record.

Mission context is never inferred: `inferred_from_traffic: false`,
`derived_from_observation: false`, and the profile file's real digest
`515e03fb9b79ba266ce6a6cc01467c987e35db68853e71043e68954b11a8495a` is published.

## 8. API and contract

Served by the **existing** read-only routes — no new endpoint was invented:

| Route | Serves |
|---|---|
| `GET /api/v1/assessments/{id}/findings/{fid}/explanation` | the full chain for `RISK-DRIFT-ESP-PRESENCE` |
| `GET /api/v1/findings/{fid}/explanation` | the same chain, disambiguated |
| `GET /api/v1/assessments/{id}/drift` | the comparison, with the source declaration |
| `GET /api/v1/drift` | the run-level surface, with per-assessment source kinds |

The assessment table row names the declared nature of the data before anything is opened:
*"…the current state is a disclosed derived fixture, not a capture of a live device"*.

The drift summary now publishes `current_source_kinds`, and per assessment
`current_source_kind` / `current_source_is_capture` / `entry_kind` /
`parent_assessment_id`, plus `comparison_count`, `assessment_count` and
`drift_origin_count` so the 13 assessments reporting 3 distinct comparisons is not
misreadable. `status_counts` remains the per-assessment contract it always was.

OpenAPI gained a `DriftCurrentSource` schema and the new summary fields. The document still
contains exactly three drift paths.

## 9. The no-drift control

The same store with the recorded capture compared against its own baseline:

- `status_counts: {"no_drift": 10, "indeterminate": 2}` — **no `drift`**
- no drift finding on any assessment
- no drift-origin assessment registered
- the comparison is still reported, with matching digests on both sides, so the absence of
  a finding is not the absence of a comparison
- the plan-based finding keeps its own technical risk, untouched
- the 2 `indeterminate` results are the assessments with no state observation at all, which
  are reported as neither drift nor agreement

## 10. The demonstration artifact

`results/end-to-end-assessment/accepted_drift_demo.json`, generated by
`scripts/write_end_to_end_demo.py` — written from the live pipeline output, never
hand-authored, so it cannot drift from reality. It contains both asset chains, the drift
summary, the control case, and an explicit `data_status` block separating the real recorded
capture (`is_capture: true`) from the controlled fixture (`is_capture: false`). No host path
appears anywhere in it.

Regenerate with:

```
.venv/bin/python scripts/write_end_to_end_demo.py
```

## 11. Regression

| Run | Result |
|---|---|
| New suite | `tests/test_end_to_end_assessment.py` — 63 passed |
| `tests/` | **1589 passed, 7 skipped, 7 warnings, 1878 subtests** |
| Full repository | **2163 passed, 22 skipped, 10 warnings, 2454 subtests** |

Before this milestone: 2100 passed, 22 skipped, 2453 subtests. Delta is exactly +63 tests
and +1 subtest. Skips unchanged at 22; the 10 warnings are the pre-existing `shap`
deprecation warnings and are unrelated.

Focused milestone regression, all green:
`test_drift_detection` + `test_mission_context` + `test_chain_of_custody` +
`test_api_store` + `test_analytics_api` + `test_api_routes` → 400 passed, 730 subtests.

## 12. What this does not establish

- **The drifted side is not a capture.** It is a disclosed derived fixture, labelled as such
  in the type, in the payload, in the table row and in the published artifact. No recorded
  capture in this repository exhibits a security-state change.
- **Drift scope is still three fields.** `address_family`, `esp.presence`, `ah.presence`. No
  cipher, DH group, PFS, IKE version, integrity algorithm, firmware, implementation,
  traffic-behaviour or ML drift is detected, because the authoritative observation path
  reports no such value.
- **The comparison establishes a difference, not intent.** Not attribution, not whether the
  change was authorized.
- **Mission context is an operator assertion.** `gw-a` and `gw-b` are declared profiles, not
  measurements; the contextualized 30 and 45 are consequences of that declaration.
- **A registered baseline can be wrong.** A baseline is a declaration that a state was
  validated; drift detects departure from it, not that the baseline was the right thing to
  have validated.
- **One comparison, two reports.** `13` assessments report `3` distinct comparisons. The
  surface publishes both numbers and says which assessments are the drift-origin alias.

## 13. Changes made

| File | Change |
|---|---|
| `correlation/api/store.py` | `DriftCurrentObservation`; shared `_register`; `_attach_drift`; drift-origin assessment registration; `drift_parent`; source-kind and comparison-count reporting in `drift_summary`; `build_store` forwarding |
| `correlation/drift/comparison.py` | `DriftCurrentSource`; `DriftAssessment.current_source`; `assess_drift(current_source=…)` |
| `correlation/drift/models.py` | `DRIFT_SOURCE_KIND_RECORDED` / `DRIFT_SOURCE_KIND_DECLARED` |
| `correlation/drift/__init__.py` | new public names |
| `correlation/custody/builder.py` | `configured.drift_current_source` fact; `drift.current_source_declared_not_captured` check; declared-source limitation |
| `correlation/api/openapi.py` | `DriftCurrentSource` schema; new summary fields |
| `tests/test_end_to_end_assessment.py` | 63 acceptance tests |
| `scripts/write_end_to_end_demo.py` | artifact generator |

**Not modified:** `controller/api.py`, `frontend/`, `requirements.txt`,
`correlation/models/observed.py`, `correlation/comparison.py`, `correlation/risk/`.
No new dependency, no new server, no database, no ML model, no detection logic.

## 14. Reproducing

```bash
.venv/bin/python -m pytest tests/test_end_to_end_assessment.py -v
.venv/bin/python scripts/write_end_to_end_demo.py
.venv/bin/python -m pytest -q
```
