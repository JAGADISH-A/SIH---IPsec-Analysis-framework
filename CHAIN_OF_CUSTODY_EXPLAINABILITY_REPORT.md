# Chain-of-Custody Explainability — Implementation Report

**Scope:** a first-class, machine-readable chain of custody for every security
finding, served read-only through `correlation/api`.
**Status:** implemented and verified. 63 new tests; full suite 1349 passed, 7
skipped, 0 failed.

---

## 1. What was built

A new `correlation/custody/` package plus two read-only HTTP routes that answer
the auditor's question — *prove this finding to me* — for **all 9** findings the
recorded store produces.

| Concern | Implementation |
| --- | --- |
| Contract | `correlation/custody/models.py` — `ChainOfCustody` and its parts |
| Assembly | `correlation/custody/builder.py` — `build_chain_of_custody()`, a pure mapper |
| Retention | `CustodyInput` in `correlation/api/store.py` — the real pipeline objects |
| Transport | `correlation/api/custody_routes.py` — two handlers, no sockets |
| Dispatch | `correlation/api/v1.py` — route registration and ordering |
| Contract doc | `correlation/api/openapi.py` — both routes + a `ChainOfCustody` schema |
| Tests | `tests/test_chain_of_custody.py` (63 tests, 1049 lines) |

### New files
- `correlation/custody/__init__.py`
- `correlation/custody/models.py`
- `correlation/custody/builder.py`
- `correlation/api/custody_routes.py`
- `tests/test_chain_of_custody.py`

### Modified files (additive only)
- `correlation/api/store.py` — retains the authoritative objects; plans responses once
- `correlation/api/v1.py` — registers the two routes
- `correlation/api/openapi.py` — documents them
- `correlation/api/routes.py` — `ApiError` gains an optional `extra` mapping
- `tests/test_analytics_api.py` — two probes added to the drift list

`controller/api.py` and the frontend are **byte-for-byte unchanged** (verified by
`git diff --stat` and by a test that AST-parses the control API's imports).

---

## 2. The two routes, and why there are two

```
GET /api/v1/assessments/{assessment_id}/findings/{finding_id}/explanation
GET /api/v1/findings/{finding_id}/explanation[?assessment_id=]
```

A **finding id is not a unique key**. `RISK-PFS-DISABLED` is raised by four of the
twelve recorded assessments, because it is a property of the planned
configuration and several plan samples share that configuration. So:

- The **nested** route addresses the `(assessment_id, finding_id)` pair, which is
  the real identity of a decision. A finding id that exists in a *different*
  assessment is a `404 finding_not_found` there — it never returns that other
  assessment's evidence.
- The **flat** route is the convenience form, and it **refuses to guess**. With
  more than one candidate it answers `409 finding_ambiguous` and lists
  `error.candidates`.

The two rejected alternatives are worse than a 409:

- *Return the first match* — attaches one capture's evidence to another
  capture's finding. The chain would verify its digests and still be about the
  wrong thing.
- *Merge the candidates* — invents a decision no assessment ever made, and
  produces a chain whose `finding_digest` matches nothing.

Returning `409` with machine-readable candidates keeps the client in charge of
the disambiguation.

---

## 3. How it reuses the pipeline (and adds no second engine)

The store already runs the real Phase 3 → 4 → 5/6 → 7 pipeline. It discarded the
domain objects and kept only the serialized bundle. `CustodyInput` now retains
them alongside the bundle, and the response plan is produced **once at build
time** by the existing `ResponsePlanner` with `clock=None`.

Every value in a chain is either copied from one of those objects or a SHA-256
over canonical JSON of one:

| Chain field | Copied from | Never recomputed |
| --- | --- | --- |
| `severity`, `title`, `summary`, `rule_id` | `RiskFinding` | ✓ |
| `risk_score`, `risk_severity`, `*_version` | `RiskAssessment` | ✓ |
| `derived.score_contribution` | `RiskAssessment.metadata.score_detail` | ✓ (the engine's own arithmetic) |
| `observed.<var>` | `CorrelationOutcome.observed_value` | ✓ |
| `expected.<var>` | `CorrelationOutcome.expected_value` | ✓ |
| `derived.comparison_status` | `ComparisonOutcome.status` / `.reason` | ✓ |
| `expected.configuration_id` / `security_posture` | `ExpectedState` | ✓ (planner's `posture_of_config`, consumed not recomputed) |
| `recommendation.*` | `ResponseRecommendation` from the reused planner | ✓ |
| `evidence[].artifact_sha256` | `EvidenceRef` | ✓ |
| `rule.traceability` | `risk.rules.RULE_TRACEABILITY` | ✓ |

Serving a chain runs **no** stage. A test deep-copies the assessment,
correlation, expected state and response plan, serves the chain three times, and
asserts all four are unchanged.

The XAI layer is not a second engine here. It contributes one `DERIVED` fact and
one non-authoritative step, and the `xai.non_authoritative` check states the
boundary explicitly.

---

## 4. The property that matters most: observation honesty

A passive `ipsec_state_builder` snapshot does **not** observe the negotiated mode
or ciphers. `correlation.artifacts.observed_evidence_values` returns `{}` on
purpose, and the comparison engine resolves those variables to `UNKNOWN` with a
documented reason.

The chain reports that faithfully rather than filling the gap. Abridged but
verbatim from `dataset-20260924-003710:3:band-medium` /
`RISK-WEAK-DH-GROUP`:

```json
{
  "fact_id": "observed.esp_dh_group",
  "category": "OBSERVED",
  "authority": "authoritative_observation",
  "authoritative": true,
  "value": null,
  "value_digest": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
  "source": "CorrelationOutcome[esp.dh_group].observed_value",
  "detail": "no authoritative observation recorded for esp.dh_group: esp.dh_group is only indirectly observable (IKE CREATE_CHILD_SA derivation) and Phase 4 does not evaluate ML; ObservedState exposes no authoritative esp.dh_group.",
  "evidence_ids": ["ev-1fe10b2a9aa3d81b8166a2283be0f465", "ev-abc8627b7b672560d9300d45431e6246"]
}
```

The `detail` is the comparison engine's own wording, not a paraphrase, and
`value_digest` is the SHA-256 of the canonical JSON `null`
(`canonical_digest(None)`), so the absence is itself content-addressed: editing
`value` to anything else changes the digest.

…plus the engine's `UNKNOWN` status in the derivation step, plus a matching
entry in `limitations`. **No** substitution from the plan, from a sibling
variable, or from a model. A test asserts `value is None` and that the detail
carries the engine's wording.

### Category and authority are separate, and both are always emitted

| category | authority | authoritative | may support |
| --- | --- | --- | --- |
| `OBSERVED` | `authoritative_observation` | yes | "it happened" |
| `EXPECTED` | `authoritative_plan` | yes | configured intent, **never** reality |
| `DERIVED` | `derived_non_authoritative` | no | rules, score, model verdicts |
| `RECOMMENDED` | `proposed_non_authoritative` | no | a proposal; never a decision |

`authority` is a read-only property derived from `category`, so a handler cannot
declare a derived fact authoritative.

### A model verdict is not an observation

An early revision of the builder emitted an `OBSERVED` fact for
`RISK-ML-CLASSIFICATION` carrying the classifier's output. That asserted the
protocol was observed to look a certain way when only a model said so. The
builder now emits **no** `OBSERVED` fact for an `ML`-sourced finding; the verdict
becomes `derived.model_verdict` with
`detail: "…a model verdict is derived evidence and is never filed as an
authoritative observation"`, and
`observation.authoritative_value_present` is `not_applicable` with the reason.
A test pins this: `assertFalse([f for f in facts if f.category == FACT_OBSERVED])`.

---

## 5. Integrity and provenance checks

Seven checks, each phrased as a comparison so a client can run it itself. A check
that could not be evaluated is never reported as `pass`; it is `unavailable`,
`fail` or `not_applicable` with the reason.

| `check_id` | What it compares | Status across the 9 recorded findings | Other status proven by test |
| --- | --- | --- | --- |
| `finding.record_digest` | canonical JSON of the authoritative `RiskFinding` | `pass` (9/9) | — |
| `evidence.artifact_digests` | re-hash each artifact vs `artifact_sha256` | `pass` | `fail` (tampered digest), `unavailable` (`verify=false`) |
| `observation.authoritative_value_present` | does an authoritative observed value exist? | `pass` / `not_applicable` | — |
| `observation.expected_observed_coherent` | is the cited observed value present and genuinely different? | `pass` / `not_applicable` | — |
| `provenance.artifact_digests` | does every input artifact carry a digest? | `pass` | `fail` (digestless source) |
| `audit.chain_linked` | is the decision anchored in the tamper-evident journal? | `unavailable` (9/9, see below) | `pass` (event ids supplied) |
| `xai.non_authoritative` | can the derived explanation have influenced anything? | `pass` (9/9) | — |

The two `not_applicable` results are the honest answer for an
`ML`-sourced finding and for a plan-sourced finding whose variable has no
authoritative observation: the check does not apply, and it says so instead of
inventing a pass. For `audit.chain_linked` the reason is in-band:

```
"audit_linkage_status": "unavailable"
```

…with a limitation stating that no audit event is linked, so the chain is not
anchored in the tamper-evident journal.

Verification goes through each ref's own `EvidenceRef.verify()`, which re-hashes
the real file read-only and reports `valid` / `unavailable` / `invalid` /
`unverified`. `invalid` is surfaced as a failed check and is **never** repaired.
A test constructs a ref with a wrong digest and asserts `verify()` returns
`invalid`, confirming the chain would report a failure rather than a pass.

### Audit linkage is honest by default

The API store builds the chain from live in-process objects, so with no journal
attached there is no persisted audit event. The chain then reports
`audit_linkage_status: "unavailable"`, a failed `audit.chain_linked` check and a
limitation. **No** event id is invented to fill the gap. Supplying real ids flips
it to `linked`/`pass` (tested).

### The model refuses a lie

`CustodyRecommendation(applied=True)` raises `ValueError`, and
`ChainOfCustody(read_only=False)` raises `ValueError`. The invariants are
structural, not merely documented.

---

## 6. Determinism

No wall clock, no UUID, no random, no set iteration.

- `canonical_digest` = `sha256(json.dumps(value, sort_keys=True,
  separators=(',',':'), ensure_ascii=True))` — reproducible by any client.
- Facts sorted by `fact_id`; evidence by `evidence_id`; steps by `index`.
- The response plan is built with `clock=None`.

**Test:** two independent `build_store()` runs produce byte-identical chains for
all 9 findings, and three consecutive requests are byte-identical.

The one thing that *can* change between runs is the filesystem, so the chain says
so instead of hiding it:

```json
"determinism": {
  "filesystem_dependent_fields": [
    "evidence[].verification_status", "evidence[].actual_sha256",
    "evidence[].artifact_present", "evidence[].verification_detail",
    "evidence[].byte_size",
    "integrity[evidence.artifact_digests].status", "..."
  ]
}
```

So a byte-diff between two runs can be attributed rather than guessed at.

---

## 7. Disclosure control

- Evidence appears only as `evidence_id` + `artifact_sha256` + size. **No** PCAP
  bytes, no `pcap_path`, no payload, no blob.
- `sources[].public_path` is reduced once at the API boundary by the existing
  `correlation.api.redact.public_path`; the custody layer has **no** field that
  could carry an absolute host path and performs no redaction of its own (no
  domain → api layering inversion).
- A test walks all 9 chains and asserts no absolute path, no `..`, and no
  backslash reaches the payload; a second test confirms a path outside the
  repository collapses to a bare basename.
- `?verify=false` is an explicit opt-out of the artifact re-hash, and the skip is
  real rather than cosmetic: the builder receives the flag, never opens the
  files, and reports every evidence link as `verification_status:
  "not_performed"` with `actual_sha256: null` and `artifact_present: null`
  (`null`, because a file that was never looked for cannot be reported as
  absent). The `evidence.artifact_digests` check becomes `unavailable` rather
  than `pass`, and the response carries `verification.performed: false`. The
  default path reports `performed: true`.

---

## 8. Verification

### Test suite
| Scope | Result |
| --- | --- |
| `tests/test_chain_of_custody.py` (new) | **63 passed**, 317 subtests |
| `tests/test_analytics_api.py` | **118 passed**, 171 subtests |
| Full suite `tests/` | **1349 passed, 7 skipped, 0 failed** (baseline was 1286 + 63 new) |

### Coverage by failure mode

| Class | Attacks |
| --- | --- |
| `TestCustodyCoversEveryFinding` | A finding with no chain looks unremarkable. Also: the contract must not shadow the XAI `FindingExplanation`. |
| `TestFactAuthorityIsStated` | A planned value, a model verdict or a missing observation being filed as an observation. |
| `TestCustodyReusesThePipeline` | Re-derivation, a recomputed score, an invented recommendation, per-request analysis. |
| `TestIntegrityChecksAreHonest` | `unavailable` or `invalid` being smoothed into `pass`; an invented audit id. |
| `TestCustodyIsDeterministic` | Wall clock, random ids, dict-order dependence, a lossy round trip. |
| `TestCustodyIsReadOnlyAndRedacted` | A leaked host path, inlined PCAP bytes, a written artifact, a coupled control API. |
| `TestCustodyRoutes` | Cross-assessment evidence bleed, a guessed match, an undocumented route, a reachable mutating verb, a changed discovery payload. |

### Regression protection
- Both new paths were added to the existing `TestOpenApiDoesNotDrift` probe
  list, so the router and the document are checked in **both** directions.
- `test_the_existing_findings_routes_are_unchanged` asserts the discovery rows
  and envelopes are byte-compatible and that no custody key leaked into them.
- The full suite ran before and after: 1286 → 1349 with no failures and no
  changes to any pre-existing assertion.

---

## 9. Known limitations of this change

Stated rather than smoothed over; several are also surfaced in-band by the chain
itself.

1. **Audit linkage is `unavailable` in the default store.** The analytics store
   runs the pipeline in-process and does not persist audit events, so chains are
   not yet anchored in the tamper-evident journal. The check and the limitation
   both say so. Wiring `AuditStore` in is a follow-up, not a fabricated id.
2. **`rule.registered` is `false` for per-variable mismatch rule ids.**
   `correlation.mismatch.address_family` is minted by `MISMATCH_FINDING_SPECS`,
   not by `RULE_REGISTRY`. Reporting only `false` would understate the rule's
   existence, so the chain also carries `base_rule_id:
   "correlation.mismatch"` and falls back to the base rule's traceability record.
3. **`CorrelationResult` is read through its serialized form.** The builder
   indexes outcome rows via `to_dict()` so it accepts either the object or the
   dict. Values are copied, not re-typed, so nothing is lost, but a new
   `ComparisonOutcome` field would need the index refreshed to be quotable.
4. **Non-repeating finding ids are not addressed.** A finding id unique to one
   assessment works on the flat route today; making the response a *list* keyed
   by assessment would be a contract change and was not made.
5. **The custody layer is not itself audited into a journal.** Each chain reports
   the *assessment's* audit linkage, not a record of having served the chain. A
   governance-grade implementation would append a custody-served event; that is
   a write, and this layer is read-only by construction.
6. **`detail` strings are English prose.** They are quoted from the engines that
   produced them (not paraphrased), which keeps the chain faithful but not yet
   localized. The machine-readable fields (`category`, `authority`, `status`,
   digests) do not depend on them.
7. **The OpenAPI document declares 3.1.0 but uses 3.0-era `nullable`.** This is
   pre-existing across the document's other schemas, not introduced here, and the
   custody schemas follow the file's existing convention rather than introducing
   a second style. A strict 3.1 validator ignores `nullable`, so optional
   custody fields would read as non-nullable. Worth normalising to
   `type: ["string", "null"]` document-wide in a separate change; the custody
   *tests* do not depend on the keyword.

---

## 10. Compliance with the stated constraints

| Constraint | Status |
| --- | --- |
| Reuse existing deterministic recommendation logic | Reused `ResponsePlanner` with `clock=None`; `derived_by: "response.planner"` |
| Do not add a second analysis engine | No new comparison, rule, severity or score. A test asserts the retained objects are unchanged after serving |
| `ObservedState` stays authoritative | Unchanged. The chain quotes it and adds no observation channel |
| No invented evidence | Only ids/digests from existing `EvidenceRef`s; a test asserts no path or payload field exists |
| No fake dependency, database or frontend | None added. `requirements.txt` and the frontend are untouched |
| `controller/api.py` not modified | `git diff --stat` empty; a test AST-parses its imports for a new coupling |
| Machine-readable | Typed models, `to_dict()`, full OpenAPI `ChainOfCustody` schema, stable digests |
| Deterministic | Two independent builds byte-identical; no clock/UUID/random |
| Read-only | Every mutating verb → 405 on a real socket; `read_only` and `applied` are model-enforced |
| Absolute paths redacted | Reduced at the API boundary; tested across all 9 chains |
