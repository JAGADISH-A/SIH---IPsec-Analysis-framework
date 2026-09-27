# Mission Context Layer — Implementation Report

**Milestone:** external mission context combined with evidence-derived risk
**Status:** complete; full suite green; no control-plane, frontend or
dependency changes
**Model version:** `mission-context-v1`
**Profile schema version:** `mission-context-v1`

---

## 1. What this milestone is, in one paragraph

The previous milestone could already prove, for any finding, exactly which
observations and evidence produced it. What it could not say is *how much that
finding matters for this particular asset* — because a missing PFS transform
means something very different on a scratch gateway than on a gateway carrying
operational communications. This milestone adds that missing context as
**operator-supplied input**, and computes a second, separately labelled
contextualized risk beside the technical risk. The technical risk is never
altered, never re-scored, and never hidden.

The single most important property of this design is a negative one: **mission
criticality is not inferred, ever.** Not from traffic, addresses, payloads, ML
output, finding volume, or severity. It is either declared by an operator or it
is absent, and when it is absent the system says so rather than guessing.

---

## 2. The premise, and what had to be true for it

The premise: *a finding that is identical on two assets deserves different
attention on each, and the difference comes from the asset's declared role and
criticality, not from anything in the capture.*

Two conditions had to hold before that could be implemented honestly:

1. **The same finding must produce the same technical result regardless of
   context.** Verified in `TestSameFindingDifferentAssets`: the `ObservedState`,
   the evidence references (ids, artifact digests, verification status), the
   `risk_score`, the `risk_severity` and the `finding_digest` are identical
   between the two runs. The only keys of the chain that differ are
   `mission_context`, `facts`, `limitations` and `integrity` — and within
   `facts`, only the `asset.*`, `configured.*` and `derived.*` entries.

2. **The asset must be identifiable.** See section 3.

---

## 3. The honest answer to the asset-identity question

**What the findings actually carry:** nothing. A `RiskFinding` has a
`finding_id`, a `rule_id`, a `severity` and evidence references. There is no
asset name, and none was invented.

**What the system does have:**

- `topology/tunnel/ipsec.clab.yml` and `configs/gw-a/`, `configs/gw-b/` name two
  real testbed gateways: `gw-a` and `gw-b`. These already exist, so the asset
  vocabulary is the testbed's, not a new one.
- `ObservedState.endpoints` contains **IP addresses only**. There is no field
  that says which gateway produced a capture.
- The controller's endpoint→gateway mapping exists, but using it would mean
  importing the control plane, which is explicitly out of scope for this
  milestone.

**The conclusion that was reached:** a finding cannot be reliably associated
with an asset from the data it carries. Rather than infer one, the asset is
**declared externally at the store boundary**:

```python
AssessmentStore(plan_path, asset_id="gw-b", mission_profiles=load_mission_profiles())
```

This is a deliberate design choice, not a workaround:

- it cannot be wrong through inference, because nothing is inferred;
- it matches how a real deployment would work — the inventory system knows which
  gateway it is looking at, the analytics pipeline need not;
- it keeps the association auditable: the declared `asset_id` appears in the
  response and in the custody facts.

**What was not done, on purpose:** no IP→gateway map, no MAC lookup, no
"closest endpoint wins" heuristic, no controller import, and no `asset_id`
fabricated from a hostname. An unmapped asset is `not_configured`, not a guess.

`ObservedState`, the correlation pipeline and the control-plane API were not
modified. A regression test asserts the mission package imports nothing from
`controller`.

---

## 4. The model

### 4.1 Declared categories

An `AssetMissionProfile` is four fields, all bounded and validated:

| Field | Allowed values | Role in the calculation |
|---|---|---|
| `asset_id` | bare name (no `/`, no `..`, not absolute) | identity only |
| `role` | `development`, `test`, `operational-communications`, `mission-support` | **descriptive only** |
| `criticality` | `low`, `medium`, `high` | weighted |
| `mission_impact` | `low`, `medium`, `high` | weighted |

### 4.2 The arithmetic

The existing technical risk is an integer in `[0, 100]` with existing severity
bands. **That range and those bands are reused, not redefined.**

```
weights:                 low = 33    medium = 66    high = 100

context_index      = (criticality_weight + mission_impact_weight) // 2
excess_bp          = ((context_index - 33) * 10000) // 67
multiplier_bp      = 10000 + (5000 * excess_bp) // 10000
contextualized_risk = min(100, (technical_risk * multiplier_bp) // 10000)
```

`bp` is basis points. Every division is integer floor division, so the result is
exact and identical on any machine — the same inputs always produce the same
number, with no floating point anywhere.

### 4.3 Properties that follow from the formula, and why

| Property | Why it holds |
|---|---|
| A `low`/`low` asset is never inflated | excess is measured from the minimum, so the multiplier is exactly `10000` bp and the score is unchanged |
| The result can never fall below technical | the multiplier is `>= 10000` |
| The result can never exceed the existing scale | clamped to the same cap the technical score already uses |
| A zero finding gains nothing | the model is multiplicative, so `0` stays `0` |
| Raising either declared value never lowers the risk | the index is monotone in each argument |
| `role` cannot move a number | it is not an input to the formula; a role rename is a no-op, tested directly |

Every one of these is a test, not a claim. `TestWeightingModel` includes a
monotonicity sweep over the full 3×3 grid in each argument, a symmetry check, a
determinism check over 50 repetitions, and a reproduction check that redoes the
multiplied arithmetic from the emitted `multiplier_bp`.

### 4.4 What is emitted with every result

`technical_risk`, `technical_severity`, `contextualized_risk`,
`contextualized_severity`, `context_index`, `multiplier_bp`,
`criticality_weight`, `mission_impact_weight`, `model_version`, `formula`,
`score_cap`, `inferred_from_traffic: false`.

A consumer can redo the arithmetic by hand and confirm the model version they
were served.

---

## 5. No profile: the behaviour that matters most

Every path that cannot find a usable profile — an unknown asset id, an empty
asset id, a store with no asset declared, a store with no profile file loaded —
returns the same thing:

```json
{
  "status": "not_configured",
  "configured": false,
  "asset_id": "gw-unmapped",
  "profile": null,
  "risk": null,
  "context_source": null,
  "context_source_path": null,
  "context_source_sha256": null,
  "reason": "no mission profile is declared for asset 'gw-unmapped' in configs/mission/asset_mission_profiles.json, so no mission context was supplied; technical risk is unchanged",
  "model_version": "mission-context-v1",
  "derived_from_observation": false
}
```

There is **no default criticality, no wildcard profile, and no "assume medium"
fallback.** A test asserts that `criticality`, `mission_impact` and `role` are
*absent* from the payload rather than present-and-null, because a key that
exists with a plausible-looking value is how an absent context becomes an
invented one.

The technical risk and severity are untouched in this state, and the chain's
limitation text says so explicitly.

---

## 6. Provenance: the boundary enforced in code

The custody model already distinguishes where a value came from. This milestone
adds one category for declared context:

| Category | Authority | Used for |
|---|---|---|
| `CONFIGURED` | `configured_assessment_context` | the declared `asset_id`, `role`, `criticality`, `mission_impact`, and the context's own source |
| `DERIVED` | `derived_non_authoritative` | the contextualized risk, which is arithmetic over the technical score and the declarations |

`CONFIGURED` is deliberately **not** in `AUTHORITATIVE_CATEGORIES`. It is
authoritative about *what the operator declared* and about nothing that was
observed on the network — a distinction the OpenAPI `facts` description now
states in words, so a client cannot read the category list and conclude
otherwise.

Enforced by tests, not convention:

- every mission fact's `source` names the profile file, and its `detail`
  disclaims observation in its own words;
- no declared value (`gw-b`, `operational-communications`, `high`) appears
  anywhere among the `OBSERVED` facts;
- `derived_from_observation` and `inferred_from_traffic` are always `false`, and
  are `const: false` in the OpenAPI schema so a server cannot serve a different
  value without breaking the contract;
- the response and the profile book never contain an absolute path — the source
  is repository-relative (`configs/mission/asset_mission_profiles.json`) and a
  test asserts the host root and home directory are absent from the payload.

The profile file's SHA-256 travels with every response
(`515e03fb9b79ba266ce6a6cc01467c987e35db68853e71043e68954b11a8495a`), so a
consumer can tell *which version of the declarations* produced a number.

---

## 7. The demonstration

Two real assessments from the shipped dataset, three runs each. The only
difference between the `gw-a` and `gw-b` runs is the `asset_id` passed to the
store; the plan, the artifacts and the analysis are identical.

### 7.1 Primary case — `RISK-PFS-DISABLED` @ `dataset-20260924-003710:4:pfs-weak`

| Asset | Status | Multiplier | Technical | Contextualized |
|---|---|---|---|---|
| `gw-a` (development, low/low) | `configured` | 10000 bp | 12 MEDIUM | **12 MEDIUM** |
| `gw-b` (operational-communications, high/high) | `configured` | 15000 bp | 12 MEDIUM | **18 MEDIUM** |
| none declared | `not_configured` | — | 12 MEDIUM | **null** |

The same missing-PFS finding reads as a moderate issue on a development
gateway and a materially more serious one on an operational gateway. Nothing
about the capture differs.

### 7.2 Band-crossing case — `RISK-ML-CLASSIFICATION` @ `dataset-20260924-003710:75:ml-mismatch`

| Asset | Status | Technical | Contextualized |
|---|---|---|---|
| `gw-a` (low/low) | `configured` | 30 HIGH | **30 HIGH** |
| `gw-b` (high/high) | `configured` | 30 HIGH | **45 CRITICAL** |
| none declared | `not_configured` | 30 HIGH | **null** |

This is the case the milestone exists for. The technical severity band is
identical in both runs; on the low-criticality asset the finding stays where
the evidence put it, and on the high-criticality asset the declared context
moves it across a band boundary.

### 7.3 An important detail about which number is being contextualized

In the second case the chain also reports `severity: LOW` for the individual
finding, while `risk_severity: HIGH` for the assessment. This is not an
inconsistency, and the report would be dishonest to hide it:

- the **contextualized view is over the assessment-level risk pair**
  (`risk_score` / `risk_severity`) — "how serious is this risk for this asset";
- the **individual finding's own `severity`** is a separate field, is a
  rule-assigned property of the finding, and is never touched by this feature.

`test_the_contextualized_view_covers_the_risk_not_the_finding` asserts the
technical pair mirrors `risk_score`/`risk_severity` exactly, and that the
finding's `severity` is unchanged between the two assets. The OpenAPI
description states the same thing.

---

## 8. Custody integration

The chain of custody gained a `mission_context` field and, **only when context
is configured**, two integrity checks and a set of mission facts.

The previous milestone's behaviour is preserved exactly:

| | No profile | Profile declared |
|---|---|---|
| Integrity checks | the original 7 | the original 7 + `mission.context_declared`, `mission.risk_preserves_technical` |
| `CONFIGURED` facts | none | 5 (`asset.asset_id`, `asset.criticality`, `asset.mission_impact`, `asset.role`, `configured.context_source`) |

A test pins the original seven check ids and the original fact count of 10 for
a chain built without context, so a future change that quietly adds a mission
check to an unconfigured chain fails loudly.

`mission.risk_preserves_technical` is a real check, not decoration: it verifies
the contextualized risk lies within `[0, score_cap]`, is not below the technical
risk, and that the technical risk itself was not changed. A test feeds it a
deliberately broken `ContextualizedRisk` (contextualized 3 against technical 12)
and asserts it reports `CHECK_FAIL`.

---

## 9. API

**No new endpoint.** The existing finding-explanation routes
(`/v1/assessments/{id}/findings/{id}/explanation` and
`/v1/findings/{id}/explanation`) already return the whole chain, so
`mission_context` is served by the existing response. There is no asset
management API, no route for reading or writing profiles, and a test asserts
the path count is unchanged at 33.

`CONFIGURED` was added to the fact `category` enum,
`configured_assessment_context` to the `authority` enum, and a `mission_context`
object schema was added to `ChainOfCustody` documenting both the configured and
`not_configured` shapes, the source provenance, and the technical/contextualized
pairs. A test asserts the documented property set matches the served payload
exactly, so the schema cannot drift from the response.

---

## 10. Source map

| File | Lines | Role |
|---|---|---|
| `correlation/mission/models.py` | 123 | bounded categories, statuses, validators |
| `correlation/mission/profiles.py` | 228 | `AssetMissionProfile`, `MissionProfileBook`, `load_mission_profiles` |
| `correlation/mission/contextualize.py` | 294 | the formula, `MissionContext`, `not_configured` |
| `correlation/mission/__init__.py` | 102 | public surface |
| `configs/mission/asset_mission_profiles.json` | 17 | the two declared testbed assets |
| `tests/test_mission_context.py` | 896 | 67 tests, 185 subtests |

Modified: `correlation/custody/models.py` (new category, authority, chain
field), `correlation/custody/builder.py` (facts, checks, limitations),
`correlation/custody/__init__.py` (export), `correlation/api/store.py` (asset
and profile inputs), `correlation/api/openapi.py` (schema).

---

## 11. Tests

`tests/test_mission_context.py` — **67 tests, 185 subtests, all passing**,
organised by the milestone's acceptance list:

| Class | Covers |
|---|---|
| `TestProfileLoadsAsConfiguration` | valid load, bounded categories, malformed file refused, unknown asset, relative path + digest, no host path disclosure, no path-like asset id |
| `TestWeightingModel` | existing scale retained, low context inflates nothing, never below technical, 50% cap, monotonicity in each argument, index symmetry, arithmetic reproducible from emitted values, determinism, model version, role excluded, existing bands reused, out-of-range input refused |
| `TestNoProfileBehaviour` | all four unconfigured paths, no default category present at all, no fallback to a known asset, technical risk untouched |
| `TestSameFindingDifferentAssets` | same finding under both assets, differing contextualized result, identical `ObservedState`, identical evidence, identical technical risk, only mission keys differ, observed facts untouched, differing facts are only mission ones, band crossing |
| `TestProvenanceBoundary` | `CONFIGURED` not authoritative, every mission fact cites the source and disclaims observation, no declared value filed as observed, values reported verbatim, non-derivation flags, limitation wording, digest in the check |
| `TestCustodyIntegration` | legacy integrity set preserved, exactly two added checks, the preservation check fails a broken model, real context passes, no context adds no checks, chain round-trip, no pipeline mutation, reproducibility across store builds |
| `TestApiAndOpenApi` | both routes expose the field, `not_configured` over the API, no absolute path served, schema declares the field and categories, documented shape matches served, no new route |
| `TestBoundaryIsEnforcedNotJustIntended` | the package imports no controller and no observed/modelled state (import allowlist), opens exactly one file and only read-only, knows only the one config path, and custody/store import no controller |

Regression runs:

| Suite | Result |
|---|---|
| `tests/test_mission_context.py` | 62 passed, 124 subtests |
| `tests/test_chain_of_custody.py` | 63 passed, 317 subtests |
| `tests/test_mission_context.py` + `test_chain_of_custody.py` + `test_analytics_api.py` | 243 passed, 612 subtests |
| Full suite | **see section 13** |

---

## 12. Boundaries honoured

Not touched: `controller/api.py`, the frontend, `requirements.txt`, the
control-plane API, `ObservedState`, correlation, the risk engine, the response
policy.

Not added: a database, a CMDB or inventory integration, a network device, any
external dependency, payload inspection, organizational-structure inference, or
mission criticality derived from traffic or ML output.

Not inferred: asset identity, criticality, mission impact, or any relationship
between a finding and a gateway.

---

## 13. Limitations, honestly

1. **The profile file is a stand-in.** `configs/mission/asset_mission_profiles.json`
   plays the part an asset inventory, classification register or operator-approved
   assessment profile would play. It is static, hand-written, and covers two
   assets. Nothing here scales it to an estate.
2. **The association is declared, not discovered.** A consumer that forgets to
   pass `asset_id` gets `not_configured` and no contextualized risk. That is the
   correct answer, but it does mean the feature only helps where an operator has
   already done the inventory work.
3. **The weight scale is a judgement.** `33/66/100` and the 50% uplift ceiling
   are reasonable, stated, and versioned — but they are choices, not derived
   from anything. A different organisation would want different numbers, which
   is why `model_version` is mandatory and the formula ships with every result.
4. **The uplift is a single multiplier.** It does not model compounding, nor the
   fact that some findings matter more than others on a given asset (a missing
   PFS transform matters more on an operational gateway than a cosmetic banner
   does). A per-finding or per-rule context weighting is future work.
5. **The 50% ceiling can move a band but not create urgency from nothing.** A
   technically negligible finding stays negligible, by design.
6. **Two declared assets only.** `gw-a` and `gw-b` are the gateways the testbed
   has. Adding a third means editing the profile file; no code change.
7. **Not deployment-ready.** The file is read at store construction and digested
   per response. There is no reload-on-change, no audit trail of who edited the
   profile file, and no signature on the declarations — the digest proves which
   file was read, not who authorised it.
8. **The contextualized number is a prioritization aid, not a finding.** It must
   not be compared across assessments as if it were a measurement, and it is not
   suitable as a compliance or reporting figure.

---

## 14. Verification

Final results, recorded after the last change to this milestone:

| Suite | Result |
|---|---|
| `pytest tests/test_mission_context.py` | **67 passed**, 185 subtests |
| `pytest tests/test_chain_of_custody.py` | 63 passed, 317 subtests |
| `pytest tests/test_mission_context.py tests/test_chain_of_custody.py tests/test_analytics_api.py` | 248 passed, 673 subtests |
| `pytest tests` (comparable to the pre-milestone baseline) | **1416 passed, 7 skipped**, 7 warnings, 1821 subtests |
| `pytest` (whole repository, incl. `controller/`) | **1990 passed, 22 skipped**, 10 warnings, 2397 subtests |

The pre-milestone baseline for `pytest tests` was 1349 passed / 7 skipped. This
milestone added exactly 67 tests, all passing, and **changed no skip count** —
1416 − 1349 = 67. The 7 skips in `tests/` and 15 in `controller/` are all
pre-existing and unrelated to mission context; the 10 warnings are pre-existing
`shap` / `numpy` deprecations raised from `controller/`.

Worktree at completion:

```
 M correlation/api/openapi.py
 M correlation/api/store.py
 M correlation/custody/__init__.py
 M correlation/custody/builder.py
 M correlation/custody/models.py
?? configs/mission/
?? correlation/mission/
?? tests/test_mission_context.py
?? MISSION_CONTEXT_REPORT.md
```

The boundary guards in `TestBoundaryIsEnforcedNotJustIntended` were themselves
mutation-checked: adding a `controller` import, an `ml` import or a write-mode
`open()` to the mission package was confirmed to fail the relevant test, and the
package passed again once the probe was removed. A guard that cannot fail is not
a guard.

`controller/api.py`, the frontend and `requirements.txt` are unmodified. The
warnings are pre-existing third-party `shap` / `numpy` deprecations and are not
raised by this milestone.
