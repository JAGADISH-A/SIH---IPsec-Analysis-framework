# Novel Feature Acceptance Report

**Subject:** Drift-Aware Security Assessment, Mission-Context-Aware Risk,
Chain-of-Custody Explainability.

**Method:** independent validation. The code was re-read from source, the
recorded data was re-scanned from disk, and every claim below was produced by
running the pipeline — not by reading the previous milestone's report. Where
this report contradicts an earlier report, that is stated explicitly.

**Headline:** two of the three capabilities are genuinely working. The third
drifts only on controlled input, and its chain of custody currently publishes a
self-contradiction. Three API contracts do not match what the server serves.
None of these is a reason to stop; all three are bounded, located and fixable.

---

## 1. Executive result

```
DRIFT-AWARE SECURITY ASSESSMENT
Status: PARTIAL
  PASS on all 7 acceptance criteria, on a controlled fixture.
  No real drift is demonstrable, and this is a property of the recorded data,
  not a defect. One defect found in the drift chain's custody integration.

MISSION-CONTEXT-AWARE RISK
Status: PASS
  All 6 criteria met on a fully real assessment with zero fixtures. The only
  caveat is that the asset profiles are operator declarations.

CHAIN-OF-CUSTODY EXPLAINABILITY
Status: PARTIAL
  Fully real, all 8 explanation questions answered with structured fields,
  tamper detection and honest verify=false behaviour all confirmed.
  PARTIAL because the drift-origin chain is self-contradictory, and because
  two served fields violate their own OpenAPI contract.
```

### Drift is PARTIAL, not PASS, and not FAIL

Drift passes all seven stated acceptance criteria. It is not marked PASS because
**no real observed drift exists in this repository** — not because anything is
broken. The distinction matters for a demo:

| Claim | Verdict |
|---|---|
| Drift detection logic is correct | **Demonstrated** (controlled fixture, plus the real IPv4/IPv6 pair) |
| Drift works on real observed data | **Not demonstrable** — no real pair differs in the ESP/AH dimension |
| Drift is fully wired end to end | **Yes**, with one integration defect (§7) |

---

## 2. Evidence matrix

| Capability | Real evidence | Controlled fixture | Automated test | API verified | Limitation |
|---|---:|---:|---:|---:|---|
| Drift | **No** (10 real captures, 1 state, zero pairs differ) | **Yes** (1 declared fixture) | 110 tests | Yes, 3 routes; 2 fields violate the contract in both branches | Never observed on real data; comparison is not scoped to an endpoint pair |
| Mission context | **Yes** (fully real chain) | No | 67 tests | Yes | Profiles are operator assertions, not measurements |
| Chain of custody | **Yes** (fully real chain, 16 facts) | Yes (drift chain) | 63 tests | Yes, 2 routes, 2 contract violations | Drift-origin chain self-contradicts; no audit-journal anchoring |

Test counts are from the focused run: 315 passed across the five novel-feature
suites. Per-suite figures are in §10.

---

## 3. Phase 1 — what the code actually does

Verified by reading source, not by trusting a report.

**1. Genuinely available from `ObservedState`** (`correlation/models/observed.py:157`).
21 fields, and *no crypto whatsoever*: `timestamp_ns`, `endpoints`,
`tunnel_seen`, `active`, six packet/byte counters, `ike_seen`,
`ike_nat_t_seen`, `esp_seen`, `ah_seen`, `observed_ike_activity`, four
`last_*_timestamp_ns`, `spis[]`, `transitions[]`. The module docstring states
the state builder does not infer encryption, integrity or IKE-SA
establishment, and the model honours that.

**2. Used for drift comparison** (`correlation/drift/canonical.py:92`). Exactly
three, all re-derived from existing comparison rules:

| variable | from | rule |
|---|---|---|
| `address_family` | `endpoints` IP version | `address_family.endpoints` |
| `esp.presence` | `esp_seen` | `presence.esp` |
| `ah.presence` | `ah_seen` | `presence.ah` |

Everything else is in `EXCLUDED_FIELDS` with a stated reason.

**3. Derived rather than observed.** `address_family` is derived from observed
endpoints. `contextualized_risk` is derived from a declared profile. Every XAI
and response-planner output is derived. `security_posture` is planner-supplied
and is consumed, never recomputed.

**4/5. Real vs controlled artifacts.** Established by re-scanning the whole
repository (§4). There is exactly **one** controlled fixture and it is the only
file anywhere reporting ESP absent.

**6. Technical risk** (`correlation/risk/scoring.py:49`). One pass over the
findings: per-category cap 30, global cap 100, severity→weight table
`{INFO 0, LOW 6, MEDIUM 12, HIGH 25, CRITICAL 40}`, then a disjoint band table
gives the severity. No clock, no randomness, no I/O — deterministic by
construction. Drift is scored through this same function; there is no separate
drift scale.

**7. Mission context** (`correlation/mission/contextualize.py:104`).
`contextualized = min(100, technical × (1 + 0.5 × (index − 33)/67))` where
`index = mean(criticality_weight, mission_impact_weight)` and
`low=33, medium=66, high=100`. It reads exactly two validated strings. The
module imports no network, traffic, address, payload or ML module; the only
network-adjacent input is the scalar `technical_risk`, passed in. It can only
raise a score, never lower one. `role` never enters the calculation.

**8/9. Finding→evidence resolution and integrity.**
`EvidenceRef` is content-addressed (`derive_evidence_id`) and pins
`artifact_sha256`. `verify()` re-hashes the real file read-only and returns
`valid` / `invalid` / `unavailable` / `unverified`, and **never writes,
repairs or substitutes** (`correlation/models/evidence.py:414`). Integrity is
then evaluated over 7 base checks plus mission and drift checks.

**10. API routes.** `GET /api/v1/assessments/{id}/findings/{fid}/explanation`,
`GET /api/v1/findings/{fid}/explanation`, `GET /api/v1/assessments/{id}/drift`,
`GET /api/v1/drift`, `GET /api/v1/drift/baselines`. All dispatch. No new route
was added by any of the three milestones, and `controller/api.py` was not used.

### The authority model holds

| Layer | Can create a finding? | Can create a score? | Can alter upstream? |
|---|---|---|---|
| `risk/rules.py` | Yes — the only source | No | — |
| `risk/scoring.py` | No | Yes, pure aggregation | No |
| `ml/*`, `comparison/ml_comparison.py` | No — metadata only, `is_authoritative_observation: False` | No | No — `matches`/`mismatches`/`unknowns` untouched |
| `xai/*` | No — never imports `make_finding` | No — copies `assessment` | No — frozen models, `score_unchanged: True` |
| `mission/contextualize.py` | No | Adds a separately-labelled `contextualized_risk` | No — technical risk passed through verbatim |

ML is fenced twice: only a positive boolean `anomaly is True` creates a finding
(`rules.py:321`), and severity above the policy ceiling **raises** rather than
silently downgrading (`rules.py:404`).

---

## 4. Phase 2 — drift acceptance

### Test A — real captures. The full table.

17 distinct recorded artifacts in the repository contain an
`ObservedState`-shaped record. All 17 were examined; none was skipped.

| Capture | Canonical state | Baseline match | Drift | Evidence type |
|---|---|---|---|---|
| `parser/tunnel_v4/state.jsonl` | `ipv4 / esp=T / ah=F` | self | — | real capture |
| `parser/tunnel_v6inner/state.jsonl` | `ipv4 / esp=T / ah=F` | ✓ same | `no_drift` | real capture |
| `observed-state/lab-verify…/state_events.jsonl` | `ipv4 / esp=T / ah=F` | ✓ same | `no_drift` | real capture |
| `observed-state/lab-verify…/state_windows.jsonl` | `ipv4 / esp=T / ah=F` | ✓ same | `no_drift` | real capture |
| `observed-state/live_state_from_events_{full,pre_rekey,wan_side_new}` | `ipv4 / esp=T / ah=F` | ✓ same | `no_drift` | real capture (3) |
| `observed-state/live_state_from_windows_{full,pre_rekey,wan_side_new}` | `ipv4 / esp=T / ah=F` | ✓ same | `no_drift` | real capture (3) |
| `transport/transport_state_snapshot.json` | `ipv4 / esp=T / ah=F` | ✓ same | n/a | real, **loader rejects (JSON form)** |
| `transport/ipv6-parser-rerun/traffic_phase_state_snapshot.json` | **`ipv6 / esp=T / ah=F`** | ✗ **differs** | see below | real, **loader rejects (JSON form)** |
| `transport/ipv6-parser-rerun/icmp_phase_state_snapshot.json` | — | — | — | real, **model rejects** (self-inconsistent) |
| `transport/ipv6-parser-rerun/v4_parity_state_snapshot.json` | — | — | — | real, **model rejects** (self-inconsistent) |
| `parser/transport_live_reverify/state.jsonl` | — | — | — | real, **model rejects** (self-inconsistent) |
| `tests/fixtures/drift/ah_substitution_state.jsonl` | `ipv4 / esp=F / ah=T` | ✗ differs | `drift` | **CONTROLLED FIXTURE** |

**Explicit statement, as required:** of the **10 usable real captures, all
10 canonicalise to one identical state digest
`460f2b4b5f53982b3ca1ec583813cc1d27c700165ff15a28cc812f336105b7c3`**, and
comparing any of them against any other yields `no_drift` — verified for all
90 ordered pairs, not sampled.

Searched across every file of every form in the repository:

- `"esp_seen": false` appears in **exactly one file**: the declared fixture.
- `"ah_seen": true` appears in **exactly one file**: the declared fixture.

**So: no real protection drift exists, and none can be manufactured without
fabrication.** This is the finding that licenses the controlled fixture.

#### One real difference exists, and it is not usable as drift

`traffic_phase_state_snapshot.json` is a **genuinely recorded** state snapshot
whose canonical state is `ipv6 / esp=T / ah=F` — a different security state from
every other artifact. Two things stop it being a real-drift demo:

1. The authoritative loader (`correlation/artifacts.py:178`) reads **JSONL
   only**, so it refuses the file. It is also absent from `REAL_OBSERVED_STATES`.
2. Its endpoints are `2001:db8:20::10/20`; the IPv4 baseline's are
   `192.168.100.1/2`. **Different tunnels, different test run** — 9.5 days
   later. Comparing them is not a security-state change on one asset.

### The scoping defect this exposes

Because the loader cannot admit it, the IPv6 observation can only be compared by
constructing `ObservedState` directly — which bypasses the authoritative entry
point. Doing so produces a real, reproducible finding:

```
baseline tunnel_v4  vs  ipv6 snapshot
  status : drift
  changed: address_family  ipv4 -> ipv6   MEDIUM
  finding: RISK-DRIFT-ADDRESS_FAMILY   score 12
  payload discloses endpoints? NO — neither '192.168.100.1' nor '2001:db8' appears
```

**`assess_drift` has no notion of which tunnel it is comparing.** A baseline
validated from one endpoint pair can be "drifted" by an unrelated tunnel, and
the payload never says the endpoints differ. This is a concrete, proven defect.
It is pinned by `TestCrossEndpointComparisonIsNotScoped`.

### Test B — controlled drift, verified against the bytes

The fixture was diffed field-by-field against the baseline artifact rather than
trusted:

```
DIFF ah_seen                 False -> True    substantive
DIFF esp_seen                True  -> False   substantive
DIFF last_esp_timestamp_ns   <ts>  -> null    consequence of esp_seen
DIFF last_ah_timestamp_ns    null  -> <ts>    consequence of ah_seen
DIFF spis[].active           True  -> False   consequence
     transitions[type]       IPSEC_TRAFFIC_OBSERVED -> IPSEC_TRAFFIC_INACTIVE
same   endpoints, all six packet/byte counters, timestamp_ns,
       observation_start_ns, last_packet_timestamp_ns, ike_seen, tunnel_seen
```

Every edit is declared in `ah_substitution_provenance.json` with path, source
SHA-256, from → to, reason, and the verbatim statement that it is **not** a
capture. The two timestamp edits are in `EXCLUDED_FIELDS`, so they produce no
drift — which is why exactly two fields change.

**The reported changed field was checked against independently computed truth:**

```
baseline canonical : {'address_family':'ipv4','esp.presence':True,'ah.presence':False}
current  canonical : {'address_family':'ipv4','esp.presence':False,'ah.presence':True}
truly differing    : ['ah.presence','esp.presence']
engine reported    : ['ah.presence','esp.presence']     MATCH
```

The full required chain holds:

```
validated baseline -> controlled changed observation -> drift comparison
-> esp.presence True->False (HIGH) + ah.presence False->True (MEDIUM)
-> findings -> severity -> risk 30/HIGH -> evidence + provenance
```

Determinism: 5 runs, 1 distinct serialization.

### Test C — unsupported categories, disclosed not implemented

`ObservedState` has nowhere to store a cipher, DH group, PFS, IKE version,
integrity algorithm, firmware or implementation identity, so these are
**undetectable, not merely unimplemented**. The API publishes them as
deliberate decisions:

```
unsupported_categories: firmware_drift, implementation_drift,
                        traffic_behavior_drift, ml_behavior_drift
```

No inference mechanism was added. This is asserted as a test: if
`ObservedState` ever grows a crypto field, the claim fails loudly.

### Drift acceptance criteria

| # | Criterion | Verdict | Evidence |
|---|---|---|---|
| 1 | No drift when state is identical | **PASS** | 90/90 real pairs `no_drift` |
| 2 | Deliberate change produces drift | **PASS** | fixture → `drift` |
| 3 | Finding names the actual changed field | **PASS** | engine output == independently computed truth |
| 4 | Risk/severity deterministic | **PASS** | 5 runs, 1 serialization; scoring has no clock/random/IO |
| 5 | Provenance separates real from controlled | **PASS** | 3 independent mechanisms (§6) |
| 6 | Tampering fails integrity, never repaired | **PASS** | §8 |
| 7 | Unsupported categories disclosed | **PASS** | published + asserted |

---

## 5. Phase 3 — mission context

Run on a **fully real** assessment (`tunnel-v6` / `RISK-ADDRESS-FAMILY-MISMATCH`)
— no fixture, no declared observation anywhere in the chain.

| | `gw-a` (low/low) | `gw-b` (high/high) | undeclared |
|---|---|---|---|
| technical risk | **12 MEDIUM** | **12 MEDIUM** | **12 MEDIUM** |
| `finding_digest` | `890871143d32…` | `890871143d32…` | `890871143d32…` |
| mission status | configured | configured | `not_configured` |
| contextualized risk | **12 MEDIUM** | **18 MEDIUM** | `None` |
| `multiplier_bp` | 10000 (neutral) | 15000 | `None` |
| `inferred_from_traffic` | false | false | false |
| `derived_from_observation` | false | false | false |

Between `gw-a` and `gw-b` only **4 of the sections** differ: `mission_context`,
`facts`, `integrity`, `limitations`.

- **facts:** 5 of 16 differ — `asset.asset_id`, `asset.criticality`,
  `asset.mission_impact`, `asset.role`, `derived.contextualized_risk`. **None is
  filed as `OBSERVED`.**
- **integrity:** 2 of 9 differ — `mission.context_declared` and
  `mission.risk_preserves_technical`, both naming the declared asset and
  reaching the same verdict. The other **7 are byte-identical**, so an operator's
  declaration cannot move a technical integrity result.
- **categories** in the chain: `CONFIGURED 5, DERIVED 6, EXPECTED 3, OBSERVED 1,
  RECOMMENDED 1` — the four-way distinction the spec requires.

Missing profile: `not_configured`, `profile: null`, `risk: null`, reason names
the file that was read, and technical risk **12 MEDIUM with an identical
`finding_digest`**. No criticality is guessed or defaulted.

| # | Criterion | Verdict |
|---|---|---|
| 1 | Same evidence → same technical finding | **PASS** |
| 2 | Technical risk unchanged | **PASS** (12 everywhere) |
| 3 | Context changes only contextualized prioritization | **PASS** (4 sections, 5 facts) |
| 4 | Missing context never invents a value | **PASS** |
| 5 | Provenance identifies the configured profile | **PASS** (path + SHA-256 `515e03fb…`) |
| 6 | No ML/network inference | **PASS** (no such import; flags false) |

**Explicitly:** mission context is **configured assessment context**, declared
by an operator in `configs/mission/asset_mission_profiles.json`. It is not
AI-inferred, not traffic-derived, and not network-derived.

---

## 6. Phase 4 — chain of custody

Fully real chain, no fixture: `dataset-20260924-003710:16:tunnel-v6` /
`RISK-ADDRESS-FAMILY-MISMATCH`. 16 facts, 7 ordered steps, 2 evidence refs, 4
limitations, all from recorded artifacts.

| Question | Answered by | Value |
|---|---|---|
| 1 What happened? | `title` | "Confirmed observation mismatch on address_family" |
| 2 Why flagged? | `summary` | rule, severity, source, and why it is a contradiction |
| 3 Which rule? | `rule.rule_id` | `correlation.mismatch.address_family` |
| 4 What evidence? | `evidence[]` | 2 refs, both `valid`, with claimed = actual digest |
| 5 Severity / risk? | `severity`, `risk_score` | MEDIUM, 12, policy `risk-policy-v1` |
| 6 Impact? | `facts[]` | `expected.address_family=ipv6`, `observed.address_family=ipv4` |
| 7 Action? | `recommendation` | `RR-RISK-ADDRESS-FAMILY-MISMATCH`, MEDIUM, `REQUIRE_REVIEW`, **applied: false** |
| 8 Where from? | `facts[].category/authority/source` | 5 categories, 5 authorities, 13 distinct sources |

The 7 steps name every stage that ran and mark XAI and the planner
`authoritative: false` while the six upstream stages are `true`.

**Provenance is a type, not a convention.** The controlled fixture is kept out
of the capture-evidence channel by three independent mechanisms: a distinct
input type (`DriftCurrentObservation`, not a recorded observation); a structured
`DriftCurrentSource` whose constructor *refuses* a source that claims both
declared and live-capture; and deliberate exclusion from `EvidenceRef` — because
`evidence_ref_for` types by file extension, and typing a fixture `.jsonl` would
assert "live XDP state". It appears only in the provenance list under role
`controlled_drift_observation`, with a digest re-verified at construction.

---

## 7. Phase 5 — the true end-to-end trace

```
recorded capture → ObservedState → ValidatedBaseline → current state
→ DriftAssessment → finding → technical risk → mission context
→ contextualized risk → chain of custody → evidence + integrity → API
```

Traced against `results/end-to-end-assessment/accepted_drift_demo.json`.
Every stage connects, and the artifact is byte-identical across regenerations
(`fbf87b6323a96449…`; the digest moved when the `controlled_fixture` note below was corrected, and is quoted from the artifact as committed).

**Stage-by-stage data status — no stage depends on fabricated data except the
one flagged:**

| Stage | Input | Status |
|---|---|---|
| ObservedState | `tunnel_v4/state.jsonl` | **real recorded** |
| ValidatedBaseline | same capture, explicitly validated by `sec-ops@ipsec-testbed` | **real recorded** |
| Current state | `ah_substitution_state.jsonl` | **CONTROLLED FIXTURE** — declared, digest-verified |
| Drift → finding → risk | existing engines, 30/HIGH | real *computation* over a declared input |
| Mission context | `configs/mission/asset_mission_profiles.json` | **real operator declaration** |
| Chain of custody | all of the above | mixed, correctly labelled |
| API | existing routes | verified |

### The demo artifact now also contains a fully real chain

Added during this validation: `fully_real_chain` —
`dataset-20260924-003710:16:tunnel-v6` / `RISK-ADDRESS-FAMILY-MISMATCH`,
`uses_fixture: false`, MEDIUM 12, 2 valid evidence refs, 8 pass + 1
`unavailable` integrity check, mission `configured` → 18. **This is the scenario
a demo can show with no disclosure caveat at all.**

---

## 8. Integrity and tamper

| Scenario | Expected | Observed | Verdict |
|---|---|---|---|
| Untampered | PASS | 8 `pass`, 1 `unavailable`, 2 refs `valid` | **PASS** |
| Tampered (reference digest) | FAIL | `invalid`, `expected_sha256` reported alongside `actual_sha256` | **PASS** |
| `verify=false` | must not claim verification | `performed: false`, refs `not_performed`, digest check `unavailable` | **PASS** |

`verify=false` also accepts `verify=0` and, critically, **never** reports
`valid` or `pass`. `verify()` never writes, repairs or substitutes.

Two integrity results that are **not** green, and are not presented as green:

- **`audit.chain_linked` is `unavailable`** on every chain, because these stores
  are built without an audit event. The chain is not anchored in the
  tamper-evident journal. It reports "cannot be checked", not "checked".
- **`observation.expected_observed_coherent` FAILS on the drift chain** — see below.

---

## 9. Defects found

Three API contract violations and one correctness defect. All are located, all
are reproducible, none is cosmetic. **None is fixed in this report** — the task
was validation, and these are listed as the minimum work in §F.

### D1 — the drift chain contradicts itself (correctness, most serious)

`correlation/api/store.py:816-817` (`_register(... observed=current,
correlation=correlation ...)`) registers the drift-origin assessment with
`observed=<the declared fixture>` but `correlation=<the plan comparison, built
from the recorded capture>`. Those are two different observations. Custody reads
its OBSERVED facts from the correlation rows, so one chain asserts both:

```
observed.esp_presence        True   [OBSERVED / authoritative_observation]
                              "observed ESP presence equals expected (present)"
derived.drift_changed_fields        esp.presence: baseline=True -> current=False
finding                            RISK-DRIFT-ESP-PRESENCE  (ESP is no longer present)
```

The integrity check correctly returns `fail` with
*"observed esp.presence=True does not establish a discrepancy against expected
True"* — a detail that is **false about the drift claim**. A frontend rendering
this chain would show "ESP present" on a finding that says ESP disappeared.
*Remedy:* give the drift-origin assessment a correlation whose rows carry the
drift comparison's own expected/current values, or teach the coherence check to
read a drift finding's `changed_fields` instead of the plan outcome.

### D2 — `ChainOfCustody.$.api` violates its own `const`

Served `"custody"`; contract requires `const: "custody.v1"`
(`openapi.py`, `ChainOfCustody.properties.api`). **Every** chain-of-custody
response fails this. A strict client validator would reject all of them.

### D3 — `ChainOfCustody.$.rule.score_contribution` type mismatch

Contract: `{"type":"integer","nullable":true}`. Served:
`"25/12/6 per the mapped severity"`. The contract appears to describe a
per-finding number that the chain does not expose.

### D4 — `GET /api/v1/assessments/{id}/drift` omits two required fields, always

`DriftAssessment` requires 10 properties, including `model_version` and
`rule_id`. **Both are absent in both branches** — configured and `not_configured`
alike. The strings `drift-model-v1` and `drift.configuration` do not appear
anywhere in the payload, so this is not a branch-specific omission: the route
simply never emits them. The `not_configured` branch
(`correlation/api/drift_routes.py:116-131`) and the configured branch are both
non-conforming.

An earlier draft of this report claimed the configured branch did emit them. That
was wrong, and checking it is what exposed the real scope: 2 fields × 2 branches
= 4 violations from one cause.

Validated by a self-contained structural validator that resolves `$ref`,
`allOf`, `anyOf`/`oneOf`, `nullable`, `const`, `enum` and `type` from the
OpenAPI document itself — **no new dependency** (`jsonschema` is not installed
and was not added). It honours OpenAPI 3.0's `nullable: true`, which is not part
of JSON Schema proper; ignoring it produces 23 spurious "null not allowed"
errors, so getting that wrong would have manufactured a defect that does not
exist. The first draft of this report did exactly that, and did over-report.

Definitive result over all seven affected responses:

```
/api/v1/assessments/{id}/findings/{fid}/explanation   2   (D2, D3)
/api/v1/findings/{fid}/explanation                    2   (D2, D3)
/api/v1/assessments/{id}/drift   [baseline]            2   (D4)
/api/v1/assessments/{id}/drift   [no baseline]         2   (D4)
/api/v1/drift                                           0   conforms
/api/v1/drift/baselines                                0   conforms
/api/v1/assessments                                     0   conforms

TOTAL 8 violations, from 4 distinct causes
```

---

## 10. Test results

```
Focused (novel-feature suites):
315 passed
0 skipped
0 failed
(553 subtests passed)

tests/:
1601 passed
7 skipped
0 failed
(1878 subtests passed, 7 pre-existing shap warnings)

Full repository:
2175 passed
22 skipped
0 failed
(2454 subtests passed, 10 pre-existing shap warnings)
```

Focused = `test_novel_feature_validation` + `test_end_to_end_assessment` +
`test_drift_detection` + `test_mission_context` + `test_chain_of_custody`.
Skips and warnings are unchanged from the pre-validation baseline (2163 passed
/ 22 skipped); the delta is exactly **+12 tests** — the new validation suite —
all passing. No test was modified, weakened, skipped or deleted.

### Tests added — 12, all for a measured gap

`tests/test_novel_feature_validation.py`. The gap: the drift milestone's own
acceptance test compares **4** real captures; the repository holds **10** usable
ones, and nothing asserted the whole corpus. So "no real pair exercises a
protection change" was a claim, not a checked fact.

- `TestTheWholeRealCorpusIsOneSecurityState` — 10/10 identical, 90/90 pairs
  `no_drift`, canonical state is exactly the 3 declared fields, corpus non-empty
  (so the others cannot pass vacuously)
- `TestTheRealCorpusContainsNoProtectionChange` — searched across **every file
  of every form** in the repo, not only loader-admitted ones: ESP-absent and
  AH-present appear only in the declared fixture; and `ObservedState` exposes no
  crypto field
- `TestRefusedArtifactsAreRefusedWithAReason` — every refusal is either a
  *declared* inconsistency or a *form* rejection; no silent skip
- `TestCrossEndpointComparisonIsNotScoped` — pins the D1-adjacent scoping
  limitation so it cannot be forgotten, and fails if the payload ever starts
  disclosing endpoints

**Not added:** tests asserting D1–D4. Encoding a known-wrong value as an
expectation would enshrine the bug; an `xfail` would hide it. Each is
reproducible from §9 and each has a named remedy.

---

## 11. End-to-end limitations

Brutally honest, separating **implemented / tested / demonstrated / observed in
real data / controlled**.

### Drift

- **Implemented** (3 comparable fields), **tested** (110 tests), **demonstrated**
  (fixture + real IPv4/IPv6 pair), **observed in real data: never**,
  **controlled** (the ESP→AH substitution that carries the demo).
- 3 of ~15 security-relevant attributes are observable. Cipher, DH group, PFS,
  IKE version, integrity algorithm, firmware and implementation identity are
  **undetectable** — not "not implemented", but *unrepresentable* in
  `ObservedState`.
- The comparison establishes a **difference between two canonical states**, not
  that the same asset changed (§4 scoping defect), and not intent or
  authorization.
- A registered baseline can itself be wrong. Drift detects departure from a
  declaration that a state was validated.
- 1 real pair *is* distinguishable in principle (IPv4 vs IPv6) but is a
  different tunnel, and the loader will not admit it.

### Mission context

- **Implemented, tested, and demonstrated on fully real data.** No fixture.
- `gw-a` / `gw-b` are **operator assertions**. The contextualized 12 and 18 are
  consequences of that assertion, and the demo should say so on screen.
- A single monotone formula, always an uplift, capped at the existing 100. It
  cannot re-rank two findings, only re-scale one.
- Minor: the contextualized severity is banded with a **freshly constructed
  default policy** (`contextualize.py:185`) rather than the policy that produced
  the technical score. Identical under the current default; would diverge under
  a custom band policy.

### Chain of custody

- **Implemented, tested, demonstrated on fully real data.**
- The drift-origin chain **contradicts itself** (D1) and would mislead a UI.
- **Not anchored in the audit journal** — `audit.chain_linked` is
  `unavailable` everywhere, so no chain here is tamper-evident end to end.
- Explanations are **structured fields and short statements**, not generated
  prose. Every value is a fact with a digest and a source; a UI must render the
  fields rather than expect a narrative.
- `recommendation.applied` is always `false` — this API can propose, never
  execute.

---

## 12. Demo readiness

```
DRIFT-AWARE SECURITY ASSESSMENT          READY WITH DISCLOSURE
  The engine is correct and its labels are honest, but every drifted
  assessment a viewer sees is a declared fixture. It must be labelled
  "controlled scenario, not a live capture" on screen, and the drift chain
  must not be shown until D1 is fixed — it displays ESP present on a
  finding that says ESP disappeared.

MISSION-CONTEXT-AWARE RISK              READY
  Works on a fully real chain with zero fixtures. The only on-screen
  requirement is that the profile is shown as an operator declaration.

CHAIN-OF-CUSTODY EXPLAINABILITY          READY WITH DISCLOSURE
  Fully real and fully usable. Disclose that the chain is not anchored in
  the audit journal. If the UI validates responses against the published
  OpenAPI document it will reject them until D2 and D3 are fixed.
```

**Recommended demo set**, all deterministic and regenerable:

| Scenario | Data | Show |
|---|---|---|
| `fully_real_chain` | **real only** | real finding, real evidence, integrity, mission uplift |
| `control_no_drift` | **real only** | a comparison that correctly finds nothing |
| `asset_contexts.gw-a` vs `gw-b` | fixture for drift | same technical finding, different prioritization |
| drift chain | **fixture** | after D1 is fixed only |

---

## 13. Engineering verdict

### A. What genuinely works now?

- **The authority model.** `ObservedState` is authoritative and carries no
  crypto; ML is fenced twice and can never move a score; XAI never imports
  `make_finding` and copies the assessment verbatim; mission context reads two
  declared strings and no network data. All verified in source, all enforced by
  construction, not convention.
- **Drift is correct within its declared scope**, and provably produces no false
  positives: 90/90 real pairs `no_drift`, 5/5 deterministic serializations, and
  the reported changed field equals independently computed truth.
- **Mission context is fully working on real data** — all 6 criteria, technical
  risk untouched, only 4 sections differ between a low and a high asset.
- **Chain of custody is genuinely working on real data** — all 8 questions
  answered with digest-bearing structured fields, evidence re-hashed and valid,
  honest `verify=false`.
- **No real drift exists**, now established by a corpus-wide scan rather than
  asserted.

### B. What only works through controlled fixtures?

**Protection drift, entirely.** ESP→AH substitution, the finding, the severity,
the 30/HIGH score, and the drift chain of custody all depend on
`tests/fixtures/drift/ah_substitution_state.jsonl`. Its provenance is exemplary —
source path, source digest, every edit from→to with a reason, and an explicit
not-a-capture statement — and it is labelled in the type, the payload, the
table row and the artifact. But it is a derived input, and no real capture in
this repository exhibits a protection change.

### C. What does not work yet?

1. **D1** — the drift-origin chain of custody is self-contradictory. Most
   serious item here.
2. **D2, D3** — two served fields violate their own OpenAPI contract, so a
   strict client rejects every custody response.
3. **D4** — the `not_configured` drift response omits two required fields.
4. **Drift comparison is not scoped to an endpoint pair** — comparing two
   unrelated tunnels yields a MEDIUM `address_family` finding.
5. **Firmware / implementation / traffic / ML-behaviour drift** — undetectable
   by design. Not fixable without extending the observation layer, which is out
   of scope and would require real new capture work.
6. **No audit-journal anchoring** — `audit.chain_linked` is always
   `unavailable`.

### D. Minimum backend work before frontend integration

Ordered; 1–3 are small and mechanical, 4 is a design decision.

1. **Fix D1** in `correlation/api/store.py` (~2 lines): give the drift-origin
   assessment a correlation whose rows carry the drift comparison's expected
   and current values. Add a test asserting no chain contains both
   `observed.X == baseline.X` and `X` in `changed_fields`.
2. **Fix D2** (`"custody"` → `"custody.v1"`) and **D3** (either emit an integer
   `score_contribution` or change the schema to a string).
3. **Fix D4** (emit `model_version` and `rule_id` in **both** branches of
   `correlation/api/drift_routes.py`, or drop them from the schema's
   `required` if the route genuinely has no rule identity to report).
4. **Decide** on endpoint scoping for drift. Cheapest honest option: require or
   record the baseline's endpoints and publish them on the comparison, so a
   reader can see whether both sides describe the same tunnel. Do **not** infer
   asset identity.
5. **Optional:** band the contextualized severity with the assessment's actual
   policy rather than a fresh default.

Then: run the demo generator, and point the frontend at the published OpenAPI
document. **No frontend code is needed for any of the three capabilities** — the
routes, the fields and the schema already exist.

### E. What should NOT be changed?

- `controller/api.py`, the frontend, `requirements.txt` — untouched, and
  should stay that way.
- `ObservedState` — do not add crypto fields to manufacture drift. The absence
  is the reason the unsupported-category list is trustworthy.
- `ComparisonEngine` and the risk rules/scoring — correct, deterministic, and
  the reason all three capabilities share one authority model. D1 lives in the
  new store integration, not here.
- The drift provenance mechanism (`DriftCurrentSource`, evidence exclusion,
  digest re-verification) — working as designed.
- `unsupported_categories` — keep publishing it. Silent absence is worse than
  a declared gap.
- The fixture's provenance file — it is the model for how controlled input
  should be declared.

### F. Exact next implementation step

Fix **D1** in `correlation/api/store.py`, then **D2, D3, D4** in
`correlation/api/openapi.py` and `correlation/api/drift_routes.py`, and land the
regression test for D1 alongside. Then re-run:

```bash
.venv/bin/python -m pytest tests/test_novel_feature_validation.py \
    tests/test_end_to_end_assessment.py tests/test_drift_detection.py \
    tests/test_mission_context.py tests/test_chain_of_custody.py -q
.venv/bin/python scripts/write_end_to_end_demo.py
```

After that the drift chain is internally consistent and the API is
self-consistent, and the three capabilities are demo-ready with the disclosure
this report specifies. Do not proceed into frontend work before D1 is fixed —
it is the one defect that would make a demo actively misleading.

---

## Appendix — reproduction

```bash
# corpus scan (Phase 2 Test A)
.venv/bin/python -m pytest tests/test_novel_feature_validation.py -v

# focused novel-feature suites
.venv/bin/python -m pytest tests/test_novel_feature_validation.py \
  tests/test_end_to_end_assessment.py tests/test_drift_detection.py \
  tests/test_mission_context.py tests/test_chain_of_custody.py -q

# whole suite, then whole repository
.venv/bin/python -m pytest tests -q
.venv/bin/python -m pytest -q

# regenerate the deterministic demo artifact
.venv/bin/python scripts/write_end_to_end_demo.py
```

**Artifacts**

| | |
|---|---|
| real baseline | `results/e2e-verification/parser/tunnel_v4/state.jsonl` (`0cefd781…`) |
| controlled current state | `tests/fixtures/drift/ah_substitution_state.jsonl` (`496ea12e…`) |
| declared provenance | `tests/fixtures/drift/ah_substitution_provenance.json` |
| operator profiles | `configs/mission/asset_mission_profiles.json` (`515e03fb…`) |
| demo artifact | `results/end-to-end-assessment/accepted_drift_demo.json` |
| new validation tests | `tests/test_novel_feature_validation.py` (12) |
