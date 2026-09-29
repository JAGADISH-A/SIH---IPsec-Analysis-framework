# Drift-Aware Security Assessment — Implementation Report

**Component:** `correlation.drift` v1 · **Model:** `drift-model-v1` · **Schema:** `v1`
**Status:** complete · **Scope:** longitudinal drift of observed IPsec security state
**Tests:** 110 new (49 subtests) · **Full repository suite:** 2100 passed, 22 skipped, 0 failed

---

## 1. What this milestone is, in one paragraph

An IPsec gateway's security state is not a fixed fact. A tunnel that was
validated last week can be running under different protection today, and nothing
in the existing pipeline would notice, because every existing comparison is
*transverse*: it answers "does this observation match the plan?" and never
"does this observation match the state that was approved earlier?". This
milestone adds the longitudinal question. An operator explicitly validates an
observed security state as a **baseline**; every later observation is reduced to
a **canonical comparable security state** and fingerprinted; the two are
compared field by field; a difference becomes a finding under the project's
**existing** risk engine and policy; and the whole claim is carried into the
chain of custody and exposed read-only over the API. One drift category is
supported — `configuration_drift` — over three directly observed fields, and
everything the observation path cannot see is excluded by declaration rather
than inferred.

---

## 2. The finding that shaped the design

The first thing Phase 1 established is that the authoritative observation path
reports almost nothing about security *state*:

* `correlation/models/observed.py` documents `CRYPTO IS NOT INFERRED`, and the
  model has no cipher, DH group, PFS, integrity-algorithm, mode or IKE-version
  field. `ebpf/ipsec_state_builder.py` records `tunnel_seen` as "any traffic was
  observed at all", not as tunnel mode.
* `correlation/artifacts.py::observed_evidence_values()` returns `{}` and
  documents why: *"the only authoritative statements about the tunnel come from
  the signals the snapshot really has: ESP/IKE presence, SPI observations, and
  window coverage."*
* The dataset plan **does** carry authoritative expected crypto — `mode`,
  `address_family`, `ike.version/encryption/integrity/dh_group`,
  `esp.encryption/integrity/dh_group/pfs` — but no observation ever reports any
  of it back.

So the honest comparable surface is three fields, and the milestone brief's
preferred examples — a DH-group change, a PFS change, a cipher change — are
**not implementable**. They are not implemented. §6 records this as a scope
decision with its reason, and `UNSUPPORTED_DRIFT_CATEGORIES` records the
categories this milestone declines, so the gaps are declared rather than silent.

---

## 3. The comparable state

`correlation/drift/canonical.py` is the only place in the codebase that decides
what participates. The rule applied: **a field participates only if the existing
comparison layer already treats it as a directly observable, security-relevant
signal.** Membership is *read* from `correlation.risk.rules.MISMATCH_FINDING_SPECS`,
never restated, so a change in the project's security-relevance judgement is
picked up automatically.

| variable | derived from | existing rule | existing relevance | existing severity |
|---|---|---|---|---|
| `address_family` | `ObservedState.endpoints` (IP version) | `address_family.endpoints` | `True` | `MEDIUM` |
| `esp.presence` | `ObservedState.esp_seen` | `presence.esp` | `True` | directional |
| `ah.presence` | `ObservedState.ah_seen` | `presence.ah` | `True` | `MEDIUM` |

The address family is derived by **reusing** the comparison layer's own
`_endpoint_address_family` rather than re-parsing addresses, so drift cannot
quietly disagree with the comparison engine about what the observation says.

**Why these three are security-relevant.** ESP present versus absent, and AH
present versus absent, decide *which protection is actually in force* for the
same traffic: ESP carries confidentiality and integrity, AH carries integrity
only, so an ESP→AH substitution is a real reduction in protection. Address
family is the outer-header IP version, already `DIRECT_OBSERVABLE`.

### 3.1 The exclusion list, as data

`EXCLUDED_FIELDS` is data, not prose, so the report, the API
(`canonicalization.excluded`) and the tests all read one list:

| excluded | reason |
|---|---|
| `timestamp_ns` | wall-clock position of a snapshot; differs on every re-observation |
| `last_ike/ike_nat_t/esp/ah_timestamp_ns` | recency of the last packet per protocol: liveness, not posture |
| `packets_seen`, `bytes_seen`, `packets_a_to_b`, `packets_b_to_a`, `bytes_a_to_b`, `bytes_b_to_a` | volume depends on capture length, not security state |
| `active` | liveness within the builder's 1000 ms timeout; an idle unchanged tunnel reports `False` |
| `tunnel_seen` | "any traffic was observed at all", not tunnel mode |
| `spis[].spi` | SPI values are chosen at random and re-rolled on every rekey |
| `spis[].first_seen_ns`, `last_seen_ns`, `packet_count`, `first/last/highest_sequence`, `sequence_delta` | per-SPI window arithmetic |
| `transitions` | observation history, carrying timestamps and the liveness flags above |
| `ike_seen`, `ike_nat_t_seen`, `observed_ike_activity` | `ike.activity` has `security_relevance: False` in the existing rule table, so IKE activity is deliberately not a security finding |

### 3.2 The digest

`canonical_state_digest` calls the project's existing
`correlation.custody.builder.canonical_digest` — `sha256` over canonical JSON
with `sort_keys=True` and tight separators. It is reused rather than
reimplemented so a baseline fingerprint is reproducible by any client that holds
the canonical state, with no second digest convention to learn.

---

## 4. The baseline is an explicit, attributable, sealed act

```python
baseline = validate_baseline(
    observed,
    baseline_id="baseline-e2e-v4",
    validated_by="sec-ops",
    validated_at="2026-09-20T09:00:00Z",
    asset_id="gw-a",
)
```

There is **no** implicit baseline, no "latest observation is trusted", no
provisional state. `validation_status` is `validated` and nothing else; any
other value is refused at construction. `baseline_id`, `validated_by` and
`validated_at` are all required and non-blank, because a historical baseline
that cannot say who approved it is not attributable.

`validated_at` is caller-supplied rather than read from a clock, so a baseline
record is fully determined by its inputs — reproducible, and byte-stable across
runs.

**Two digests, two jobs.** `state_digest` fingerprints the comparable state, so
two observations can be compared by digest. `baseline_digest` seals the *whole*
record, including the provenance metadata the state digest does not cover.
Editing `validated_by` changes the seal even though the state digest is
untouched. `to_dict()` copies rather than shares `canonical_state`, so a caller
editing a serialised record cannot reach through it and mutate the live object.

A record arriving from disk (`from_dict`) is verified against its declared seal
*at load time*, and `assess_drift` re-verifies before comparing, so a tampered
baseline raises `BaselineIntegrityError` rather than entering the comparison
path.

### 4.1 A gap found and closed during implementation

An empty `ObservedState` reports `esp_seen=False, ah_seen=False` — and a first
implementation would have accepted one as a baseline, sealing "ESP is not in
force" as an approved historical state. That is the absence of evidence
promoted to a fact. `validate_baseline` now refuses any observation that saw no
traffic, using the same informative-observation guard the comparison side uses.

---

## 5. The four outcomes, and what each refuses to claim

| status | meaning | what it does **not** claim |
|---|---|---|
| `no_drift` | every comparable field matches the baseline | that comparable fields outside the declared set agree |
| `drift` | ≥1 declared comparable field differs | intent, attribution, authorisation, or that the current capture's technical risk changed |
| `not_configured` | no baseline was supplied | anything at all — no comparison was made |
| `indeterminate` | the current observation cannot support a comparison | either drift or agreement |

**`indeterminate` is the important one.** An observation that saw no traffic
reports every presence flag as `False` by non-observation. Reading that as "ESP
is no longer in force" would be the classic absence-of-evidence failure. Instead
the comparison is withheld entirely: no field is reported as changed, none as
agreed, and no finding is raised. The guard
(`observation_is_informative`) is the same test the existing comparison layer
uses for `traffic.activity`: `tunnel_seen` or a non-zero packet count.

**Unestablishable ≠ equal.** A comparable field that either side cannot
establish — for example an address family with no usable endpoints — is reported
as `unknown_variables`, excluded from the determination, and the reason says so
("reported as unknown, not as agreement"). Absence of a value is never recorded
as a value: `canonical_security_state` omits an unestablishable field rather than
writing `None`.

---

## 6. Scope: one category, and the three that are declined

`configuration_drift` is the only supported category.
`UNSUPPORTED_DRIFT_CATEGORIES` records `firmware_drift`,
`implementation_drift`, `traffic_behavior_drift` and `ml_behavior_drift` as
deliberately not implemented, published in the API response and the OpenAPI
schema so a client sees the boundary rather than inferring it from silence.

None of them could be supported: the repository contains no authoritative
firmware, vendor, implementation-version or payload-derived signal to compare,
and deriving one from traffic would be an unverified inference of exactly the
kind `ObservedState`'s own docstring forbids.

**Drift detection does not establish intent, attribution, or authorisation.** It
establishes that the protection observed in force differs from a state somebody
validated earlier. That statement is in the limitations of every chain that
carries drift.

---

## 7. Acceptance: four real captures, one security state, no drift

The decisive test uses recorded data, not mocks. These four artifacts are real
`ebpf.ipsec_state_builder` snapshots, and they differ substantially in exactly
the fields the exclusion list names:

| capture | packets | SPIs | NAT-T | `tunnel_v6inner` note |
|---|---|---|---|---|
| `parser/tunnel_v4/state.jsonl` | 200 | `0x00000000` | `false` | the baseline |
| `parser/tunnel_v6inner/state.jsonl` | 194 | `0x00000000` | `false` | name notwithstanding, IPv4 endpoints |
| `observed-state/live_state_from_events_full.jsonl` | 93 | 4 random | `true` | |
| `observed-state/lab-verify-…/state_events.jsonl` | 30 | 4 random, disjoint | `true` | |

All four reduce to **one** canonical state and **one** digest:

```
{"address_family": "ipv4", "esp.presence": true, "ah.presence": false}
460f2b4b5f53982b3ca1ec583813cc1d27c700165ff15a28cc812f336105b7c3
```

and all four report `no_drift` against the baseline with `risk is None` — no
finding, because there is nothing to find. The test class
`TestTheRealAcceptanceCriterion` first asserts that the captures *really do*
differ in the excluded fields, so the result cannot be a tautology.

A companion test applies a whole rekey — different SPI, counters, sequences,
window, history and NAT-T visibility — and still requires `no_drift`.

---

## 8. The demonstration: a declared derivation, not a fake capture

Every real capture in this repository reports the same posture (IPv4, ESP
present, AH absent), so **no real pair exercises a protection change**. Rather
than invent one silently, the drift case is a derived fixture that declares
itself:

* `tests/fixtures/drift/ah_substitution_state.jsonl` — the real
  `tunnel_v4` snapshot with the ESP protection replaced by AH.
* `tests/fixtures/drift/ah_substitution_provenance.json` — names the source
  artifact and its **real SHA-256**, states
  `"kind": "disclosed_derived_observation"`, states
  *"This file is NOT a packet capture and not a recording of any real system"*,
  and lists every edit with its from/to values and whether it is substantive or
  a consequence.

The two substantive edits are `esp_seen: true → false` and
`ah_seen: false → true`. The other four (`last_esp_timestamp_ns`,
`last_ah_timestamp_ns`, `spis[].active`, `transitions[type]`) are declared
consequences, each with its reason. `TestTheDerivedFixtureIsDeclared` asserts
that the derived file differs from the real one in **exactly** the declared
fields — so the fixture cannot quietly drift from its own description — and
that the directory contains no `.pcap`.

Result:

```
status   : drift
score    : 30 HIGH  (existing RiskPolicy, risk-policy-v1)
  RISK-DRIFT-ESP-PRESENCE  HIGH    esp.presence  True  -> False
  RISK-DRIFT-AH-PRESENCE  MEDIUM  ah.presence   False -> True
unchanged: address_family
baseline state digest : 460f2b4b5f53982b…
current  state digest : ccaed704121592f3…
```

Severity is not invented: `RISK-DRIFT-ESP-PRESENCE` is `HIGH` because the
existing `_esp_presence_severity(True, False)` says so — a protection that was
in force and is no longer observed is HIGH, the reverse is LOW because that is
config drift rather than a confirmed loss of protection.

---

## 9. No parallel engine

Drift findings are ordinary `RiskFinding` objects, scored by the existing
`score_findings` under the existing `RiskPolicy.default()`. There is no drift
scale, no drift policy, no drift weighting:

* category: the existing `CATEGORY_CONFIGURATION_MISMATCH`
* severity: read from the existing `MISMATCH_FINDING_SPECS`
* score: `correlation.risk.scoring.score_findings`, 0–100, `risk-policy-v1`
* evidence, identity, findings model: all the existing types

`RiskEngine.assess` itself cannot be reused, because it requires an
`ExpectedState` — and feeding it a baseline would mean fabricating `mode`, IKE
crypto and traffic fields the observation does not contain. The longitudinal
comparator is therefore a small canonical baseline-vs-current differ that calls
the existing rule table and hands its findings to the existing scoring path. It
is not a second detection or risk engine.

`Finding.rule_id` is `drift.configuration`, which distinguishes a drift finding
from a plan-mismatch finding in logs and audits while reusing everything else.

---

## 10. Custody integration

A drift finding's chain carries the claim as facts, checks and limitations, and
the two kinds of claim are filed separately so a reader can tell who asserted
what:

| fact | category | asserts |
|---|---|---|
| `configured.drift_baseline` | `CONFIGURED` | the baseline id, both digests, who validated it and when — *"NOT an observation made by this capture"* |
| `observed.drift_current_state` | `OBSERVED` | the current observation's canonical digest |
| `derived.drift_changed_fields` | `DERIVED` | the field-level difference, each entry with its baseline and current value |
| `derived.drift_unknown_fields` | `DERIVED` | comparable fields that were neither compared nor agreed |

Integrity checks:

* `drift.baseline_explicit` — both digests present, `validation_status`
  `validated`, digest algorithm stated, `client_verifiable: true`.
* `drift.fields_within_declared_scope` — every counted change is inside the
  declared comparable set, and transient values cannot produce drift.
* `drift.indeterminate_claims_nothing` — added when the outcome is
  `indeterminate`.

The limitations state, in the chain itself, that no cipher/DH/PFS/IKE-version/
firmware/implementation/traffic/ML drift is detected and why; that SPI values,
counters, timestamps and history are excluded and this repository's own captures
(93 and 30 packets, disjoint SPI sets) as evidence; and that drift establishes
deviation, not intent or authorisation.

The whole comparison is also serialised as `ChainOfCustody.drift`, so the drift
claim is auditable from the chain alone. **A chain built with no drift is
unchanged**: with no baseline, no drift fact, check, limitation or section
appears, and there is a test asserting that.

---

## 11. Mission context

Drift findings take the same contextualisation path as any other finding: a
drift `RiskAssessment` is an ordinary `RiskAssessment`, so
`mission_context(technical_risk=…, technical_severity=…)` applies unchanged.
Tests assert that contextualising a drift assessment never alters the technical
score or severity, that a high-criticality profile may raise the *contextualised*
view while the finding's own severity is untouched, and that a drift chain
carries both the mission facts and the drift section together.

---

## 12. Persistence: the smallest thing that could work

`BaselineRegistry` is a dict, optionally backed by an append-only JSONL file —
matching how the rest of the repository stores data. No database, no migration
tooling, no new dependency. The default is in-memory, so a caller that has not
opted into persistence still gets real semantics without touching disk.

* **Append-only.** `baseline_id` is unique; re-registering is refused, because a
  baseline that can be silently replaced is not a baseline. A persistent
  registry refuses `remove`.
* **Verified on the way in and out of the store.** A hand-edited registry file
  raises `BaselineIntegrityError` naming the line, rather than being trusted
  into a comparison.
* **Explicit asset filter.** `for_asset` filters on a declared `asset_id`; a
  baseline with no asset is not returned for any asset.

---

## 13. API — read-only, three GETs

| route | returns |
|---|---|
| `GET /api/v1/drift` | run-level summary: configured baseline, both digests, per-assessment outcomes, `supported_categories`, `unsupported_categories`, and the full `canonicalization` declaration |
| `GET /api/v1/drift/baselines` | the registered baselines, each as a full sealed record |
| `GET /api/v1/assessments/{id}/drift` | one assessment's comparison |

No endpoint accepts a body, an action, or a write; a baseline is established by
an operator through the drift layer and only ever *read* here. The mission
milestone's route guard was updated to name these three routes explicitly, and
now additionally asserts that **every** path in the document is a `GET`.

**An unconfigured store says so.** `GET /api/v1/drift` on a store with no
registry returns `configured: false` with a reason and an empty `status_counts`.
An empty result is not "no drift found" — the reason text says so explicitly, so
a client cannot read absence as a clean bill of health. The same holds for
`/api/v1/drift/baselines` (empty list ≠ no drift) and for a known assessment
with no comparison (`not_configured`).

OpenAPI gained `DriftSummary`, `DriftAssessment`, `DriftBaselineList`,
`DriftBaselineSide`, `DriftCurrentSide`, `Canonicalization` and
`ValidatedBaseline`, plus a `drift` property on `ChainOfCustody`, a `drift` tag,
and a test asserting every `$ref` resolves and that each declared property set
equals the served shape exactly.

---

## 14. Source map

| file | role |
|---|---|
| `correlation/drift/models.py` | versions, the four statuses, `configuration_drift`, and the declined categories |
| `correlation/drift/canonical.py` | the comparable projection, the exclusion data, the digest, the informative-observation guard |
| `correlation/drift/baseline.py` | `ValidatedBaseline`, `state_digest` vs `baseline_digest`, the seal, load-time verification |
| `correlation/drift/comparison.py` | `validate_baseline`, `assess_drift`, `FieldChange`, the existing-engine finding bridge |
| `correlation/drift/registry.py` | append-only, optionally file-backed storage |
| `correlation/api/drift_routes.py` | the three read-only handlers |
| `correlation/api/store.py` | optional `baselines`/`baseline_id`; comparison once at build time |
| `correlation/custody/{builder,models}.py` | the three drift helpers and the `drift` chain section |
| `correlation/api/{v1,openapi}.py` | dispatch and documentation |
| `tests/test_drift_detection.py` | 110 tests |
| `tests/fixtures/drift/` | the declared derivation and its provenance |

---

## 15. Boundaries honoured

Asserted in `TestTheBoundariesAreEnforcedNotJustIntended`, not merely intended:

* `controller/api.py`, the frontend and the control-plane API are **unmodified**
  (`git status` shows only `correlation/` and `tests/` changes).
* `requirements.txt` unchanged; no new dependencies.
* `ObservedState` **not** rewritten — the test asserts no crypto field was added
  to it, and that `observed_evidence_values()` still returns `{}`.
* `ComparisonEngine` **not** replaced or modified; the drift comparator reuses
  its derivations and the risk rule table.
* No second scoring scale: the score comes from `score_findings` under
  `risk-policy-v1`.
* The drift package imports no orchestration, network or subprocess module.
* Only `configuration_drift` is ever emitted, per the tests and the schema enum.

---

## 16. Limitations, honestly

1. **Three fields.** Cipher, DH group, PFS, integrity algorithm, mode and IKE
   version drift are not detected, because no observation reports them. A drift
   assessment in this system can say *which protection is in force* changed; it
   cannot say *which cipher* changed.
2. **A baseline is only as good as its validation.** The system checks that a
   baseline is a validated, sealed record. It cannot check that the state was
   validated *correctly* by the person who validated it. `validated_by` and
   `validated_at` make the act attributable; they do not make it correct.
3. **The demonstration is a declared derivation.** No real capture in this
   repository exhibits a protection change, so the drift case is a fixture with
   published provenance. It is not evidence about a real system.
4. **`indeterminate` is a coverage limit, not a clean result.** A gateway that
   is genuinely down and a gateway that is idle look identical to a passive
   sensor. Both report `indeterminate`; distinguishing them needs an
   authoritative reachability signal this system does not have.
5. **Baseline selection is the operator's.** `baseline_id` is named explicitly;
   there is no "most recent" or "most similar" fallback. An operator who names
   the wrong baseline gets a wrong comparison, correctly computed.
6. **One dataset run.** The store compares every assessment in the run against a
   single named baseline. Per-asset baseline selection would need an explicit
   mapping, which was not required here.
7. **Drift is not compromise.** A legitimate, authorised reconfiguration looks
   identical to an unauthorised one at this layer. Authorisation lives in the
   governance and response surfaces, not here.

---

## 17. Verification

| suite | result |
|---|---|
| `tests/test_drift_detection.py` | **110 passed, 49 subtests** |
| `tests/test_chain_of_custody.py` + `tests/test_mission_context.py` + `tests/test_api_store.py` + `tests/test_api_v1.py` + `tests/test_analytics_api.py` | **289 passed, 680 subtests** |
| `tests/` (full) | **1526 passed, 7 skipped**, 7 warnings, 1877 subtests (baseline 1416 / 7 / 1821) |
| repository (full) | **2100 passed, 22 skipped**, 10 warnings, 2453 subtests (baseline 1990 / 22 / 2397) |

The delta is exactly the 110 new drift tests and their subtests. The existing
diff is additive: 957 inserted lines across 6 files, with 4 removed lines being
two extended signatures and the mission route-count guard.

### Test classes, as claims

| class | asserts |
|---|---|
| `TestTheRealAcceptanceCriterion` | four real captures, one digest, no drift — and that they really do differ |
| `TestTheCanonicalizationIsNarrowAndJustified` | exactly three fields, each already security-relevant; no crypto variable; exclusions justified |
| `TestExcludedFieldsCannotProduceDrift` | every excluded field perturbed individually, plus a whole rekey, leaves the digest untouched |
| `TestBaselineIsNeverInferred` | no implicit baseline; attribution and clock-free determinism; an empty or trafficless observation cannot become a baseline |
| `TestBaselineIntegrityIsDetectable` | both digests catch what they claim, including provenance edits and `to_dict` aliasing |
| `TestTheFourDeclaredOutcomes` | all four statuses, both digests per side, both values per change |
| `TestDriftReusesTheExistingRiskEngine` | ordinary findings, severities from the existing table, existing policy, existing scale |
| `TestTheRegistryIsAppendOnlyAndOptional` | uniqueness, ordering, JSONL round-trip, tamper refusal naming the line |
| `TestDriftReachesTheChainOfCustody` | configured/observed/derived facts, both integrity checks, limitations, self-contained serialisation, and an unchanged chain when unconfigured |
| `TestDriftFlowsIntoMissionContext` | drift contextualises like any finding and never raises technical severity |
| `TestTheStoreOnlyComparesWhenTold` | no registry means no comparison; a missing or unnamed `baseline_id` is `not_configured` |
| `TestTheDriftApiIsReadOnly` | three routes, envelopes, 404s, and `not_configured` rather than `no_drift` |
| `TestTheDocumentedContractMatchesWhatIsServed` | every `$ref` resolves; each declared property set equals the served shape |
| `TestTheDerivedFixtureIsDeclared` | the fixture declares its source, digest, every edit, and that it is not a capture |
| `TestTheBoundariesAreEnforcedNotJustIntended` | forbidden files untouched, `ObservedState` not rewritten, no new dependencies, digest helper reused |
| `TestDeterminism` | byte-identical repeats, no clock, stable ordering |
