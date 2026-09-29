# XAI / Explainability Layer — Implementation & Regression Report

**Scope:** `sentinel-frontend` only (Packet Analysis workspace → Packet Investigation).
**Revision 2 — finding-scoped custody/provenance:** the per-finding custody chain now follows the
analyst's selected finding instead of the highest-severity finding (details in §5).
**Backend changes:** none. **New endpoints:** none. **Live-capture / XDP / journal / polling changes:** none.
**Verification date:** 2026-09-29, against the live analytics store (12 assessments, 12 findings).

---

## 1. What was added

An evidence-grounded, inline **"Explain this finding"** panel inside the existing Packet
Investigation → Overview tab, plus an explicit separation of the two severity concepts that
were previously blended.

| # | Change | File |
|---|---|---|
| 1 | New `XaiExplanation` panel (collapsible; grounds the why in backend records) | `src/components/packet/XaiExplanation.tsx` (new) |
| 2 | Extracted the shared drift renderer so the XAI panel and the config view cannot drift apart | `src/components/packet/AssessmentDriftBlock.tsx` (new), reused by `AssessmentExplanation.tsx` |
| 3 | Assessment risk is captioned as **assessment / packet risk**; an explicit *Risk vs severity* note appears when it differs from the explained finding's severity | `src/components/packet/AssessmentExplanation.tsx` |
| 4 | **Selected-finding focus:** the findings strip and the Findings tab choose *which* finding is explained; assessment-level facts never move with the selection | `PacketInvestigation.tsx`, `PacketWorkspace.tsx`, `AssessmentExplanation.tsx` |
| 5 | `anchorRowFor` no longer leaks `finding.severity` into the packet/assessment risk slot | `src/hooks/useFindingFilters.ts:131` |
| 6 | Risk filter help states its scope, and the question mark carries a full accessible explanation | `src/components/packet/FindingFilterBar.tsx`, `src/index.css` |
| 7 | **Finding-scoped custody:** a dedicated `useFindingCustody(assessmentId, findingId)` hook owns the per-finding request; the assessment hook no longer fetches any finding-level data | `src/hooks/usePacketInvestigation.ts` |
| 8 | Custody section states whose chain it is (finding id, assessment id, default vs selected) with loading, per-finding error and retry; the XAI technical details gained a finding-scoped *Evidence custody / Chain position / Hash / Provenance / Verification* block | `AssessmentExplanation.tsx`, `XaiExplanation.tsx`, `PacketInvestigation.tsx` |
| 9 | Regression coverage for all of the above | `smoke/finding-filters-smoke.ts`, `smoke/investigation-smoke.ts` |

No new page, no second evidence implementation, no second configuration renderer: the XAI panel
**links to** the existing Evidence tab and reuses the existing `RiskChip` / `Prov` /
`ConfigCompareGrid` primitives and the existing dark `pw-*` theme.

---

## 2. Backend data actually used (no invention)

Everything the panel prints comes from records the analytics service already returns. The
investigation already fetched the full assessment bundle, so the panel required **no new
request**.

| Panel element | Source field |
|---|---|
| Assessment risk | `bundle.risk.severity`, `bundle.risk.overall_score`, `bundle.risk.risk_policy_version` |
| Score attribution | `bundle.risk.score_detail.contributions[]`, `.raw_sum`, `.severity_band` |
| Finding severity / confidence | `finding.severity`, `finding.confidence` (exact backend values) |
| Why it was flagged | `bundle.xai.finding_explanations[].why_it_was_flagged`, `.reason`, `.expected`, `.observed`, `.condition`, `.description` |
| Matched rule | `finding.rule_id`, `finding.condition` |
| Key factors | `finding.contributing_factors[]`, `finding.evidence_refs[]` |
| ML record | `bundle.ml` + `bundle.xai.ml_explanations[0]` (`model_version`, `traffic_class`, `classification_confidence`, `anomaly_score`, `explanation`, `limitations`, `evidence_refs`) |
| Configuration impact | `finding.related_variable`, `finding.expected_value`, `finding.observed_value`, `bundle.expected`, `bundle.correlation.rows[]` |
| Drift | `GET /api/v1/assessments/{id}/drift` (already fetched by the investigation) |
| Evidence | existing custody explanation + `EvidenceIntegrity`; the panel's **View evidence** button switches to the existing Evidence tab |
| Custody / provenance | `GET /api/v1/assessments/{id}/findings/{SELECTED finding_id}/explanation` — re-read per selected finding (see §5) |

**Deliberately not done:** no new explainability endpoint, and **no ML feature-importance or
per-feature attribution** — the backend does not return it, so the panel states
*"Model feature attribution is not available for this assessment"* rather than inventing an
explanation from the anomaly score.

---

## 3. Risk vs finding severity (two concepts, never blended)

The store proves these are different numbers: assessments are
`6 INFO / 1 LOW / 3 MEDIUM / 2 HIGH` while their findings are `7 MEDIUM / 2 LOW` — a **HIGH
assessment carries only MEDIUM (or lower) findings**.

* Packet table `RISK` and the context strip's *Security status* = **assessment/packet risk**
  (`risk.highest_severity`).
* FINDINGS `Risk` filter and every finding chip = **`finding.severity`**.
* The XAI panel prints a **trio**: *Assessment risk* (assessment) · *Finding severity* (this
  finding) · *Confidence* (backend score) — three labelled, separately-provenanced facts.
* When they differ, the Overview prints a `Risk vs severity` note naming both values, phrased
  for the finding actually being explained ("The primary finding…" vs "The selected finding…").
* `anchorRowFor` previously used `f.severity` for the packet risk, so opening a finding from
  the strip could display a MEDIUM packet risk for a HIGH assessment. It now uses
  `f.assessment?.severity ?? f.severity`, and the regression suite pins this down.

---

## 4. Selected-finding focus

"Explain this finding" always means the row the analyst actually chose.

* Clicking a row in the FINDINGS strip opens the assessment investigation **focused on that
  finding** (`focusFindingId` in `PacketWorkspace.tsx`).
* Every finding in the Findings tab has its own **Explain this finding** button, which focuses it
  and returns to the Overview.
* The explained finding is marked `data-explained="true"` / *"explained below"*; the XAI panel
  re-reads the same selection (`data-xai-finding-id`).
* A selection belonging to a different assessment is ignored, so the Overview can never explain
  another packet's finding.
* The selection also drives the custody chain and artifact integrity — see §5.
* The custody chain, the *Findings raised · highest finding severity* line, and the
  assessment-level facts stay assessment-level by design (the custody endpoint is fetched for the
  highest-severity finding).

---

## 5. Custody / provenance follows the selected finding (revision 2)

### The behaviour that was wrong

`usePacketInvestigation` fetched the per-finding explanation in a "Phase B" that ran
`selectPrimaryFinding(findings)` and requested
`GET /api/v1/assessments/{id}/findings/{PRIMARY finding_id}/explanation` **regardless of what the
analyst had selected**. So a HIGH assessment with three findings always showed the custody chain of
its most severe finding: the XAI rationale, severity, confidence, factors and evidence followed the
selection, but the custody chain silently did not. Everything downstream of that chain — the chain's
facts, steps, recommendation, limitations, its finding digest, and the artifact integrity record
read from that chain's evidence — was therefore another finding's provenance, presented next to the
selected finding's explanation.

### The behaviour now

Finding-level scope is a first-class input, not an afterthought:

* `usePacketInvestigation(assessmentId)` is now **assessment-only** (bundle, findings, drift). It
  performs no finding-level request at all.
* `useFindingCustody(assessmentId, findingId)` owns the finding scope: it calls the existing
  `getFindingExplanation` endpoint with **the selected finding id**, and reads artifact integrity
  from the artifact referenced by *that* chain.
* `PacketInvestigation` derives `explained = focusedFinding ?? selectPrimaryFinding(findings)` and
  passes `explained.finding_id` to the hook. Every finding-level surface — XAI rationale, severity,
  confidence, key factors, evidence, custody chain, artifact integrity and the Ask AI evidence
  context — reads that same `explained` finding.
* The highest-severity finding is still the *default* target when nothing is selected, and it is
  **labelled as a default** (`default (highest-severity finding)`) instead of being passed off as an
  analyst choice. Any selection replaces it.

Resulting contract, verified in the smoke:

| | Select Finding A | Select Finding B |
|---|---|---|
| XAI rationale / severity / confidence / factors | A | B |
| Evidence references & integrity | A | B |
| Custody request (`…/findings/{id}/explanation`) | A's id | B's id |
| Custody facts, steps, digest, provenance, verification | A's chain | B's chain |

### Data separation

**Assessment-level (never moves with a finding selection):** packet/assessment risk
(`risk.severity`, `risk.highest_severity`), overall score and `score_detail` contributions, traffic
profile, IKE/SA context, expected configuration, correlation status, dataset/scenario/slot,
assessment identity and the risk policy version.

**Finding-level (always follows the selection):** finding id, title, rule, severity, confidence,
source/model version, rationale, contributing factors, evidence references, evidence type, and the
custody chain with its facts, steps, digest, provenance sources, integrity checks, recommendation
and limitations.

**Guard rails in the hook and the views**

* No request at all when there is no assessment or no selected finding (an assessment with zero
  findings asks for nothing and renders an explicit "none is requested" empty state).
* Switching findings **clears the previous chain first**, so another finding's custody can never
  linger; a monotonic run counter plus `AbortController` discard any late response for a finding the
  analyst has already left.
* If the response's `finding_id` does not match the request, the chain is discarded and reported as
  a mismatch error instead of being displayed.
* A failure is rendered **against that finding** (id in the message, a Retry that re-requests the
  same id) and never falls back to another finding's chain.
* Artifact integrity is read from the selected chain's own `evidence[]`, and its absence narrows the
  evidence section rather than failing the chain.

### What the custody section shows

Collapsed, it now states ownership before anything is expanded — *Finding `<id>` · `<title>` ·
default/selected* and *Assessment `<id>`* — then loading, error+retry, or the chain summary.
Expanded, it keeps the existing facts/steps/recommendation/limitations. The XAI panel's *Technical
details* gained a compact, finding-scoped **Evidence custody** block (finding + assessment id, chain
position, hash, provenance, verification state) that points at the Evidence tab rather than
duplicating it.

## 6. Panel hierarchy

Collapsed: the finding's title + severity chip + a single **Explain this finding** action.
Expanded, in order:

1. **What Sentinel detected** — the backend's own `why_it_was_flagged` / `reason` verbatim.
2. **The assessment, the finding, the confidence** (trio above) + the finding's source
   (deterministic rule vs ML-derived) and evidence type.
3. **Key factors** — each with its own evidence attribution; a factor with no evidence says so.
4. **Configuration impact** — the finding's `related_variable`, expected vs observed, through the
   existing `ConfigCompareGrid`, including the "relevant configuration only / show all" control.
5. **Drift** — shared honest block (no baseline, no record, or a real comparison).
6. **Evidence** — integrity + **View evidence** jump into the existing Evidence tab.
7. **Custody chain · technical details** — collapsed `<details>`, same data as before.
8. **Ask AI (below)** — one line, with a button to the existing Ask AI section. The panel is
   *the* deterministic why; Ask AI remains the conversational follow-up.

### Deterministic vs ML

* The finding's origin is stated: `source === 'ML'` → *ML-derived*; otherwise *deterministic
  rule* (matched against `bundle.xai.finding_explanations` by `finding_id`).
* The **ML context** block is shown whenever the model actually ran for the assessment, and says
  honestly when the explained finding is *not* the model-derived one ("This finding came from a
  deterministic rule… that result is carried by its own finding").
* The model's own `explanation` and `limitations` are printed as recorded.

### Confidence

Only exact backend values are displayed: `ml.classification_confidence` for the model verdict and
`finding.confidence` for the finding, each labelled with its source. Nothing is recomputed,
averaged, or presented as if confidence were severity. A finding with no recorded confidence says
*"not recorded — deterministic rule"*.

---

## 7. Honest missing-data states

| Situation | What the UI says |
|---|---|
| No assessment on the packet | No assessment request is made; no XAI action is offered at all. |
| Assessment with no finding | No XAI action; the Overview states there is nothing to explain. |
| `xai.finding_explanations` has no entry for the finding | States that no deterministic rule explanation is available and names the fallback (the finding's own recorded description/reason). |
| Backend recorded no `reason` line | States that explicitly. |
| Finding has no `evidence_refs` | States that no artifact is attached — nothing is verified "by reference". |
| ML not executed | "ML was not executed for this assessment." |
| ML executed, no feature attribution | "Model feature attribution is not available for this assessment." |
| No configuration comparison for the variable | "No configuration comparison is available for this finding." |
| Drift: baseline not configured / no record / clean | Each distinguished: "not available … no comparison was made" ≠ "no drift was detected". |
| Selected finding's custody read fails | Error **naming that finding id** with a Retry that re-requests the same id; no other finding's chain is substituted. |
| Selected finding's custody is still loading | The previous chain is already gone; a "reading the custody chain for `<id>`…" state is shown. |
| Selected finding has no custody chain | "The backend did not return a custody chain for `<id>`; the technical evidence above is all that is recorded." |
| Assessment has no finding at all | No finding-level request is made; the custody section says so explicitly. |
| Assessment fetch fails (stale) | Unchanged error state with working **Retry** (covered by smoke). |

---

## 8. Regression coverage

### `smoke/finding-filters-smoke.ts` — 52 checks, all pass (was 44)
* Risk-filter help affordance + accessible explanation of the Risk filter's scope.
* "The store contains an assessment severity that differs from one of its findings" (guards the
  data premise; the row chosen is on a finding id that is **unique** in the store, so the row
  matched by text cannot belong to a different assessment).
* `risk=HIGH` never returns a MEDIUM/LOW finding from a HIGH assessment, and `risk=MEDIUM/LOW`
  finds those findings.
* The packet table `RISK` column carries assessment severities, never finding severities.
* Clicking the split finding opens **its own** assessment, shows the **assessment** severity as
  the packet risk, renders the explicit *Risk vs severity* note, and still shows the finding's own
  severity as a separate chip.

### `smoke/investigation-smoke.ts` — 94 checks, all pass (was 36)
* No-risk packet offers **no** XAI action.
* Assessment with no finding offers no XAI action and says so honestly.
* The verdict chip is labelled *assessment / packet risk* and carries the store's
  `highest_severity`; differing values are called out; identical values avoid duplicate chips.
* XAI (ML assessment): opens inline, separates assessment risk from finding severity, uses the
  exact backend confidence, renders the backend detection + key factors with evidence, reports the
  real model version, states feature attribution is unavailable, keeps configuration/drift/evidence
  grounded, keeps technical details collapsible, and is positioned separately from Ask AI.
* XAI (deterministic finding): reports *deterministic rule* (never model-derived), quotes the
  backend rationale verbatim, names the matched rule and condition, lists key factors each with
  evidence, keeps severity/confidence separate, ties configuration impact to the finding's own
  variable, never claims "no drift" when no baseline exists, ties evidence to the finding id, and
  reports an honest absence when the explainability engine has no entry.
* **View evidence** from the panel reaches the existing Evidence tab (one evidence implementation).
* Selected-finding focus: each finding has its own action; selecting a different finding re-points
  the Overview and the XAI panel, the *Risk vs severity* note follows the selection, the
  assessment risk does not move, and a deterministic finding is never dressed up as model-derived.
* Existing coverage preserved: 5-tab workflow, IKE & SA comparison with provenance, evidence chain
  and integrity, custody chain expansion, stale-assessment error + retry, no-finding state.

#### Custody-follows-the-selection (new, 21 checks)

Driven on a live **HIGH assessment that carries only MEDIUM findings** (so assessment risk and
finding severity are provably different values at the same time), with the smoke's request recorder
extended to fault or stall one finding's custody call. Both chains are also read directly from the
service, so the DOM is judged against values that cannot be confused between the two findings.

1. *No selected finding* → **no** finding-level custody request on the wire, plus the honest empty
   state and no XAI action.
2. *Default target* → the highest-severity finding, explicitly labelled `default
   (highest-severity finding)`; the request used that id; the displayed chain is that finding's own
   summary + digest, and the other finding's are absent.
3. *HIGH + MEDIUM* → the verdict chip, the XAI assessment chip and the trio all read `HIGH` while
   the finding chip reads `MEDIUM`; custody is the MEDIUM finding's chain.
4. *Select Finding B* → the XAI panel and the marked finding both switch to B; a custody request is
   issued for **B's id**; the custody section shows B's summary, digest and chain facts, and none of
   A's remain visible anywhere; the section names B and the assessment; the assessment risk chip does
   not move.
5. *Stale transition* → with B's request stalled, the previous chain is already gone and a loading
   state is shown; when it completes, A's own chain is displayed.
6. *Failure + retry* → the error is attached to the selected finding with a Retry for that id; no
   other finding's chain appears; the retry re-requests the same id; while the service is still
   failing the error stays honest; once it recovers the retry restores that finding's own chain and
   the error is gone.

---

## 9. Verification

| Command | Result |
|---|---|
| `npm run typecheck` | pass |
| `npm run build` | pass |
| `npm run smoke` (offline behaviour) | pass |
| `npm run smoke:timestamp` | pass |
| `npm run smoke:nojournal` | pass |
| `npm run smoke:finding-filters` | **52/52** |
| `npm run smoke:investigation` | **94/94** |
| `npm run smoke:livecapture` | 6 pre-existing environment failures, unchanged; the two risk-chip / FINDINGS-bar checks pass |

Commands were run **sequentially** — the smoke scripts share `dist-ssr/`, so parallel runs race.

### Known environment limitation (unchanged by this work)
`smoke:livecapture` still fails its six waiting-state/growth checks: the sensor's eth0/eth1 pair
does not match the expected capture interface and no SA is active, so a replayed journal never
grows (`93 → 93`), pkt/s samples are all `0`, and console noise appears during the run. This is
capture-side and was out of scope; nothing in this change touches XDP, the journal, the cursor,
packet streaming, traffic generation, or observation gates.

---

## 10. Remaining gaps (not implemented on purpose)

1. **No ML feature attribution.** The backend returns a classification, a confidence, an anomaly
   score and a narrative — no per-feature importance. The UI says so instead of guessing. A future
   `ml_explanations[].feature_importance` array would slot into the existing ML context block with
   no UI redesign.
2. **Two reads per selected finding.** The rationale comes from `bundle.xai` (one bundle fetch) and
   the chain from the per-finding endpoint, so a finding is described by two backend structures. They
   are the same data from two angles, but a backend that unified them would remove the join.
3. **The default target is still "most severe".** With no selection the highest-severity finding is
   explained and its custody fetched. This is now labelled as a default rather than hidden, but a
   product decision could make an explicit selection mandatory.
4. **Custody is refetched on every selection change.** There is no cache, so flipping between two
   findings of the same assessment re-requests both. A per-assessment custody cache would remove the
   churn; it is deliberately not added yet because a stale cache is a worse failure than a re-read.
5. **Ask AI remains a prompt builder.** It receives the assessment id and a composed evidence
   summary; it is not an explanation engine and is labelled as a follow-up conversation.
