# Security Assessment Explanation — Implementation Report

Feature: the in-workspace **security assessment explanation** layer inside the existing
Packet Investigation workflow (packet → assessment → the analyst's story: criticality →
confidence → why flagged → configuration comparison → evidence → explain → ask AI).

No new sidebar pages, no new API fetches, no mock data, no invented scores. Every rendered
value is the analytics plane's own record, labelled with its provenance.

---

## 1. Files changed

| File | What happened |
|---|---|
| `sentinel-frontend/src/components/packet/AssessmentExplanation.tsx` | **New** — the ranked explanation surface (verdict, findings, confidence, why-flagged, traffic type, relevant/all configuration, A/B comparison, combination, drift, evidence, custody chain, next steps, Ask AI). |
| `sentinel-frontend/src/components/packet/primitives.tsx` | **New** — single-sourced evidence primitives (`Prov`, `RiskChip`, `VerdictChip`, `IntegrityVerdict`, `ComparisonVerdict`, `expectedConfigRows`, `ConfigCompareGrid`), shared by Gateway Config and the explanation so the two cannot drift. |
| `sentinel-frontend/src/components/packet/PacketInvestigation.tsx` | Refactor — Overview now renders `AssessmentExplanation`; moved-in blocks deleted; tab jump wired via `onShowEvidence={() => setTab('evidence')}`; Config tab now uses the shared grid. |
| `sentinel-frontend/smoke/investigation-smoke.ts` | Extended — scenarios A (risk-less, zero-on-wire), B (real ML assessment: confidence / traffic class / why / relevant config / combination / drift), B2 (real endpoint assessment: Gateway A↔B, evidence chain, View-evidence jump, custody reveal), C (quiet assessment: honest absent states), D (stale assessment error + retry). |

## 2. Backend contracts reused — none invented

`GET /api/assessments/:id` (bundle), `/api/v1/assessments/:id/findings`, `/api/v1/assessments/:id/drift`,
`/api/v1/assessments/:id/findings/:findingId/explanation` (custody chain), `/api/v1/evidence/:id` (integrity),
`/api/v1/capture/events` (the packet feed). The story reads only the already-loaded investigation state
(`usePacketInvestigation`); a risk-less packet still causes **zero** assessment requests on the wire (asserted).

## 3. Overall hierarchy (requirement 1)

Fixed story order, rendered on the Overview tab: **Security assessment verdict → Findings → Confidence →
Why flagged? → Traffic type → Relevant configuration → Configuration comparison (Gateway A↔B) →
Configuration combination → Configuration drift → Evidence & provenance → Explain this finding →
Assessment → Next steps → Ask AI**.

## 4. Criticality (requirement 2)

Big verdict card on top — shared `RiskChip` + overall score, severity band (`HIGH (20–39)` from
`risk.score_detail.severity_band`), sum of contributions, risk policy version, finding count.

## 5. Findings as sub-conclusions (requirement 3)

Each finding listed under the verdict with its severity chip, rule id, category and its own confidence
when the store records one. The primary finding (highest severity, store order) drives the deep-dive.

## 6. Confidence (requirement 4)

Only backend scores are rendered — **no scoring engine in the browser, no recomputation**:
- **Classification confidence** = `ml.classification_confidence` (e.g. `0.534 → 53.4%`, with the model
  version `traffic_rf_v1`). Hidden when `ml.present` is false.
- **Primary-finding confidence** = `finding.confidence` when non-null; otherwise the honest
  "not recorded — deterministic rule" (the deterministic engine records no statistical confidence).
- The block carries `data-confidence` with the exact backend value so a later global/flow confidence
  filter can key on the same field. Note also says no calibration curve is provided, so none is shown.

## 7. Why flagged — sub-conclusion scheme (requirement 5)

The primary finding is explained as labelled rows: **Detected** (condition) → **Cause** (custody
`summary` else `reason`) → **Parameter** (`related_variable`, expected vs observed + the comparison
verdict) → **Evidence** (type + pcap path) → **Impact** (description) → **Recommended** (recommendation
reason). Each row's provenance is explicit.

## 8. Configuration comparison (requirement 6)

**Gateway A ↔ Gateway B** — the two observed endpoint addresses with per-direction packets/bytes
(`packets_a_to_b`, `packets_b_to_a`, `bytes_a_to_b`, `bytes_b_to_a`), plus the single configured intent
(configuration id + posture). The section states plainly that the backend provides one configured set
per assessment, not a separate per-gateway config, so only one configured column exists.

## 9. Relevant vs all configuration (requirement 7)

"Relevant configuration" opens showing only the rows the findings pinned (`related_variable`, e.g.
`esp.pfs`, `esp.encryption`), each row marked `· flagged` and compared with the observed record and its
`UNKNOWN/MATCH/MISMATCH` verdict. A **Show all configuration →** button reveals every expected row
(Shared `ConfigCompareGrid`; "Show only flagged" collapses again).

## 10. Configuration combination (requirement 8)

Honest absent state by design: "**No configuration combination analysis is available for this finding.**"
The plane records per-variable comparison rows but no cross-parameter combination/co-occurrence
analysis, so none is presented. Verified against the live store (exact string asserted in the smoke).

## 11. Configuration drift (requirement 9)

Real block: `DRIFT DETECTED` with `baseline → current` changed fields when the store has a baseline;
else the verbatim backend reason ("not configured — a baseline must be established explicitly and is
never inferred"); else "no drift"; else "no drift record was returned". No fabricated baseline.

## 12. IKE/SA context (requirement 10) and traffic type (requirement 11)

**Observed SA** (handshake flags, association count, packets/bytes, correlation engine verdict) sits
with the comparison. **Traffic type** is three always-separate rows: **Detected** (capture adapter
classification, `observed`), **Inferred (model)** (ML traffic class + confidence, labelled `model`,
never promoted to observation), **Configured** (expected profile). A note reinforces that ML applies to
the flow/analysis window, not a single packet.

## 13. Evidence connection (requirement 12)

Finding → Evidence → Provenance chain rendered in full (`finding_id → evidence_id → source`), per-ref
artifact rows (pcap path, size, sha256 head, source), the integrity record when the backend returned
one, a loading state while integrity is in flight, honest "no artifact attached" when there is none —
and a **View evidence →** button that jumps to the existing Evidence tab (asserted interactively).

## 14. XAI entry point (requirement 13)

**Explain this finding** opens the full custody chain inline: facts (category chips, value,
`authoritative` marker), pipeline steps, the recommendation (action/priority/reason/rationale/roles)
and the recorded limitations — plus an "open finding →" link to `/findings/:assessmentId/:findingId`.
Asserted to reveal facts/steps/recommendation/limitations on click.

## 15. Ask AI entry point (requirement 14)

**Ask AI** sits at the end of the story (next steps), reusing the existing `AiBoundary` behaviour but with
an enriched context that now carries confidence, relevant configuration, combination status, evidence
and drift. The context note ("AI output is labelled INFERRED and never rendered as observation") is kept.

## 16. UX & visual consistency (requirement 15/16)

Pixar-style sequence (summary → findings → evidence → judgment → next steps) ending with **next steps:
open the full finding, verify the evidence, or ask AI**. Continuous dark theme, `pw-*` tokens, the same
severity chips / comparison verdicts / provenance labels everywhere (single-sourced in `primitives.tsx`),
progressive disclosure (subhead first, technical detail under it), no duplicated chips.

## 17. Testing (requirement 18)

`npm run typecheck` PASS, `npm run build` PASS, `npm run smoke` PASS (ssr/contract/dom/offline/timestamp
clean), **`smoke:investigation` 34/34 PASS**, `smoke:nojournal` PASS.
`smoke:livecapture` **cannot pass in this environment (unchanged, environment-blocked, not a regression)**:
the sensor interface is `eth0` not `eth1`, host-a↔host-b is unreachable with no active SA, so the feed
serves the recorded `live_events_full.jsonl` replay in `available` state (93 events, zero new ones);
waiting-state, growth, pkt/s and poll-timing/console-error items fail for that reason. The `dom` smoke
(which mounts PacketWorkspace + the new investigation) reports no console errors, confirming the
investigation surface itself is clean. Confidence/criticality/why/comparison/combination/drift/traffic/
evidence/XAI/Ask-AI/missing-data scenarios are all asserted against the **live** analytics store.

## 18. Genuinely missing backend data (documented, rendered honestly)

- No per-gateway A/B configuration (one configured set + observed A/B geometry only) — stated, not faked.
- No configuration *combination* analysis — explicit "not available for this finding" state.
- Crypto observed values are `UNKNOWN`/`null` (negotiated payloads are never decrypted) — shown as
  "not provided by backend", never as a value.
- Deterministic findings record no statistical confidence — rendered as such, not as 0%.
- No confidence *filter* and no calibration curve exist in the backend API — the UI exposes the exact
  score via `data-confidence` for a future filter and says no calibration is shown.
- Drift baselines are not configured in this store — the reason is shown verbatim, and "not configured"
  is never presented as "no drift".

Remaining gaps (outside this feature's scope, noted for later): live-capture traffic phases are blocked
by the lab topology (false `eth1` interface expectation); no audit-journal linkage is shown in this layer
(the custody chain records `no audit event is linked`); the confidence filter UI is intentionally not
built until the backend offers a filter contract.

— Sentinel frontend · assessment explanation layer.