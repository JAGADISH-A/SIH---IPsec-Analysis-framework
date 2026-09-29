# Finding Filters + Risk/Criticality Triage Report

Feature: a horizontal FINDINGS filter bar on the Packet Analysis workspace that
narrows findings (never the live packet stream) by backend risk/criticality,
confidence, traffic, finding type, and drift — plus an explicit, readable
risk chip in the packet table using the backend's exact severity labels.

Files changed:

- `src/hooks/useFindingFilters.ts` — new. Loads the finding index, the
  assessment header registry, per-assessment drift, and the ML bundles of
  ML-assessed flows; derives every filter option from the live store and
  applies deterministic client-side AND filtering.
- `src/components/packet/FindingFilterBar.tsx` — new. The compact horizontal
  bar + the compact findings-results strip (one clickable row per finding).
- `src/pages/PacketWorkspace.tsx` — the bar is mounted as the FIRST row of the
  workspace; the local `RiskBadge` was removed and the shared `RiskChip`
  primitive is used in the risk column; packets whose assessment matches the
  filtered findings get a subtle accent; a finding click opens the matching
  packet's investigation (or an assessment-anchored investigation when no
  captured packet exists in the buffer).
- `src/components/packet/PacketInvestigation.tsx` — the held-snapshot notice
  now distinguishes a findings-anchored selection from an evicted packet.
- `src/index.css` — `pw-filter-*`, `pw-findings-*`, `pw-row-finding` styles
  (dark theme, scoped under `.pw-root`).
- `smoke/finding-filters-smoke.ts` — new harness (44 checks).
- `smoke/live-capture-smoke.ts` — Phase 3 now also asserts the risk chip and
  the filter bar during the live run.
- `package.json` — `smoke:finding-filters` added; the `smoke` chain runs it.

## A. Risk column — data trace (requirement 8)

The packet table's risk value is not cosmetic and is not flattened. The chain
is:

```
live packet (xdp_monitor) -> /api/v1/capture/events risk projection
  -> risk.highest_severity  (the assessment store, by observed SPI)
  -> CaptureRow.severity    (src/lib/packetRows.ts:61)
  -> RiskChip (primitives.tsx)
```

- The `INFO` labels currently visible in this store's buffer are the REAL
  severity of assessment `…:1:nat-t` (severity `INFO`, `finding_count 0`). They
  are not an empty/no-finding state collapsed to INFO and not a packet-derived
  guess — the backend recorded severity `INFO` for that observed SPI.
- No HIGH/MEDIUM/LOW packet rows exist in the current buffer because the
  buffer only carries SPI `3450011795` / `3433976547` (the nat-t tunnel). The
  store's MEDIUM/LOW/HIGH assessments are exposed through the findings filter
  surface and, when their SPI is actually observed, through the table.
- The severity taxonomy rendered is the backend model's: `INFO`, `LOW`,
  `MEDIUM`, `HIGH`, `CRITICAL` (`severityRank` order), each as an uppercase
  text label in a chip (no reliance on colour alone).

## B. Risk chip (requirements 1–3, 8)

- One shared risk component only: the table now uses the same `RiskChip` as
  the investigation, so severity can never render differently in the two
  places.
- Text is always present (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`),
  so it stays readable for colour-blind users, screenshots, prints and low
  brightness.
- A packet with no assessment risk renders `—` (honest unknown), never an
  artificial LOW.
- Asserted by the smoke's severity matrix (all five labels + the `—`
  fallback).

## C. Filter bar location and design (requirements 4, 9, 10)

- One horizontal compact row at the very top of the workspace, above the live
  feed row: `FINDINGS` + `Risk ▾ Confidence ▾ Traffic ▾ Finding ▾ Drift ▾`
  + `Clear Filters` + a live summary.
- It is a bar with small dropdowns, not a sidebar, modal or drawer. It wraps
  onto a second row on narrow widths; the live packet table remains the
  dominant element ("LIVE • packet feed" row is unchanged beneath it).

## D. Filters and the exact backend data driving each

| Filter | Options | Data source |
| --- | --- | --- |
| Risk | All, CRITICAL, HIGH, MEDIUM, LOW, INFO | `finding.severity` |
| Confidence | All, ≥90%, ≥80%, ≥70%, ≥50% | `finding.confidence` (null for deterministic rules); the ML finding carries the classifier probability |
| Traffic | derived store labels | assessment header `traffic_profile` + inferred `ml.traffic_class` when ML ran |
| Finding | distinct `finding_id` present in the store | `finding.finding_id` |
| Drift | All, With drift, Without drift | `getAssessmentDrift(id).drift_detected` (per-assessment backend state) |

Traffic options are genuinely derived — this store offers `Email`, `ICMP`,
`Messaging`, `Web` and does NOT offer `VoIP`/`Video` because no finding is
tagged to those (profiles exist but have zero findings), so nothing is
hard-coded.

## E. Combination, result count, clear, empty state

- All filters combine with AND: `Risk=MEDIUM AND Traffic=Email` returns only
  findings satisfying both (verified 3 in this store).
- The summary is computed from the filtered store and never fabricated:
  `9 findings · 7 MEDIUM · 2 LOW · 12 assessments` (no filters), degrading to
  `X of 9 findings` when filters are active.
- `Clear Filters` is disabled/subtle with no active filters; it resets to
  "All" everywhere and the full list returns.
- Empty states are explicit:
  - store has no findings: `The assessment store contains no findings yet.`
  - store has findings but none match: `No findings match the selected
    filters.` + a `Clear Filters` button.
  Nothing is invented — no fake findings, packets, or risk values.

## F. Packet click → investigation (requirement 6)

- Clicking a packet row with a risk chip already opens the Packet Investigation
  with risk, confidence, finding, why-flagged, traffic type, relevant
  configuration, Gateway A↔B, combination, drift, evidence/provenance — this
  surface is unchanged (the 36-check `smoke:investigation` still passes).
- Clicking a filtered finding opens its assessment's investigation: when a
  buffered packet carries that assessment it selects the real packet;
  otherwise it opens an assessment-anchored investigation (built only from
  store data; packet-specific columns render `—`) and states honestly that
  no captured packet is in the live buffer. No separate Findings page was
  created.

## G. No-finding packets stay honest (requirement 7)

The `INFO` rows are the backend's real INFO assessment; packets with no risk
are `—`. Absence of a finding is never promoted to LOW. Verified on the wire
and in the smokes.

## H. Live capture unaffected (requirement 13)

The filter bar touches nothing in the capture path: no changes to XDP
observation, the JSONL journal, cursor polling, the feed row, the traffic
scope filter, or the packet table. Filters only read the findings store.
The smoke asserts the packet table, the `buffered`/`in journal` line, the IST
clock and the risk chip all remain while a find filter is active.

## I. Tests and results

- `npm run typecheck` — PASS
- `npm run build` — PASS
- `npm run smoke` (ssr + timestamp + contract + dom + finding-filters +
  offline) — PASS — `ALL ROUTES RENDERED`, `TIMESTAMP CLOCK OK`,
  `ALL API CONTRACTS OK`, `ALL PAGES RENDERED LIVE DATA`,
  `FINDING FILTERS + RISK TRIAGE OK` (44 checks), `OFFLINE BEHAVIOUR CORRECT`
- `npm run smoke:investigation` — 36/36 PASS, `PACKET INVESTIGATION (+ EXPLANATION) OK`
- `npm run smoke:nojournal` — PASS (`NO-JOURNAL STATE CORRECT`)
- `npm run smoke:livecapture` — the two new checks added to Phase 3 pass
  (risk chip + filter bar during a live run); the remaining 6 failures are the
  known environment-blocked ones (sensor interface mismatch eth0/eth1 and no
  active SA → the feed replays the recorded journal as `available`, so the
  waiting-state, traffic-growth and pkt/s checks cannot pass here; `no console
  errors` carries the act()-polling noise). No capture code was modified.

New `smoke/finding-filters-smoke.ts` coverage (derived from the live store,
not hard-coded):

1. RiskChip matrix — INFO/LOW/MEDIUM/HIGH/CRITICAL exact labels + `—` fallback.
2. Bar renders at top; all five dropdowns; Clear Filters; summary line.
3. No filters → every store finding listed; summary counts match the store.
4. Risk provides exactly All/CRITICAL/HIGH/MEDIUM/LOW/INFO.
5. Risk=MEDIUM → N; Risk=LOW → M; Risk=HIGH → honest empty state + Clear.
6. Confidence ≥50% → only backend-confidenced findings; ≥90% → honest zero;
   All restores.
7. Traffic=Email narrows; options exclude VoIP/Video (derived, not hard-coded);
   Traffic=ICMP narrows to the ML-inferred finding.
8. Finding filter narrows to the exact rule id.
9. Drift=Without selects all (no baseline configured); Drift=With → honest
   zero (nothing drifted).
10. AND combination (MEDIUM · Email) intersects correctly.
11. Clear Filters restores list + summary.
12. Live table still renders; journal/buffered line; IST clock; risk chip.
13. Packet click still opens the investigation (honest no-finding state).
14. Finding click opens the real assessment investigation via the anchor;
    explicit "no captured packet" notice; resolves to the real assessment.

## J. Missing backend data (gaps, none fabricated)

- Confidence: deterministic findings (rule-driven) expose no statistical
  confidence (`confidence: null`), so any ≥N% confidence filter excludes them.
  This is honest and mirrors the investigation surface ("no confidence score").
- Drift: this store has no validated baseline; every assessment reports
  `not_configured` / `drift_detected=false`. The `With drift` bucket is
  therefore empty, and `Without drift` reflects the backend's reported state,
  with the per-finding tag reading `no baseline configured`.
- Risk/criticality: the store has no CRITICAL finding and no HIGH packet in
  the live buffer; those chips only appear when the backend actually records
  them. Nothing is invented to populate the ramp.