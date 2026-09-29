# Achievement–Impact Report: Packet Timestamps, Dark Theme Unification, and the In-Workspace Packet Investigation

Scope: `sentinel-frontend/` (UI) plus two backend touchpoints —
`correlation/streaming/live_adapter.py` (the timestamp root cause) and
`correlation/api/capture_feed.py` (field coherence). Everything was verified
against the LIVE analytics store (`:8081`) and control plane (`:8000`) exactly as
a browser would consume them; no mock data was introduced anywhere.

---

## A. Achievements

### A.1 Packet timestamps are now real Analyst data (root cause fixed, not patched)

The symptom was "packet times look like sensor uptime": rows showed small
numbers when the UI appended `-7h`. The root cause was upstream, not in the
frontend: the sensor's `xdp_monitor` wrote `bpf_ktime_get_ns()` (CLOCK_MONOTONIC)
as the event timestamp
(`ebpf/xdp_monitor.bpf.c` → `e->timestamp = bpf_ktime_get_ns()`).

- `correlation/streaming/live_adapter.py` now converts once, at ingest:
  `realtime_offset_ns = time.time_ns() - clock_gettime_ns(CLOCK_MONOTONIC)`,
  and `_wall_clock(ts)` maps non-positive values to `0` and everything else to
  `ts + offset`. The envelope and packet-level timestamps are both produced from
  this wall clock.
- `correlation/api/capture_feed.py` keeps `timestamp_ns` and
  `packet.timestamp` in lock-step (`timestamp_ns: int(packet.timestamp)`).
- The old frontend `-7h` hack was deleted. `src/lib/timeZone.ts` renders, once,
  in the analyst's local timezone (IST, UTC+5:30): `HH:MM:SS.mmm IST` in the
  workspace list with a tooltip of full IST + UTC + source; `YYYY-MM-DD
  HH:MM:SS.mmm IST` / `... UTC` in the investigation details. A sub-1e12 value
  is treated as seconds-precision (a deliberate, documented contract, not a
  guess), and non-positive values are rejected as `—`.

Served, verified realtime: the restarted live store returns
`timestamp_ns ≈ 1790663580503·10⁹` (i.e. current epoch) with
`timestamp_ns === packet.timestamp`.

### A.2 The whole app now shares the dark Packet-Analysis visual language

Before, only Packet Analysis was dark-themed; Assessments/Findings pages were a
light UI inside a dark app. Now `src/index.css` declares `@theme` tokens
(`--color-canvas`, `--color-ink`, `--color-sentinel`, the severity ramp
`critical/high/medium/low/info/good`, …), `html { color-scheme: dark }`, and
every hardcoded light color in components was converted to a token or a
dark-bright inline literal (`format.ts` severity/comparison styles, `ui.tsx`
primary button + text link, `Sidebar` active nav). A grep audit confirms no
remaining hardcoded light colors in JSX outside the token definitions and the
offline-red literal. No page changed its information architecture — this was a
visual unification, nothing was hidden.

### A.3 Packet Analysis is now the packet-level investigation entry point

The inspector pane of `PacketWorkspace` was replaced by a full
`PACKET INVESTIGATION` surface (`src/components/packet/PacketInvestigation.tsx`,
data via `src/hooks/usePacketInvestigation.ts`):

- Header always renders; a packet is selected by clicking a capture row.
- A packet the store never assessed shows the honest empty state — "No security
  finding associated with this packet/flow." — and makes **zero** assessment
  requests.
- An assessed SPI loads its real assessment in two phases (Phase A parallel:
  assessment + findings + drift, hard-failing; Phase B parallel-settled:
  explanation + evidence integrity, soft-nulled) and renders five views:
  **Overview**, **Findings**, **IKE & SA**, **Gateway Config**, **Evidence**,
  each with the +5-more correlation rows kept and a `Level of certainty` footer.
- **Why flagged?** shows Detected / Cause / Evidence / Impact from the real
  found instability + primary finding.
- **Ask-AI** sends the real packet + bundle context (echoed back) so the case
  travels with the prompt; `connected=false` result is shown honestly as
  `not_connected`.
- Data the backend does not provide is *labeled*, never invented: one
  `expected` config column + added-probe endpoints note, "not provided by
  backend" crypto rows, traffic-type provenance (`configured` / `observed` /
  ML-inferred).
- No new sidebar/nav items were added; `/findings/:id` deep links remain the
  only secondary path.

### A.4 Verification harness

Two new smokes + updated ones, all wired into `package.json`:

- `smoke/timestamp-smoke.ts` (offline, deterministic): pins the IST/UTC
  millisecond conversions, seconds-precision recovery, the sensor-uptime guard,
  and missing/invalid handling → passes.
- `smoke/investigation-smoke.ts` (live, mounts the panel directly under
  `MemoryRouter` in jsdom): risk-less packet renders the empty state with zero
  assessment traffic on the wire; a real assessment renders all five tabs, the
  SPI (hex-padded), a link to the real `assessment_id`, and provenance; a stale
  id renders the server error state with a retry → passes.
- `smoke/dom-smoke.ts` now asserts the workspace surfaces the investigation, the
  analyst-local IST clock, and accepts the audit monitor's honest empty-journal
  state; `smoke/contract-smoke.ts` asserts `timestamp_ns === packet.timestamp`
  and the 1.7e18..now realtime window; `smoke/live-capture-smoke.ts` gained a
  click-through phase asserting the IST wall clock in rows and that selection
  resolves to an honest investigation state (views *or* the empty state).

## B. Impact

- A network operator now sees the moment an event happened (IST wall clock)
  alongside UTC, from one inline conversion — the `-7h`-style confusion is gone
  at the source.
- Assessments, findings, drift, explanation, and evidence are reachable from the
  packet list without leaving the workspace; the analyst never has to re-search
  cross-screen.
- The store's word is preserved verbatim: every field a backend cannot supply is
  explicitly labeled rather than fabricated, and every investigation resolves to
  one of three honest states (empty, tabs, server error) — verified on the wire.

## C. Verification (all run, all green except where the environment prevents it)

| Command | Result |
|---|---|
| `npm run typecheck` (`tsc -b --noEmit`, strict `noUnusedLocals`) | PASS |
| `npm run build` | PASS |
| `npm run smoke` (ssr, timestamp, contract, dom, offline) | PASS |
| `npm run smoke:investigation` (live :8081) | 11/11 PASS |
| `npm run smoke:nojournal` (:8099) | PASS |
| `npm run smoke:livecapture` (:8082, live sensor journal) | Phase 0 (waiting) PASS; Phase 1/2 traffic phases could not be exercised |
| Analytics `:8081` restarted post-fix | serves realtime epoch; `timestamp_ns === packet.timestamp`; CORS allows the `192.168.182.128:5173` dev origin |

The live-capture constraint is environmental, not code: the current lab
redeployment exposes only `eth0` on `clab-ipsec-sensor` (the documented
deployment uses `eth1`), `host-a → host-b` is unreachable, and there is no
active SA/data plane on the sensor's mirror link — `xdp_monitor eth0` attaches
and counts zero packets, so the feed's growth assertions cannot be satisfied
while the lab has no configured IPsec flow. The smoke remains intact and is now
interface-overridable (`LIVE_CAPTURE_SENSOR_IF`); every monitor *state*
(attached/waiting/stopped) and Phase 3 (IST clock + honest investigation
resolution) passed.

## D. Remaining gaps (all labeled in the UI today)

1. Per-gateway A/B config comparison — the store keeps a single `expected`
   column; the panel labels the endpoints note instead of inventing a split.
2. Negotiated IPsec crypto suite — not provided by the backend; rows say so.
3. Live feed exercise requires a lab with an active SA on the sensor's mirror
   link (see C).

Nothing was committed; the backends are left running for browser use
(analytics `:8081`, control `:8000`, no-journal `:8099`).