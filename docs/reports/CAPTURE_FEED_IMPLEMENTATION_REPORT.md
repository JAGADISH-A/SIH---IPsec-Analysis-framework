# Capture Feed — Live-Traffic View (Option A)

**Date:** 2026-09-28
**Scope:** the first page (`PacketWorkspace`) now renders the *actual* observed
traffic of the IPsec testbed, served read-only by a new `/api/v1/capture/events`
endpoint. This implements the chosen **Option A**: expose the existing capture
pipeline, do not build a second one.

---

## 1. What changed

### Backend (Server A — `correlation/api/`, stdlib, still read-only)

| File | Change |
|---|---|
| `correlation/api/capture_feed.py` | **New.** `CaptureFeedService` — a byte-offset tail over the `xdp_monitor` JSONL packet journal. Raw XDP events are normalized through the **existing** `XdpEventAdapter` (`correlation/streaming/live_adapter.py`) so a captured packet reaches the API in the canonical stream shape. Also: `build_risk_index` (SPI → assessment projection, verbatim copies), `risk_for_spi`, `protocol_label` (ESP/AH/IKE/ESP_IN_UDP/UDP/TCP/ICMP/DNS…), `packet_info`. Minimal follow-up: an attached-but-empty journal returns the explicit waiting state (not "live, no packets"). |
| `correlation/api/v1.py` | New route `GET /api/v1/capture/events?cursor=&limit=`. Pure handler; `503 capture_feed_unavailable` when no feed is attached — mirroring how the audit surface behaves. |
| `correlation/api/live.py` | `Phase10Context.capture_feed` field + `attach_capture_feed()`; surfaced in summary. |
| `correlation/api/app.py` | CLI `--capture-feed <path>`, env `ANALYTICS_API_CAPTURE_FEED`; with `--phase10` and no explicit path it auto-attaches the repo's recorded live-tap journal `results/observed-state/live_events_full.jsonl`. |
| `correlation/api/config.py` | `ENV_CAPTURE_FEED` constant. |
| `correlation/api/openapi.py` | Documented `/api/v1/capture/events` (the existing `self_check` drift test stays green). |
| `tests/test_capture_feed.py` | **New.** 28 tests (tail semantics, torn-line handling, deterministic ids, waiting state, protocol labels, verbatim risk projection, 503 path, OpenAPI presence). |

The capture feed is **additive and isolated**: no existing route, contract or
test was altered. `scripts/serve-backend.sh` needed no change — `--phase10` now
attaches the feed by default.

### Frontend (`sentinel-frontend/`, the React/Vite/TS app)

| File | Change |
|---|---|
| `src/api/analytics.ts` | Added `getCaptureEvents({cursor, limit})`. |
| `src/types/index.ts` | Added `CapturePacket` / `CaptureEventsResponse` wire types. |
| `src/hooks/useCaptureFeed.ts` | **New.** Polls the feed with an exact byte cursor; states: `connecting / live / paused / waiting / unavailable / offline / degraded`. Bounded buffer with eviction counter, dedupe by content+offset id, live rate (`pps`), pause/resume/clear/reconnect. Minimal follow-up: during a live poll with no *fresh* events, `pps` reports 0 instead of the stale last rate. |
| `src/lib/packetRows.ts` | Rewritten for the capture feed (Wireshark-style `No. / Time / Source / Destination / Protocol / Length / Info / SPI / Risk`). |
| `src/pages/PacketWorkspace.tsx` | First page rewritten to the capture workspace: real `LIVE ●` pill, `Waiting for testbed traffic…` state, feed chip (`feed: live_events_full.jsonl`), IPsec-only filter, packet inspector with the feed's verbatim fields, per-packet risk pane linking to assessments. |
| `src/hooks/useAssessmentObservations.ts` | Deleted (was the old dataset-framing enrichment; now unused). |
| `src/index.css` | Larger table type (13 px), higher row height, wider table for the new columns. |
| `smoke/contract-smoke.ts`, `smoke/dom-smoke.ts` | Extended to assert the new capture contract and the new page. |

`useLiveTraffic` / the audit journal / `AnalystConsole`/`LiveTrafficMonitor` are
**untouched** — the capture view uses a separate feed and hook.

---

## 2. Data flow

```
xdp_monitor (gateway WAN mirror)            ebpf/xdp_monitor, JSONL
   │  appends per-packet lines
   ▼
results/observed-state/live_events_full.jsonl    (or ANALYTICS_API_CAPTURE_FEED)
   │  byte-offset tail (read-only, cursor resumes exactly)
   ▼
CaptureFeedService.poll(cursor, limit)        correlation/api/capture_feed.py
   │  XdpEventAdapter.normalize()          (existing streaming adapter)
   ▼
GET /api/v1/capture/events                    correlation/api/v1.py (stdlib server)
   │  packet + protocol_label + info + risk(SPI→store, verbatim)
   ▼
useCaptureFeed → PacketWorkspace               Wireshark-style live view
```

`risk` is join-by-SPI against the deterministic `AssessmentStore`: a packet's
`risk.assessments[]` carries `severity`, `risk_score`, `finding_count` and the
`assessment_id` copied **verbatim** from the store header of every assessment
that observed that SPI. No risk is ever computed from the packet itself.

---

## 3. Constraints honored (from the agreed Option A)

| Constraint | Where it holds |
|---|---|
| No synthetic/fake packets | The endpoint serves only real lines from the xdp_monitor journal; a missing/empty journal returns the explicit waiting state (`present:false` + `reason`). |
| Reuse existing capture source + normalization | `XdpEventAdapter.normalize()` is the single reuse point; no second capture or aggregation path. |
| No packet parsing in the frontend | `protocol_label` and `info` are computed server-side; the UI only formats served fields. |
| Read-only endpoint | No request ever writes to the journal; `read_only:true` in every response. |
| Real packets when the testbed generates traffic | Live append to the journal is the source of new rows; the byte cursor resumes exactly. |
| Explicit empty/waiting state | `Waiting for testbed traffic…` empty state + reason string; `503 capture_feed_unavailable` only when the feed is not attached at all. |
| Risk/severity only from existing backend results | SPI→assessment verbatim projection; unmatched SPI renders an em dash. |
| Preserve existing API contracts and tests | No existing route changed; full existing suites still green (see §5). |
| Additive/isolated | New module + hook + page; `useLiveTraffic`/audit surface untouched. |
| PPT claim "Passive Capture — Mirror IPsec traffic at the gateway" | The page now shows the actual observed testbed traffic, never a hardcoded/demo dataset; rows are no longer labelled `capture: dataset-…`. |

---

## 4. Deliberately not done

- **No new capture system**: the XDP monitor stays the only capture source.
- **No WebSocket/SSE**: polling with an exact byte-offset cursor matches the
  project's own "the analytics plane has no stream" contract and keeps the API
  stdlib, read-only and process-independent.
- **No live merging of the audit journal**: `/api/v1/audit/events` remains the
  audit surface; the capture view does not consume it.
- **No risk scoring of packets**: a packet is only ever *matched* to assessments
  that observed its SPI.
- **No changes to `correlation/api/routes.py`** — the pre-existing duplicated
  `/api/cors` block there is out of scope and untouched.
- **No persistence, pagination UI or PCAP download from the live view** — the
  evidence/PCAP surface is the existing `/api/v1/evidence/*`.

---

## 5. Verification performed

### Backend tests (repo venv, cwd = repo root)
```bash
.venv/bin/python -m pytest tests/test_api_routes.py tests/test_api_server.py \
  tests/test_api_adapters.py tests/test_api_store.py tests/test_analytics_api.py \
  tests/test_audit_api.py tests/test_health.py tests/test_metrics.py \
  tests/test_live_adapter.py tests/test_evidence.py -q
# 294 passed, 1249 subtests passed

.venv/bin/python -m pytest tests/test_analytics_api.py tests/test_chain_of_custody.py \
  tests/test_drift_detection.py -q
# 291 passed, 545 subtests passed  (OpenAPI self_check drift green with the new path)

.venv/bin/python -m pytest tests/test_capture_feed.py tests/test_api_v1.py tests/test_audit_api.py -q
# 119 passed, 1070 subtests passed   (incl. waiting-state-when-empty journal test)
```

### Live end-to-end (fresh server, `--phase10 --capture-feed`)
```bash
.venv/bin/python -m correlation.api.app --phase10 \
  --capture-feed results/observed-state/live_events_full.jsonl --no-static --port 8099

curl 'http://127.0.0.1:8099/api/v1/capture/events?limit=2'
# → present:true, total:93, cursor advances, has_more:true
# → first packet: ESP 192.168.100.1→192.168.100.2 spi 0xcda30093 seq 7
# → risk.present:true (joined verbatim to dataset-20260924-003710:1:nat-t, INFO/score 0)

# waiting state, journal missing:
#   present:false, state:"waiting",
#   reason:"no capture journal at no-such-feed.jsonl; waiting for the gateway monitor to write"

# waiting state, journal attached but empty (monitor just started):
#   present:false, state:"waiting",
#   reason:"capture journal live_events.jsonl is empty; waiting for the gateway monitor to write"

curl http://127.0.0.1:8099/api/v1/openapi.json   # → /api/v1/capture/events documented
```

For the live end-to-end against the running testbed, see **section 8**.

### Frontend (sentinel-frontend)
```bash
npm run typecheck        # clean
npm run build            # clean (dist rebuilt)
npm run smoke            # ssr: ALL ROUTES RENDERED
                         # contract: ALL API CONTRACTS OK (incl. new capture checks)
                         # dom: ALL PAGES RENDERED LIVE DATA (incl. new workspace checks)
                         # offline: OFFLINE BEHAVIOUR CORRECT
npm run smoke:experiment # EXPERIMENT ROUNDTRIP OK
```
For the live smokes the analytics server (8081) was restarted with the new code
(`--phase10 --audit-journal /tmp/opencode/analysis-events.jsonl`), which serves
both the audit journal and the capture feed. Two server generations were used:
the recorded-journal default (93 packets) for deterministic contract/dom checks,
and the live testbed journal via `ANALYTICS_API_CAPTURE_FEED` for the
`smoke:livecapture` run (section 8).

---

## 6. How to run it

```bash
# one command, dev defaults (scripts/serve-backend.sh) — analytics + control
./scripts/serve-backend.sh

# or explicitly, for the capture view on a repo-root journal
.venv/bin/python -m correlation.api.app --phase10 \
  --capture-feed results/observed-state/live_events_full.jsonl \
  --host 127.0.0.1 --port 8081

cd sentinel-frontend && npm run dev        # dashboard on http://localhost:5173
```

The default feed is the repo's recorded live-tap journal (93 packets). To make
the view genuinely live, point `ANALYTICS_API_CAPTURE_FEED` at the gateway
monitor's on-host journal (see section 8) — then the page shows the testbed's
real traffic as it is captured. While a feed writes nothing, the page shows
`Waiting for testbed traffic…` instead of fabricating rows.

---

## 7. Risk notes

- **Default feed path is a recorded file.** When `--phase10` is on and no path
  is given, the repo's recorded journal is attached. That is the honest,
  same-shaped source for development; a production server should point
  `ANALYTICS_API_CAPTURE_FEED` at the gateway's live journal — exactly what
  section 8 demonstrates on the testbed.
- **Unattached feed is a hard 503** (`capture_feed_unavailable`), distinct from
  the waiting 200 — the UI surfaces the difference. An *empty-but-writable*
  journal also returns the waiting state (`present:false`,
  `reason:"capture journal … is empty; waiting for the gateway monitor to write"`)
  so the page never mislabels a quiet monitor as "live, no packets".
- **Backlog vs live.** A `cursor` page returns journal order within `limit`; a
  client that falls behind simply catches up on the next poll. Rotated/truncated
  journals (cursor past EOF) retail from the top.
- **Only complete lines are served**; a torn final line mid-write is never
  surfaced, so a partially written packet can never be mistaken for a complete
  one.

---

## 8. Live testbed integration (Phase 1 completion)

**Goal.** Prove the capture feed consumes the *production* pipeline — the
`xdp_monitor` journal written by the real containerlab testbed — with an
actively growing journal and no browser refresh, while keeping the recorded
93-packet journal for deterministic tests.

> Constraint honored: the single existing capture source (`xdp_monitor`) is
> untouched, the frontend design is unchanged, and the only config/path change
> is the host bind that lets the gateway's journal reach the analytics process.

### 8.1 Discovered live journal path

The testbed (`./scripts/run.sh`) starts `xdp_monitor` **inside** the sensor
container and appends packet lines to `/tmp/xdp.jsonl` there. That was
container-internal, so the capture view while `--phase10` defaulted to the
recorded journal. The live journal is now host-visible at:

```
results/observed-state/xdp/live_events.jsonl   (host)
/opt/xdp-journal/live_events.jsonl             (sensor container, same file)
```

### 8.2 Exact configuration used

- `topology/tunnel/ipsec.clab.yml`, sensor node:
  `binds: [../../results/observed-state/xdp:/opt/xdp-journal]` — the single
  config/path change (genuinely required; the monitor itself is unchanged).
- Monitor (unchanged from `run.sh`): `xdp_monitor eth1 --json` writes
  `/opt/xdp-journal/live_events.jsonl` (`xdp.err` confirms generic/SKB mode,
  "Peer MTU is too large to set XDP" — the expected fallback).
- Analytics server, bound `0.0.0.0` (router-visible), env override:
  ```bash
  ANALYTICS_API_CAPTURE_FEED=/home/jagan/ipsec-testbed/results/observed-state/xdp/live_events.jsonl
  .venv/bin/python -m correlation.api.app --phase10 \
    --audit-journal /tmp/opencode/analysis-events.jsonl --no-static --host 0.0.0.0 --port 8081
  ```
- Frontend served its dev build; the configured API URLs point at this host
  (192.168.182.128) — both servers bind `0.0.0.0`, as `serve-backend.sh` does.
- Traffic: the testbed's own generation (ping burst `host-a → host-b`); the
  smoke restarts `xdp_monitor` for a fresh empty journal so the waiting→live
  transition is observable.

### 8.3 Evidence the journal grew during the run

`npm run smoke:livecapture` (new, `sentinel-frontend/smoke/live-capture-smoke.ts`):

```
in-journal series : 288 -> 580 -> 868 -> 1147 -> 1429 -> 1717 -> 2014 -> 2263 -> 2263
cursor series     : 6776 -> 33838 -> 60900 -> 87910 -> 114972 -> 142048 -> 169110 -> 196172 -> 223248
pkt/s series      : 97, 98, 97, 96, 104, 114, 120, 0
events delivered  : 2065 (starting 198, peaking 2263)
rows rendered     : 198 -> 2000
ESP packets in tail : 664
```

The journal grew from ~198 to **2263** live events (the XDP sensor's own
capture, one line per packet). After the traffic burst stopped, the journal and
cursor **froze** (2263 / 223248 held) and pkt/s dropped to 0 — the view follows
the monitor exactly and never fabricates.

### 8.4 Packets/events received by the frontend during the live run

~**2065 events** were delivered to the mounted `PacketWorkspace` across the
520 ms polls (cursor 6,776 → 223,248 bytes), rendered as 198 → 2,000 rows
(buffer cap with eviction), **664 ESP packets** in the sampled tail, pkt/s 97–120
reflecting the real rate.

### 8.5 No browser refresh required

The `live-capture-smoke` mounts the workspace **once** (no remount, reload or
HMR across the run) and asserts growth from within that single mount: rows and
the `LIVE ● 201 pkt/s` pill appeared purely from `useCaptureFeed` polling the
byte cursor. `ok packets arrive without any browser refresh (total grew)`.

### 8.6 Risk / assessment correlation result

- **Deterministic path (recorded journal):** `81/93` packets carry
  `risk.present:true`, joined verbatim by SPI — recorded SPI `3450011795`
  → `dataset-20260924-003710:1:nat-t`, `INFO`, score 0.
- **Live path:** every served live event carries a risk block from the
  SPI→store projection; the live lab SA has a **new** SPI (fresh handshake), so
  `risk.present:false` is the *honest* result, not an error — the join mechanism
  is intact (`ok every served event carries a risk block (from the store by SPI)`).
- Regression proof: `test_matching_spi_carries_assessment_risk` keeps passing.

### 8.7 Tests passed (live environment)

```
Backend : 119 passed, 1070 subtests (test_capture_feed, test_api_v1, test_audit_api)
Frontend: smoke:dom        ALL PAGES RENDERED LIVE DATA
          smoke:contract   ALL API CONTRACTS OK
          smoke:offline    OFFLINE BEHAVIOUR CORRECT
          smoke:livecapture 15/15 checks ok (waiting → growth → freeze)
          typecheck + build clean
```

The complete Phase 1 loop is closed: containerlab gateway XDP capture →
`CaptureFeedService` tail → `/api/v1/capture/events` → PacketWorkspace, live,
with no second capture system and no design change.