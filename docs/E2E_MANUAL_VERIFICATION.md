# Sentinel Manual E2E Verification Runbook

Repeatable, human-run end-to-end procedure for the Sentinel IPsec testbed at
`http://192.168.182.128:5173/`. Everything below was executed and verified in a
headless-Firefox browser against the real API stack on 2026-09-29 (see
"Verified transcript" outputs). Run it exactly once before a demo so you know
the exact output to expect; then re-run any section live.

## 1. What this runbook proves

| Check | Expectation |
|---|---|
| Analytics API reachable from the browser | `connected`, packet table renders |
| Control API reachable from the browser | `connected`, experiment pages work |
| CORS for the LAN origin | server returns `Access-Control-Allow-Origin: http://192.168.182.128:5173` |
| Idle/recorded state | no rows masquerade as live; "LIVE · 0 pkt/s"; recorded-history note |
| Live state (deterministic replay) | rows render, rate > 0, no recorded-not-live warning |
| Stop traffic | rows disappear again, "no current live traffic" appears |
| Restart demo | LIVE state returns (repeatable) |
| Findings / investigations | 9 findings, 12 assessments, packet rows open the investigation panel |
| Evidence / audit | honest empty whenever the analysis journal is absent or empty |
| Live restart (repeatability) | `demo-start` → `demo-stop` → `demo-start` all succeed (proven 3×) |

## 2. Architecture and ports

```
Browser (http://192.168.182.128:5173)
  ├── analytics API  http://192.168.182.128:8081  (read-only, phase-10 + capture feed)
  ├── control API    http://192.168.182.128:8000  (experiment/run surface)
  └── vite dev server 127.0.0.1:5173 (--host 0.0.0.0)
```

| Service | Port | Starts with | Health probe | Stop |
|---|---|---|---|---|
| vite (frontend) | 5173 | `.venv/bin/vite --host 0.0.0.0` (or `npm run dev`) | `GET /` → 200 | kill pid (only yours) |
| analytics API | 8081 | `e2e-live-demo.sh up` / `serve-backend.sh` | `/api/health`, `/api/v1/health` → 200 | `e2e-live-demo.sh down` |
| control API | 8000 | see `up` | `/health` → 200 | `e2e-live-demo.sh down` |
| nojournal baseline | 8099 | (pre-existing env) | optional | not managed |

Frontend env (sentinel-frontend/.env): `VITE_ANALYTICS_API_URL=http://192.168.182.128:8081`,
`VITE_CONTROL_API_URL=http://192.168.182.128:8000`. Do not edit; this file is
the reason the browser targets the LAN IPs.

## 3. Prerequisites

- `python3`, `.venv/` with `requirements.txt` installed, `sentinel-frontend/node_modules` present.
- Demo assessment store materialised: `scripts/init-demo-data.sh` (populates
  `results/`, including the 12 assessments / 9 findings used below). If missing,
  run it once.
- Recorded packet artifact: `results/observed-state/live_events_full.jsonl`
  (93 real `xdp_monitor_event` lines shipped in the repo).
- **No `sudo` is needed** for the demo. Root is required only for the real
  containerlab lab (section 7), which is unavailable on this host — see §8.
- Note: `scripts/stop.sh` **destroys the containerlab lab** — it is never used
  in this runbook's start/stop/cleanup steps.

## 4. Start the backend stack

Two equally valid entry points. They never start a second server on an occupied
port; if a port is taken they reuse it when it already answers the exact probes,
otherwise they stop with the exact `kill` command to use.

Supported-managed flow (recommended):

```bash
./scripts/e2e-live-demo.sh up
```

Verified output (trimmed):

```
[OK] 8081 free
[OK] analytics API answering: http://127.0.0.1:8081/api/health
[OK] 8000 free
[OK] control API answering: http://127.0.0.1:8000/health
[OK] CORS: http://192.168.182.128:5173 allowed (exactly what a browser needs)
[OK] analytics  /api/health=200 /api/v1/health=200
[OK] control    /health=200
  feed: verdict=RECORDED state=available present=True current=False source=live_events_full.jsonl total=93 ...
```

Alternative (interactive, foreground, same policy):

```bash
FRONTEND_ORIGIN=http://192.168.182.128:5173 ./scripts/serve-backend.sh
```

CORS allow-list derivation (both scripts, identical): fixed loopback dev origins
(`http://localhost:5173`, `http://127.0.0.1:5173`, `:3000` both, `:8000` both)
plus `$FRONTEND_ORIGIN`. Setting `ANALYTICS_API_ALLOWED_ORIGINS` overrides the
derivation entirely — if you override, include the loopback origins again,
because the override replaces (never appends to) the defaults. The analytics
also gets `--audit-journal` per `ANALYTICS_AUDIT_JOURNAL` (default
`/tmp/opencode/analysis-events.jsonl`), matching `start-live-analytics.sh`.

Check what is listening and who owns each port:

```bash
ss -ltnp | grep -E ":(5173|8081|8000)\b"
./scripts/e2e-live-demo.sh status     # ownership + feed verdict + health in one table
```

## 5. Health checks (exact commands)

```bash
curl -s -o /dev/null -w "analytics %{http_code}\n"  http://127.0.0.1:8081/api/health
curl -s -o /dev/null -w "v1        %{http_code}\n"  http://127.0.0.1:8081/api/v1/health
curl -s -o /dev/null -w "control   %{http_code}\n"  http://127.0.0.1:8000/health
curl -s -o /dev/null -w "frontend  %{http_code}\n"  http://127.0.0.1:5173/

curl -s http://127.0.0.1:8081/api/v1/health | python3 -m json.tool | head -40
curl -s "http://127.0.0.1:8081/api/v1/capture/events?limit=500" | python3 -c \
  "import sys,json;d=json.load(sys.stdin);print(d['current'],d['total'],d['source'])"
curl -s "http://127.0.0.1:8081/api/v1/findings?limit=500" | python3 -c \
  "import sys,json;d=json.load(sys.stdin);print('findings',d['total'])"
```

Expected: all `200`; `capture/events` shows `False 93 live_events_full.jsonl`
at idle; `findings` shows `9`.

## 6. CORS verification (the exact bug that was fixed)

The original symptom ("Analytics unreachable", `network_error`, "CORS problem")
had three causes, all now fixed:

1. The analytics (8081) and control (8000) listeners were dead → the browser
   cannot reach them. Fixed by starting the stack (section 4).
2. When 8081 was up, it had been started without `FRONTEND_ORIGIN`, so its
   allow-list was loopback-only and `http://192.168.182.128:5173` was blocked.
   Fixed by the derived allow-list.
3. `serve-backend.sh` had no occupancy detection: a second analytics attempt
   died with `EADDRINUSE` while its own verification probed the stale instance
   and printed a misleading `[FAIL] cors`. Fixed by the reuse-or-refuse
   preflight (it now prints `kill <pid> # pid owning <port>` when needed).

Verify as a browser would — the response must echo the origin verbatim:

```bash
curl -s -D - -o /dev/null http://127.0.0.1:8081/api/health \
  -H "Origin: http://192.168.182.128:5173" | grep -i access-control
# => Access-Control-Allow-Origin: http://192.168.182.128:5173

# loopback origins must still be allowed (they are in the derived list):
curl -s -D - -o /dev/null http://127.0.0.1:8081/api/health \
  -H "Origin: http://127.0.0.1:5173" | grep -i access-control
```

A request without a matching origin gets no `Access-Control-Allow-Origin`
header and no `Vary: Origin` mismatch — that is the block the browser enforces.

## 7. Traffic generation

### 7a. Deterministic browser-demo replay (no lab, no root — RECOMMENDED)

Uses the shipped 93 recorded `xdp_monitor_event` lines as the *writer* of a
demo journal. Every row the browser renders is a real recorded packet; the
backend's `current` verdict decides live-vs-recorded, and the frontend never
presents recorded rows as live.

```bash
./scripts/e2e-live-demo.sh demo-start    # enter LIVE
#  verdict=LIVE state=available current=True source=live_events.jsonl
./scripts/e2e-live-demo.sh demo-stop     # back to RECORDED
./scripts/e2e-live-demo.sh demo-start    # repeatable, on and off, indefinitely
```

Demo journal: `results/observed-state/demo/live_events.jsonl` (user-writable
scratch; `demo-start` truncates it). It is **never** the sensor journal
`results/observed-state/xdp/live_events.jsonl`. Direct use:

```bash
python scripts/demo-capture-replay.py  # appends at 1 line/s until Ctrl-C
```

### 7b. Real IPsec traffic through the lab (requires the full lab)

The control plane (`POST /experiments`) generates real IPsec traffic on the
containerlab topology (gw-a/gw-b/host-a/host-b/sensor with `eth1`):
`sudo ./scripts/run.sh`, then experiments via the browser Run Assessment page.
Six deterministic profiles live in `controller/traffic.py` (builtin
`scripts/trafficgen.py` or vendored D-ITG backends).

### 7c. Genuine XDP capture — ENVIRONMENT-LIMITED (do not fake)

Genuine live capture comes from the XDP sensor inside the gateway, which needs
the `eth1` mirror interface. On this host there is no `eth1` (sensor has only
eth0), `clab-ipsec-gw-b` is absent from the lab, and `sudo -n` is unavailable,
so the sensor reports its honest waiting state
(`xdp.err: ERROR: interface 'eth1' not found`). This is the intended,
unfabricated behavior; 7a simulates the same read path for demos.

## 8. Browser verification checklist (headless + human)

The exact assertions used (your eyes may perform the same checks):

1. **Packet Analysis (idle/RECORDED)** — `http://192.168.182.128:5173/`
   - headline `LIVE IPSEC TRAFFIC`, cap `LIVE · 0 pkt/s`
   - zero table rows; empty state: "No current IPsec traffic observed. The
     journal live_events_full.jsonl holds 93 recorded packets … recorded
     history, not current traffic…"
   - statusline warns the journal is not current
   - Findings section sits below the live section (collapsible)
2. **System Status** — `/system`
   - headline "Both API planes are connected"; Analytics API `connected`,
     Analytics components `connected`, Control API `connected`; no
     `unreachable` anywhere (this was red before the fix).
3. **Demo LIVE** — run `./scripts/e2e-live-demo.sh demo-start`
   - rows render and keep growing; cap reads `LIVE · 1 pkt/s` (replay rate);
     empty state and the recorded-not-live warning disappear.
4. **Stop** — `demo-stop`, refresh → rows gone again, `LIVE · 0 pkt/s`, and
   the recorded-history empty state returns within ~8s.
5. **Restart** — `demo-start` → live rows return (repeatability, §10 step P).
6. **Investigation flow** — click a packet row on the Packet Analysis page →
   the investigation panel opens with source/destination/IPsec context; a
   finding in the Findings page opens its explanation. ML/human attribution is
   never fabricated (page states when no ML observation exists).
7. **Evidence & audit (honest surfaces)** — analytics is started with
   `--audit-journal` (`ANALYTICS_AUDIT_JOURNAL`, default
   `/tmp/opencode/analysis-events.jsonl`) exactly like `start-live-analytics.sh`.
   When that path is absent or empty the server prints "nothing will be
   fabricated" and the audit/evidence routes answer with **zero events**
   (`/api/v1/audit` → `total 0`, `/api/v1/evidence` → `count 0`,
   `/api/v1/health` → `evidence: unavailable`). The server refuses to guess.
   A **real** analysis audit journal is written by the controller only after a
   lab experiment; attach it by pointing `ANALYTICS_AUDIT_JOURNAL` at it and
   restarting. `results/audit/events.jsonl` is the **observation** journal and
   is *not* a valid audit store — the app correctly refuses it rather than
   mislabelling it.

## 9. Stop, recover, clean up

```bash
./scripts/e2e-live-demo.sh demo-stop   # replay off, analytics back on recorded feed
./scripts/e2e-live-demo.sh down        # stop only the servers this script started
```

Never `kill` a process this script did not start; `status` tells you who owns
each port. If a port is occupied by a stale server, the script prints the
exact `kill <pid>` to run. The containerlab lab, the sensor journal, and any
other analytics instance (e.g. the 8099 baseline) are left untouched.

## 10. Verified end-to-end script (human, one session)

| Step | Command / action | Expected |
|---|---|---|
| A | `./scripts/e2e-live-demo.sh status` | 8081/8000 reported correctly; live stack listed |
| B | `./scripts/e2e-live-demo.sh up` | all `[OK]`, CORS allowed, feed `RECORDED total=93` |
| C | health curl battery (§5) | all 200 |
| D | CORS curls (§6) | ACAO echoes LAN origin; loopback also allowed |
| E | browser: `/` idle | 0 rows, `LIVE · 0 pkt/s`, recorded-history empty state, warning |
| F | browser: `/system` | both planes connected, no unreachable |
| G | browser: `/findings` | 9 findings; open one → explanation panel |
| H | `demo-start` | `verdict=LIVE current=True` |
| I | browser: `/` live | rows grow, cap `1 pkt/s`, no warning, no empty state |
| J | click a row | investigation panel opens (IPsec context real, no fabrication) |
| K | `demo-stop` | `verdict=RECORDED current=False` |
| L | browser: `/` again | rows gone within ~8s; recorded empty state returns |
| L2 | `status` | replay stopped; analytics owned + recorded again |
| M | health battery again | all 200 (no drift after the toggle) |
| N | `demo-start` → browser: `/` | LIVE returns (repeatable start/stop) |
| O | `demo-stop`; leave stack recorded | clean baseline for the next session |
| P | `demo-start` again | LIVE returns every time (proven 3/3 in verification) |

## 11. Known limitations (stated honestly, never hidden)

- Genuine XDP live capture cannot run on this host (no `eth1`, `gw-b` missing,
  no passwordless sudo). §7a is the sanctioned demo substitute and drives the
  identical read-only feed path.
- Evidence/audit surface is zero until a **real** analysis audit journal exists
  (a demo substitute is never fabricated to make dashboards look alive; the
  server states the missing-journal reason verbatim).
- The LAN browser tab may log harmless `BrokenPipeError` noise if it
  disconnects mid-response; it does not affect the server.
- `scripts/stop.sh` destroys the lab — never run it for demo shutdown.

## Referenced files

- `scripts/e2e-live-demo.sh` — managed up/status/health/demo-start/demo-stop/down/replay.
- `scripts/demo-capture-replay.py` — deterministic replay writer (demo journal).
- `scripts/serve-backend.sh` — interactive stack startup with occupancy preflight.
- `correlation/api/capture_feed.py` — the read-only, mtime-based liveness feed.
- `correlation/api/config.py` — `DEFAULT_ALLOWED_ORIGINS`, `ANALYTICS_API_ALLOWED_ORIGINS`.
- `sentinel-frontend/.env` — the LAN API URLs the browser uses.
- `docs/reports/FRONTEND_LIVE_E2E_VERIFICATION_REPORT.md` — companion evidence report.