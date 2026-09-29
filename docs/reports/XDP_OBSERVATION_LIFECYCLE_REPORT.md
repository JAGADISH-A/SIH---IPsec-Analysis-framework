# XDP Observation Lifecycle — Automatic Live Observation Across the Testbed Lifecycle

**Date:** 2026-09-29
**Scope:** close the missing link between the Testbed UI (control plane), the
sensor's `xdp_monitor` (observation surface) and the Sentinel live view.  A
fresh experiment now guarantees, before any traffic is generated, that the live
XDP feed is really flowing into `results/observed-state/xdp/live_events.jsonl`
— the same journal the Sentinel capture feed (`/api/v1/capture/events`) tails.

---

## 1. Root cause (confirmed)

Every *fresh* experiment runs `containerlab destroy --cleanup` and redeploys,
which recreates the sensor container (`cmd: sleep infinity`).  The controller
deployed, configured IPsec, verified SAs and generated traffic — but it never
started `xdp_monitor` inside the recreated sensor.  Result: the live journal
stayed frozen, the analytics capture feed saw no growth, and Sentinel kept
showing the previous experiment's packets.  The dataset-reuse path (recovered
topology) had the same gap: a running/reusable testbed was never asked to
prove its observation surface was live.

---

## 2. What changed

### New module: `controller/xdp_observation.py` (controller-owned lifecycle)

| Concern | Behaviour |
|---|---|
| Idempotent entry point | `ensure_xdp_monitor()` — reuse, start, or restart; never >1 monitor; never lies. |
| Process truth | pgrep parses `pid / argv / stdout-fd`. A monitor is "ours" only if argv contains the interface `eth1` AND `readlink /proc/<pid>/fd/1` == `/opt/xdp-journal/live_events.jsonl`. |
| Duplicate safety | Reuses an accepted monitor; kills foreign/stale processes (`pkill -9 -x xdp_monitor`) before starting a replacement. |
| Binary install | `docker cp ebpf/xdp_monitor<->/usr/sbin/xdp_monitor` only when absent. |
| Start (hardened) | `docker exec -d … setsid sh -c 'xdp_monitor eth1 --json > journal 2> err'` — setsid + fully-redirected session so it survives detached-exec teardown; `>` truncates the journal so each experiment starts a clean live stream (the recorded historical journal `results/observed-state/live_events_full.jsonl` is never touched). |
| Readiness proof | **live** iff the monitor is ours **AND** (its `SUCCESS: attached XDP in generic (SKB) mode` marker appears in `xdp.err` **OR** the truncated journal already contains sampled event lines — direct proof the feed is delivering). |
| Failure handling | Raises `ObservationReadinessError` — message always begins *"IPsec testbed is running, but live XDP observation is unavailable: …"*; connectivity/traffic are never attempted after a readiness failure. |

### Controller wiring

| File | Change |
|---|---|
| `controller/executor.py` | `ensure_live_observation(mode, …)` wrapper (tunnel → `ensure_xdp_monitor`; transport → `{"status": "not-applicable", …}`, the transport topology has no sensor). `run_experiment` reordered to **DEPLOY → IPSEC → OBSERVATION → CONNECTIVITY → TRAFFIC** with the observation readiness gate before connectivity/traffic; `result["observation"]` recorded. |
| `controller/campaign.py` | `execute_trial_pipeline` runs observation readiness (timing stage `"observation"`) after the deploy-or-reuse + IPsec verification and before connectivity, on **both** the fresh and the reused dataset path; `"observation"` in the returned dict. |
| `controller/api.py` | `PIPELINE_STAGES = (DEPLOY, IPSEC, OBSERVATION, CONNECTIVITY, TRAFFIC)` — an observation failure is reported/categorized at the OBSERVATION stage, not swallowed as a generic error. |
| `controller/timing.py` | `"observation"` timing stage documented. |

### Testbed UI (minimal, intact separation)

| File | Change |
|---|---|
| `frontend/app.js` | `OBSERVATION` ("Preparing Live Observation") added to `STAGE_DEFS`, `STAGE_LABELS`, and the stage caption; `classifyError` maps `/xdp|observation|monitor|live journal/` to the **Live Observation** error chip. No redesign. |

### Sentinel (observation/analysis plane — **not** rebuilt)

| File | Change |
|---|---|
| `sentinel-frontend/src/pages/RunAssessment.tsx` | `OBSERVATION` stage row added to `STAGE_SEQUENCE` (cosmetic, additive). |
| `sentinel-frontend/src/types/index.ts` | Stage comment updated. |

The Sentinel data path is unchanged: `live_events.jsonl` → `GET /api/v1/capture/events` → `useCaptureFeed` → PacketWorkspace. Nothing in Sentinel starts traffic, XDP, or a second pipeline.

### Test fix triggered by the feature

| File | Change |
|---|---|
| `controller/test_topology_portability.py` | Expected tunnel-bind list intentionally extended with the sensor live-journal bind `results/observed-state/xdp:/opt/xdp-journal` (documented in the module docstring as a deliberate surface addition). |

---

## 3. Data flow (after the fix)

```
Testbed UI (Docker Compose/flask)            Sentinel (React/Vite)
   Run Experiment ──POST /experiments──▶ control API (:8000)
                                           │
                      run_experiment       │
   DEPLOY ── containerlab destroy+up ──────┘ (fresh sensor, sleep infinity)
   IPSEC  ── config + initiate + SA verify
   OBSERVATION ── ensure_xdp_monitor   (idempotent)
                      ├─ docker cp ebpf/xdp_monitor   (once)
                      └─ docker exec -d setsid xdp_monitor eth1 --json
                           > results/observed-state/xdp/live_events.jsonl  (bind /opt/xdp-journal)
   readiness = our process alive AND (generic marker OR journal events)
   CONNECTIVITY ── ping PASS
   TRAFFIC ── trafficgen → real ESP packets through the tap
                                      │
                              veth tap → sensor eth1 → XDP counts each packet
                                      │
         analytics feed (:8081) ── tails live_events.jsonl ──┘
            /api/v1/capture/events ──▶ PacketWorkspace (poll; no refresh)
```

---

## 4. Test suites (final numbers)

### Backend (repo venv, cwd = repo root)

```
# controller/ (full suite, incl. new lifecycle tests)
572 passed, 1 skipped, 572 subtests passed

# capture-feed / v1 / audit / analytics-API / control-API / topology-portability / xdp-lifecycle
284 passed, 1249 subtests passed

# controller/test_xdp_observation.py (new lifecycle + ordering unit tests, FakeLab harness)
21 passed
```

### Frontend (`sentinel-frontend`)

```
npm run typecheck ............ OK
npm run build ................ OK (11.6s)
npm run smoke (ssr+contract+dom+offline) .... green ("ALL API CONTRACTS OK")
npm run smoke:livecapture .... LIVE CAPTURE LIFECYCLE OK  (in-journal series
                              climbs 297 → 589 → … → 2263 in a SINGLE mount —
                              proves PacketWorkspace grows without refresh)
npm run smoke:nojournal ...... NO-JOURNAL STATE CORRECT (server with no journal)
```

---

## 5. Real end-to-end verification (Testbed UI → real IPsec traffic → XDP → Sentinel)

Three real experiments were run on the live lab (each `destroy --cleanup`
+ redeploy → fresh sensor).

### Experiment 1 — first cut (`610c2f70`)
`COMPLETED`, observation `action=started pid=59`, connectivity PASS, traffic
PASS (web/10s/20 packets).  Readiness snapshot read `journal_size: 0` at the
instant of attachment — a race that motivated the liveness refinement below.

### Experiment 2 — marker-only gate (`3bd2d22d`)
`FAILED` at **OBSERVATION** with *"IPsec testbed is running, but live XDP
observation is unavailable: xdp_monitor did not attach in generic mode"*.
Investigation (sensor-side `xdp.err`, `readlink /proc/<pid>/fd/1`): the monitor
was attached and sampling the whole time (mDNS events appeared immediately,
counters ticked) but this build of `xdp_monitor` never flushes its attach
banner to the error file.  The marker-only gate was too strict — a genuine
false negative, correctly surfaced by the gate instead of silently proceeding.
This drove the improved proof: **generic marker OR non-empty (truncated)
journal**.

### Experiment 3 — final gate (`492407a9`)
`COMPLETED`:
```
observation: {status: live, action: started, container: clab-ipsec-sensor,
              interface: eth1, pid: 60,
              journal: …/results/observed-state/xdp/live_events.jsonl,
              journal_lines: 2 at readiness  (link-local events = journal proof)}
connectivity: {packet_loss: 0.0, status: PASS}
traffic:      {status: PASS, profile: voip, duration: 15, packets: 750,
               bytes: 120000, bitrate_bps: 63998, pps: 50.0}
```
Journal after traffic: `771 lines / 107,018 bytes`, of which **762 ESP**
packets.  Analytics live feed answering:
```
GET /api/v1/capture/events
state: available · present: true · events served: 200 (paginated, cursor-capable)
Access-Control-Allow-Origin: http://192.168.182.128:5173   (LAN origin allowed)
```

### Runtime artifacts (post-experiment 3)

```
results/observed-state/xdp/live_events.jsonl   771 lines / 107,018 B  (roots)
results/observed-state/xdp/xdp.err             libbpf MTU note + counter blocks, ESP: 762
sudo docker exec clab-ipsec-sensor pgrep -x xdp_monitor   → 60
/proc/60/fd/1 → /opt/xdp-journal/live_events.jsonl        (bind mount target)
```

---

## 6. PASS / FAIL matrix

| # | Requirement | Result |
|---|---|---|
| 1 | Testbed UI = control plane; Sentinel = observation/analysis plane; no duplicated controls/pipelines in Sentinel | **PASS** (only stage label/comment added in Sentinel; data path untouched) |
| 2 | Automatic XDP start after (re)deployment, writing `results/observed-state/xdp/live_events.jsonl` | **PASS** (exp 3: `action=started pid=60` on a freshly recreated sensor) |
| 3 | Idempotency: reuse running monitor; start when missing; restart stale/foreign; never >1; process verified | **PASS** (unit tests: reuse, idempotent reuse, start-when-missing, foreign-restart, wrong-iface restart, duplicate prevention, not-staying-alive) |
| 4 | Failure handling: readiness gate with clear *"IPsec testbed is running, but live XDP observation is unavailable: …"*; traffic blocked on failure; no dataset corruption | **PASS** (exp 2 failed at OBSERVATION with exactly this message; ordering tests assert connectivity/traffic never run) |
| 5 | Experiment order DEPLOY → IPsec config → SA verify → OBSERVATION → connectivity → traffic; dataset-reuse path preserved | **PASS** (poll traces + `TestRunExperimentOrdering` / `TestCampaignObservationOrdering`) |
| 6 | Testbed UI minimal changes only (OBSERVATION stage), no redesign | **PASS** (`frontend/app.js` additive) |
| 7 | Sentinel live integration verified, not rebuilt (`live_events.jsonl` → `/api/v1/capture/events` → `useCaptureFeed`) | **PASS** (`smoke:livecapture`: growing series without refresh; feed `state: available`) |
| 8 | Existing testbed intact: containerlab, strongSwan, traffic generation, dataset generation/labels, tcpdump capture, APIs, frontend/backend contracts | **PASS** (full backend + frontend suites green; topology-portability test updated intentionally for the new bind) |
| 9 | Real end-to-end Testbed-UI-button flow A–K incl. redeploy survival | **PASS** (3 live experiments; see §5) |
| 10 | Final report with PASS/FAIL matrix | **PASS** (this document) |

Failure observed during verification: **1** (experiment 2 — the too-strict
marker-only gate), which was diagnosed from sensor internals and fixed by the
journal-evidence proof; the gate's job is precisely to surface such gaps.

---

## 7. How to run

```bash
# both backends (analytics :8081 with live feed + audit journal, control :8000)
ANALYTICS_API_CAPTURE_FEED=$PWD/results/observed-state/xdp/live_events.jsonl \
ANALYTICS_API_ALLOWED_ORIGINS="http://localhost:5173,http://127.0.0.1:5173,http://192.168.182.128:5173" \
  bash ./scripts/start-live-analytics.sh
setsid nohup .venv/bin/uvicorn controller.api:app --host 0.0.0.0 --port 8000 --log-level info \
  > /tmp/opencode/control-8000.log 2>&1 < /dev/null &

# Testbed UI → Run Experiment. Sentinel PacketWorkspace shows new traffic live.
```

The observation lifecycle is now owned by the controller: after every
successful deployment and before traffic, `ensure_xdp_monitor()` proves the
live feed is flowing, or the experiment stops at the OBSERVATION stage with a
message that a human can act on.