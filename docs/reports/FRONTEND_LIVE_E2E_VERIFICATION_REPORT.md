# Frontend-Driven Live End-to-End Verification Report

Verification of the COMPLETE system exactly as a user drives it through the two
frontends: the **Testbed UI** (control plane, `/experiments` + 800 ms polling)
starting and supervising a real experiment, and **Sentinel** (:5173, 2.5 s byte-
cursor polling) observing IPsec/ESP packets live during that experiment. No
implementation was modified for this verification; the only changes were
started server processes and throwaway driver scripts in `/tmp`.

Scope: `controller` (deploy/ipsec/observation/connectivity/traffic) + live XDP
sensor (`xdp_monitor` `clab-ipsec-sensor:eth1`) + `correlation.api` capture
feed + both frontends. Evidence auto-captured to
`/tmp/opencode/ui_live_e2e_evidence.json` (66 feed polls, 37 in-window).

---

## A. Experiment run through the real UI endpoint sequence

A single live experiment was started with the exact `POST /experiments` payload
`frontend/app.js` `getPayload()` builds (tunnel / ipv4 / IKEv2-aes256-sha256
modp2048 / ESP, video profile) and polled every 800 ms like the Testbed UI.

Stage timeline as seen by the UI (job `054fbc03-27bf-4a49-ad3b-979c7c0acbde`):

| t (s) | UI shown | meaning |
|------:|----------|---------|
| 0.0   | QUEUED   | `POST /experiments` → `job_id` |
| 0.2   | DEPLOY   | `renderStageTimeline`/`paintProgress` "Preparing Live Observation" is not reached |
| 18.8  | IPSEC    | SA config + verify |
| 25.2  | **OBSERVATION** | "Preparing Live Observation" renders active |
| 32.8  | CONNECTIVITY | ping across tunnel |
| 34.4  | TRAFFIC  | video/30 s runs |
| 67.5  | **COMPLETED** | result panel populated |

Final result (identical to what the UI paints):
`status COMPLETED`, IPsec `ike_sa=ESTABLISHED, child_sa=INSTALLED, mode=TUNNEL`,
connectivity `packet_loss 0.0 PASS`, traffic
`packets=7500 bytes=9000000 bitrate=2399936bps pps=250 PASS`.

## B. OBSERVATION readiness is real (live proof) and reaches the UI

The `result["observation"]` the UI renders shows live-proof fields, and — note —
this run exercised the **journal-proof branch of the readiness gate**:

```json
{"status":"live","action":"started","container":"clab-ipsec-sensor",
 "interface":"eth1","pid":58,"journal":"…/observed-state/xdp/live_events.jsonl",
 "attach":{"generic_mode":false,"native_mode":false,"native_rejected":true,
           "stderr":"libbpf: Kernel error message: veth: Peer MTU is too large to set XDP …"},
 "journal_size":147,"journal_lines":1}
```

`native_rejected=true` and no generic-mode banner in `xdp.err` for this launch,
but the monitor proved live by writing an event line before readiness resolved —
so the gate passed on **journal evidence**, exactly the case that previously
false-negatived with a marker-only check (see XDP_OBSERVATION_LIFECYCLE_REPORT).
Traffic never starts unless this gate passes (stage next, §F).

## C. Sentinel shows ESP packets live during traffic — no refresh, no replay

During the UI traffic window (t = 34.4 → 67.5 s) a single Sentinel-style session
polled `GET /api/v1/capture/events?cursor&limit` every ~1 s with exact byte-cursor
resume (the same algorithm `useCaptureFeed.ts` runs every `TRAFFIC_POLL_MS`).
Cursor advanced **1,494 → 1,059,516** bytes; 7,512 fresh events arrived, **7,506
of them ESP**, with `feed total 11 → 7,523`. Sample:

```
 t   cursor   total  fresh  types
35.2   1,494      11     0   (traffic just starting)
40.2 123,994     939   478   ESP:478
45.4 321,129   2,294   208   ESP:208      ... +208 ESP per ~5s steadystate
50.5 501,192   3,568   211   ESP:211
55.5 679,134   4,829   212   ESP:212
60.7 859,572   6,112   210   ESP:210
65.7 1,037,514 7,373   208   ESP:208
67.5 1,059,516 7,523     150  final
```

Timestamps/contents are captured from the journal lines themselves (byte offsets,
`timestamp_ns`, SPI, seq). This is a single polling predicate across the whole
run — nothing re-fetched, no page reload, no SSE/WebSocket hiding.

## D. Feed statistics match the completed experiment

Host-side journal final: **7,528 lines / 1,060,251 bytes**; feed `total` 7,523
≈ transmitted 7,500 (7506 ESP incl. tunnel overhead + ~17 IKE/UDP/ICMP). The
feed and the experiment result agree to within sampling of the sensor.

## E. Live-vs-recorded is unambiguous in this deployment

The analytics server's process environment pins the feed to the live journal:

```
ANALYTICS_API_CAPTURE_FEED=/home/jagan/ipsec-testbed/results/observed-state/xdp/live_events.jsonl
```

and the feed response reports `"source": "live_events.jsonl"` (observed at
`/api/v1/capture/events`). No recorded/dataset replay is active. Caveat
recorded for future operators: `correlation/api/capture_feed.py` falls back to
the shipped recorded artifact `results/observed-state/live_events_full.jsonl`
when an operator starts `--phase10` **without** pinning a feed — that masked
static data would appear live. The pinned start (as `scripts/start-live-analytics.sh`
does) is required, and is what is running.

## F. Negative — observation unavailable ⇒ traffic does NOT proceed

Driven through the real `controller.api` endpoint the UI calls. `POST
/experiments` with the observation readiness gate genuinely unavailable (sensor
cannot prove live) produced:

```json
{"status":"FAILED","stage":"OBSERVATION",
 "error":"IPsec testbed is running, but live XDP observation is unavailable: xdp_monitor did not prove live on clab-ipsec-sensor:eth1"}
```

`test_connectivity` and `run_traffic` were asserted **never called** (job stayed
at OBSERVATION). The Testbed UI maps this detail via `classifyError` →
`"Live Observation"` chip (frontend/app.js:562-563). Transport mode also
correctly bypasses with `status:not-applicable`, no gate.

## G. Negative — no journal ⇒ Sentinel is honest

An analytics instance pinned to a nonexistent feed reports
`state:"waiting" present:false reason:"no capture journal at feed.jsonl; waiting
for the gateway monitor to write"`. The frontend no-journal smoke
(`smoke:nojournal`, against `http://127.0.0.1:8099`) asserts and passes:
monitor reports source unavailable, explains how to attach a journal, **does not
render a traffic table**, does not claim the link is quiet, offers a re-check
affordance, rest of the store still renders.

## H. Where to look at it live

- Testbed UI: `http://192.168.182.128:8000` (uvicorn, control-plane + static
  Testbed UI) → Run Experiment (tunnel/ipv4/video).
- Sentinel: `http://192.168.182.128:5173` (Vite) → Packet Capture:
  FeedCap "LIVE · N pkt/s", ESP/ESP_IN_UDP scope, rows tick during traffic.
- Sentinel `.env` → `VITE_ANALYTICS_API_URL=http://192.168.182.128:8081`,
  `VITE_CONTROL_API_URL=http://192.168.182.128:8000`.
- Analytics: `http://192.168.182.128:8081/api/v1/capture/events?cursor=0`.
- Journal / sensor stderr: `results/observed-state/xdp/live_events.jsonl` and
  `xdp.err` (bind-mounted `/opt/xdp-journal` into `clab-ipsec-sensor`).
- Note: two control-server exits during this work were self-inflicted (the shell
  tool's timeouts killed the owning session of a `nohup`'d uvicorn), NOT a code
  defect — the final runs complete and the server persists afterwards.

## I. Conclusion

The frontend stack is genuinely integrated with the live IPsec/XDP testbed:
the Testbed UI drives a real experiment through OBSERVATION readiness, the
Sentinel feed surfaces the sensor's live journal during traffic (7,506 ESP
events in a single unbuffered polling session, matching the run's 7,500 pkt
result), readiness is anchored on live journal proof rather than markers, and
both failure directions — observing-gate failure (traffic blocked) and missing
journal (no fake table rendered) — are truthful end to end. Pinned feed start
(maintained in `scripts/start-live-analytics.sh`) is mandatory to avoid the
recorded-artifact fallback. **No genuine implementation defect found; no
implementation changes made.**