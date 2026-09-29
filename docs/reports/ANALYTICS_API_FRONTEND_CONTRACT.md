# Analytics API — Frontend Contract

**Audience:** anyone writing a browser client (or a CLI client) against
`correlation/api/` — "Server A", the analytics and governance API.

This is the document to code against. It is the human-readable companion to the
machine-readable contract served at `GET /api/v1/openapi.json`; where the two
disagree, the OpenAPI document is generated from the same route table and
validated against it in CI, so it does not drift.

---

## 1. What this API is, and is not

| | |
|---|---|
| **Process** | Its own stdlib HTTP server. `python -m correlation.api.app` |
| **Port** | `8081` by default. **Not** `8000` — that is the testbed control API. |
| **Framework** | None. Python standard library only. |
| **Mutations** | **None exist.** Every mutating verb returns `405`. |
| **Authentication** | **None.** See §7 before you expose it. |
| **Relationship to the control API** | Independent. It is not mounted into it and does not import it. |

There are two separate servers in this testbed, and they are deliberately not
joined:

```
  browser  ──►  control API        controller/api.py    FastAPI     port 8000
                (runs the testbed, owns the testbed lock and dataset actions)

  browser  ──►  analytics API      correlation/api/app.py  stdlib   port 8081
                (read-only: assessments, evidence, audit, governance, findings)
```

If you need a run/assessment list, come to **this** API. If you need to start a
test, stop a VM, or upload a dataset, that is the control API and it is a
different service with a different threat model. Nothing here can do that.

---

## 2. Starting it

```bash
# read-only analytics over recorded results
python -m correlation.api.app --phase10

# with the analysis audit journal, so run discovery works
python -m correlation.api.app --phase10 \
    --audit-journal results/audit/analysis-events.jsonl

# serving a UI from this process (optional; needs a built dashboard/)
python -m correlation.api.app --phase10 --plan out/plan.json
```

Configuration is environment-first. CLI flags win over the environment.

| Variable | Default | Meaning |
|---|---|---|
| `ANALYTICS_API_HOST` | `127.0.0.1` | Bind address. Loopback by default. |
| `ANALYTICS_API_PORT` | `8081` | Bind port. |
| `ANALYTICS_API_ALLOWED_ORIGINS` | loopback dev origins | Comma-separated CORS allow-list. |
| `ANALYTICS_API_CAPTURE_FEED` | recorded live-tap journal | Path to the `xdp_monitor` packet journal served read-only at `/api/v1/capture/events` (see §6.6). |

```bash
# a real deployment: bind all interfaces, allow exactly one dashboard origin
ANALYTICS_API_HOST=0.0.0.0 \
ANALYTICS_API_PORT=8081 \
ANALYTICS_API_ALLOWED_ORIGINS=https://dashboard.example \
  python -m correlation.api.app --phase10
```

Startup prints the effective policy, and warns when you bind a non-loopback
address without authentication or when no origin is allowed.

### The `/api/v1` surface needs `--phase10`

Without it, every `/api/v1/*` path returns a **structured `503`** with
`error.code = "phase10_unavailable"`. This is deliberate and should be handled
in your client as "the live surface is not attached", not as a crash:

```json
{ "error": { "code": "phase10_unavailable",
             "message": "/api/v1 requires --phase10 (live context not attached)",
             "detail": "...", "request_id": "..." } }
```

`/api/v1/openapi.json` and `/api/v1/docs` are always available — you can fetch
the contract even when the data routes are not.

---

## 3. CORS

A cross-origin `fetch` succeeds only when the response carries
`Access-Control-Allow-Origin` matching the page's origin. This API sends that
header **only for allow-listed origins**.

- Unset `ANALYTICS_API_ALLOWED_ORIGINS` → a narrow loopback development default
  (`http://localhost:8000`, `:3000`, `:5173`, and the `127.0.0.1` equivalents).
- Set it → exactly what you set. Comparison ignores case and trailing slash.
- Set it to `""` → **nothing is allowed.** An explicitly cleared allow-list locks
  the API down; it does not fall back to the defaults.
- `*` is honoured but is never the default, because this API is unauthenticated
  and `*` would let any web page read the evidence and audit surface. It echoes
  the requesting origin back rather than sending a bare `*`.

Discover the live policy without guessing:

```bash
curl -s localhost:8081/api/v1/health | jq .cors
```

`Vary: Origin` is always sent with a CORS header, so a shared cache cannot serve
one origin's allow header to another. Credentials are never enabled.

---

## 4. Errors

Every non-2xx response has the same shape:

```json
{ "error": { "code": "assessment_not_found",
             "message": "no assessment ...",
             "detail":  "no assessment ...",
             "request_id": "3f9c1a77e0b14d8ea5c2f6b90d1a4e88" } }
```

| Field | Use it for |
|---|---|
| `code` | **Branch on this.** Stable and machine-readable. |
| `message` | Show to a human. May be reworded. |
| `detail` | Legacy alias of `message`; identical value. Kept for older clients. |
| `request_id` | Quote it in a bug report — it matches the server log line. |

The same value is returned in the `X-Request-Id` response header on **every**
response. If your browser sends `X-Request-Id`, that value is reused (sanitised
and length-bounded) so a console line can be matched to a log entry.

**Branch on `code`, never on `message`.** Codes you will meet:

| `code` | Status | Meaning |
|---|---|---|
| `phase10_unavailable` | 503 | Server started without `--phase10`. |
| `assessment_not_found` / `evidence_not_found` / `run_not_found` / `audit_event_not_found` / `governance_event_not_found` | 404 | No such resource. |
| `invalid_query_parameter` | 400 | A filter or page value was rejected. |
| `unknown_route` / `unknown_resource` | 404 | No such endpoint. |
| `method_not_allowed` | 405 | You sent a mutating verb. Nothing changed. |
| `evidence_unavailable` | 404 | The id is not registered for download, or its file will not resolve. |
| `audit_journal_unreadable` | 500 | The journal will not parse. Reported, not partially served. |
| `runs_unavailable` | 503 | No audit journal attached, so the set of runs is unknown. |
| `assessments_unavailable` | 503 | No assessment store attached to `/api/v1`. |
| `origin_not_allowed` | 403 | Preflight from an origin outside the allow-list. |
| `internal_error` | 500 | A bug. Report `request_id`. |

No response contains a stack trace or a host filesystem path. Caller-supplied
values echoed into an error are length-bounded.

---

## 5. Pagination

Every list endpoint accepts:

| Parameter | Type | Default | Notes |
|---|---|---|---|
| `limit` | int ≥ 1 | `100` | Capped at `5000`. |
| `offset` | int ≥ 0 | `0` | Past the end is an **empty page, not an error**. |

and returns, alongside its array:

```json
{ "count": 2, "total": 9, "limit": 2, "offset": 0, "has_more": true }
```

`total` is the count **after filters, before paging**. Loop while `has_more`.

```js
async function* pages(path) {
  let offset = 0;
  for (;;) {
    const r = await fetch(`${path}?limit=200&offset=${offset}`);
    if (!r.ok) throw Object.assign(new Error(r.statusText), { body: await r.json() });
    const page = await r.json();
    for (const item of page[ARRAY_KEY]) yield item;
    if (!page.has_more) return;
    offset += page.count;
  }
}
```

A bad `limit`/`offset` is a `400`, never a silent fallback to the default — a
client that sent `limit=abc` and got `200` with 100 items would paginate wrong
forever without knowing why.

The array key differs per endpoint (`items`, `runs`, `findings`, `events`,
`evidence`, `assessments`, `headers`); `count`/`total`/`has_more` are uniform.

> `/api/v1/runs/{run_id}/audit` returns `event_count` (total),
> `returned_event_count` (this page) and `has_more`, because it pages events
> grouped into windows.

---

## 6. Routes

### 6.1 Contract and health

| Route | Notes |
|---|---|
| `GET /api/v1/openapi.json` | OpenAPI 3.1. Always available, even without `--phase10`. |
| `GET /api/v1/docs` | Dependency-free HTML view of the same routes. |
| `GET /api/v1/health` | Component health **plus the effective `cors` policy**. |
| `GET /api/health` | Phase-8 liveness. Always available. |
| `GET /api/v1/metrics` | Prometheus text exposition. |
| `GET /api/v1/traffic-generator` | Status only. |

### 6.2 Assessments (recorded, deterministic)

| Route | Notes |
|---|---|
| `GET /api/assessments` | Table. Array key is `headers` (historical). Paged. |
| `GET /api/assessments/{id}` | Full bundle. |
| `GET /api/assessments/{id}/correlation` | Per-SA correlation evidence. |
| `GET /api/assessments/{id}/risk` | Risk assessment and findings. |
| `GET /api/assessments/{id}/xai` | Explainability. |
| `GET /api/assessments/{id}/ml` | ML classification and inputs. |
| `GET /api/assessments/{id}/evidence` | Evidence references. |
| `GET /api/assessments/{id}/ipsec-state` | Expected vs observed IPsec state. |

`{id}` is the pipeline's own composite id, e.g.
`dataset-20260924-003710:5:band-worst`. They appear in `/api/assessments` —
**enumerate them there; do not hard-code them.**

### 6.3 Discovery (added for state restoration)

| Route | Notes |
|---|---|
| `GET /api/v1/runs` | Runs that have recorded audit events. `503` with no journal. |
| `GET /api/v1/runs/{run_id}` | One run summary. |
| `GET /api/v1/assessments` | Paged/filterable rows. Filters: `scenario`, `severity`, `mode`, `address_family`, `security_posture`, `traffic_profile`, `configuration_id`, `dataset_run_id`, `sequence`, `window_index`. `sort=risk&order=asc\|desc`. |
| `GET /api/v1/assessments/{id}` | One full bundle. |
| `GET /api/v1/assessments/{id}/findings` | Findings for one assessment. |
| `GET /api/v1/findings` | Every finding, flat. Filters: `severity` (comma-separated ok), `category`, `assessment_id`, `dataset_run_id`, `model_version`. |

Use these on page load so the browser does not have to keep "what am I looking
at" in JavaScript memory — a refresh can rebuild its state entirely from the
backend.

**Findings are backend-produced and read-only.** They are copied verbatim from
the Phase-6 risk engine: nothing here is re-scored, re-ranked or re-categorised.
A finding is not globally unique — the same rule can fire against several
assessments — so key on `(assessment_id, finding_id)`.

### 6.4 Evidence

| Route | Notes |
|---|---|
| `GET /api/v1/evidence` | All registered references. |
| `GET /api/v1/evidence/{evidence_id}` | One reference. No host path. |
| `GET /api/v1/evidence/{evidence_id}/pcap` | Raw capture bytes. |
| `GET /api/v1/runs/{run_id}/evidence` | Per analysis window. `?window_index=N`. |
| `GET /api/v1/audit/events/{event_id}/evidence` | Evidence behind one recorded stage. |
| `GET /api/v1/responses/{recommendation_id}/evidence` | Evidence for a response proposal. |

**Downloading a capture**

```js
// Content-Disposition: attachment; the browser saves it rather than navigating
const res = await fetch(`/api/v1/evidence/${id}/pcap`);
if (!res.ok) throw (await res.json()).error;
const blob = await res.blob();
```

`Content-Type: application/vnd.tcpdump.pcap`, `Content-Length` set, body
streamed in 64 KiB chunks (not buffered whole). The `Content-Disposition`
filename is derived from the evidence id, so it never reveals a directory.

The download succeeds **only** for an explicitly registered evidence id whose
file resolves inside the configured evidence root, passes a symlink-escape
check, and has a known capture extension. A caller cannot supply a path: the
registry is the only thing that maps an id to a file. `404` means the id is
unregistered or unresolvable; it never means "here is some other file".

### 6.5 Audit and governance

| Route | Notes |
|---|---|
| `GET /api/v1/audit/events` | Filters: `stage`, `event_type`, `run_id`, `window_index`, `since_seq`. Paged. |
| `GET /api/v1/audit/events/{event_id}` | One event. |
| `GET /api/v1/audit/events/{event_id}/evidence` | Its evidence. |
| `GET /api/v1/audit/runs` | Per-run summaries. |
| `GET /api/v1/audit/runs/{run_id}` | One run summary. |
| `GET /api/v1/runs/{run_id}/audit` | Ordered per-window lifecycle. Paged. |
| `GET /api/v1/governance` | Governance chain. Paged; chain order preserved. |
| `GET /api/v1/governance/{event_id}` | One event + chain position. |

The audit journal is treated as evidence: an event's `event_id` is re-derived
and verified on read, so a tampered record is reported rather than served. A
journal that will not parse yields `500 audit_journal_unreadable` — never a
partial list.

`source` and `authoritative` are echoed verbatim. `comparison-engine` is never
presented as `observation/state-builder`, and `ml` is never presented as
authoritative. `observation/state-builder` is the only authoritative source.

### 6.6 Capture feed (the live-traffic / packet view)

The capture feed is a **read-only tail** of the gateway's `xdp_monitor` packet
journal. It does not aggregate, decode or re-invent anything: each raw XDP JSON
event is normalized through the existing streaming adapter
(`correlation/streaming/live_adapter.py`) and served in the canonical stream
shape fields the rest of the API already uses (`timestamp`, `interface`,
`protocol`, `source`, `destination`, `spi`, `sequence`, `packet_length`,
`source_port`, `destination_port`, `classification`, `direction`).

| Route | Notes |
|---|---|
| `GET /api/v1/capture/events?cursor=&limit=` | Tail of the packet journal. `cursor` is a byte offset the server returns; resume is exact. `limit` caps a page (default 200, max 2000). |

**Policy (must be preserved by any client):**

- **No fabricated packets.** With no journal attached the route returns a
  structured `503` `capture_feed_unavailable`. With a journal attached but no
  packets yet it returns `200` with `present: false` and a human `reason` —
  the explicit "no current traffic yet" state, which the UI renders as
  `LIVE · 0 pkt/s` + "No current IPsec traffic observed.". Both states are
  rendered, never filled.
- **Currentness is backend-decided, never approximated.** Every envelope
  carries the server's own `current` verdict: a journal is current only while
  it is actively being written (write activity within `freshness_window_ms`,
  default 8000, overridable via `ANALYTICS_API_CAPTURE_FRESHNESS_MS`). A
  journal that exists but is not being written reports `current: false` — its
  rows are **recorded history, not current live traffic**, and the workspace
  must present them as history (empty live table + explicit note) rather than
  as live rows.
- **No packet parsing in the browser.** The feed computes `protocol_label`
  ("ESP", "AH", "IKE", "ESP_IN_UDP", "UDP", "TCP", "ICMP", "DNS", …) and an
  `info` string (SPI/seq for IPsec, port pairs otherwise). The frontend formats
  only.
- **Risk is a verbatim projection of the assessment store.** Each packet's
  `risk` block is built by joining the packet SPI against the SPIs each
  assessment observed, copying `severity`/`risk_score`/`finding_count` and the
  `assessment_id` unchanged. A SPI no assessment observed renders
  `risk.present: false` — the UI draws an em dash, it never scores the packet.

Attaching the feed:

```bash
# explicit
python -m correlation.api.app --phase10 --capture-feed results/observed-state/xdp/live_events.jsonl

# or via the environment
ANALYTICS_API_CAPTURE_FEED=/path/to/live_events.jsonl python -m correlation.api.app --phase10
```

With `--phase10` on and no explicit path, the recorded live-tap journal
`results/observed-state/live_events_full.jsonl` is attached as the default. It
is a **static recorded artifact**, so under the currentness policy it reports
`current: false` and the workspace shows the recorded-history empty state
rather than presenting those 93 real packets as live traffic. A gateway monitor
writing to the same path (or the live path above) makes the view genuinely
live. The journal is **never written** from a request.

Response shape (all fields always present):

```json
{
  "api": "capture-events-v1",
  "schema": "packet",
  "state": "available | waiting",
  "read_only": true,
  "present": true,
  "reason": null,
  "source": "live_events_full.jsonl",
  "frame": "Passive capture of the gateway traffic path (xdp_monitor). …",
  "cursor": 11573,
  "start_cursor": 0,
  "size": 11573,
  "total": 93,
  "count": 2,
  "limit": 2,
  "has_more": true,
  "current": false,
  "freshness_window_ms": 8000,
  "last_write_age_ms": 86400000,
  "journal_mtime_ms": 1726063049755,
  "server_time_ms": 1726149449755,
  "newest_observed_at_ms": 1726062927854,
  "events": [
    {
      "id": "<sha256 of offset:raw line>",
      "source": "live_events_full.jsonl",
      "offset": 0,
      "timestamp_ns": 17260803212308,
      "schema": "packet",
      "packet": { "timestamp": 17260803212308, "interface": "",
                  "protocol": 50, "source": "192.168.100.1",
                  "destination": "192.168.100.2", "spi": 3450011795,
                  "sequence": 7, "packet_length": 154, "source_port": 0,
                  "destination_port": 0, "classification": "ESP",
                  "direction": null, "sensor_type": "ESP" },
      "protocol_label": "ESP",
      "info": "SPI 0xcda30093, seq 7",
      "spi": 3450011795,
      "direction": null,
      "risk": { "present": true, "highest_severity": "INFO",
                "highest_risk_score": 0,
                "assessments": [{ "assessment_id": "dataset-20260924-003710:1:nat-t",
                                  "severity": "INFO", "risk_score": 0,
                                  "finding_count": 0 }] }
    }
  ]
}
```

The `id` is a content+offset digest, so it is deterministic across polls and
stable as the journal grows. Only complete (newline-terminated) lines are ever
served, so a torn final line being written by the sensor is never surfaced, and
a rotated/truncated journal (cursor past EOF) retails itself from the top.

**The liveness fields** (all additive, present in every envelope `status()`
return):

- `current` (boolean) — the backend's verdict that the journal is being
  actively written. Decided server-side from `last_write_age_ms <=
  freshness_window_ms`, never by the client. `false` means: whatever the
  journal holds is recorded history, and the workspace must not render it as a
  live packet table.
- `freshness_window_ms` (int) — the server's write-freshness window (default
  8000; `ANALYTICS_API_CAPTURE_FRESHNESS_MS`, minimum 1000). Also used for the
  capture view's automated freshness display.
- `last_write_age_ms` (int | null) — how long ago the journal file's mtime was
  updated; `null` when no journal exists.
- `journal_mtime_ms` (int | null) — the journal's own last-write wall clock.
- `server_time_ms` (int) — when the envelope was built.
- `newest_observed_at_ms` (int | null) — wall-clock time of the newest complete
  (newline-terminated) line, best-effort from the trailing content;
  informational only, never used to decide `current` (write activity is, so a
  replay that only re-writes header bytes is still not "live").

The workspace renders live rows **only** when `current` is `true`. Otherwise it
shows `LIVE · 0 pkt/s` with "No current IPsec traffic observed." and a note
explaining that held journal rows are recorded history (they remain reachable
in the findings/evidence surfaces, never as the live stream).

---

## 7. Security model — read this before deploying

**There is no authentication.** Anyone who can reach the port can read the full
assessment, evidence, audit and governance surface. That is acceptable for a
loopback development tool and is **not** acceptable on a shared network.

Because the API is strictly read-only, the blast radius of an unauthorised
reader is *confidentiality of results*, not integrity or availability:

- No route starts, stops, reconfigures or approves anything.
- No route reaches the response engine or XDP.
- No route writes any file. The audit journal and governance ledger are opened
  read-only by this process; the governance ledger is appended to by the
  response engine, never by a handler.
- A capture is a protocol artifact, not a conclusion. Every evidence payload
  reports `authoritative: false` and points at the observation event that *is*
  authoritative.

What *is* disclosed and should be considered sensitive: assessment results,
finding detail, evidence capture bytes, audit and governance history, and
(in a misconfigured deployment) host filesystem paths — which this API does not
emit.

**If you must expose it beyond loopback:** put it behind an authenticating
reverse proxy, set `ANALYTICS_API_ALLOWED_ORIGINS` to exactly your dashboard
origin, and bind deliberately. The server warns on stderr when you bind a
non-loopback address, but it cannot enforce a policy on its own.

---

## 8. Worked example

```js
const API = 'http://127.0.0.1:8081';

async function get(path, params = {}) {
  const qs = new URLSearchParams(params).toString();
  const res = await fetch(`${API}${path}${qs ? '?' + qs : ''}`);
  if (!res.ok) {
    const { error } = await res.json();
    if (error.code === 'phase10_unavailable') return null;  // server not started with --phase10
    throw new Error(`${error.code}: ${error.message} (request ${error.request_id})`);
  }
  return res.json();
}

// restore state on page load, entirely from the backend
const runs = await get('/api/v1/runs');
const assessmentId = runs?.runs?.[0]?.run_id;   // then map to an assessment via /api/v1/assessments
const findings = await get('/api/v1/findings', { severity: 'CRITICAL,HIGH' });
const openapi = await get('/api/v1/openapi.json');
```

`fetch` is same-origin-agnostic in the usual way: point `API` at the port you
bound, and make sure that origin is in `ANALYTICS_API_ALLOWED_ORIGINS`.
