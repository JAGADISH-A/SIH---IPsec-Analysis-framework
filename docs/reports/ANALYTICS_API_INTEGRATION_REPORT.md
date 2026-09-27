# Analytics API — Frontend/Backend Integration Report

**Scope:** make `correlation/api/` ("Server A", the analytics and governance
API) usable by a browser client, without modifying the analysis engine, the
control API, or the frontend.

**Baseline:** `93375d5 feat : multiple SA correlation added` (clean tree)
**Result:** `1860 passed, 22 skipped, 0 failed` (baseline was `1742 passed,
22 skipped`) — **+118 tests, no regressions.**

**Companion document:** [`ANALYTICS_API_FRONTEND_CONTRACT.md`](./ANALYTICS_API_FRONTEND_CONTRACT.md)
— the contract a client codes against.

---

## 1. Constraints honoured

| Constraint | Evidence |
|---|---|
| Do not modify the control API (`controller/api.py`) | `sha256` at `HEAD` and in the worktree are both `c98d1a53…05d4`. `git diff --stat -- controller/` is empty. |
| Do not modify the frontend | No file under `frontend/` is touched. |
| Do not modify the analysis engine | No file under `correlation/` outside `correlation/api/` is touched. `git diff --stat` covers 9 files, all in `correlation/api/` or `tests/`. |
| Do not port decision logic | Every new payload is a projection of existing engine output. Covered by `TestDiscoveryProjectsExistingData::test_no_finding_is_renamed_rescored_or_dropped`, which asserts every field of every finding survives byte-identical. |
| Keep the two servers separate | `TestControlApiSeparation` asserts the analytics package never imports `controller`, and the control API never imports `correlation.api`. |

### Note on the audit document

The task referenced `FRONTEND_BACKEND_INTEGRATION_AUDIT.md`. **That file does
not exist in this repository** (`find` over the tree returns nothing). The
findings below were therefore re-derived directly from the code and each one
was independently reproduced before being fixed — see §3, where each finding
records the observation that confirmed it. If a written audit exists elsewhere,
it should be reconciled against §3; the underlying observations are recorded
here in enough detail to check.

---

## 2. Architecture as found

Two independent HTTP servers, unconnected:

| | Analytics API (Server A) | Control API (Server B) |
|---|---|---|
| Module | `correlation/api/app.py` | `controller/api.py` |
| Framework | stdlib `ThreadingHTTPServer` | FastAPI + uvicorn |
| Default port | `8000` (**collides with B**) | `8000` |
| Mounts the other? | No | No |
| Imports the other? | No | No |

`correlation/api/live.py:Phase10Context` is the only wiring object; every
dependency on it is explicit and optional, and an absent one produces a
structured `503` rather than a fabricated empty result.

Handler modules are pure functions tested without sockets; `app.py` was a thin
transport. That separation is preserved — every new handler is a pure function
and the new tests cover both layers independently.

---

## 3. Findings, and what was done

### 3.1 `/api/v1/*` dropped the connection when `--phase10` was absent

**Reproduced.** `app.py:_api` dispatched `/api/v1` straight to `_api_v1`,
bypassing the `phase10_unavailable` guard that lives in `handle_combined`. The
handler then dereferenced the missing context:

```
/api/health     -> 200
/api/v1/health  -> RemoteDisconnected: Remote end closed connection without response
```

A frontend cannot distinguish this from a dead server, and there is no status
code, no body, and nothing in the log to act on.

**Fixed.** The guard was moved to be the single dispatcher (`app.py:handle_combined`),
so every `/api/v1/*` path answers `503` with a parseable body. Verified across
13 representative v1 paths. `test_the_guard_lives_in_the_shared_dispatcher_not_the_handler`
pins it to the dispatcher so a future adapter inherits it for free.

### 3.2 No CORS, and no `OPTIONS` handler

There was no `do_OPTIONS`, so `http.server` returned its `501 Unsupported
method` HTML for every preflight — indistinguishable from a broken server in
devtools. There were no CORS response headers on any route.

**Fixed.** New `config.py` (env-driven policy, resolved once) and `cors.py`
(header computation, testable without a socket). Every response — success,
`4xx`, `5xx` and preflight — now carries CORS headers when the origin is
allowed, and none when it is not. `Vary: Origin` prevents a shared cache from
serving one origin's allow-header to another.

Security-relevant decisions:

- The default is a narrow loopback list, **not** `*`.
- `*` is honoured but must be configured explicitly.
- **`ANALYTICS_API_ALLOWED_ORIGINS=""` allows nothing.** An explicitly cleared
  allow-list locks the API down rather than silently restoring the development
  defaults — otherwise clearing the variable in a deploy manifest would *widen*
  access. Covered by `test_unset_and_empty_are_different_configurations`.
- Preflight from a disallowed origin is `403` *without* the allow header: visible
  in logs and to `curl`, still blocked by the browser.

### 3.3 Absolute host paths reachable over HTTP

Three fields disclosed the deploy layout and service account from an
unauthenticated API:

| Location | Field |
|---|---|
| `evidence_routes.py:422` | `served_from` — the absolute capture path |
| `evidence_routes.py:493` | `journal` — the absolute governance ledger path |
| `evidence_routes.py:520` | `journal` (event detail) + `observation_journal` |

Also: `chain_detail` echoed a raw exception, and `AuditJournalUnreadable` was
interpolated into a `500` body — both could embed a path or journal content.

**Fixed.** New `redact.py`. Paths are reduced to repository-relative →
root-relative → **basename only**, never absolute. Exceptions go to the log,
not the response. Caller-supplied values echoed into errors are length-bounded.

> A claim in the task brief that `sources[].path` was leaking was **not**
> correct: those paths were already repository-relative. They were left
> untouched, and `test_evidence_detail_served_from_is_not_absolute` pins the
> behaviour so a future change cannot quietly make them absolute.

One existing test asserted the leak
(`test_governance_journal.py: assertEqual(payload["journal"], self.path)`). It
was updated to assert the *safe* contract — non-absolute, correct basename,
`host_path_disclosed: False` — rather than deleted.

### 3.4 `limit`/`offset` echoed but ignored on the run audit trail

`AuditStore.run_trail()` accepted a query, applied only its filters, and
discarded the paging. A client paging a long run re-fetched the entire run every
page and could never reach the end.

**Fixed.** Paging is now applied to the filtered event set before windows are
grouped, so `limit`/`offset` mean the same thing here as on the flat event list.
`event_count` stays the total; `returned_event_count` and `has_more` were added
and threaded through the route. Covered by five tests including
`test_pages_do_not_overlap`, which walks the pages and asserts the ids are
disjoint and complete.

### 3.5 No way to enumerate what exists

There was no endpoint to list runs, assessments or findings, so a frontend could
not restore its state after a refresh — it had to keep the current selection in
JavaScript memory.

**Fixed.** New `discovery.py` adds six routes (§4). Every value is a projection
of engine output: runs come from the audit journal, assessments from the
existing `AssessmentStore`, findings copied verbatim from
`risk.findings[]`. Nothing is recomputed, scored, ranked or suppressed.

`/api/v1/runs` returns `503 runs_unavailable` when no journal is attached, not
`{"runs": []}` — an empty list reads as "there are no runs" and a frontend would
render an empty state for a server that simply was not told where its journal is.

### 3.6 Default port collided with the control API

Both defaulted to `8000`. Starting both was an opaque `EADDRINUSE`. Confirmed
during verification: port 8000 was already occupied in this environment.

**Fixed.** Server A defaults to `8081`, configurable via `ANALYTICS_API_PORT`.

### 3.7 Unhandled exceptions returned a traceback

An unexpected error in a handler propagated to `BaseHTTPRequestHandler`, which
emits a bare connection close — the same unusable failure as §3.1. Any handler
bug was therefore invisible and undebuggable.

**Fixed.** A catch-all logs the traceback server-side and returns a structured
`500` with a `request_id` that matches the log line. This was not theoretical:
it caught a definition-order bug in `openapi.py` during development and returned
a correct `500` rather than a dropped connection.

### 3.8 Captures were buffered whole

`PcapService.download()` did `handle.read()`. A capture is routinely tens of
megabytes, so every concurrent browser download doubled peak memory.

**Fixed.** `open_stream()` streams in 64 KiB chunks with `Content-Length` and
`Content-Disposition: attachment`. Resolution goes through the same hardened
`PcapRegistry.resolve`, so streaming is not a weaker path: allow-listed id,
contained under the root, symlink-escape check, known extension. The
`Content-Disposition` filename is built from the validated evidence id, so it
cannot leak a directory or be steered by a crafted registered filename.

### 3.9 No machine-readable contract

**Fixed.** `openapi.py` serves OpenAPI 3.1 at `/api/v1/openapi.json` (31 routes)
and a dependency-free HTML view at `/api/v1/docs` — no CDN, so it works offline
and adds no supply-chain surface.

It is hand-written rather than framework-generated, which is only defensible
because it is **validated against the live router in both directions**:
`test_every_documented_route_is_really_routable` and
`test_every_live_route_is_documented` fail if a route is added without
documenting it or documented without existing. This caught a real error — an
invented `/api/v1/audit/runs/{id}/events` that does not exist.

`servers` is deliberately empty: the server is reachable under several host
names, and a wrong entry sends code generators to a host that does not exist.

### 3.10 Missing observability and coverage gaps

Fixed alongside the above: `X-Request-Id` on every response (a client-supplied
id is sanitised and reused for correlation), `HEAD` support, `405` for `PATCH`,
`Allow` headers per RFC 9110, and the error envelope extended with `message` and
`request_id` while **retaining** the historical `detail` key.

---

## 4. API surface change

| | Before | After |
|---|---|---|
| Documented routes | 0 (no OpenAPI) | 31 |
| Discovery routes | 0 | 6 |
| CORS | none | allow-list + preflight |
| Authenticated | — | no (documented, §6) |

**Added:** `GET /api/v1/runs`, `/api/v1/runs/{run_id}`, `/api/v1/assessments`,
`/api/v1/assessments/{id}`, `/api/v1/assessments/{id}/findings`,
`/api/v1/findings`, `/api/v1/openapi.json`, `/api/v1/docs`.

**Additive changes to existing routes:** pagination fields on every list;
`request_id`/`message` on errors; `cors` on `/api/v1/health`; streaming headers
on the PCAP route. **No response field was removed or renamed** — `headers`,
`detail`, `evidence_count` and `journal` all keep their meaning.

---

## 5. Verification

### 5.1 Full suite

```
1860 passed, 22 skipped, 10 warnings, 1889 subtests passed
```

Baseline was `1742 passed, 22 skipped, 1708 subtests`. No failures, no
regressions. The 10 warnings are pre-existing and unrelated (Starlette
`BlockingPortal` deprecation, pytest collection warnings, SHAP
`PendingDeprecationWarning`).

### 5.2 New tests — `tests/test_analytics_api.py`, 118 tests / 165 subtests

Split by layer: handler tests need no socket; transport tests drive a real
server on an ephemeral port. Covers CORS resolution and headers, preflight,
read-only enforcement, the error envelope, config precedence, pagination
helpers and real paging, path redaction, discovery fidelity, PCAP streaming, and
OpenAPI drift.

Every regression from §3 has a test named after it.

### 5.3 Live cross-origin test, real separate origin

A frontend HTTP server was started on `http://localhost:3000` and the analytics
API on `127.0.0.1:8081`, configured exactly as `main()` configures it. Every
check passed:

```
STEP 1 — browser preflight
  status 204                       : PASS
  Access-Control-Allow-Origin      : PASS  (http://localhost:3000)
  Allow-Methods has GET            : PASS
  Allow-Headers echoes accept      : PASS
  Max-Age set for caching          : PASS  (600s)

STEP 2 — the real GET
  200                              : PASS
  readable by the browser          : PASS
  Vary: Origin present             : PASS  (cache-poisoning guard)
  page has findings                : PASS  count=2 total=9
  findings are backend-produced    : PASS

STEP 3 — a page on an origin we did NOT allow
  no Allow-Origin header           : PASS  -> browser blocks the read
  preflight rejected with 403      : PASS

STEP 4 — the read-only promise over the wire
  every mutating verb -> 405       : PASS   (Allow: GET, HEAD, OPTIONS)
  nothing was created              : PASS   (total still 9)

STEP 5 — the contract a client generates from
  OpenAPI 3.1.0, 31 routes         : PASS
  HTML contract page               : PASS

STEP 6 — no host path in any reachable response
  leaks across 6 routes            : PASS
```

### 5.4 Startup from the documented command

```
$ ANALYTICS_API_PORT=8081 ANALYTICS_API_ALLOWED_ORIGINS=https://ops… \
    python -m correlation.api.app --phase10 --no-static
[analytics-api] store built: 12 assessments (deterministic, …)
[phase10] passive-observation /api/v1 surface attached
[analytics-api] listening on http://127.0.0.1:8081 (api only)
[analytics-api] cors allowed origins: https://ops.sihcolayer.internal
[analytics-api] read-only API: GET, HEAD, OPTIONS; every mutating verb is 405.
```

### 5.5 Scope proof

```
$ git diff --stat -- controller/
(empty)
$ git show HEAD:controller/api.py | sha256sum
c98d1a53aefb57db63265615fd9b0182fb7f22030a2cdd35ba8249d9c86b05d4
$ sha256sum controller/api.py
c98d1a53aefb57db63265615fd9b0182fb7f22030a2cdd35ba8249d9c86b05d4
```

---

## 6. Security position after this change

**Unchanged, and now enforced on the wire:** the API is read-only. No route
starts, stops, approves, resolves, dismisses or overrides anything; no route
reaches the response engine or XDP; no route writes a file. Mutation attempts
return `405` with `Allow: GET, HEAD, OPTIONS` and the request body is never
read.

**Improved:** no CORS headers for un-allow-listed origins; no stack traces or
host paths in any response; bounded echo of caller-supplied values; `PATCH`
now covered; per-request correlation ids; the port no longer collides with the
control API.

**Still open, by design:** there is no authentication. The server binds loopback
and warns on stderr when it does not. Because the surface is read-only, the
blast radius of an unauthorised reader is confidentiality of results, not
integrity or availability. Before exposing it beyond loopback, put it behind an
authenticating proxy, set `ANALYTICS_API_ALLOWED_ORIGINS` to exactly the
dashboard origin, and bind deliberately. This is documented in §7 of the
contract rather than left implicit.

**Also unchanged:** audit `event_id`s are re-derived and verified on read, so a
tampered record is reported rather than served; a journal that will not parse
yields `500`, never a partial list; `source`/`authoritative` are echoed
verbatim, and `observation/state-builder` remains the only authoritative source;
captures report `authoritative: false`.

---

## 7. Deliberately not done

- **No authentication or authorisation layer.** Every route is read-only, so
  auth would gate only confidentiality; inventing a scheme without a requirement
  would add risk and lock in a policy. Documented instead (§6).
- **No WebSocket/SSE.** The existing surface is polled counters; a realtime
  channel is a product decision, not an integration blocker.
- **No OpenAPI code generation.** Stdlib-only was the constraint; generation
  needs a framework, and the schema is drift-checked instead.
- **No change to the analysis engine or the control API**, as instructed.
- **No frontend change**, as instructed — the frontend's own port of the
  contract is out of scope here.
- **`sources[].path` left alone**, because it was already safe (§3.3).

## 8. Files

**New:** `correlation/api/config.py`, `cors.py`, `discovery.py`, `openapi.py`,
`redact.py`; `tests/test_analytics_api.py`;
`docs/reports/ANALYTICS_API_FRONTEND_CONTRACT.md`.

**Modified:** `app.py` (transport: CORS, preflight, error handling, request ids,
streaming, startup), `v1.py` (routing, discovery, health), `routes.py` (error
envelope, pagination), `evidence_routes.py` (redaction, pagination),
`audit_routes.py` (pagination passthrough, error sanitisation), `audit_store.py`
(paging regression fix), `pcap.py` (streaming), `live.py` (cors policy field).

**Modified test:** `tests/test_governance_journal.py` — one assertion that
asserted the path leak now asserts the safe contract (§3.3).
