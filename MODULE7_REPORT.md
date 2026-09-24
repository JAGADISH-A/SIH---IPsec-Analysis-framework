# Module 7 — Engineering Dashboard: Dataset Generation UI

## 1. What changed (files)

| File | Change |
| --- | --- |
| `frontend/index.html` | Rewritten into an engineering dashboard: header, two-column grid (manual experiment on the left, dataset generation on the right), full-width dataset statistics card, and the testbed flow card. No new framework; plain static HTML/CSS/JS served by the existing FastAPI app. |
| `frontend/app.js` | Rewritten, preserving the Modules 1-5 manual experiment flow and adding the dataset generation UI logic (state, polling, rendering, resume, results). |
| `frontend/styles.css` | Appended the Module 7 layout/components (dashboard grid, dataset card, statistics card, posture badges, progress bars) and responsive breakpoints; all existing component styles retained. |
| `controller/test_dataset_api.py` | Test-only robustness changes (no backend logic touched): `wait_status` / `wait_finalized` default timeouts increased from 15s to 300s so the large scripted runs (500/1000 samples, multiple `fsync`ed state writes per sample) never time out under load; two acceptance tests now wait for finalization before temp-dir teardown (removes an `rmtree` race); `test_completion_not_reported_below_target` now waits for the first committed sample before asserting (removes an early-RUNNING snapshot race). |

No changes to any backend controller logic. No ML / Zeek / tshark / sampling-plan code was touched.

## 2. UI changes

- **Dataset Generation card** is the primary control: a "Security Configuration × Traffic Profile = Dataset Sample" axes strip, an exact-target input, and a Generate Dataset button.
- **Live status area** shows: run id, status badge, a success-based progress bar + percentage ("progress is based only on successful samples"), a big `successes / target` count, Attempts / Failed / Interrupted metrics, and a "Currently generating" block (sequence, traffic, security posture chip, and the full IKE/ESP config read from the backend's `current_configuration`).
- **ESP Integrity = None** is rendered for AES-GCM samples (the backend reports `esp.integrity: null`).
- **Results card** ("Dataset Statistics", backend-derived only): traffic distribution, security posture distribution (count + %) and a run summary (feature rows, metadata records, finalization status, artifact paths) from the lightweight results endpoint — never the full Parquet.
- **Manual experiment preserved and improved**: the original experiment controls remain exactly as before, and all options are driven from `GET /experiments/configurations` (the single backend source of truth).
- **Two-column responsive layout**: grid collapses to a single column below 1120px; input row and distribution rows collapse further at 620px.
- **Accessibility**: `role="radiogroup"/"radio"/"switch"`, `aria-valuenow/min/max` on the progress bar, `role="alert"` on errors, `aria-label`s on the cards.

## 3. API endpoints consumed by the UI

- `GET /health` — controller health pill.
- `GET /experiments/configurations` — manual experiment option lists (modes, families, IKE/ESP, traffic profiles/duration).
- `POST /experiments` + `GET /experiments/{id}` — manual experiment run/status polling (unchanged).
- `GET /dataset-runs/settings` — `maximum_target_samples` (shown under the input; never used to clamp the request).
- `POST /dataset-runs` — create run with the exact `{"target_samples": N}`.
- `GET /dataset-runs/{id}` — live status polling.
- `POST /dataset-runs/{id}/resume` — resume a PAUSED run (same run id).
- `GET /dataset-runs/{id}/results` — backend-derived distributions + counts.

## 4. Dataset generation flow (UI)

1. `loadDatasetSettings()` fetches the maximum and displays it as a note.
2. `readDatasetTarget()` validates a positive integer; values above the backend maximum produce a friendly client-side error (the backend additionally rejects with 422 — the UI never clamps/changes the number).
3. `startDatasetRun()` POSTs the exact target; on 201 it stores the returned `dataset_run_id`, renders COMPLETED/RUNNING state and starts polling. 409/422/404/network failures render an inline `role="alert"` error, separate from the status area.
4. While a run is executing (CREATED/RUNNING/PAUSED) the Generate button is disabled; after COMPLETED or FAILED it re-enables so a new run can start.
5. `renderDataset()` is driven entirely by the backend status payload, including `progress_percentage`, `current_*`, `attempted_runs`, `failed_samples`, `interrupted_samples`, `error` and `finalization`.

## 5. Exact-target behaviour

- The user-supplied number is never hardcoded, defaulted, clamed, or reinterpreted by the UI. The flight path observed end-to-end: `POST {"target_samples": 2}` -> plan of exactly 2 sample slots -> 2 committed successful samples (`successful_samples == 2`, `committed_samples == 2`, `feature_row_count == 2`); `POST {"target_samples": 500}` travels and completes as 500.
- Success-based progress: `progress_percentage` is the backend's `successful_samples / target_samples * 100`. Failed/interrupted attempts never move it; only committed successes do.

## 6. Polling behaviour

- Dataset status is polled every 2.5s via `GET /dataset-runs/{id}`; each poll runs under a monotonically-increasing token so overlapping/out-of-order pollers are impossible (a stop/restart invalidates pending ticks).
- When the backend reports COMPLETED, the UI enters a short "finalization grace" window (fast re-polls every 1s, up to 12) because the status flips to COMPLETED before `finalization.json` is written; once `finalization.status == COMPLETED` (or the window elapses) polling stops and `GET .../results` is fetched once.
- FAILED and PAUSED stop polling immediately (no useless re-polling).
- Polling stops gracefully on 404, non-OK responses, malformed payloads, or lost connection — each case renders a specific inline error.

## 7. Pause / resume

- When a run is PAUSED the status area shows a "Dataset generation paused" banner and a **Resume Dataset** button (event-delegated on the status container).
- Resume POSTs `/dataset-runs/{id}/resume`; on 200 the same run id is kept and polling restarts. 409/400/404 each render a specific message. The backend enforces that resume only happens for CREATED/PAUSED runs and validates the plan fingerprint.

## 8. Error handling

- Manual experiment: 409 busy ("...or the testbed is busy generating a dataset"), 422 invalid config, 404 job lost, staging classifier for deploy/ipsec/connectivity/traffic failures; concise messages for invalid selection (GCM requires ESP Integrity None, missing profile, out-of-range duration).
- Dataset: per-status messages for 409 (another run or a manual experiment owns the shared testbed), 422 (target above maximum / invalid), 404 (run not found), plus network-loss cases; all server `detail` strings are surfaced verbatim when present.

## 9. Responsive

- Two columns ≥1120px; single column below. Distribution grid collapses columns; target input row and run button stack at <620px; long run ids ellipsize; wraps kept on chips/badges. Verified by CSS review + static class/id coverage; see §10 for the environment limitation.

## 10. Tests performed & results

- **Syntax**: `gjs` loads `frontend/app.js` with a non-`SyntaxError` reference error only (document not defined) — parse clean. No node/browser available in this environment.
- **Static contract**: every one of the 55 ids referenced by `app.js` exists in `index.html`; all 122 UI-referenced CSS classes have matching selectors.
- **Live API verification** (`TestClient` against the real `controller.api.app` plus a dependency-injected scripted run): `GET /`, `/static/styles.css`, `/static/app.js`, `/health`, `/dataset-runs/settings` → 200; `POST` invalid targets → 422; full lifecycle (RUNNING mid-flight snapshot with `current_configuration`, COMPLETED with `successful_samples==target`, `attempted_runs`, `failed_samples`, `progress_percentage`, `finalization`, results with distributions/`feature_row_count`/`artifact_paths`), GCM `esp.integrity` null, FAILED with `error`, PAUSED→resume (same run id) → COMPLETED, 404 handling — 90 checks, all passing.
- **Backend regression**: `python -m unittest discover -s controller -p "test_*.py"` → **220 tests, OK** (412), stable across repeated runs after making the two Module 6 test helpers load-tolerant and race-free (see §1).
- **Manual cases A-I mapping** (verified via the API-level checks above; a live browser of the generated HTML is not available on this machine): 2→POST 2 exact; 500→POST 500 exact; failure progress (attempts/failed don't advance progress); 2/2 completed; PAUSED resume; duplicate-start prevention (409 + generate disabled while active); GCM→ESP Integrity shown as None; IPv6 display in current-config rows; distributions always from backend payloads.

## Limitations

No browser is available in this session, so true pixel-level responsive/visual checks and console interaction testing could not be performed; DOM/network behaviour was verified statically and via the API contract checks above.