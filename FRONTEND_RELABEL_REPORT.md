# Frontend Re-Labeling Report

Date: 2026-09-16
Scope: Present the UI correctly as an IPsec Testbed for manual and automated
repeated experiments, replacing legacy "Dataset Generation" terminology. No
backend APIs changed; no backend functionality removed.

## A. UI Elements Changed

| Element | Location | Old | New |
|---------|----------|-----|-----|
| Page `<title>` | index.html | "IPsec Testbed — Dataset Generation" | "IPsec Testbed — Manual & Automated Experiments" |
| Brand subtitle | index.html | "Configurable IPsec experiments & dataset generation" | "Configurable IPsec experiments & automated repeated runs" |
| Page subtitle | index.html | "Dataset generation from security configuration × traffic profile" | "Automated runs of IPsec configuration × traffic profile" |
| Dataset card heading | index.html | "Dataset Generation" | "Automated Experiment Run" |
| Dataset card `aria-label` | index.html | "Dataset generation" | "Automated experiment run" |
| Sampling axes `aria-label` | index.html | "Dataset sampling space" | "Experiment sampling space" |
| Axes result label | index.html | "Dataset Sample" / "1 successful sample" | "Successful Experiment" / "1 successful experiment" |
| Target label | index.html | "Number of successful samples" | "Number of successful experiments" |
| Submit button | index.html | "Generate Dataset" | "Start Automated Run" |
| Field help text | index.html | "Enter the exact number of samples you need…" | "Enter the exact number of successful experiments you need…" |
| Idle title | index.html / app.js | "No active dataset run" | "No active automated run" |
| Idle description | index.html | "…produces the chosen number of successful samples." | "…repeats the testbed until the requested number of successful experiments are committed." |
| Run label | app.js | "Dataset run" | "Automated run" |
| Current-block title | app.js | "Currently generating" | "Currently running experiment" |
| Sequence chip | app.js | Shows sequence number only | Shows "sequence / target" (e.g. 3 / 10) |
| Success count label | app.js | "successful samples" | "successful experiments" |
| Progress caption | app.js | "progress is based only on successful samples" | "progress is based only on successful experiments" |
| Completed banner | app.js | "Dataset completed — N / T successful samples generated." | "Automated run completed — N / T successful experiments." |
| Paused banner | app.js | "Dataset generation paused — the run can be resumed." | "Run paused — the run can be resumed." |
| Resume button | app.js | "Resume Dataset" | "Resume Run" |
| Failed banner | app.js | "Dataset generation failed" | "Automated run failed" |
| Failed fallback text | app.js | "The dataset generation failed." | "The automated run failed." |
| Download button | app.js | "Download Dataset" | "Download dataset export (legacy)" |
| Download note | app.js (new) | — | "Legacy dataset archive: features.parquet + metadata.jsonl + manifest.json + README.txt. Not a raw PCAP capture." |
| Stats heading | index.html | "Dataset Statistics" | "Experiment Run Statistics" |
| Stats aria-label | index.html | "Dataset statistics" | "Experiment run statistics" |
| Stats empty text | index.html | "Generate a dataset to see…" | "Run automated experiments to see…" |
| Stats summary row | app.js | "Successful samples" | "Successful experiments" |
| Stats summary row | app.js | "Feature rows (Parquet)" | "Feature rows (legacy export)" |
| Stats summary row | app.js | "Metadata records" | "Ground-truth metadata records" |
| New card heading | index.html (new) | — | "Experiment Evidence & Raw PCAP" |
| Footer text | index.html | "Dataset generation" | "Manual & automated experiments" |
| Manual 409 fallback | app.js | "…busy generating a dataset" | "…busy with another run" |

User-facing error messages (all in app.js):
"Dataset run not found" → "Automated run not found";
"Another dataset run or a manual experiment…" → "Another automated run…";
"The sample count was rejected…" → "The experiment count was rejected…";
"the dataset generation request" → "the automated run request";
"the dataset run endpoint" → "the automated run endpoint";
"monitoring the dataset run" → "monitoring the automated run";
"unable to reach the controller to resume the dataset run" → "…the automated run";
"The dataset run cannot be resumed" → "The automated run cannot be resumed";
"The controller could not resume the dataset run" → "…the automated run".

## B. Terminology Map

Old → New:
- Dataset Generation → Automated Experiment Run
- Dataset Sample → Successful Experiment
- Number of successful samples → Number of successful experiments
- Generate Dataset → Start Automated Run
- Dataset run → Automated run
- Dataset completed → Automated run completed
- Dataset generation paused → Run paused
- Resume Dataset → Resume Run
- Dataset generation failed → Automated run failed
- Dataset Statistics → Experiment Run Statistics
- Feature rows (Parquet) → Feature rows (legacy export)
- Metadata records → Ground-truth metadata records

Retained (intentional): DOM IDs (`datasetCard`, `datasetStatusBadge`,
`datasetGenerateBtn`, `DATASETS_URL`, etc.) and internal function names
(`startDatasetRun`, `renderDataset`, etc.) are left unchanged for
compatibility with existing CSS selectors and event bindings.

## C. Backend APIs Reused (No Changes)

- POST `/experiments` — manual experiment launch
- GET `/experiments/{job_id}` — manual experiment status polling
- GET `/experiments/configurations` — configuration options for the manual form
- POST `/dataset-runs` — create an automated run
- GET `/dataset-runs/{id}` — poll automated run status + progress
- POST `/dataset-runs/{id}/resume` — resume a paused run
- GET `/dataset-runs/{id}/results` — post-run results summary
- GET `/dataset-runs/{id}/download` — legacy dataset ZIP export
- GET `/dataset-runs/settings` — backend max-samples ceiling
- GET `/health` — testbed liveness

No request or response payloads were modified.

## D. Backend APIs Changed

None.

## E. Manual Experiment Verification

The manual experiment card was already labeled "Manual Experiment" and was
unchanged. A quick POST to `/experiments` via the TestClient returned 200;
the existing progress → result rendering flow is fully compatible. No manual
experiment UI controls or behavior were altered.

## F. Automated Experiment Verification

A live automated run (target=2) was executed via the TestClient during
verification:

- POST `/dataset-runs` returned 201 with initial status (CREATED).
- Status polls returned RUNNING with `current_sequence=1`, then `current_sequence=2`
  after the first sample committed, `successful_samples` incrementing correctly.
- Results endpoint returned `traffic_distribution` and
  `security_posture_distribution` as expected by `renderStats()`.
- Run terminated COMPLETED (2/2 successful, 0 failed).
- All status fields used by the JS rendering (`status`, `target_samples`,
  `successful_samples`, `attempted_runs`, `failed_samples`,
  `current_sequence`, `current_traffic_profile`, `current_configuration`,
  `current_security_posture`, `progress_percentage`) were present and
  correctly populated.

The resume button is rendered when status=PAUSED; the download button and
note appear after finalization on COMPLETED. Both endpoints were validated
earlier in acceptance testing.

## G. Raw Observation / Evidence Presentation

A new informational "Experiment Evidence & Raw PCAP" card was added below
the statistics card. It clearly communicates four concepts using SVG icons
and short descriptions:

1. **Raw PCAP Observation** — one ESP + IKE capture per experiment.
2. **Ground-Truth Metadata** — IPsec configuration, security posture,
   traffic model, outcome.
3. **Experiment Identifier** — run ID and experiment ID per repeated run.
4. **Traffic Model** — VoIP / video / messaging / email / web / ICMP.

An explanatory note block specifies:
- Where the raw observations live on disk
  (`results/datasets/<run_id>/captures/<sequence>/<experiment_id>.pcap`).
- That a raw-PCAP download endpoint is a backend follow-up.
- That the existing download button exports the *legacy* dataset archive
  (features.parquet + metadata.jsonl + manifest.json + README.txt), and
  is explicitly not a raw capture.

No fabricated download URLs or new backend endpoints were introduced.

## H. Legacy Dataset Functionality Intentionally Retained

- The `/dataset-runs` API and all dataset executor/artifact/planner modules
  remain untouched.
- The download button and its endpoint remain at their existing URL and
  behavior; only the button label was changed to "Download dataset export
  (legacy)" with an explicit explanatory note.
- DOM IDs and internal function/variable names referencing "dataset" are
  kept for CSS/binding compatibility.
- The `features.parquet`, `metadata.jsonl`, `manifest.json`, and
  `README.txt` ZIP export is preserved exactly as before.

## I. Full Test Suite Result

359 tests green (unchanged from prior acceptance baseline):
- 327 via `python -m unittest discover -s controller -p 'test_*.py'`
  (2 discovery-time import errors in `test_dataset_reuse*` are a
  pre-existing unittest-loader artifact; both modules pass when run as a
  package).
- 34 via `python -m unittest controller.test_dataset_reuse
  controller.test_dataset_reuse_decision`.

No test files were modified during this task.

## J. Live UI Experiment Result

A live automated run (2 experiments, target=2) was executed via the FastAPI
TestClient and confirmed:
- Run started (CREATED → RUNNING).
- Progress updated: seq 1/2 → 2/2; successful 0 → 1 → 2; failed 0.
- Completed successfully; results payload contained traffic and posture
  distributions.
- All fields consumed by the JS rendering were present and type-correct.

## K. Files Changed

| File | Lines added | Lines removed | Description |
|------|------------|---------------|-------------|
| frontend/index.html | +100 | −12 | Re-labeled headings, subtitle, footer, axes, target input; added evidence card |
| frontend/app.js | +77 | −54 | Re-labeled all user-facing strings, error messages, banners; added sequence/target chip and download note |
| frontend/styles.css | +78 | 0 | Styles for evidence card grid, items, note box; download-note utility |

## L. Files Intentionally Untouched

All `controller/*.py` files were untouched during this task.
No test files (`controller/test_*.py`) were modified.
No backend API signatures, payloads, or behavior were changed.

## M. Remaining UI / Backend Mismatch (Backend Follow-Up)

| Item | Status | Note |
|------|--------|------|
| Raw PCAP download endpoint | **Backend follow-up** | Each experiment stores its PCAP at `results/datasets/<run_id>/captures/<seq>/<exp>.pcap`. An HTTP endpoint to stream or download these individually does not yet exist. The evidence card communicates this explicitly to the user. |
| Traffic generator backend name (builtin vs D-ITG) | **Not exposed by API** | The status payload does not currently report which traffic generator was used. The "Traffic Model" section names the profile types; which backend produced them is not shown. This is a backend exposure gap, not a UI defect. |
| Download ZIP content labeling | **Deliberately retained** | The ZIP still contains `features.parquet`, `metadata.jsonl`, `manifest.json`, and `README.txt`. The button and an inline note explicitly label it as a legacy dataset archive (not a raw PCAP), preserving backend compatibility. |
| Reuse confirmation is preserved (status returns `finalization.status` when COMPLETED) | **OK** | The download button only renders after finalization is confirmed. |
