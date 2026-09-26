# Final Verification Report

Status: **verified**. Branch `feature/security-assessment`, HEAD `909410d`, Python 3.14.4.
This report describes the repository as it stands now. For how each defect was
found and fixed, see the historical log
[IMPLEMENTATION_STATUS_AUDIT.md](IMPLEMENTATION_STATUS_AUDIT.md).

---

## 1. Scope

An IPsec testbed that turns captured IKE/ESP traffic into security assessments.

In scope for this verification:

- The correlation/assessment library (`correlation/`, 105 Python modules).
- The dataset/ML pipeline (`controller/`) and the Phase-1-to-Phase-10 stages.
- The read-only dashboard API and its static frontend.
- Evidence registration, integrity, and the audit/governance journal.
- Repository hygiene: layout, generated files, tracked build artifacts.

Out of scope is stated explicitly in section 11. No architecture, feature, or
production logic was changed during the repository cleanup; the only source
edits were four documentation-pointer strings (section 12).

## 2. Architecture

| Layer | Location | Responsibility |
| --- | --- | --- |
| Config | `config.py`, `campaign.json`, `campaign-quality.json` | Topology and quality campaign definitions. The two default files stay at the repository root because they are the `controller.campaign` / `controller.quality` defaults. |
| Capture / orchestration | `controller/` | Dataset generation, feature windows, dataset build, ML train/infer. |
| Correlation | `correlation/` | Identity, expected/observed models, comparison, ML, risk, XAI, response, audit. |
| Evidence | `correlation/evidence_linkage.py`, `correlation/artifacts.py` | Per-window evidence references, registry, digest verification, safe PCAP serving. |
| Governance | `correlation/response/audit.py` | Append-only audit journal with a hash chain. |
| API | `correlation/api/` | Read-only dashboard API (store-backed) plus the `/api/v1` evidence, audit, and governance routes. |
| Docs | `docs/` | Architecture, verification, reports, development guide. |

Data flow: recorded or live IKE/ESP events are normalized into windows, each
window is bound to the PCAP that produced it, and every stage of the pipeline
carries those references forward into the assessment bundle.

## 3. Implemented components

- **IKE normalization** builds `ObservedState` without the `NameError` that
  previously aborted normalization on unnamed IKE_SA_INIT exchanges.
- **Real RF inference on the production path.** `correlation/ml/controller_bridge.py`
  loads the trained RandomForest and is wired into the production stage rather
  than only the standalone script. A tripwire test fails if that link is removed.
- **Evidence linkage.** `EvidenceRef` values are attached to windows, travel with
  every stage, and are recorded in the assessment bundle.
- **Evidence registry and integrity.** Artifacts are registered with SHA-256 and
  byte size; downloads verify the digest before serving; paths outside the
  evidence root are refused.
- **Governance journal.** Audit events are appended to a JSONL journal whose
  per-record `prev_hash`/`record_hash` chain is verified on load.
- **Model provenance.** Every RF result records the exact model SHA-256, feature
  contract, and training report digest.
- **Dashboard on recorded artifacts.** The store reads the real Phase-3 plan,
  real state-builder snapshots, real v2 feature windows, and real RF output.

## 4. Verified path

The end-to-end path was executed on real data, not fixtures.

- 44 windows, 308 audit events.
- All seven pipeline stages carried real PCAP evidence on 44/44 windows.
- 44 distinct per-window evidence IDs, each correctly bound to its own window.
- The registry served 270276 bytes; the SHA-256 matched the journal, integrity
  reported `valid`, and an out-of-root request was refused.

Evidence is present at every stage rather than only at the end, which is what
makes the assessment defensible after the fact.

## 5. Evidence provenance

Each RF result carries the model digest, and all 44 results agree:

```
model_sha256 = 1f31b76ebb56cba8ca91229fd1d83e3d374d4dae359c97f885c1f849d52cb938
```

That digest equals the on-disk artifact and the value recorded in
`results/ml/train_report.json`, so a result can always be traced to the exact
model that produced it.

Real evidence PCAP:

```
results/datasets/acc-eng-02/captures/0001/acc-eng-02-exp-0001-attempt-01.pcap
sha256 = bfd5c205549eedb460ede653c9458e1774245c27af01cec04219244a7551087d
```

## 6. Audit and governance

- 308 events, hash chain verified, no gaps or rewrites.
- The journal persists across restarts rather than living in memory.
- Governance endpoint returns `chain_verified=true`.
- 31 dedicated governance tests.

## 7. API

Verified against a running server started with `--phase10`:

| Request | Result |
| --- | --- |
| `GET /api/v1/health` | 200, component statuses reported |
| `GET /api/v1/audit/events?limit=2` | 200, `total=308` |
| `GET /api/v1/audit/events/{id}` | 200, includes `evidence_refs` with the real PCAP digest |
| `GET /api/v1/audit/runs` | 200 |
| `GET /api/v1/governance` | 200, `chain_verified=true` |
| Unknown audit sub-routes | 404, `unknown_route` |

The list endpoint returns a deliberately compact `_summary` projection; full
`evidence_refs` are available on the single-event endpoint. That is by design,
not a gap.

The dashboard API is read-only: `POST`, `PUT`, and `DELETE` all return 405.

Caveat: requesting `/api/v1/health` **without** `--phase10` raises
`AttributeError: 'NoneType' object has no attribute 'health'` instead of a
clean 503-style "live context not attached" response. Pre-existing, not
introduced here, and left unchanged because this task is repository cleanup.

## 8. Dashboard

The store loads recorded real artifacts, not placeholders:

- 12 assessments, 9 findings, 163 unknown observations, 1 ML classification
  disagreement, `xai_available=true`.
- Severity split: 2 HIGH, 3 MEDIUM, 1 LOW, 6 INFO.
- 11 of 12 assessments carry 20 real evidence references, each with a 64-hex
  SHA-256. The twelfth is the `unknown` failed-run case, correctly empty.
- `/api/assessments` reports the artifact sources it read, including the real
  plan and the `tunnel_v4` state and window files with their digests.

## 9. Findings

All six defects are closed:

1. IKE normalization `NameError` on unnamed IKE_SA_INIT.
2. Dashboard reading placeholders instead of recorded artifacts.
3. RF inference not on the production path.
4. No evidence registration, verification, or safe serving.
5. Audit journal not persisted.
6. RF results without exact model provenance.

Deliberate or documented, not defects:

- Nearest-centroid `model_metadata` is an intentional, separately labelled
  artifact and is not an RF provenance gap.
- The static PSK is documented lab configuration.
- Zeek live tap and Kafka are out of scope (section 11).

## 10. Known limitations

- `results/` is 1.5 GB and git-ignored with zero tracked files. Real evidence
  must be regenerated with the pipeline scripts; a fresh clone has none of it.
  The 2.5 KB test PCAP is tracked so the test suite itself is reproducible.
- The `results/` content is the only source of the real artifacts, so evidence
  verification is meaningful on a populated working tree, not on a clean clone.
- The health-endpoint caveat in section 7.
- The audit list projection is intentionally compact (section 7).
- Dataset generalization claims stay bounded by the lab data; this repository
  does not claim production traffic coverage.

## 11. Explicitly out of scope

Not present and not to be added under the current mandate: Kafka, Zeek live
integration, distributed infrastructure, secret management, and any new
feature work. The unwired alternative architectures remain documented as
such in `docs/architecture/ML_ARCHITECTURE_CONFORMANCE.md`.

## 12. Test results

```
1689 passed, 22 skipped, 10 warnings, 1708 subtests passed
in 281.57s (0:04:41)
```

- 89 test files inspected; no byte-identical duplicates.
- No tests deleted. `controller/test_config.py` and `controller/test_generator.py`
  collect zero tests but are retained `__main__` utilities referenced by
  historical commands, and both are documented as such.
- 1711 tests collected (1689 passed + 22 skipped).
- Targeted real-data and tripwire suites: 147 passed
  (evidence registration 14, evidence linkage 79, governance 31, model
  provenance 10, production path 13).
- The 22 skips are environment-dependent (Zeek/Kafka/root-only) and skip cleanly.

Repository hygiene verified alongside the suite:

- 153 tracked `*.cpython-310.pyc` files were removed from version control. They
  were stale bytecode from an older interpreter, already covered by
  `.gitignore`, and unused by Python 3.14. They remain recoverable from history.
- `out/` and the bytecode caches are now ignored; the required 2.5 KB test PCAP
  is tracked through a precise `!controller/testdata/*.pcap` exception, so the
  suite still runs on a fresh clone.
- 41 documentation and campaign files were moved, not rewritten; all moves are
  recorded as renames with identical content (`R100`) except the historical
  audit, which was edited (`R098`).
- The only source-code edits made during cleanup were four documentation-pointer
  strings in `controller/reuse.py`, `controller/dataset_artifacts.py`,
  `controller/test_dataset_reuse.py`, and `controller/test_dataset_reuse_decision.py`.
  No production logic changed.

## 13. Reproduction commands

All commands were executed as written from the repository root with the local
`.venv` (Python 3.14.4).

```bash
# full suite
.venv/bin/python -m pytest -q

# real evidence, registry, governance, provenance, production path (147 passed)
.venv/bin/python -m pytest -q \
  tests/test_evidence_production_registration.py \
  tests/test_evidence_linkage.py \
  tests/test_governance_journal.py \
  tests/test_ml_model_provenance.py \
  tests/test_ml_production_path.py

# regenerate real experiments and captures (needed on a fresh clone; writes results/)
.venv/bin/python -m controller.campaign --campaign campaign.json

# rebuild the dashboard store + static snapshot from real recorded artifacts
.venv/bin/python -m correlation.tools.execute_phase8 --plan <path-to-plan.json>

# live API: /api/v1 requires --phase10
.venv/bin/python -m correlation.api.app --phase10 --port 8795 \
  --audit-journal <journal.jsonl> \
  --evidence-root results \
  --governance-journal <governance.jsonl>
```

Note that `execute_phase8` writes `out/dashboard_snapshot.json` by default.
`out/` is a generated-output directory and is git-ignored, which is why it is
not part of the repository.

## 14. Evidence and artifact locations

| Artifact | Path |
| --- | --- |
| RF model | `results/ml/model_traffic_rf_v1.joblib` |
| Training report | `results/ml/train_report.json` |
| Real input events | `results/observed-state/live_events_full.jsonl` |
| Real evidence PCAP | `results/datasets/acc-eng-02/captures/0001/acc-eng-02-exp-0001-attempt-01.pcap` |
| Dataset plan | `results/datasets/dataset-20260924-003710/staging/plan.json` |
| Tracked test fixture | `controller/testdata/wan_side_esp_ike_sample.pcap` |
| Historical audit | `docs/verification/IMPLEMENTATION_STATUS_AUDIT.md` |
| Repository guide | `docs/development/REPOSITORY_GUIDE.md` |
