# SIH Correlation Layer — Verification Report

Workspace: `D:\sihcorelationlayer` (standalone copy of the SIH IPsec Correlation Layer)
Scope: Phase 1-10 implemented surfaces
Method: read + static analysis + full test suite + end-to-end execution harness.
Verification is read-only: no source, test, config, or policy changes were made.

Status vocabulary:
- **PASS** — works and is proven by tests and/or a live end-to-end run.
- **PARTIAL** — functional, but with a documented limitation or deviation.
- **FAIL** — defect or unmet claim.
- **NOT TESTABLE** — no executable surface in this workspace.

---

## Overall result

| Item | Result | Evidence |
|---|---|---|
| Full test suite | **PASS** | `python -m unittest discover -s tests -t .` → `Ran 762 tests ... OK (skipped=1)` (~1.2 s). |
| The 1 skip | expected | `test_symlink_escape_blocked_or_skipped` (`tests.test_pcap_security`) — "symlinks not supported on this platform" (Windows limitation; documented in `README.md`). |
| Import integrity | **PASS** | `compileall` on all `correlation/` modules → EXIT=0; import walk of all 96 submodules → 0 failures. |
| Determinism of decision paths | **PASS** | No `random`/`uuid`/`os.system`/`subprocess`/`pickle` in executing code. Identical inputs → identical outputs. The only nondeterminism is provenance-only: `datetime.now(timezone.utc)` default in `correlation/adapters/expected_state.py:125` (`utcnow_iso()`), which is injectable and writes `materialized_at` metadata only. |
| Standalone isolation | **PASS** | No runtime imports from `D:\sihipsec` or `D:\sihcolayer`. References to those roots exist only in docstrings/provenance strings (e.g. `streaming/schema.py` contract description) and in one read-only CLI helper `verify_authoritative_contract(sihipsec_root)` (`correlation/ml/feature_contract.py:102`) that requires an explicit argument, has no default, and is invoked only from the `tools/execute_phase5.py` CLI — never at import or in the runtime pipeline. |
| Static stub scan | **PASS** | No placeholder/stub in executable paths. `raise NotImplementedError` at `correlation/execution/base.py:209` is the abstract `ProductionExecutor.operation_descriptor` default; all three executors (XDP/Firewall/StrongSwan) implement it. |
| End-to-end synthetic scenario | **PASS** | 16/16 checks passed (details below). |

## Per-phase matrix

| Phase | Surface | Status | Evidence / Notes |
|---|---|---|---|
| 1 — Discovery | (read-only inspection of `D:\sihipsec`) | **NOT TESTABLE** | No executable surface in this workspace by design (per `README.md`). |
| 2 — Canonical data contract | `correlation/models/` + serialization | **PASS** | `test_correlation_contract`, `test_identity`, `test_response_models`; JSON round-trips exercised in E2E (`StreamEvent` canonical ↔ JSONL). JSON-compatible primitives only, no pickle. |
| 3 — Expected-state materialization | `correlation/adapters/expected_state.py`, `tools/materialize_expected.py` | **PASS** | E2E materialized 6 samples from the committed fixture `tests/fixtures/datasets/dataset-20260916-231246/staging/plan.json` (mode=tunnel, posture=STRONG); `test_expected`, `test_materialize_expected`. `run_id` inferred from plan path; read-only vs. source repo. |
| 4 — Comparison engine | `correlation/comparison/` | **PASS** | E2E induced a mode MISMATCH and recorded evidence correctly. Conservative defaults honored: crypto variables stay UNKNOWN unless authoritative `observed_values` are supplied; absence only becomes MISMATCH on a COMPLETE live window; `capture_filter`/`configuration_id`/`security_posture` compress to NOT_APPLICABLE; ML outcomes never enter matches/mismatches/status. Backed by `test_comparison_engine*`. |
| 5 — ML integration layer | `correlation/ml/` | **PASS** *(see note)* | `train_nearest_centroid` → `MLInferencePipeline` → `MLResult(traffic_class=voip)` ran live in E2E with the 59-feature contract enforced (missing features fail fast). Fail-fast feature validation, confidence only when the model provides probabilities, anomaly seam stays None when unsupported. **Note (documentation dissonance, not functional):** `models/ml.py` docstrings and the `README.md` package map still describe a "placeholder / contract only; no ML" — stale text relative to the shipped deterministic stdlib-only nearest-centroid test-double in `correlation/ml/`. Functionality is real and tested; the docs wording is misaligned with the shipped demo. |
| 6 — Risk assessment | `correlation/risk/` | **PASS** | E2E: score=25, severity=HIGH, 1 deduplicated rule-tagged finding. Rule-set matches the authoritative SIH posture model (PFS-off/CBC → MEDIUM(12), modp2048+PFS → LOW(6), AES-128 never a weakness, UNKNOWN/NOT_APPLICABLE never vulnerabilities, ML capped at LOW, no CRITICAL finding alone). `test_risk_engine`, `test_risk_rules`, `test_risk_scoring`. |
| 7 — XAI explainability | `correlation/xai/` | **PASS** | E2E: `ml_explanations=1`, `finding_explanations=1`. Explains existing decisions only; never creates findings, recomputes scores, or fabricates evidence (asserted). `test_xai_engine`, `test_xai_evidence`, `test_xai_explainers`, `test_xai_models`, `test_xai_score`. |
| 8 — Dashboard backend | `correlation/api/` + `correlation/api/store.py` | **PASS** *(backend)* | E2E: `build_store(PLAN)` → 12 assessments. All `test_api_*` pass: routes, adapters, server, store, v1, pcap API + pcaps on the committed fixture. PCAP download is ID-based with path-traversal hardening. The Vite/React `dashboard/` frontend was **not** re-built in this environment (no `npm` run performed); the stdlib backend it consumes is fully tested. |
| 9 — Response & policy enforcement | `correlation/response/` | **PASS** | E2E full lifecycle: plan (1 recommendation, `requires_approval=True`) → `request_approval` → `approve(APPROVED)` → `authorize(AUTHORIZED)` → `execute_dry_run` (`DRY_RUN`, `NO_NETWORK_ACTION`, `network_effect=False`) → audit ledger SHA-256 chain verifies (8 events). State machine enforced: `authorize` before approval raises `ResponseStateError`; a terminal (SUCCEEDED) recommendation cannot execute again; executors reject unsupported action→executor pairs with NOT_SUPPORTED. Safety claims held: severity alone never exceeds REQUIRE_REVIEW; high-impact actions are approval+authorization gated; ML findings capped at REQUIRE_REVIEW; `auth_context`/role capability table verified against `authorization.py`. `test_response_*` all pass. |
| 10 — Production operations & live streaming | `correlation/execution/`, `correlation/streaming/`, `api/live.py`, `api/v1.py`, `observability/` | **PASS** | E2E: (a) control plane in DRY_RUN → `SUCCEEDED` / `WOULD_APPLY`, `network_effect=False`; (b) PRODUCTION mode without a host → `DEPENDENCY_UNAVAILABLE` (honest fail-closed, never fake success), default host is `UnavailableHost`; (c) windowing aggregated 2 ESP events into a 100 ms window; (d) `StreamEvent` canonical SHA-256 `event_identity` round-trips JSONL. Gate order verified in `gates.py`: recommendation → authorization → approval → idempotency → expiry → executor (mode + allow-list + host). `ProductionConfig.from_env` raises unless production is explicitly enabled. `test_phase10_*`, `test_stream_*`, `test_execution_*`, `test_production_executor`, `test_xdp_executor`, `test_firewall_executor`, `test_swanctl_executor`, `test_live_adapter`, `test_ml_provider`, `test_health`, `test_metrics` all pass. |

## End-to-end scenario (16/16 PASS)

A synthetic IPsec assessment was driven through the real implementation, not mocks:
Phase 3 (materialize fixture plan) → Phase 4 (`mode` mismatch vs. a near-match `ObservedState`) → Phase 5 (train deterministic centroid demo model, classify `LiveFeatureWindow` → `voip`) → Phase 6 (risk: score 25 / HIGH) → Phase 7 (finding + ML explanations) → Phase 8 (`build_store` on the fixture plan → 12 assessments) → Phase 9 (plan → approval → authorization → dry-run execute → 8-event SHA-256 audit chain verified) → Phase 10 (DRY_RUN control-plane execution → `WOULD_APPLY`; PRODUCTION without host → `DEPENDENCY_UNAVAILABLE`; windowing aggregation; stream canonical round-trip). All 16 checks passed.

Deliberately-negative checks also passed exactly as designed:
- `authorize()` before approval → `ResponseStateError` (state machine enforced).
- Executing a recommendation that already reached SUCCEEDED → `DENIED`.
- `REQUIRE_REVIEW` action + XDP executor → `NOT_SUPPORTED` (executors only accept their supported structured actions: BLOCK_FLOW/ISOLATE_FLOW for XDP & firewall, TERMINATE/RENEGOTIATE for StrongSwan).
- PRODUCTION mode with no reachable host → `DEPENDENCY_UNAVAILABLE`, `network_effect=False`.

## Known notes (no functional impact)

1. **Documentation dissonance (Phase 5):** `correlation/models/ml.py` and `README.md` still label the ML model as "contract only / placeholder, no ML", while `correlation/ml/` ships a working deterministic nearest-centroid demo. Recommend aligning docs with the shipped implementation.
2. **Provenance nondeterminism (Phase 3):** `utcnow_iso()` default timestamp is written to `materialized_at` metadata. Injectable and not part of any decision; if byte-identical artifacts are required, pass an explicit timestamp.
3. **Test suite skip:** the single skipped test is a Windows symlink-platform limitation, documented in `README.md`; all remaining 762 tests pass.

## Repository cleanliness

Verification was read-only. The only artifact produced in the workspace is this report; the temporary E2E harness lived outside the workspace (`C:\Users\Saru\AppData\Local\Temp\opencode\`) and has been removed.