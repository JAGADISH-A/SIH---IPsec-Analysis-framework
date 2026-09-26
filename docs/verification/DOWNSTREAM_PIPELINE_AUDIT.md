# Downstream Pipeline Audit — Correlation Result → Risk → XAI → Audit → Response → Approval → XDP Action

**Architecture (current, authoritative):** the deployed application is **PASSIVE-ONLY**.

> XDP/eBPF is used for passive observation. The sensor is non-inline and receives mirrored/tapped traffic.
> XDP enforcement actions are not part of the deployed passive application architecture.

**Scope:** originally a read-only architecture/status audit of the downstream pipeline; this revision records the
follow-up change that **removed the unused XDP enforcement/action path from the application architecture** and
reclassified `correlation/execution/` as retained **test-only** machinery. The passive chain (Risk → XAI → Audit →
Response planning) is unchanged and remains authoritative.

**Test evidence baseline (audit session, full suite):** `1333 passed / 22 skipped / 0 failed / 576 subtests`
(downstream/API/execution-focused subset: `493 passed / 0 failed`). All downstream-relevant suites passed.

---

## 1. COMPONENT STATUS TABLE

| Component | Implementation | Integration | Evidence (wiring) | Status |
|---|---|---|---|---|
| **Risk Engine (Phase 6)** | **Full** — `correlation/risk/`: `engine.py` (`RiskEngine.assess`), `policy.py` (`RiskPolicy`: weights INFO0/LOW6/MED12/HIGH25/CRIT40, caps category30/score100, severity bands, dedup, `ml_handling` LOW-cap, `unknown_handling` never-vulnerability), `scoring.py` (deterministic bands), `rules.py` (`RULE_REGISTRY` + `RULE_TRACEABILITY` + `MISMATCH_FINDING_SPECS`: only security-relevant mismatches → findings; UNKNOWN/NOT_APPLICABLE never a vulnerability; ML findings capped informational; anomaly never → risk) | **Wired (authoritative)** — `correlation/api/store.py:276` `RiskEngine(RiskPolicy.default()).assess(...)` (Phase-8 dashboard) and `correlation/streaming/pipeline.py` (Phase-10 live path); consumed read-only, posture taken as-is (never recomputed) | `tests/test_risk_engine.py`, `test_risk_rules.py`, `test_risk_scoring.py` — PASS; `correlation/tools/execute_phase6.py` determinism (two runs byte-identical) | ✅ **Implemented + Integrated** |
| **XAI (Phase 7)** | **Full** — `correlation/xai/`: `engine.py` (`ExplainabilityEngine.explain(assessment, correlation, ml_result, evidence_refs)`), `explainers.py` (pure `explain_finding`/`explain_ml_result`), `models.py` (provenance-tagged results; explains from persisted `score_detail`), `evidence.py`, `score_explanation.py`, `templates.py` — read-only, deterministic, never alters score/severity/findings. Correlational XAI is template/phrase-based | **Wired** — `correlation/api/store.py:284` + `correlation/streaming/pipeline.py` (Phase-7 stage, explains ML classification); SHAP/model explainability (observational only, `controller/shap_analysis.py` + `controller/ml_inference.explain`, never affects risk) verified in `test_shap.py` as non-interfering | `tests/test_xai_engine.py`, test_xai_explainers/evidence/models/score/score_explanation.py — PASS; determinism in execute_phase8 | ✅ **Implemented + Integrated** (template XAI) / ✅ SHAP = separate observational surface |
| **Audit Layer (Phase 8)** | **Full** — `controller/audit.py` (append-only JSONL with fsync, event schema v1) *and* `correlation/response/audit.py` (`AuditLedger`, append-only EVENT_* constants) | **Partial** — observation events (`audit_observer.py`: TAP→TShark→`record_event`) write to `results/audit/events.jsonl` (append-only, verified on disk). **Governance events (risk/XAI/**response**) live only** in the in-memory `AuditLedger` + deterministic API store; they are NOT written to the persistent JSONL | `controller/test_audit.py`, `tests/test_response_audit.py` — PASS; `/home/jagan/ipsec-testbed/results/audit/events.jsonl` present | 🟡 **Implemented + partially integrated** (obs persisted; governance chain in-memory only) |
| **Response / Policy (Phase 9)** | **Full** — `correlation/response/`: `engine.py` (`ResponseEngine`: state machine DETECTION→RISK→RECOMMENDATION→AUTHORIZATION→APPROVAL→EXECUTION(dry-run)→RESULT, validated transitions, append-only ledger), `policy.py` + `rules.py` (severity caps, ML `REQUIRE_REVIEW` cap, high-impact approval, expiry), `planner.py`, `executor.py` (`DryRunExecutor` default), `execution/` (gates, targets, host, idempotency) | **Plan-only wired** — `pipeline.py` calls `engine.plan()` (recommendations, **no execution**); approval/authorization/execution exposed nowhere in the live API (dashboard is read-only) | `tests/test_response_engine/approval/authorization/audit/policy/planner/executor/execution_gates/execution_idempotency.py` — PASS | 🟡 **Implemented + partially integrated** (plan stage only) |
| **Analyst Approval** | **Full** — `correlation/response/approval.py` (`request_approval`/`approve`/`reject`), `authorization.py` (`authorize`, `AuthorizationContext`, role-gated) | **Not wired** — no live analyst entry point; `approve()` reached only by tests. No endpoint accepts an approval | `tests/test_response_approval.py`, `test_response_authorization.py` — PASS (state machine correct) | 🔴 **Implemented, NOT integrated** (no production caller) |
| **XDP Action (Phase 10)** — *deprecated, not deployed* | **Full but TEST-ONLY** — `correlation/execution/`: `executors.py` (`XdpExecutor`/`FirewallExecutor`/`StrongSwanExecutor`: structured ops, allow-listed targets, dry-run default), `base.py`/`gates.py` (`ExecutionControlPlane` two-layer gateway: authorization + approval gates + idempotency + allowlist + host availability, fail-closed), `host.py` (host + `UnavailableHost`), `settings.py` (`enable_production_execution` **default OFF**). The package now carries an explicit test-only/deprecation banner | **REMOVED from the application** — the `Phase10Context.execution` field, its default `ExecutionControlPlane` construction, `Phase10Context.from_settings`, and the `execution_mode`/`enable_production_execution`/`executions_recorded` summary keys have all been deleted. `correlation/api/live.py` no longer imports `correlation.execution`; no production caller exists anywhere in `correlation/` | `tests/test_execution_gates.py`, test_execution_idempotency, test_xdp_executor, test_firewall_executor, test_swanctl_executor, test_production_executor, test_phase10_integration.py — PASS | ⛔ **Not deployed** (retained test-only; no production caller by design) |

---

## 2. EXISTING DATA FLOW (real repo flow)

Deterministic, stdlib-only, no timestamps/random/network (double-run byte-identical).

```
controller/streaming (live TAP -> TShark, or fixtures)
        │  ESP/IKE observation events ──────────────► results/audit/events.jsonl   [append-only]
        ▼
correlation/streaming/pipeline.py  (Phase 10, live)
   WindowRecord -> ObservedStateBuilder -> feature window
        -> MLInferenceProvider (MLResult, optional)
        -> ComparisonEngine        (Phase 4: expected vs observed)
        -> RiskEngine.assess       (Phase 6: posture + correlation + ML-as-evidence)
        -> ExplainabilityEngine    (Phase 7: XAI, read-only)
        -> ResponseEngine.plan     (Phase 9: recommendations ONLY — no execution)
        └────────────► correlation/api/store.py  (Phase 8 dashboard bundle:
                          expected/observed/correlation/risk/xai/evidence)
```

Authoritative wiring points verified:
- `correlation/streaming/pipeline.py` — Phase 4→6→7→9.plan chained in-suite; "NEVER executes network actions".
- `correlation/api/store.py:276,284` — real RiskEngine + ExplainabilityEngine build each assessment bundle.
- `controller/audit.py` + `controller/audit_observer.py` — append-only JSONL for observations.

---

## 3. MISSING BOUNDARIES (exact disconnected interfaces)

1. **Risk → Response**: connected (pipeline `.plan`). **OK.**
2. **ResponseEngine.plan → Analyst Approval**: disconnected. `approval.request_approval`/`approve`/`reject` and
   `authorization.authorize` exist and are correct, but **no live caller** — the planning/approval/authorization/
   execute state machine is exercised only in tests. An analyst cannot approve anything through any endpoint.
3. **Approval → Authorization → Execution gateway**: **closed by design (no longer a gap).** `ExecutionControlPlane.execute_dry_run`
   (gates: authorization + approval-required + idempotency + allowlist + host availability, fail-closed) remains
   implemented and tested, but it now has **no production caller**: the `Phase10Context` no longer constructs an
   `ExecutionControlPlane` at all, and no module under `correlation/` imports `correlation.execution`. The pipeline
   still never executes network actions. This boundary is intentionally left open because the deployed application is
   passive-only; closing it would mean adding an enforcement path, which is out of architecture.
4. **XDP Action target**: **closed by design (no longer a gap).** `XdpExecutor` supports `BLOCK_FLOW`/`ISOLATE_FLOW`
   with an allow-list, but no application module accepts an action, an approval or a target, and
   `enable_production_execution` defaults to **False** (dry-run-only, fail-closed). The real XDP/eBPF sensor is a
   **passive, non-inline observer** fed by mirrored/tapped traffic; it performs no action on traffic.
5. **Governance audit → persistent ledger**: disconnected. Observation events persist (JSONL), but
   risk/XAI/response/approval events remain in the in-memory `AuditLedger` (append-only within process); they are
   not appended to `results/audit/events.jsonl`. No link between the in-memory response ledger and the on-disk
   append-only audit store.
6. **ML boundary (existing, still upheld)**: ML is consumed strictly as model evidence (a `MLResult`);
   `ml_handling` caps ML-derived severity at informational/`REQUIRE_REVIEW`; anomaly score is never converted to a
   risk contribution; SHAP stays observational and never feeds risk. (No new finding — verified intact.)

---

## 4. TEST EVIDENCE (exact counts)

- **Full suite (this session):** 1333 passed / 22 skipped / 0 failed / 576 subtests.
- **Downstream-focused subset run explicitly:** 493 passed / 0 failed across risk, XAI, response
  (engine/approval/authorization/audit/policy/planner/executor), execution gates/idempotency, firewall/swanctl/
  XDP/production executors, API adapters/routes/server/store/v1/pcap, metrics, `controller/test_audit.py`,
  `controller/test_shap.py` (SHAP non-interference).
- Component suites (all PASS): `test_risk_engine.py`, `test_risk_rules.py`, `test_risk_scoring.py`,
  `test_xai_engine.py`, `test_xai_explainers.py`, `test_xai_evidence.py`, `test_xai_models.py`,
  `test_xai_score.py`, `test_response_engine.py`, `test_response_approval.py`, `test_response_authorization.py`,
  `test_response_audit.py`, `test_response_policy.py`, `test_response_planner.py`, `test_response_executor.py`,
  `test_execution_gates.py`, `test_execution_idempotency.py`, `test_xdp_executor.py`, `test_firewall_executor.py`,
  `test_swanctl_executor.py`, `test_production_executor.py`, `test_phase10_integration.py`, `test_api_*.py`,
  `test_pcap_api.py`, `test_metrics.py`, `controller/test_audit.py`, `controller/test_shap.py`.
- Persisted artifact verified: `results/audit/events.jsonl` present (append-only observation audit).

---

## 5. FILES REQUIRING FUTURE CHANGES (only if the next milestone below is taken on)

The XDP enforcement/action path is **out of architecture** and is deliberately NOT proposed below. The retained
`correlation/execution/` package is test-only and needs no production wiring.

- `correlation/api/v1.py` / `correlation/api/routes.py` — add read-only `GET` that surfaces pending-approval
  recommendations (still no action/target acceptance).
- `correlation/response/engine.py` (+ `audit.py` sink) — close boundary 5: append governance events
  (assessment/approval) to the persistent append-only JSONL, linking the in-memory response ledger to
  `results/audit/events.jsonl`. This is a pure observability change and requires no execution plane.
- `correlation/api/live.py` — any future `GET` surface must stay read-only and passive; the `executor` health
  component has been replaced with an `xdp_sensor` component describing the non-inline passive observer.

*(Changed in this revision: `correlation/api/live.py` — removed the `execution` field, the default
`ExecutionControlPlane` construction, `from_settings`, and the execution summary keys; `correlation/api/app.py` —
removed the `phase10.execution` startup print; `correlation/execution/__init__.py` — added a test-only/deprecation
banner. Pre-existing prior-task artifacts remain: `M tests/test_phase10_integration.py`,
`?? correlation/ml/controller_bridge.py`, `?? tests/test_ml_controller_bridge.py` — untouched.)*

---

## 6. RECOMMENDED NEXT MILESTONE (one smallest boundary — NOT implemented here)

**Close boundary 5: persist the governance audit chain (read-only, no execution).**

Extend the append-only JSONL audit store so that Risk/XAI/Response *governance* events (assessment, recommendation,
approval) are appended to `results/audit/events.jsonl` alongside the existing observation events, rather than living
only in the in-memory `AuditLedger`.

Why this is the single smallest boundary:
- It is **purely additive observability** — it reuses the already-tested, already-fsync'd append-only writers in
  `controller/audit.py`; it introduces no new state machine, no executor and no network operation.
- It is fail-closed by construction: a failed append cannot produce a fabricated success, and it cannot alter any risk
  score, severity, finding, recommendation or approval decision.
- It leaves the passive architecture untouched: the pipeline stays plan-only, the dashboard stays read-only, and no
  action/approval/target endpoint is introduced.

Everything downstream (Risk→XAI→Response.plan) is already wired and authoritative, and the pipeline's design intent —
"recommendations require explicit approval; enforcement is never implicit" — is now enforced by **absence**: the
application contains no execution path to bypass. Analyst-approval read-only surfacing (§5, first bullet) is the
natural follow-up, since it too requires no execution capability.
