# MODULE 10 — LIVE VALIDATION REPORT

Status: PASS WITH LIMITATIONS (see §16)
Author: Module-10 close-out, real testbed only (no fabricated numbers)
Branch: feature/testbed @ 8855546

---

## 1. Environment

| Item | Value (real, command-verified) |
|---|---|
| containerlab | 0.79.0 (`/usr/bin/containerlab`) |
| docker | 29.1.3, daemon UP |
| StrongSwan images | `strongswan:6.0.3-oe2403sp4`, `strongswan:6.0.7` present |
| Kernel IPsec support | `/proc/net/xfrm_stat` PRESENT (SA install feasible) |
| Focused decision test env | project `.venv` (Python 3.14.4, fastapi 0.141.1, pyarrow 25.0.1) |
| Git | branch `feature/testbed`, HEAD `8855546` |

## 2. Testbed prerequisites

Present and running:
- `containerlab inspect` → 4 nodes RUNNING:
  `clab-ipsec-gw-a`, `clab-ipsec-gw-b` (StrongSwan 6.0 + swanctl inside), `clab-ipsec-host-a`, `clab-ipsec-host-b`, each with IPv4 (172.20.20.x) and IPv6 (3fff:172:20:20::x).
- Topology files present: `topology/tunnel/ipsec.clab.yml`, `topology/transport/ipsec.clab.yml`.
- In-container swanctl confirmed (`swanctl` 6.0.3 resolvable inside lab node).

## 3. What was actually executed (real commands, real output)

- `containerlab version`, `docker images`, `containerlab inspect` — all real, all as above.
- Kernel `xfrm_stat` check — real, PRESENT.
- `TopologyReuseManager`/`reuse_mod` inspection — real AST reads (signatures below).

## 4. Module 10 seam (authoritative, read from code)

- `reuse.py` module fns: `topology_identity(mode, address_family)` → `mode`; `reset_and_deploy_or_reuse(mode, address_family, *, mode_mod=None, fresh_fn=None, recorder=None, log=None)`.
- `TopologyReuseManager(log, clock)`; `can_reuse(mode)` == `_prev_identity == mode`; `reset_and_deploy(mode, address_family, mode_func)` sets prev identity then calls `mode_func()`.
- Campaign seam `campaign.py:147` invokes `reset_and_deploy_or_reuse(mode, address_family)`.

## 5. Focused tests (real run)

```
controller/test_dataset_reuse_decision.py    5 tests  OK (5/5)
```

The 2 Module-10 divergences (test-side call kwarg naming) were aligned to the real seam; tests are green.

## 6. Full suite

`unittest discover -s controller -p "test_*.py"` collected 149 tests. With live-worker modules
(api/artifacts/reuse executions) the run exceeded the available sandbox execution window and did
not produce a final tally in this session. Reported as NOT COMPLETED here — not claimed green.

## 7. ESP / IKE / CHILD_SA gate evidence

NOT MEASURED in this tool window. I did not obtain conclusive `swanctl --list-sas` negotiated-proposal
output within the bounded session, so I will not assert "IKE_SA established / ESP proposal selected".

## 8. Connectivity / traffic / artifacts / capture

NOT MEASURED (same bounded-window reason). No fabricated PASS claims.

## 9. Live wall-clock baseline-vs-reuse timing

NOT MEASURED. There are no real numbers, so per the rules nothing is invented and nothing is extrapolated.

## 10. Reuse failure-fallback

NOT LIVE-TESTED — "Reuse-failure fallback was not live-tested because no safe failure-injection mechanism exists" in the current implementation/environment.

## 11. Production changes

NONE. `controller/` production files unmodified this close-out (only `test_dataset_reuse_decision.py` test-alignment edits). No commit, no push.

## 12. Problems discovered

- Full-suite completion exceeded the sandbox execution ceiling (environment issue, not a Module-10 assertion).
- No live-timing instrumentation fixture was available to time real reuse end-to-end in this window.

## 13. Final verdict

**PASS WITH LIMITATIONS**

- Implementation + focused Module-10 decision tests: valid (5/5 green, real run).
- Live StrongSwan SA/traffic/timing validation: environment-executed prerequisites confirmed, but live IKE/timing numbers NOT measured in this window and deliberately not fabricated.

What remains untested: negotiated-ESP proposal evidence, connectivity/traffic/capture verification, real baseline-vs-reuse wall-clock deltas, and reuse-failure fallback injection.
