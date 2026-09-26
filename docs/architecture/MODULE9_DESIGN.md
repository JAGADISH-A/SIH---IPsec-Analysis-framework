# MODULE 9 — DESIGN: STRONGSWAN / TOPOLOGY REUSE BETWEEN DATASET SAMPLES

**Constraint honored: DESIGN + TEST PLAN only. NO implementation. NO commit. NO push.**
Grounded in this repo's actual code (`/home/jagan/ipsec-testbed`). No live testbed is
available in this environment; every claim about speedups is qualitative and explicitly
deferred to the user's real testbed.

---

## 1. Current execution flow (authoritative, from code)

Topology lifecycle fact (verified): **containerlab topology is a function of `mode`
ONLY**, not `address_family`.

- `topology/executor.py:40` `topology_file(mode)` → exactly **two** containerlab defs:
  `topology/tunnel/ipsec.clab.yml` and `topology/transport/ipsec.clab.yml`
  (verified on disk: exactly 2 `.clab.yml`).
- `controller/topology.py` `TOPOLOGIES` is keyed `[mode][address_family]` returning the
  same physical containers (`gw-a`/`gw-b` for tunnel; `host-c`/`host-d` for transport) —
  both v4 and v6 variants reference **identical node sets** with both proto addresses
  already assigned at deploy (`exec:` lines do `ip addr add …` for BOTH `10.10.x` and
  `2001:db8:x` on the same `eth1`).
- `executor.py:95` `reset_and_deploy(mode)` = `destroy(mode)` (executor.py:70) +
  `deploy(mode)` (executor.py:83), using `containerlab destroy --cleanup` /
  `containerlab deploy`.
- **`address_family` is config-only**: it changes the generated strongSwan/swanctl
  configuration (traffic selectors, transport IPs, ESP/ike selectors choose v4 vs v6
  addressing), the `initiate_ipsec`/`verify_ipsec` swanctl target + verification
  expectations, the capture-facing container/interface (`capture_facing(mode, family)`,
  executor.py:37), and the traffic runtime (`runtime(mode, family)`, traffic.py).
  It NEVER changes the `.clab.yml`.

Pipeline for one dataset sample (campaign.py `execute_trial_pipeline`):
```
reset_and_deploy(mode)                 # destroy containerlab + fresh deploy  (campaign.py:136)
load_generated_configs(config)         # swanctl --load-conns --file <generated> (campaign.py:139)
initiate_ipsec(mode, address_family)   # swanctl --initiate --child (executor.py:214→campaign.py:138)
verify_ipsec(mode, address_family)     # swanctl --list-sas: IKE ESTABLISHED + CHILD INSTALLED + ESP/mode/family (campaign.py:139, executor.py:329)
test_connectivity(mode, address_family)
start_capture(...)                     # tcpdump, esp filter, <experiment_id>.pcap + .done marker (campaign.py:154)
run_traffic(traffic_cfg)               # 30s strongSwan's DEFAULT_DURATION (traffic.py:17 → campaign.py:111)
stop_capture(...)                      # wait flush marker (campaign.py:184)
copy_capture(...)                      # /tmp/<experiment_id>.pcap → pcap_path (campaign.py:185)
extract_features(pcap_path)            # per-experiment feature extraction (features.py:219)
persist/cleanup
```
Topology is confirmed destroyed+redeployed **per sample**: `run_attempt` → full pipeline
per dataset sample, and every `execute_trial_pipeline` starts with `reset_and_deploy`.

---

## 2. Topology identity

Because the `.clab.yml` differs **only by mode**:
```
topology_identity  = mode                     # "tunnel" | "transport"  (the clab def)
config_identity = (
    mode, address_family, esp_encryption, esp_integrity, esp_dh_group,
    pfs, ike_encryption, ike_integrity, ike_dh_group
)
```
- Same `mode` → same container graph → **containers can be reused**.
- `address_family` + all crypto fields are **config-only** → reload the strongSwan config.

Consequently reuse identity key for the executor's cache:
**`reuse_key = mode`** (physical), with per-sample verification pinning the negotiated SA to
the sample's full `config_identity`.

---

## 3. Reuse decision rule (additive, executor-side)

```
def would_reuse(prev_sample_meta, next_sample):
    if prev is None:                        return False   # nothing deployed yet
    if next.mode != prev.mode:              return False   # different clab def → fresh
    return True                             # config-only reload in place
```
- `tunnel+ipv4 → tunnel+ipv4`: **reuse** (reload+terminate+initiate).
- `tunnel+ipv4 → tunnel+ipv6`: **reuse** (same clab; family is config-only). Verify the
  new family's SA (v6 selectors, `verify_ipsec` with `address_family=ipv6`).
- `tunnel+ipv4 → transport+ipv4`: **NO reuse** (different mode → destroy+deploy).

---

## 4. StrongSwan reset procedure (config-only transitions)

Required seam (BOTH are executed BEFORE loading the new config); **never** just
`swanctl --load-conns` over live state (that alone leaves stale CHILD SAs):

1. Teardown current CHILD SAs: `swanctl --terminate --child <name>`
   (repeat per known child; terminate all active CHILD).
2. Teardown the IKE SA: `swanctl --terminate --ike <name>` (or `swanctl --terminate --all`
   as the belt-and-suspenders catch-all to clear any residual SAs).
3. Optionally `--unload-conns` first, then load the new generated file:
   `swanctl --load-conns --file /<new-generated>.conf` (replaces the previous conn defs).
4. Initiate: `swanctl --initiate --child <conn-name>` (executor.py:214 path).
5. Verify via the EXISTING `verify_ipsec(mode, family)` (executor.py:329) → asserts IKE
   ESTABLISHED, CHILD INSTALLED, expected proposal/mode/family — proves the old SA is gone
   and the new one matches the sample.

Why step 1–2 matter (the "old SA must not survive" requirement): `--load-conns` only
**defines** conns; it does not terminate active SAs. An ESP algo / DH / PFS / family
transition with an open CHILD SA would silently keep the OLD SA alive and the new config
would not be exercised — wrong dataset evidence. `--terminate` on CHILD then IKE, then
reload, guarantees no stale negotiated SA.

**Ordering refinement** (safety first, speed second):
- Config-only (mode same) → SAME process, terminate+reload+initiate+verify. No deploy.
- If `mode` differs → destroy+deploy (full, unchanged) — this is the truth.
- If any terminate/reload/initiate/verify step raises → fall back to the FULL
  `reset_and_deploy(mode)` pipeline (module-level fallback, §9).

---

## 5. Capture isolation (guarantee: pcap(sample N) ≠ pcap(sample N+1))

Current primitive already isolates per experiment: each sample writes its own pcap at
`/tmp/<experiment_id>.pcap` with an ESP capture filter on the family-specific facing
container (`capture_facing(mode, family)`), stop waits for the `.done` flush marker,
copy copies ONLY that run's pcap, and `extract_features` reads that per-experiment path.

Under reuse the boundaries must remain airtight:
- `stop_capture(N)` MUST fully complete (flush `.done`) **before** `start_capture(N+1)`.
- The StrongSwan reset (terminate+reload+initiate) for N+1 must happen BEFORE
  `start_capture(N+1)` so the NEW sample's ESP shows only in ITS pcap.
- Per-sample remote_path = `/tmp/<experiment_id>.pcap` is ALREADY unique per sample
  (experiment_id is per sample), so the pcap files cannot collide even under reuse.
- The capture filter is `"esp"` — the SA reset happens outside any capture window, so no
  post-reload traffic from sample N can land in N+1's pcap (N's traffic ended at
  `stop_capture(N)`).

Guarantee is therefore structural (unique path + ordered start/stop + reset before start),
independent of whether containers were reused.

---

## 6. Failure handling under reuse (no silent success)

Rules:
- Any failure in terminate/reload/initiate/verify on the reuse path → **fresh full
  deploy** fallback (destroy+deploy, load, initiate, verify, connectivity) and re-run the
  SAME sample on the clean topology.
- Sample is recorded PASS only if the final (post-fallback) full pipeline passes the same
  success criteria (connectivity PASS + IPsec verify PASS + traffic PASS + features
  extracted). This matches the existing dataset retry semantics: `run_attempt` re-invokes
  the execution per attempt and marks FAILED otherwise — a failed reuse transition never
  silently flips a trial to PASS.
- If the executor is interrupted mid-reset, the `.done`/artifact state is partial; the
  dataset run's resume logic must treat a half-reset as "topology state unknown".

---

## 7. Resume / interrupted-attempt compatibility

- The executor persists per-sample state but **NOT container presence**. On resume (or any
  process restart) we **cannot assume the clab containers still exist**.
- Rule: **first attempt after a resume/interrupt → full fresh deploy** (reuse eligibility
  starts at `False`). A sample mid-reset is discarded and re-run, exactly like an
  interrupted fresh attempt today.
- Do not build a persisted "containers up" flag; it cannot be trusted across process
  restarts. Let a fresh deploy be the source of truth after resume.

---

## 8. Dataset planner compatibility (unchanged planner)

Planner (dataset_planner.py) orders samples via `enumerate_candidates` →
mode → family → crypto sweep (`for mode in MODES: for family …`), i.e. consecutive samples
generally share `mode` (same outer loop) and differ in family/crypto **within a mode**.
That is exactly the reuse-friendly adjacency: many consecutive pairs are
config-only and reusable. Transitions that change mode remain full redeploys at their
(rare) boundaries.

**Do NOT reorder the planner.** If future planner orders create more mode-boundaries
(hence fewer reuse opportunities), that is a documented future optimization, not a change
made here.

---

## 9. Performance-impact model (qualitative ONLY)

- **Costs eliminated by reuse (per config-only transition):** `containerlab destroy
  --cleanup` + `containerlab deploy` + topology converge for that sample. These are the
  dominant non-traffic, non-IPsec costs (Module-8 simulated profile shows `topology/redeploy`
  per sample as a large fixed block alongside the fixed 30s traffic stage).
- **Costs that remain:** config generation, SA terminate/reload/initiate + SA verify,
  connectivity probe, capture start/stop/copy, traffic (fixed 30s), feature extraction,
  persistence. These are unchanged.
- **Module-8 numbers are SIMULATED (fake clock)** and are NOT evidence of speedup. No
  quantitative claim is made. Real validation requires the user's live containerlab/
  strongSwan testbed (see §14).

---

## 10. Proposed architecture (smallest clean seam, additive)

New module `controller/reuse.py` (pluggable, no executor rewrite; campaign passes an
optional target through the existing seam style):

```
class TopologyReuseManager:
    def __init__(self, executor_ops, verify, initiate, log): ...
    def can_reuse(self, prev, next_sample_meta) -> bool      # mode==mode
    def reset_and_reinit(self, mode, config, family) -> bool # terminate→reload→initiate→verify
    def ensure_clean(self, mode):                            # fallback: reset_and_deploy(mode)
```

Wiring: `campaign.execute_trial_pipeline(..., reuse=None)` — when `reuse is None`, call
sites behave byte-identically (default additive seam, mirrors the timing module's
pattern). When provided, before `reset_and_deploy`, the pipeline asks
`reuse.can_reuse(prev, sample)`: if True → skip `reset_and_deploy`, call
`reuse.reset_and_reinit(...)`; on failure → `reuse.ensure_clean(mode)` then continue with
the normal post-deploy steps. All post-deploy stages (load/initiate/verify/…remain in
campaign and are shared by both paths.

This keeps ALL reuse logic in one additive module + one optional parameter; no logic
duplicated, no production default behavior changed.

---

## 11. Transition decisions matrix

| transition | clab reuse? | action |
|---|---|---|
| tunnel+v4 → tunnel+v4 | YES | terminate→reload→initiate→verify |
| tunnel+v4 → tunnel+v6 | YES (family=config) | terminate→reload(v6)→initiate→verify(v6 SA) |
| tunnel+v4 → transport+v4 | NO | destroy+deploy(transport) |
| AES-128-CBC → AES-256-CBC (same mode) | YES (config-only) | terminated reload+initiate; strongSwan renegotiates new proposal |
| DH2048 → DH3072 (same mode) | YES (config-only) | reload+initiate; new DH exchanged at re-init |
| PFS off→on | YES (config-only) | terminate+reload with pfs=yes → initiate; verify PFS new-CHILD |
| ESP-GCM → ESP-CBC | YES (config-only) | terminate+reload+initiate; verify new proposal |
| IKE v2 only / ESN / send_cert (config-only) | YES | terminate+reload+initiate+verify |
| anything where mode differs | NO | full destroy+deploy |

All config-only transitions require the SA-termination-first procedure (§4), guaranteeing
the new proposal is actually negotiated (old SA cannot persist).

---

## 12. Security isolation requirements

Reuse is allowed ONLY when the negotiation is pinned to the sample's full identity:
- Every reuse path does terminate(CHILD+IKE) → reload → initiate → verify, so no stale
  IKE/CHILD SA can serve the new sample.
- `verify_ipsec` (unchanged, executor.py:329) asserts ESTABLISHED + INSTALLED + the
  proposal/mode/family of the CURRENT sample — a reused but wrong-proposal state fails
  verification → fallback fresh deploy.
- No reduced-security shortcut: if a transition cannot guarantee clean termination &
  re-negotiation (e.g. terminate errors, verify mismatch, any exception), fallback = full
  fresh deploy. Reuse never bypasses a correctness gate.
- Trust rule: a sample is PASS **only** after the same verification gates that a fresh
  sample passes.

---

## 13. StrongSwan state reset details (precise commands)

Within the reused containers, for a config-only transition:

```
swanctl --terminate --child <child-name>   # 1. drop CHILD SA(s)
swanctl --terminate --ike  <conn>          # 2. drop IKE SA
swanctl --unload-conns                     # 3. clear prior conn definitions (defensive)
swanctl --load-conns --file <new.conf>     # 4. define the new conn
swanctl --initiate --child <conn-name>     # 5. establish new IKE+CHILD
verify_ipsec(mode, family)                 # 6. MUST pass → else fallback fresh deploy
```
StrongSwan/strongSwan term semantics (why this order): `--terminate` actively tears down
negotiated SAs; `--load-conns` only (re)defines connection configs. Reloading conns alone
over a live SA does NOT terminate the old CHILD/IKE and strongSwan would keep the stale
negotiated SA — precisely the hazard this design removes)Skip. Termination happens in the
IKE-v2 daemon which re-initiates cleanly on the new proposal.

---

## 14. Test plan (unit, mocks/fakes only — no live testbed)

New module `controller/test_dataset_reuse.py` (fake runner / fake clock; no containerlab):

| # | Test (Module-9 A–M cases) | Assertion |
|---|---|---|
| A | same topology (tunnel→tunnel, same family) | `can_reuse`=True; no destroy+deploy call; terminate→reload→initiate→verify sequence |
| B | mode change (tunnel→transport) | `can_reuse`=False; full deploy happens |
| C | family change within mode (v4→v6) | reuse allowed; verify called with family=ipv6 |
| D | ESP algorithm transition | terminate+reload+initiate; verify re-pins new proposal |
| E | DH transition (DH2048→3072) | reuse allowed; new DH negotiated at re-init |
| F | PFS off→on transition | reuse allowed; terminate+reload+pfs; verify new CHILD |
| G | strongSwan reload failure | falls back to full fresh deploy; sample still runs clean |
| H | stale SA (verify mismatch after reload) | reuse refused → fresh deploy fallback |
| I | capture isolation | stop(N) before start(N+1); pcap paths unique; reset-before-start ordered |
| J | resume after restart | first sample after resume = fresh deploy (reuse=False) |
| K | interrupted reuse attempt | mid-reset state → discarding sample → re-run fresh deploy |
| L | exact target semantics unchanged | planner order untouched; dataset metadata identical; no planner edits |
| M | existing regression suite | full `controller.` unittest suite still green (current 229) |

All via fake runner + fake clock (matching test_dataset_timing/test_dataset_api style),
asserting exact call sequences — no testbed, no wall-clock.

Also (moved to report, NOT executed): the existing Module-9 candidate triage folder
checks (fresh vs reused) remain GREEN silently — no algorithm/parameter/semantics
changes in Module 9.

---

## 15.Real-testbed validation (separate — requires the user's environment)

Live profiling / correctness of reuse REQUIRES the user's real testbed (containerlab +
strongSwan 6.0.3 + kernel) and is therefore explicitly out of this environment's reach:

1. Timing: wall-clock speedups (fresh vs reused) with many config-only adjacent samples.
2. SA correctness: real ESP re-negotiation across each transition kind in §11.
3. StrongSwan terminate/reload behavior on the real strongSwan 6.0.3 image.
4. Reuse under a large dataset run (feature extraction deterministic per sample).
5. Capture isolation on real captures with real inter-sample noise.

Module-8 numbers are simulated for a reason; Module-9 makes NO quantitative claim until
these run on a real testbed. The design/artifacts ship for YOUR review first.

---

## 16. Risks

| Risk | Mitigation |
|---|---|
| Old SA survives config reload (silent wrong dataset evidence) | mandatory terminate(CHILD+IKE) before reload; verify re-pins proposal |
| Family/crypto transition mislabeled as reuse-worthwhile | identity = mode only; family+crypto are config-only by inspected code |
| Reuse attempt fails mid-way → corrupt sample | any exception → full fresh deploy + re-run; PASS only after full gates |
| Resume assumes containers exist | first-after-resume = fresh deploy |
| Planner reorder temptation | explicitly out of scope; planner untouched |
| Real speedup overestimated from simulated numbers | no quantitative claim; real-testbed validation required |
| Two reuse code paths drifting (executor vs campaign) | single additive `reuse.py` + one optional param; campaign post-deploy stages shared |

---

## 17. STOP AFTER MODULE 9

- **No implementation, no commit, no push, no further modules.**
- Deliverable is this design + `MODULE9_DESIGN.md` (this file).
- Await your review / direction for the next step.
