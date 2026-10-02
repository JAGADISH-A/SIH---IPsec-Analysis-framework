<div align="center">

# 🛡️ IPsec Sentinel

**Observation-only IPsec security assessment, built on a reproducible
Containerlab/strongSwan testbed.**

`Containerlab` `strongSwan 6.0.3` `eBPF / XDP` `TShark` `Zeek`
`Python 3.14.4` `FastAPI` `React 19` `TypeScript` `Vite 7`
`scikit-learn` `SHAP` `D-ITG 2.8.1`

</div>

---

IPsec Sentinel converts passive observations of IKEv2 and ESP traffic into
deterministic, evidence-linked security assessments. It negotiates nothing,
terminates nothing, and enforces nothing. It exists to answer one question with
defensible evidence:

> For a given IPsec tunnel, what was planned, what was actually observed, how do
> the two differ, how significant is the difference, and which evidence supports
> that conclusion?

| | |
| --- | --- |
| **Project** | IPsec Sentinel (internal codename `SIHColayer`) |
| **Domain** | IPsec / IKEv2 tunnel security assessment, network telemetry |
| **Operating model** | Passive observation only — no negotiation, termination, or enforcement |
| **Platform** | Ubuntu Linux, Docker, Containerlab, strongSwan 6.0.3, eBPF/XDP |
| **Runtime** | Python 3.14.4 (`requirements.txt`), Node.js 20.19+ / 22.12+ (Vite 7) |
| **Primary surfaces** | Read-only analytics API, advisory explanation service, React analyst dashboard |
| **Licensing** | No `LICENSE` file is present. See [License](#-license). |
| **Status** | Research-grade. Per-capability status is enumerated in [Feature inventory](#-feature-inventory). |

---

## 📖 Table of contents

| | | |
| --- | --- | --- |
| [Fundamental observation boundary](#-fundamental-observation-boundary) | [Architecture](#-architecture) | [HTTP API reference](#-http-api-reference) |
| [Status legend](#-status-legend) | [Repository layout](#-repository-layout) | [Feature and model contract](#-feature-and-model-contract) |
| [Feature inventory](#-feature-inventory) | [Testbed quick start](#-testbed-quick-start) | [Deterministic risk scoring](#-deterministic-risk-scoring) |
| [Status at a glance](#-status-at-a-glance) | [Operating the analysis services](#-operating-the-analysis-services) | [Recorded results](#-recorded-results) |
| | | [Known limitations](#-known-limitations) |
| | | [Security considerations](#-security-considerations) |
| | | [Engineering invariants](#-engineering-invariants) |
| | | [Documentation](#-documentation) · [License](#-license) |

---

## 🔬 Fundamental observation boundary

Passive IPsec metadata on the WAN side cannot establish which cipher, integrity
algorithm, Diffie-Hellman group, PFS setting, IKE version, or tunnel mode a
negotiated Security Association actually uses. This is a property of the
observation position, not an implementation shortfall.

The assessment engine is built around that constraint rather than in spite of it:

* Comparison rules **do** exist for every one of those variables. They resolve
  through `_authoritative_or_unknown()` (`correlation/comparison/rules.py:183`),
  which returns an `UNKNOWN` outcome with a recorded reason whenever no
  authoritative observed value is available.
* `UNKNOWN` and `NOT_APPLICABLE` never escalate into a vulnerability. Only a
  variable whose security relevance is explicitly registered in
  `MISMATCH_FINDING_SPECS` can raise a finding from a mismatch.
* `INSUFFICIENT_EVIDENCE` is emitted only where policy enables it, in preference
  to a guess.

Consequently, expected-state comparison remains meaningful — it compares a
planned configuration against what is genuinely observable and reports the
remainder as unverified.

```
        what was planned                    what the wire actually shows
   ┌──────────────────────┐            ┌───────────────────────────────────┐
   │  mode                │            │  ESP / AH protocol number         │ ✔
   │  address family      │            │  outer IP header version           │ ✔
   │  SPI, endpoints      │            │  SPI, src, dst                    │ ✔
   │  traffic activity    │            │  packet counts, rates, profiles   │ ✔
   │  ike.version         │            │  —                                │ ✖ UNKNOWN
   │  ike.encryption      │            │  —                                │ ✖ UNKNOWN
   │  ike.integrity       │            │  —                                │ ✖ UNKNOWN
   │  ike.dh_group        │            │  —                                │ ✖ UNKNOWN
   │  esp.encryption      │            │  —                                │ ✖ UNKNOWN
   │  esp.integrity       │            │  —                                │ ✖ UNKNOWN
   │  esp.dh_group        │            │  —                                │ ✖ UNKNOWN
   │  esp.pfs             │            │  —                                │ ✖ UNKNOWN
   └──────────────────────┘            └───────────────────────────────────┘
                    │                                       │
                    └───────────────┬───────────────────────┘
                                    ▼
                      ✖ never a finding on its own
                        ⇒ compare what is observable,
                          report the rest as unverified
```

---

## 🏷️ Status legend

Each capability below carries one label. Labels describe the behaviour of the
code in this repository, not the intent of any design document.

| Symbol | Label | Meaning |
| --- | --- | --- |
| ● | `IMPLEMENTED` | Functional code with automated test coverage and a verified execution path. |
| ◐ | `PARTIAL` | Functional across a narrower input domain than the design implies; the restriction is stated in the same row. |
| ◐ | `EXPERIMENTAL` | Executes correctly under laboratory conditions; not hardened for production. |
| ◐ | `DRY-RUN` | Computes and reports a plan; performs no real action. |
| ○ | `PLANNED` | Specified in documentation; not implemented. |

---

## 📊 Status at a glance

```
  ●  IMPLEMENTED        ◐  PARTIAL / EXPERIMENTAL / DRY-RUN        ○  PLANNED

  OBSERVATION
    tunnel lab ............. ●     transport-mode lab ....... ●
    multi-SA lab ........... ◐     strongSwan IKEv2 ......... ●
    tc/mirred mirror ....... ●     eBPF/XDP sensor .......... ●
    IPv6 ext-header ........ ○     TShark / Zeek ............ ●
    traffic profiles ....... ●     generator backends ....... ●

  DATASET & ML
    dataset generation ..... ●     feature schema v2 ....... ●
    100 ms windows ......... ●     offline/live parity .... ●
    grouped split .......... ●     random forest ........... ●
    provenance ............. ●     SHAP .................... ◐
    anomaly detection ...... ○     ML as evidence .......... ●

  ASSESSMENT ENGINE
    expected state ......... ●     observed state .......... ●
    RFC 4303 correlation ... ●     comparison (23 rules) ... ●
    risk rules (7) ......... ●     deterministic score ..... ●
    drift .................. ◐     mission context ......... ●
    chain of custody ....... ◐     evidence registry ....... ●
    governance journal ..... ●     response planning ....... ◐

  SURFACES
    analytics API .......... ●     OpenAPI document ........ ●
    Prometheus metrics ..... ●     control plane ........... ●
    explanation service .... ◐     analyst dashboard ....... ●
    auth / authorization ... ○     Kafka transport ......... ◐
```

---

## 🧩 Feature inventory

### 📡 Observation and capture

| Capability | Status | Implementation |
| --- | --- | --- |
| Containerlab tunnel lab (5 containers) | `IMPLEMENTED` | `topology/tunnel/ipsec.clab.yml`, verified by `scripts/run.sh`. |
| Containerlab transport-mode lab | `IMPLEMENTED` | IPv4 and IPv6; `topology/transport/ipsec.clab.yml`. |
| Multi-SA lab (three gateways) | `EXPERIMENTAL` | `topology/multi-sa/`, `scripts/multi-sa-testbed.sh`. |
| strongSwan IKEv2 and CHILD_SA configuration | `IMPLEMENTED` | PSK; `configs/gw-a/swanctl/`, `configs/gw-b/swanctl/`. |
| Passive `tc`/`mirred` mirroring on `gw-a eth2` | `IMPLEMENTED` | Two chained actions: in-gateway `audit-tap0` tap **and** `eth3 → sensor:eth1`. |
| eBPF/XDP sensor | `IMPLEMENTED` | Classifies `ESP`, `AH`, `IKE`, `IKE-NAT-T`, `OTHER`; generic/SKB mode (see [limitation 3](#known-limitations)). |
| XDP IPv6 extension-header traversal | `PLANNED` | Only the immediate IPv6 header is parsed (`ebpf/xdp_monitor.bpf.c:138`); ESP behind an extension header is classified `OTHER`. |
| TShark and Zeek PCAP parsing | `IMPLEMENTED` | `controller/zeek.py`, `controller/audit_observer.py`. |
| Deterministic traffic profiles | `IMPLEMENTED` | `voip`, `video`, `messaging`, `email`, `web`, `icmp` (`controller/traffic.py:51`). |
| Generator backends | `IMPLEMENTED` | Built-in and D-ITG 2.8.1, selected with `IPSEC_TRAFFIC_GENERATOR`. |

### 🤖 Dataset and machine learning

| Capability | Status | Implementation |
| --- | --- | --- |
| Planned-sample dataset generation | `IMPLEMENTED` | `controller/dataset*.py`; resumable and serialised by the testbed lock. |
| 59-feature schema, version `v2` | `IMPLEMENTED` | Canonical snapshot in `correlation/ml/feature_contract.py`. |
| 100 ms live feature windows | `IMPLEMENTED` | `ebpf/xdp_window_aggregator.py`, `controller/live_features.py`. |
| Offline and live feature parity | `IMPLEMENTED` | A single computation path; the live path is a bridge, not a re-implementation. |
| Grouped stratified dataset split (70/15/15) | `IMPLEMENTED` | Grouped by `configuration_id`; seed 7. |
| Random Forest classifier (500 trees) | `IMPLEMENTED` | `controller/train_random_forest.py`; production path bridged by `correlation/ml/controller_bridge.py`. |
| Model provenance recording | `IMPLEMENTED` | Every inference records the model SHA-256, the feature contract, and the training-report digest. |
| SHAP explainability | `EXPERIMENTAL` | Offline and on demand (`controller/shap_analysis.py`). Deliberately absent from every API and dashboard route. |
| ML-driven anomaly detection | `PLANNED` | No anomaly classifier exists; `ml.anomaly` is a registered rule without a signal source. |
| ML contribution to severity | `IMPLEMENTED` | ML output is recorded as evidence (`source=ML`) and never acts as the severity authority. |

### ⚖️ Assessment engine

| Capability | Status | Implementation |
| --- | --- | --- |
| Expected-state materialization | `IMPLEMENTED` | `correlation/adapters/expected_state.py`. |
| Observed-state construction | `IMPLEMENTED` | `correlation/models/observed.py`, `ebpf/ipsec_state_builder.py`. |
| RFC 4303 SA correlation | `IMPLEMENTED` | `correlation/sa_correlation.py`; refuses to resolve ambiguous selectors. |
| Comparison rule set (23 rules) | `IMPLEMENTED` | `correlation/comparison/rules.py`; configuration, posture, presence, activity, window containment, SPI. |
| Risk rule set (7 rules) | `IMPLEMENTED` | `correlation/risk/rules.py`; gated by `MISMATCH_FINDING_SPECS`. |
| Deterministic scoring | `IMPLEMENTED` | See [Deterministic risk scoring](#-deterministic-risk-scoring). |
| Drift-aware assessment | `PARTIAL` | Three comparable fields only: `address_family`, `esp.presence`, `ah.presence` (`correlation/drift/canonical.py:94-114`). No real drift is demonstrable from recorded data. |
| Mission-context risk | `IMPLEMENTED` | `correlation/mission/`; operator-declared asset profiles. The technical score is preserved unchanged. |
| Chain of custody per finding | `PARTIAL` | `correlation/custody/`; accurate for all findings except the drift-origin chain, which is internally inconsistent (see [limitation 7](#known-limitations)). |
| Evidence registry and integrity | `IMPLEMENTED` | SHA-256 digest and byte size per artifact; `correlation/evidence_linkage.py`, `correlation/api/pcap.py`. |
| Governance journal with hash chain | `IMPLEMENTED` | `correlation/response/audit.py`; per-record `previous_hash` and `event_hash`, verified on load, 64-zero genesis. |
| Response planning | `DRY-RUN` | `correlation/response/`; `dry-run` is the only executor type. Production execution is disabled by default. |

### 🖥️ Surfaces

| Capability | Status | Implementation |
| --- | --- | --- |
| Analytics API | `IMPLEMENTED` | stdlib `ThreadingHTTPServer`. Phase-8 `/api` plus the observable-only `/api/v1` surface. `GET`, `HEAD`, `OPTIONS` only; every mutating verb returns `405`. |
| Analytics OpenAPI document | `IMPLEMENTED` | `GET /api/v1/openapi.json`. |
| Prometheus metrics endpoint | `IMPLEMENTED` | `GET /api/v1/metrics`. |
| Testbed control plane | `IMPLEMENTED` | FastAPI; `controller/api.py` and `controller/dataset_api.py`. |
| Advisory explanation service | `EXPERIMENTAL` | `correlation/ai/`; deterministic scope gate, built-in glossary, grounded templates, optional OpenAI-compatible provider. |
| SHAP in the API or dashboard | `PLANNED` | Intentionally not wired. |
| Analyst dashboard | `IMPLEMENTED` | `sentinel-frontend/`; React 19, TypeScript, Vite 7. 13 canonical routes with legacy redirects and explicit empty states. |
| Kafka window transport | `PARTIAL` | Implemented in `correlation/streaming/`; disabled by default. The in-memory transport is the supported default. |
| Authentication and authorization | `PLANNED` | Not present on any surface. See [Security considerations](#-security-considerations). |

---

## 🏗️ Architecture

### System view

```text
                      TESTBED  (Containerlab + strongSwan 6.0.3)
 ┌───────────────────────────────────────────────────────────────────────────┐
 │  host-a ── gw-a ══[ br-wan ]══ gw-b ── host-b          sensor (passive)    │
 │  10.10.1.10   │                  │       10.10.2.10      ip_forward=0    │
 │               └ eth2 ──tc mirred─┴──> eth3 ──veth──> eth1 (sink only)     │
 │                 ├──> audit-tap0   (in-gateway tap, tshark)                │
 │                 └──> sensor ──eBPF/XDP──> JSONL journal (host-visible)     │
 └───────────────────────────────────────────────────────────────────────────┘
        │                                                  │
        │ offline path: PCAP                    live path: XDP JSONL
        ▼                                                  ▼
 ┌───────────────────────────────────────────────────────────────────────────┐
 │ TShark / Zeek ──> normalized events ──> 100 ms windows ──> 59 features      │
 │                          (controller/)  ebpf/xdp_window_aggregator.py      │
 └───────────────────────────────────────────────────────────────────────────┘
        │  ExpectedState (from plan)          ObservedState (from windows)
        ▼                                          ▼
 ┌───────────────────────────────────────────────────────────────────────────┐
 │ SA correlation (RFC 4303) ──> 23 comparison rules ──> 7 risk rules        │
 │ ──> deterministic score ──> findings + custody + evidence refs            │
 │ ──> drift (3 fields) ──> mission context ──> governance journal          │
 │                                    (correlation/)                          │
 └───────────────────────────────────────────────────────────────────────────┘
        │                          │                          │
        ▼                          ▼                          ▼
 correlation/api/            correlation/ai/          sentinel-frontend/
 analytics API (read-only)   advisory explanations    React analyst dashboard
```

### The two observation paths converge on one computation

```text
     OFFLINE PATH                                    LIVE PATH
     ────────────                                    ─────────

     PCAP files                                      XDP JSONL journal
     audit-tap0 · sensor capture                     host-visible, not copied
          │                                               │
     ┌────▼─────┐                                  ┌──────▼────────┐
     │ TShark   │                                  │ xdp_window_   │
     │ Zeek     │                                  │ aggregator.py │
     │ controller/zeek.py                          │ 100 ms windows│
     └────┬─────┘                                  └──────┬────────┘
          │  normalized events                             │
          └───────────────────┬────────────────────────────┘
                              ▼
          ┌───────────────────────────────────────────┐
          │  controller/features.py                  │
          │  ONE computation · 59 features · schema v2│
          └───────────────────┬───────────────────────┘
                              ▼
              LiveFeatureWindow   ·   dataset row
              + EvidenceRef bound to the capture
```

### Feature windowing

```text
  packets   │ │  │ │   ││  │  │ │  │ │ │  │   ││ │  │ │  │ │   │
  ──────────┴─┴──┴─┴───┴┴──┴──┴─┴──┴─┴─┴──┴───┴─┴─┴──┴──┴─┴───┴──► t
              │     │        │         │         │     │      │
              └─────┘        └─────────┘         └─────┘      └────┘
               w0           w1                 w2           w3     100 ms
                │             │                   │             │
                ▼             ▼                   ▼             ▼
           59 features   59 features         59 features   59 features
           + EvidenceRef + EvidenceRef       + EvidenceRef + EvidenceRef
```

### Assessment pipeline

```text
  ┌── PLAN ───────────────┐        ┌── OBSERVATION ──────────────┐
  │ campaigns/*.json      │        │ PCAP · XDP · 100 ms windows  │
  │ dataset planner       │        │ controller/features.py       │
  └───────────┬───────────┘        └──────────────┬───────────────┘
              │ ExpectedState                      │ ObservedState
              │ adapters/expected_state.py         │ models/observed.py
              └────────────────┬───────────────────┘
                               ▼
              ┌─────────────────────────────────────┐
              │ SA correlation — RFC 4303           │  SPI · src · dst · selectors
              │ ambiguity ⇒ refuse, never guess     │
              └────────────────┬────────────────────┘
                               ▼
              ┌─────────────────────────────────────┐
              │ 23 comparison rules                 │  MATCH · MISMATCH · UNKNOWN
              └────────────────┬────────────────────┘
                               ▼
              ┌─────────────────────────────────────┐
              │ 7 risk rules                        │  gated by MISMATCH_FINDING_SPECS
              └────────────────┬────────────────────┘
                               ▼
              ┌─────────────────────────────────────┐
              │ deduplicate → score → severity band │  caps: category 30 · global 100
              └────────────────┬────────────────────┘
                               ▼
        ┌──────────────┬───────┴────────┬──────────────────┐
        ▼              ▼                ▼                  ▼
    findings      custody chain   evidence refs     drift · mission
                                                 governance journal
```

### Evidence, custody, and the governance journal

```text
  capture file
       │  sha256 digest + byte size
       ▼
  EvidenceRegistry ─────────────────┐
       │                             │ digest verified before serving
       ▼                             ▼
  EvidenceRef                  GET /api/v1/evidence/{id}/pcap
       │                        out-of-root request ⇒ refused
       │ travels with every stage
       ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ ChainOfCustody — keyed by the (assessment_id, finding_id) pair│
  │   fact → source artifact → digest → verification state       │
  └──────────────────────────────────────────────────────────────┘
       │
       ▼
  GET /api/v1/assessments/{id}/findings/{fid}/explanation
  GET /api/v1/findings/{fid}/explanation?assessment_id=
```

```
  governance journal — append-only JSONL, hash-chained

  genesis
  previous_hash = 0x000…000  (64 zeros)
        │
        │  previous_hash = H(event 1)
        ▼
  ┌──────────────┐
  │   event 1    │──► event_hash = H(canonical event 1 ‖ previous_hash)
  └──────┬───────┘
         │  previous_hash = H(event 1)
         ▼
  ┌──────────────┐
  │   event 2    │──► event_hash = H(canonical event 2 ‖ previous_hash)
  └──────┬───────┘
         │  previous_hash = H(event 2)
         ▼
  ┌──────────────┐
  │   event n    │
  └──────────────┘

  chain verified on load ⇒ tamper-evident, not tamper-proof
```

### Data-flow guarantees

1. **Observation is passive.** No stage of the pipeline configures, negotiates,
   or terminates a Security Association. `gw-a` is the authoritative *observation
   point*, not an enforcement point.
2. **Evidence is carried, not reconstructed.** Each feature window is bound to the
   capture that produced it, and that reference propagates through every
   subsequent stage into the assessment bundle. Every finding carries a validated
   `rule_id` and `evidence_type`; backing `EvidenceRef` values are attached
   wherever the pipeline holds an artifact to cite, and `UNKNOWN` is returned in
   preference to fabricating one.
3. **Unknown is a first-class outcome.** An absent observation yields `UNKNOWN` or
   `INSUFFICIENT_EVIDENCE` — never a substituted value, and never an inflated
   severity.
4. **Determinism is enforced by test.** Identical inputs produce identical scores,
   severities, findings, and bundles across the comparison engine, the API store,
   and the custody builder.
5. **The analytics surface cannot mutate.** `POST`, `PUT`, `PATCH`, and `DELETE`
   return `405` on every path, including unrecognised ones, with an
   `Allow: GET, HEAD, OPTIONS` header.

---

## 🗂️ Repository layout

### Layer view

```text
  ┌──────────────────────────────────────────────────────────────┐
  │  CAPTURE          controller/          ebpf/                 │
  ├──────────────────────────────────────────────────────────────┤
  │  PIPELINE         controller/          dataset → ML          │
  ├──────────────────────────────────────────────────────────────┤
  │  ASSESSMENT       correlation/         expected → observed  │
  │                                     → risk                 │
  ├──────────────────────────────────────────────────────────────┤
  │  SURFACES         correlation/api     correlation/ai        │
  │                    sentinel-frontend/                       │
  ├──────────────────────────────────────────────────────────────┤
  │  LAB              topology/  configs/  scripts/  images/    │
  ├──────────────────────────────────────────────────────────────┤
  │  PROOF            tests/  demo/analytics/  docs/            │
  └──────────────────────────────────────────────────────────────┘
```

### Tree view

```text
.
├── controller/              Capture orchestration, dataset and ML pipeline, control plane
│   ├── features.py          The single feature computation (59 features)
│   ├── live_features.py     Live-record bridge (no second implementation)
│   ├── dataset*.py          Dataset run lifecycle, planner, artifacts, quality
│   ├── train_random_forest.py / ml_inference.py / evaluate_model.py
│   ├── shap_analysis.py     Offline explainability (not served)
│   ├── api.py               FastAPI testbed control plane
│   └── zeek.py, audit.py    Capture parsing and journaling
├── correlation/             Assessment engine and read-only surfaces
│   ├── models/              ExpectedState, ObservedState, LiveFeatureWindow
│   ├── adapters/            Plan to ExpectedState materialization
│   ├── sa_correlation.py    RFC 4303 selector with ambiguity refusal
│   ├── comparison/          23 rules and the comparison engine
│   ├── risk/                7 rules, policy, scoring, findings
│   ├── drift/               Baselines, canonical fields, comparison, registry
│   ├── mission/             Operator asset profiles and context
│   ├── custody/             Per-finding chain of custody
│   ├── ml/                  Feature contract, inference, production bridge
│   ├── response/            Planner, policy, approval, dry-run executor, audit
│   ├── evidence_linkage.py, artifacts.py
│   ├── api/                 stdlib analytics API: /api, /api/v1, OpenAPI
│   ├── ai/                  Advisory explanation service (stdlib, scope gate)
│   └── streaming/           Window transport (memory default, Kafka optional)
├── ebpf/                    XDP program, userspace loader, window aggregator,
│                            observed-state builder
├── topology/                tunnel/, transport/, multi-sa/ Containerlab definitions
├── configs/                 strongSwan swanctl configuration: gw-a/, gw-b/,
│                            transport/; plus mission/ asset profiles
├── campaigns/               Named experiment plans
├── scripts/                 install / run / status / stop lifecycle, demos
├── gateway-image/ host-image/ transport-host-image/     Container images
├── sentinel-frontend/       Current analyst dashboard (React + TypeScript + Vite)
├── frontend/                Superseded static dashboard, served by controller/api.py
├── tests/                   107 test modules
├── demo/analytics/          Committed offline demonstration fixture
├── vendor/ditg/             D-ITG 2.8.1 build provenance
└── docs/                    architecture/, development/, reports/, verification/
```

`results/` and `out/` are generated locally and are intentionally untracked. The
committed fixture is `demo/analytics/`, with checksums recorded in
`demo/MANIFEST.sha256`.

---

## 🚀 Testbed quick start

The full lifecycle is scripted. From the repository root:

```bash
./scripts/install.sh   # host prerequisites, images, eBPF build, topology validation
./scripts/run.sh       # deploy or converge, then full verification   [requires root]
./scripts/status.sh    # concise health report, at any time
./scripts/stop.sh      # teardown via the deployment destroy path   [requires root]
```

`run.sh` and `stop.sh` recreate `br-wan` and invoke Containerlab, and therefore
require root. `install.sh` and `status.sh` run unprivileged.

```
  install.sh                     run.sh                     status.sh        stop.sh
  ──────────                     ──────                     ──────────        ───────
  prerequisites                  deploy / converge          health report    teardown
  container images               10 verification checks     any time         destroy path
  eBPF build                     converge if healthy
  topology validation
        │                            │                          │               │
        └────────────────────────────┴──────────────────────────┴───────────────┘
                                          br-wan · Containerlab
```

### 🖧 Nodes

| Node | Role | Addresses |
| --- | --- | --- |
| `host-a` | LAN-A endpoint | `10.10.1.10/24`, `2001:db8:1::10/64` |
| `gw-a` | Gateway; authoritative observation point | `10.10.1.1/24`, `192.168.100.1/24`, `2001:db8:1::1/64` |
| `gw-b` | Gateway | `192.168.100.2/24`, `10.10.2.1/24`, `2001:db8:2::1/64` |
| `host-b` | LAN-B endpoint | `10.10.2.10/24`, `2001:db8:2::10/64` |
| `sensor` | Passive observation sink | mirrored feed on `eth1`; `ip_forward=0` |

```
     LAN-A                    WAN                          LAN-B
  ┌─────────┐          ┌───────────────┐             ┌─────────┐
  │ host-a  │ eth1      │               │      eth1   │ host-b  │
  │.10.1.10 ├──────────► gw-a ═══ br-wan ═══ gw-b ├─────────►.10.2.10
  │         │      eth2 │  .10.1.1      │  .100.2   │         │
  └─────────┘          │  .100.1       │  .10.2.1  └─────────┘
                       └───────┬───────┘
                               │ eth3 (veth, copy-only mirror)
                               ▼
                        ┌─────────────┐
                        │   sensor    │  ip_forward=0
                        │ eth1 sink   │  NOT a br-wan member
                        │ eBPF / XDP  │
                        └─────────────┘
```

`br-wan` is a root-namespace bridge carrying **only** `gw-a eth2` and `gw-b eth2`.
The sensor is never a `br-wan` member. `br-wan` must exist before
`containerlab deploy`, so deployment and teardown must always proceed through
`scripts/deploy-ipsec.sh` rather than a bare `containerlab deploy`.

### 📋 Prerequisites

* Ubuntu (Linux), Docker with a running daemon, Containerlab.
* `clang`/`llvm`, `bpftool`, `libbpf`/`libelf`/`libz`, `make` for the eBPF monitor.
* `python3` with `pyyaml`, for topology validation.
* Python 3.14.4 with `requirements.txt`, for the analysis pipeline.
* Node.js 20.19+ or 22.12+ (the Vite 7 requirement), for `sentinel-frontend/`.

`install.sh` reports each prerequisite as `[OK]`, `[WARN]`, or `[FAIL]`, and exits
non-zero only for a missing **required** item. It reports only; it does not install
system packages.

### 📦 Container images

```bash
docker build -t ipsec-test-gateway:6.0.3     ./gateway-image
docker build -t ipsec-test-host:24.04        ./host-image
docker build -t ipsec-transport-host:24.04  ./transport-host-image
```

The gateway image is based on `openeuler/strongswan:6.0.3-oe2403sp4` and adds
`tcpdump`, `tshark`, and the observation helpers.

### 🪞 Observation path

```text
gw-a eth2 (ingress + egress) ── tc mirred (two chained actions)
        ├──> bridge tap "audit-tap0"        (tshark -i audit-tap0)
        └──> eth3 ── veth ──> sensor eth1    (tcpdump, eBPF/XDP)
```

```bash
# Mirror filters are attached to the ingress/egress parents of eth2.
docker exec clab-ipsec-gw-a tc filter show dev eth2 ingress | grep mirred
docker exec clab-ipsec-gw-a tc filter show dev eth2 egress  | grep mirred

# Forensic tap.
docker exec clab-ipsec-gw-a tshark -i audit-tap0 -c 20

# Live XDP journal (generic/SKB mode is the verified path on veth).
docker exec clab-ipsec-sensor /usr/sbin/xdp_monitor eth1 --json
```

> **Note.** `tc filter show dev eth2` without an `ingress` or `egress` suffix
> reports only the root qdisc and will not list `clsact` mirrors. `run.sh` and
> `status.sh` already query the correct parents.

### 🔐 IPsec configuration

From `configs/gw-a/swanctl/conf.d/ipsec.conf`; `gw-b` mirrors it with swapped
addresses and identities.

```text
connection "gw-a-to-gw-b"
  version            = 2
  local_addrs        = 192.168.100.1        remote_addrs = 192.168.100.2
  local  { auth = psk, id = gw-a }          remote { auth = psk, id = gw-b }
  proposals          = aes256-sha256-modp2048
  children { "lan-a-to-lan-b"
      local_ts = 10.10.1.0/24              remote_ts = 10.10.2.0/24
      esp_proposals = aes256gcm16-modp2048
      start_action = trap                  # established on demand, not at boot
  }
```

Because `start_action = trap`, the Security Association is established when
traffic triggers it. To establish it explicitly:

```bash
docker exec clab-ipsec-gw-a swanctl --initiate --child lan-a-to-lan-b
docker exec clab-ipsec-gw-a swanctl --list-sas      # expect ESTABLISHED
```

### ✅ Automated verification

`scripts/run.sh` performs the following checks and exits non-zero if any
required check fails.

| # | Check |
| --- | --- |
| 1 | All five containers are running. |
| 2 | `gw-a eth1/eth2/eth3`, `audit-tap0`, and `sensor eth1` are present. |
| 3 | At least one `mirred` action per direction on `gw-a eth2`. |
| 4 | `swanctl --list-sas` reports `ESTABLISHED` for `lan-a-to-lan-b`. |
| 5 | XFRM states and outbound tunnel policies are installed. |
| 6 | `host-a → host-b` and `host-b → host-a` connectivity with zero packet loss. |
| 7 | Mirrored packet counts on `gw-a eth2` and `sensor eth1` agree. |
| 8 | `audit-tap0` observes live ESP frames. |
| 9 | `sensor ip_forward=0` and the sensor is absent from `br-wan`. |
| 10 | XDP ESP events on `sensor eth1` in generic/SKB mode; non-fatal when absent. |

> **Note — intentional dataplane behaviour.** Both gateways forward LAN traffic
> through the tunnel and also emit a plaintext copy onto the WAN, because static
> `main`-table routes coexist with strongSwan's policy-routing table 220. Receivers
> discard the plaintext at XFRM ingress, so connectivity measurements remain
> exact. The plaintext copy is mirrored to the sensor in full and surfaces as
> `OTHER` for ICMP. This is by design and is not a defect introduced by the
> observation work.

---

## ⚙️ Operating the analysis services

Configuration is environment-first. `.example.env` contains no secrets and every
value in it is safe by default.

```bash
cp .example.env .env
```

### Service map

```text
  browser
     │
     ├──────────────────────── :5173   sentinel-frontend
     │                                   React analyst dashboard, no server state
     │
     ▼
  :8081   correlation.api.app          stdlib · read-only
     │      ├── /api                    Phase-8 surface
     │      ├── /api/v1                 observable surface
     │      ├── /api/v1/metrics         Prometheus exposition
     │      └── /api/v1/openapi.json    maintained contract
     │
     ├──────────────────────── :8082   correlation.ai.service
     │                                   stdlib · advisory
     │                                   ├── /ai/health
     │                                   ├── /ai/glossary
     │                                   └── /ai/explain   ← the only POST
     │
     └──────────────────────── :8000   uvicorn controller.api:app
                                         FastAPI · experiment control
                                         ├── /experiments/*
                                         └── /dataset-runs/*   shared lock
```

### 📊 Analytics API

```bash
python -m correlation.api.app --phase10        # binds 127.0.0.1:8081 by default
```

Recognised environment variables: `ANALYTICS_API_HOST`, `ANALYTICS_API_PORT`,
`ANALYTICS_API_ALLOWED_ORIGINS`, `ANALYTICS_API_CAPTURE_FEED`. The `--host`,
`--port`, and `--allowed-origins` flags take precedence over the environment. The
8081 default keeps the service clear of the control plane on 8000.

### 💬 Advisory explanation service

```bash
python -m correlation.ai.service                # binds 127.0.0.1:8082
```

Every question is classified by a deterministic scope gate before any other
processing. Out-of-scope questions are refused with a stated reason; terminology
questions are answered from the built-in glossary; in-scope questions are answered
from a grounded template and are passed to an OpenAI-compatible provider only when
one is configured. The service has no route that alters an assessment, score,
finding, evidence record, or journal entry.

```
  question
     │
     ▼
  ┌──────────────────────┐   out of scope      ⇒ refusal with a reason
  │  deterministic       │──────────────┐
  │  scope gate          │              │
  └──────────┬───────────┘              │
             │ in scope                 │
             ▼                          │
     ┌───────────────┐                  │
     │ intent?       │                  │
     └───────┬───────┘                  │
   terminology│      decision           │
             ▼          ▼                ▼
        glossary    grounded        OpenAI-compatible
                      template       provider — only if
                                      configured; never
                                      decides, writes, or
                                      mutates anything
```

### 🎛️ Testbed control plane

```bash
uvicorn controller.api:app --host 127.0.0.1 --port 8000
```

`controller/api.py` defines the application object; it contains no `__main__`
block and does not invoke `uvicorn` itself.

### ▶️ Running both services together

`scripts/serve-backend.sh` is the supported entry point for concurrent
operation. It starts the analytics API (`127.0.0.1:8081`, with `--phase10
--no-static`) and the control plane (`127.0.0.1:8000`), owns their process IDs,
and shuts both down cleanly. The testbed lifecycle scripts deliberately do not
manage server processes.

### 🖥️ Analyst dashboard

```bash
cd sentinel-frontend
npm ci
npm run dev          # or: npm run build && npm run preview
npm run typecheck
npm run verify       # full smoke-harness suite
```

`sentinel-frontend/` is the current dashboard. `frontend/` is a superseded
vanilla-JS interface, retained because `controller/api.py` still serves it at `/`
and `/static`.

#### Dashboard routes

`sentinel-frontend/src/router.tsx` defines 13 canonical routes. Canonical URLs
name product concepts rather than implementation modules; legacy
implementation-shaped URLs remain functional as redirects so that existing
bookmarks and integrations continue to resolve.

| Canonical path | Purpose |
| --- | --- |
| `/` | Overview and packet workspace |
| `/assessments`, `/assessments/:assessmentId` | Assessment list and detail |
| `/findings`, `/findings/:assessmentId/:findingId` | Cross-cutting finding list; finding detail keyed by the `(assessment, finding)` pair |
| `/reports` | Report surface |
| `/run`, `/run/:jobId` | Start a testbed experiment and observe its progress |
| `/activity` | Analyst console and live activity feed |
| `/evidence` | Evidence registry browser |
| `/explainability` | Explainability view |
| `/analysis` | Machine-learning view |
| `/system` | Component and pipeline status |

```
  / ──────────────────────────── Overview · packet workspace
  ├── /assessments ─────────── List
  │   └── /assessments/:id ─── Detail
  ├── /findings ────────────── Cross-cutting list
  │   └── /findings/:aid/:fid  Detail — keyed by the pair
  ├── /reports ─────────────── Report surface
  ├── /run ─────────────────── Start experiment
  │   └── /run/:jobId ──────── Progress
  ├── /activity ────────────── Analyst console
  ├── /evidence ────────────── Registry browser
  ├── /explainability ──────── XAI
  ├── /analysis ────────────── Machine learning
  └── /system ──────────────── Component status

  redirects    /console → /activity        /overview → /
               /xai → /explainability      /ml → /analysis
               /experiments → /run         /experiments/:jobId → result page
```

### 🧪 Running without the laboratory

The committed fixture allows the analytics surface to be exercised without Docker,
root privileges, or network access.

```bash
./scripts/init-demo-data.sh          # copy demo/analytics/ into results/, verify, prove the store builds
./scripts/init-demo-data.sh --verify # verify only; copies nothing
./scripts/serve-backend.sh           # analytics API and control plane
```

Fixture integrity can be verified independently at any time:

```bash
cd demo && sha256sum -c MANIFEST.sha256
```

For a managed live-traffic demonstration against a full frontend stack,
`scripts/e2e-live-demo.sh` orchestrates the flow:

```bash
./scripts/e2e-live-demo.sh up          # analytics :8081, control :8000, vite :5173
./scripts/e2e-live-demo.sh health      # readiness, CORS, and feed-verdict probes
./scripts/e2e-live-demo.sh demo-start  # switch to an actively-appended live journal
./scripts/e2e-live-demo.sh demo-stop   # return to the recorded baseline
./scripts/e2e-live-demo.sh down        # stop only the servers this script started
```

The script refuses to start a second server on an occupied port and terminates
only processes it created itself.

---

## 🔌 HTTP API reference

All three services are read-only with respect to assessments. The analytics and
explanation services expose exactly one mutating-verb route, `POST /ai/explain`,
which submits a question and mutates nothing.

```
  ┌──────────────────────────────────────────────────────────────────┐
  │  POST · PUT · PATCH · DELETE   →   405 on every path             │
  │  Allow: GET, HEAD, OPTIONS                                        │
  ├──────────────────────────────────────────────────────────────────┤
  │  single exception:  POST /ai/explain  — takes a question,       │
  │                                     changes nothing              │
  └──────────────────────────────────────────────────────────────────┘
```

### 📦 Analytics API — Phase-8 surface (`correlation/api/routes.py`)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/health` | Store health. |
| `GET` | `/api/assessments` | Assessment list; accepts pagination parameters. |
| `GET` | `/api/assessments/{assessment_id}` | A single assessment bundle. |
| `GET` | `/api/assessments/{assessment_id}/{sub-resource}` | One of `expected`, `observed`, `correlation`, `risk`, `xai`, `ml`, `evidence`, `ipsec-state`. |

### 🗃️ Analytics API — `/api/v1` observable surface (`correlation/api/v1.py`, `openapi.py`)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/v1/health` | Component health and the effective CORS policy. |
| `GET` | `/api/v1/metrics` | Prometheus text exposition. |
| `GET` | `/api/v1/traffic-generator` | Traffic generator status. |
| `GET` | `/api/v1/capture/events` | Live capture event tail; experiment-gated. |
| `GET` | `/api/v1/evidence` | Evidence registry listing. |
| `GET` | `/api/v1/evidence/{evidence_id}` | A single evidence record with integrity status. |
| `GET` | `/api/v1/evidence/{evidence_id}/pcap` | Digest-verified PCAP stream. |
| `GET` | `/api/v1/runs` | Dataset run discovery. |
| `GET` | `/api/v1/runs/{run_id}` | A single run. |
| `GET` | `/api/v1/runs/{run_id}/evidence` | Evidence bound to one run. |
| `GET` | `/api/v1/runs/{run_id}/audit` | Audit events for one run. |
| `GET` | `/api/v1/audit/events` | Journal events; filterable and pageable. |
| `GET` | `/api/v1/audit/events/{event_id}` | A single journal event. |
| `GET` | `/api/v1/audit/events/{event_id}/evidence` | Evidence backing one journal event. |
| `GET` | `/api/v1/audit/runs` | Runs as recorded by the journal. |
| `GET` | `/api/v1/audit/runs/{run_id}` | A single journal run. |
| `GET` | `/api/v1/governance` | Governance events. |
| `GET` | `/api/v1/governance/{event_id}` | A single governance event. |
| `GET` | `/api/v1/assessments` | Assessment listing with provenance. |
| `GET` | `/api/v1/assessments/{id}` | A single assessment. |
| `GET` | `/api/v1/assessments/{id}/findings` | Findings for one assessment. |
| `GET` | `/api/v1/assessments/{id}/drift` | Drift comparison for one assessment. |
| `GET` | `/api/v1/assessments/{id}/findings/{finding_id}/explanation` | Chain of custody for the `(assessment, finding)` pair. |
| `GET` | `/api/v1/findings` | Cross-assessment finding listing. |
| `GET` | `/api/v1/findings/{finding_id}/explanation` | Convenience form; refuses to infer the assessment. |
| `GET` | `/api/v1/drift` | Drift overview. |
| `GET` | `/api/v1/drift/baselines` | Validated drift baselines. |
| `GET` | `/api/v1/responses/{recommendation_id}/evidence` | Evidence behind a planned response. |
| `GET` | `/api/v1/openapi.json` | The maintained OpenAPI description. |
| `GET` | `/api/v1/docs` | Human-readable route index. |

`POST`, `PUT`, `PATCH`, and `DELETE` return `405` with an
`Allow: GET, HEAD, OPTIONS` header on every path.

### 💬 Advisory explanation service (`correlation/ai/service.py`)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/ai/health` | Engine state and provider configuration status. |
| `GET` | `/ai/glossary` | Built-in terminology dictionary. |
| `POST` | `/ai/explain` | Answer one grounded question. Question length is bounded; the response is advisory. |

### 🎛️ Testbed control plane (`controller/api.py`, `controller/dataset_api.py`)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/` | Serves the legacy static dashboard. |
| `GET` | `/health` | Liveness. |
| `GET` | `/experiments/configurations` | Supported modes, address families, and algorithm sets. |
| `POST` | `/experiments` | Start one manual experiment. |
| `GET` | `/experiments/{job_id}` | Experiment status. |
| `GET` | `/dataset-runs/settings` | Configured sample ceiling. |
| `POST` | `/dataset-runs` | Create and start a dataset run; `409` if the testbed is occupied. |
| `GET` | `/dataset-runs/{dataset_run_id}` | Run state and progress. |
| `POST` | `/dataset-runs/{dataset_run_id}/resume` | Resume after a pause; rejects a changed plan fingerprint. |
| `GET` | `/dataset-runs/{dataset_run_id}/results` | Final dataset artifacts. |
| `GET` | `/dataset-runs/{dataset_run_id}/download` | Artifact download. |

Dataset runs and manual experiments share a single testbed reservation lock, so
the two can never execute concurrently.

```
       manual experiment                      dataset run
       POST /experiments                     POST /dataset-runs
                │                                    │
                └──────────────┬─────────────────────┘
                               ▼
                    shared testbed reservation lock
                    ⇒ 409 when the testbed is occupied
                    ⇒ the two can never execute concurrently
```

---

## 📐 Feature and model contract

* Schema version `v2` with **59 declared features**. Names, ordering, and the
  integer/float split are frozen in `correlation/ml/feature_contract.py` and
  re-verified against the authoritative module whenever it is importable.
* Missing values are never imputed with zeros. The adapter fails fast, rejecting
  `NaN` and infinities, booleans, strings, extra keys, and absent keys.
* The model consumes **57** features. `burst_packet_ratio` and `ike_packet_count`
  are constant across every recorded sample (`1.0` and `4` respectively) and are
  therefore excluded; the exclusion is recorded in the training report.
* An artifact's `feature_names` must equal the canonical ordering before inference
  constructs its input vector, so a reordered or stale model fails loudly rather
  than predicting against a misaligned input.
* Machine learning never sets severity. `rule_ml_classification_disagreement`
  contributes a finding only where a documented policy threshold is crossed.

```
  schema v2 · 59 declared
  ┌───────────────────────────────────────────────────────────────┐
  │  59 declared features                                        │
  │      │                                                       │
  │      ├── burst_packet_ratio  ─┐  constant across every       │
  │      └── ike_packet_count    ─┘  recorded sample ⇒ excluded   │
  │            │                                                  │
  │            ▼                                                  │
  │  57 features ──> ordering frozen ──> artifact must match     │
  │                                              │               │
  │                                              ▼  mismatch     │
  │                                        fails loudly, never  │
  │                                        predicts misaligned   │
  └───────────────────────────────────────────────────────────────┘

  validation   NaN / inf · bool · str · extra key · missing key  ⇒ reject
               missing values are never imputed with zero
```

---

## ⚖️ Deterministic risk scoring

Each enabled finding contributes its severity weight. Duplicates are removed
**before** scoring. A per-category cap bounds the contribution of any single
finding theme, a global cap bounds the total, and the result maps to exactly one
severity through disjoint bands. Identical inputs therefore always produce
identical scores and severities.

| Severity | Weight |
| --- | --- |
| `INFO` | 0 |
| `LOW` | 6 |
| `MEDIUM` | 12 |
| `HIGH` | 25 |
| `CRITICAL` | 40 |

Per-category cap: `30`. Global cap: `100`.

A mismatch produces a finding **only** for variables whose security relevance is
explicitly registered in `MISMATCH_FINDING_SPECS`. `UNKNOWN` and `NOT_APPLICABLE`
never become vulnerabilities by default, and `INSUFFICIENT_EVIDENCE` is emitted
only where policy enables it.

```
  findings ──► deduplicate ──► per-category cap 30 ──► global cap 100 ──► band
                 (before          (no single theme        (total
                  scoring)          can dominate)          bounded)

  weights      INFO 0 · LOW 6 · MEDIUM 12 · HIGH 25 · CRITICAL 40
  outcome      exactly one severity, through disjoint bands
  provenance   a mismatch becomes a finding only where the variable's
               security relevance is registered in MISMATCH_FINDING_SPECS
  non-escalation   UNKNOWN · NOT_APPLICABLE  ⇒  never a vulnerability
                   INSUFFICIENT_EVIDENCE   ⇒  only where policy enables it
```

---

## 📈 Recorded results

The figures below are drawn from artifacts and reports committed to this
repository. They describe laboratory runs against synthetic traffic and are not
production benchmarks.

### Traffic classifier

Source: `demo/analytics/ml/train_report.json`.

| Property | Value |
| --- | --- |
| Samples | 300 (212 train / 42 validation / 46 test) |
| Split strategy | Grouped, stratified, greedy by `configuration_id`; 70/15/15, seed 7 |
| Source dataset runs | `dataset-20260923-221430`, `dataset-20260924-003710` (SHA-256 fingerprinted) |
| Classes | `voip`, `video`, `messaging`, `email`, `web`, `icmp` |
| Model | `RandomForestClassifier`, `n_estimators=500`, `random_state=7`, out-of-bag scoring enabled |
| Out-of-bag score | `1.0` |
| 5-fold cross-validation accuracy / macro-F1 | `1.0` / `1.0` |

```
  300 samples ─┬─ 212 train ──┐
               ├─  42 validation ──┐   grouped · stratified · greedy
               └─  46 test ────┘   by configuration_id · seed 7
                                    │
                                    ▼
                  6 classes · deterministic generators
                  distinct, well-separated packet-size
                  and inter-arrival signatures

                  ⇒ perfect scores are expected here
                  ⇒ they characterise the pipeline,
                    not detection capability
```

> **Interpretation.** Perfect scores are expected under these conditions and do not
> constitute evidence of generalisation. Each class originates from a deterministic
> generator with a distinct, well-separated packet-size and inter-arrival signature,
> and the corpus spans six classes across two dataset runs. The reproducible
> pipeline, the grouped split, and the provenance chain are the substantive results;
> the accuracy figures are not a detection capability and should not be presented
> as one.

### End-to-end recorded path

Source: `docs/verification/FINAL_VERIFICATION_REPORT.md`. Across 44 windows and 308
audit events, all seven pipeline stages carried real PCAP evidence on 44 of 44
windows, 44 distinct per-window evidence identifiers were each bound to their own
window, and a digest-verified PCAP was served from the registry while out-of-root
requests were refused.

### Test-suite extent

107 test modules are present. The chain-of-custody work alone contributed 63
tests, with a recorded full-suite result of 1349 passed and 7 skipped at that
commit. **The suite was not executed as part of this documentation revision**, so
these counts are historical record rather than a fresh run.

---

## ⚠️ Known limitations

The following are properties of the current implementation. None is worked around
in code, and each is stated so that results are not over-interpreted.

### 📡 Observation

1. **Negotiated cryptographic parameters are not recoverable from passive
   metadata.** Cipher, integrity algorithm, DH group, PFS, IKE version, and tunnel
   mode resolve to `UNKNOWN` from the WAN side. See
   [Fundamental observation boundary](#-fundamental-observation-boundary).
2. **XDP does not traverse IPv6 extension headers**, so ESP carried behind one is
   classified `OTHER`.
3. **Native/driver XDP attachment is unavailable on veth.** Generic/SKB mode is
   the verified path; this is a virtualisation constraint rather than a code
   defect.
4. **Both gateways emit a plaintext copy of LAN traffic onto the WAN** by design.
   See the note in [Automated verification](#-automated-verification).

### ⚖️ Assessment

5. **Drift compares three fields**: `address_family`, `esp.presence`,
   `ah.presence`. No real observed drift exists in the recorded data, so drift is
   demonstrated on a controlled fixture and on the real IPv4/IPv6 pair only.
6. **Drift comparisons are not scoped to an endpoint pair.** A comparison is not
   attributed to a specific endpoint interface.
7. **The drift-origin chain of custody is internally inconsistent.** Known defect;
   see `NOVEL_FEATURE_ACCEPTANCE_REPORT.md` §7.
8. **Two served custody fields violate their own OpenAPI contract** in both
   branches. Same source.
9. **Mission asset profiles are operator declarations**, not measurements.
10. **Machine learning supplies no anomaly signal.** The `ml.anomaly` rule is
    registered without a classifier behind it.
11. **Explainability via SHAP is offline only** and is deliberately absent from the
    API and dashboard.

### ▶️ Execution and operations

12. **Response execution is dry-run only.** `dry-run` is the sole executor type;
    production execution is disabled by default and requires explicit
    configuration.
13. **Kafka window streaming is disabled by default.** The in-memory transport is
    the supported default.
14. **No authentication, authorization, or rate limiting exists on any surface.**
    See [Security considerations](#-security-considerations).
15. **No `LICENSE` file is present.** See [License](#-license).

### 📦 Packaging and documentation

16. **`scripts/start-live-analytics.sh` is not a portable entry point.** It
    hardcodes an audit-journal path and a log path under `/tmp/opencode/` and
    binds `0.0.0.0` by default. Use `scripts/serve-backend.sh`, or invoke
    `python -m correlation.api.app` directly.
17. **`scripts/init-demo-data.sh` refers to a `demo/README.md` that does not
    exist**, so the fixture's provenance and selection audit are undocumented in
    this checkout.

---

## 🔒 Security considerations

* **No authentication or authorization is implemented.** Any process able to
  reach a bound port can read every assessment, finding, evidence record, audit
  event, and governance event, and can start testbed experiments through the
  control plane. Bind to loopback and treat port reachability as equivalent to
  full disclosure.
* **The control plane sets `allow_origins=["*"]` with all methods and headers.**
  It must not be exposed on a shared or routable interface.
* **Evidence captures may contain payload data.** Downloads are digest-verified
  and confined to the evidence root, but the bytes themselves are sensitive.
* **The explanation service transmits question text and grounded context to a
  third-party provider when one is configured.** Leave it disabled, or scope the
  transmitted context, before operating against real captures.
* **`.env` may contain provider credentials.** Start from `.example.env`; never
  commit a populated `.env`.
* **The testbed executes privileged containers and mirrors live traffic.** Isolate
  it from any network whose confidentiality matters.

```
  threat surface
  ───────────────
  :8081  analytics        read every assessment · finding · evidence · journal
  :8082  explanation      transmits question text and context when a
                          provider is configured
  :8000  control plane    starts experiments · allow_origins=["*"]

  no authentication · no authorization · no rate limiting
  ⇒  bind to loopback · treat port reachability as full disclosure
```

---

## 🧭 Documentation

Begin with
[`docs/verification/FINAL_VERIFICATION_REPORT.md`](docs/verification/FINAL_VERIFICATION_REPORT.md)
for current scope, architecture, verification results, and known limitations. The
complete index is in [`docs/README.md`](docs/README.md).

| Document | Scope |
| --- | --- |
| [`docs/verification/FINAL_VERIFICATION_REPORT.md`](docs/verification/FINAL_VERIFICATION_REPORT.md) | Repository scope, architecture, and end-to-end verification. |
| [`NOVEL_FEATURE_ACCEPTANCE_REPORT.md`](NOVEL_FEATURE_ACCEPTANCE_REPORT.md) | Independent acceptance of drift, mission context, and custody, including identified defects. |
| [`CHAIN_OF_CUSTODY_EXPLAINABILITY_REPORT.md`](CHAIN_OF_CUSTODY_EXPLAINABILITY_REPORT.md) | Custody contract, the two routes, and why a finding identifier is not a key. |
| [`DRIFT_AWARE_ASSESSMENT_REPORT.md`](DRIFT_AWARE_ASSESSMENT_REPORT.md) | Drift design and its constraints on real data. |
| [`MISSION_CONTEXT_REPORT.md`](MISSION_CONTEXT_REPORT.md) | Mission profiles and risk contextualisation. |
| [`END_TO_END_ASSESSMENT_REPORT.md`](END_TO_END_ASSESSMENT_REPORT.md) | End-to-end assessment walkthrough. |
| [`docs/development/REPOSITORY_GUIDE.md`](docs/development/REPOSITORY_GUIDE.md) | Repository conventions and the committed-fixture policy. |
| [`docs/architecture/SCHEMA.md`](docs/architecture/SCHEMA.md) | Domain schemas. |
| [`docs/architecture/STATE_CONSTRUCTION.md`](docs/architecture/STATE_CONSTRUCTION.md) | Construction of observed state. |
| [`docs/architecture/MULTI_SA_CORRELATION.md`](docs/architecture/MULTI_SA_CORRELATION.md) | Multi-SA correlation design. |
| [`docs/architecture/ML_CORRELATION_BOUNDARY.md`](docs/architecture/ML_CORRELATION_BOUNDARY.md) | Why machine learning cannot determine severity. |
| [`docs/reports/ANALYTICS_API_FRONTEND_CONTRACT.md`](docs/reports/ANALYTICS_API_FRONTEND_CONTRACT.md) | The API contract the browser client is written against. |

---

## 🧱 Engineering invariants

This is a research testbed rather than a product, and the following properties
are load-bearing. Each is protected by a tripwire test; a change that removes one
of them should be treated as a change in the system's guarantees, not as a
refactor.

1. Observation remains passive. No stage configures, negotiates, or terminates a
   Security Association.
2. `UNKNOWN` never becomes a vulnerability.
3. Every finding carries a validated `rule_id` and `evidence_type`, with evidence
   references attached wherever an artifact exists to cite.
4. Scoring remains deterministic, and its constants live in `RiskPolicy` rather
   than in the scoring engine.
5. The analytics API remains read-only and answers `405` for every mutating verb.
6. Negotiated cryptographic parameters are never inferred from passive metadata.

---

## 📄 License

**No `LICENSE` file exists in this repository.** Until one is added, the code is
unlicensed and no rights are granted. Redistribution or derivative use should not
proceed until licensing is resolved.
