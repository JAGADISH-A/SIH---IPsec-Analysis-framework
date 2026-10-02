# IPsec Sentinel (SIHColayer)

**An observation-only IPsec security assessment framework built on a reproducible
Containerlab/strongSwan testbed.**

IPsec Sentinel turns passive observations of IKEv2 and ESP traffic into
*deterministic, evidence-linked security assessments*. It negotiates nothing,
terminates nothing, and never enforces anything. It answers one question
defensibly:

> For this IPsec tunnel, what was planned, what was actually observed, how do
> they differ, how much does the difference matter, and what evidence supports
> that conclusion?

The repository contains four cooperating parts:

| Part | What it is |
| --- | --- |
| **Testbed** | A Containerlab + strongSwan 6.0.3 IPsec lab with passive packet mirroring and an eBPF/XDP sensor. |
| **Capture & ML pipeline** (`controller/`) | PCAP/XDP → 100 ms feature windows → dataset generation → Random Forest training and inference. |
| **Assessment engine** (`correlation/`) | Expected/observed state, 23 comparison rules, 7 risk rules, drift, mission context, chain of custody, governance journal, evidence registry. |
| **Read-only surfaces** (`correlation/api/`, `correlation/ai/`, `sentinel-frontend/`) | An analytics API, an advisory explanation service, and a React analyst dashboard. |

> **Scope honesty, stated up front.** Passive IPsec metadata cannot reveal which
> cipher, DH group, PFS setting, IKE version, or tunnel mode a *negotiated* SA
> actually uses. The observation code deliberately refuses to guess: unavailable
> variables become `UNKNOWN`, and `UNKNOWN` never escalates into a vulnerability
> on its own. Comparison rules do exist for those variables, and they use
> `_authoritative_or_unknown` (`correlation/comparison/rules.py:183`): if no
> authoritative observed value exists, the outcome is `UNKNOWN` with the reason
> recorded — which is the honest result, not a detection.

---

## Status legend

Every feature below is labelled with one of these. The labels describe the
**code in this repository**, not the aspiration in a design document.

| Label | Meaning |
| --- | --- |
| `IMPLEMENTED` | Working code with automated tests and a verified path. |
| `PARTIAL` | Working for a narrower input domain than the design implies; the gap is named in the same row. |
| `EXPERIMENTAL` | Runs, but only in lab conditions; not hardened. |
| `DRY-RUN` | Computes and reports a plan; performs no real action. |
| `PLANNED` | Documented, not built. |

---

## Feature inventory

### Observation and capture

| Capability | Status | Notes |
| --- | --- | --- |
| Containerlab tunnel lab (5 containers) | `IMPLEMENTED` | `topology/tunnel/ipsec.clab.yml`; verified by `scripts/run.sh`. |
| Containerlab transport-mode lab | `IMPLEMENTED` | IPv4 + IPv6, `topology/transport/ipsec.clab.yml`. |
| Multi-SA lab (three gateways) | `EXPERIMENTAL` | `topology/multi-sa/`, `scripts/multi-sa-testbed.sh`. |
| strongSwan IKEv2 + CHILD_SA configs | `IMPLEMENTED` | PSK, `configs/gw-{a,b}/swanctl/`. |
| Passive `tc`/`mirred` mirror on GW-A `eth2` | `IMPLEMENTED` | Two chained actions: in-gw-a `audit-tap0` tap **and** `eth3 → sensor:eth1`. |
| eBPF/XDP sensor (`ESP`/`AH`/`IKE`/`IKE-NAT-T`/`OTHER`) | `IMPLEMENTED` | Generic/SKB mode; native/driver mode is unavailable on veth by design. |
| XDP IPv6 extension-header traversal | `PLANNED` | Only the immediate IPv6 header is parsed (`ebpf/xdp_monitor.bpf.c:138`). ESP after an extension header is seen as `OTHER`. |
| TShark / Zeek PCAP parsing | `IMPLEMENTED` | `controller/zeek.py`, `controller/audit_observer.py`. |
| Deterministic traffic profiles | `IMPLEMENTED` | `voip, video, messaging, email, web, icmp` (`controller/traffic.py:51`). |
| Built-in and D-ITG 2.8.1 generator backends | `IMPLEMENTED` | `IPSEC_TRAFFIC_GENERATOR=builtin\|ditg`. |

### Dataset and ML

| Capability | Status | Notes |
| --- | --- | --- |
| Planned-sample dataset generation | `IMPLEMENTED` | `controller/dataset*.py`; resumable, testbed-locked. |
| 59-feature schema (schema `v2`) | `IMPLEMENTED` | Canonical snapshot in `correlation/ml/feature_contract.py`. |
| 100 ms live feature windows | `IMPLEMENTED` | `ebpf/xdp_window_aggregator.py`, `controller/live_features.py`. |
| Offline/live feature parity | `IMPLEMENTED` | One computation path; the live path is a bridge, not a re-implementation. |
| Grouped stratified dataset split (70/15/15) | `IMPLEMENTED` | Grouped by `configuration_id`, seed 7. |
| Random Forest classifier (500 trees) | `IMPLEMENTED` | `controller/train_random_forest.py`; production path bridged by `correlation/ml/controller_bridge.py`. |
| Model provenance recording | `IMPLEMENTED` | Every inference records model SHA-256, feature contract, training-report digest. |
| SHAP explainability | `EXPERIMENTAL` | Offline/on-demand (`controller/shap_analysis.py`). **Not** exposed via any API or dashboard route. |
| ML-driven anomaly detection | `PLANNED` | No anomaly classifier exists; `ml.anomaly` is a registered rule with no signal behind it. |
| ML as a severity input | `IMPLEMENTED` | ML output is evidence (`source=ML`), never the severity authority. |

### Assessment engine

| Capability | Status | Notes |
| --- | --- | --- |
| Expected-state materialization from a plan | `IMPLEMENTED` | `correlation/adapters/expected_state.py`. |
| Observed-state construction (offline + live) | `IMPLEMENTED` | `correlation/models/observed.py`, `ebpf/ipsec_state_builder.py`. |
| RFC 4303 SA correlation, with ambiguity refusal | `IMPLEMENTED` | `correlation/sa_correlation.py`. |
| 23 comparison rules | `IMPLEMENTED` | `correlation/comparison/rules.py`; config, posture, presence, activity, window, SPI. |
| 7 risk rules | `IMPLEMENTED` | `correlation/risk/rules.py`; keyed by `MISMATCH_FINDING_SPECS` security relevance. |
| Deterministic scoring | `IMPLEMENTED` | `INFO=0, LOW=6, MEDIUM=12, HIGH=25, CRITICAL=40`; per-category cap 30; global cap 100; disjoint severity bands (`correlation/risk/scoring.py`). |
| Drift-aware assessment | `PARTIAL` | Only 3 comparable fields exist: `address_family`, `esp.presence`, `ah.presence` (`correlation/drift/canonical.py:94-114`). No real drift is demonstrable from recorded data. |
| Mission-context risk | `IMPLEMENTED` | `correlation/mission/`; operator-declared asset profiles. Keeps the technical score untouched. |
| Chain of custody per finding | `PARTIAL` | `correlation/custody/`; real for every finding except the drift-origin chain, which self-contradicts. |
| Evidence registry + SHA-256 integrity | `IMPLEMENTED` | `correlation/evidence_linkage.py`, `correlation/api/pcap.py`. |
| Governance journal with hash chain | `IMPLEMENTED` | `correlation/response/audit.py`; per-record `previous_hash` + `event_hash`, verified on load. Genesis uses 64 zeros. |
| Response planning | `DRY-RUN` | `correlation/response/`; the only executor type is `dry-run`. Production execution is disabled by default. |

### Surfaces

| Capability | Status | Notes |
| --- | --- | --- |
| Analytics API (stdlib `ThreadingHTTPServer`) | `IMPLEMENTED` | Phase-8 `/api` + observable-only `/api/v1`. `GET`/`HEAD`/`OPTIONS` only; every mutating verb returns `405`. |
| Analytics OpenAPI document | `IMPLEMENTED` | `GET /api/v1/openapi.json`. |
| Prometheus metrics endpoint | `IMPLEMENTED` | `GET /api/v1/metrics`. |
| Testbed control API (FastAPI) | `IMPLEMENTED` | `controller/api.py` + `controller/dataset_api.py`. |
| Advisory AI explanation service | `EXPERIMENTAL` | `correlation/ai/`; deterministic scope gate, glossary, grounded templates; optional OpenAI-compatible provider. |
| SHAP in the API/UI | `PLANNED` | Deliberately not wired. |
| React analyst dashboard (`sentinel-frontend/`) | `IMPLEMENTED` | 13 canonical routes, legacy redirects, honest empty states. |
| Kafka streaming | `PARTIAL` | `correlation/streaming/` implements it; disabled by default (`SIH_STREAM_KAFKA_ENABLED=false`), in-memory transport is the default. |
| Authentication / authorization | `PLANNED` | **None anywhere.** See [Security considerations](#security-considerations). |
| License | — | No `LICENSE` file exists. Treat the code as unlicensed until one is added. |

---

## Architecture

```text
                     TESTBED (Containerlab + strongSwan 6.0.3)
 ┌───────────────────────────────────────────────────────────────────────────┐
 │  host-a ── gw-a ══[ br-wan ]══ gw-b ── host-b          sensor (passive)    │
 │  10.10.1.10   │                  │       10.10.2.10      ip_forward=0    │
 │               └ eth2 ──tc mirred─┴──> eth3 ──veth──> eth1 (sink only)     │
 │                 ├──> audit-tap0 (in-gw-a tap, tshark)                     │
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
 analytics API (read-only)   advisory explanations    React dashboard
```

### Data flow guarantees

1. **Observation is passive.** Nothing in the pipeline configures, negotiates, or
   terminates an SA. GW-A is the authoritative *observation point*, not an
   enforcement point.
2. **Evidence is carried, not reconstructed.** Each window is bound to the PCAP
   that produced it, and the reference travels with every stage into the
   assessment bundle. Every finding carries a validated `rule_id` and
   `evidence_type`; the backing `EvidenceRef` values are attached wherever the
   pipeline has an artifact to point at, and `UNKNOWN` findings are produced
   rather than fabricated when it does not.
3. **Unknown is a first-class outcome.** A missing observation yields `UNKNOWN` /
   `INSUFFICIENT_EVIDENCE`, never a guessed value and never an inflated severity.
4. **Determinism is tested.** Identical inputs produce identical scores,
   severities, findings, and bundles; the determinism test modules cover the
   comparison engine, the API store, and the custody builder.
5. **The API cannot mutate.** The analytics API answers `405` for `POST`, `PUT`,
   `PATCH`, and `DELETE` on *every* path, including unknown ones.

---

## Repository layout

```text
.
├── controller/              Capture orchestration, dataset + ML pipeline, control API
│   ├── features.py          The only feature computation (59 features)
│   ├── live_features.py     Live-record bridge (no second implementation)
│   ├── dataset*.py          Dataset run lifecycle, planner, artifacts, quality
│   ├── train_random_forest.py / ml_inference.py / evaluate_model.py
│   ├── shap_analysis.py     Offline XAI (not served)
│   ├── api.py               FastAPI testbed control plane
│   └── zeek.py, audit.py    Capture parsing and journaling
├── correlation/             Assessment engine and read-only surfaces
│   ├── models/              ExpectedState, ObservedState, LiveFeatureWindow
│   ├── adapters/            Plan → ExpectedState materialization
│   ├── sa_correlation.py    RFC 4303 selector, ambiguity refusal
│   ├── comparison/          23 rules + deterministic comparison engine
│   ├── risk/                7 rules, policy, scoring, findings
│   ├── drift/               Baselines, canonical fields, comparison, registry
│   ├── mission/             Operator asset profiles and context
│   ├── custody/             Per-finding chain of custody
│   ├── ml/                  Feature contract, inference, production bridge
│   ├── response/            Planner, policy, approval, dry-run executor, audit
│   ├── evidence_linkage.py, artifacts.py
│   ├── api/                 stdlib analytics API, /api + /api/v1, OpenAPI
│   ├── ai/                  Advisory explanation service (stdlib + scope gate)
│   └── streaming/           Window transport (memory default, Kafka optional)
├── ebpf/                    XDP program, userspace loader, window aggregator,
│                            observed-state builder
├── topology/                tunnel/, transport/, multi-sa/ Containerlab files
├── configs/                 strongSwan swanctl configs: gw-a/, gw-b/, transport/,
│                            plus mission/ asset profiles
├── campaigns/               Named experiment plans
├── scripts/                 install / run / status / stop lifecycle + demos
├── gateway-image/ host-image/ transport-host-image/     Container images
├── sentinel-frontend/       Current React + TypeScript + Vite dashboard
├── frontend/                Superseded static dashboard (served by controller/api.py)
├── tests/                   107 test modules
├── demo/analytics/          Committed offline demo fixture (see below)
├── vendor/ditg/             D-ITG 2.8.1 build provenance
└── docs/                    architecture/, development/, reports/, verification/
```

`results/` and `out/` are generated locally and are not committed. The committed
fixture is `demo/analytics/`, with checksums in `demo/MANIFEST.sha256`.

---

## Quick start: bring up the testbed

Everything is scripted. From the repository root:

```bash
./scripts/install.sh   # host prereqs + images + eBPF build + topology validation
./scripts/run.sh       # deploy (or converge) + full verification   [needs root]
./scripts/status.sh    # concise health report, any time
./scripts/stop.sh      # teardown, reuses the deployment destroy path [needs root]
```

`run.sh` and `stop.sh` recreate `br-wan` and invoke Containerlab, so they require
root. `install.sh` and `status.sh` run unprivileged.

### Nodes

| Node | Role | Address |
| --- | --- | --- |
| `host-a` | LAN-A host | `10.10.1.10/24`, `2001:db8:1::10/64` |
| `gw-a` | Gateway — **authoritative observation point** | `10.10.1.1/24`, `192.168.100.1/24` |
| `gw-b` | Gateway | `192.168.100.2/24`, `10.10.2.1/24` |
| `host-b` | LAN-B host | `10.10.2.10/24`, `2001:db8:2::10/64` |
| `sensor` | Passive observation sink | mirrored feed on `eth1`, `ip_forward=0` |

`br-wan` is a root-namespace bridge carrying **only** `gw-a eth2` and `gw-b eth2`.
The sensor is never a `br-wan` member. `br-wan` must exist before
`containerlab deploy`; always deploy and tear down through `scripts/deploy-ipsec.sh`,
never with a bare `containerlab deploy`.

### Requirements

* Ubuntu (Linux), Docker with a running daemon, Containerlab.
* `clang`/`llvm`, `bpftool`, `libbpf`/`libelf`/`libz`, `make` for the eBPF monitor.
* `python3` with `pyyaml` for topology validation.
* Python 3.14.4 plus `requirements.txt` for the analysis pipeline.
* Node.js 20.19+ or 22.12+ (the Vite 7 requirement) for `sentinel-frontend/`.

`install.sh` reports each prerequisite as `[OK]` / `[WARN]` / `[FAIL]` and exits
non-zero only for a missing **required** item. It does not install system
packages.

### Build the images

```bash
docker build -t ipsec-test-gateway:6.0.3     ./gateway-image
docker build -t ipsec-test-host:24.04        ./host-image
docker build -t ipsec-transport-host:24.04  ./transport-host-image
```

The gateway image is based on `openeuler/strongswan:6.0.3-oe2403sp4` and adds
`tcpdump`, `tshark`, and the observation helpers.

### How observation works

```text
gw-a eth2 (ingress + egress) ── tc mirred (two chained actions)
        ├──> bridge tap "audit-tap0"        (tshark -i audit-tap0)
        └──> eth3 ── veth ──> sensor eth1    (tcpdump, eBPF/XDP)
```

```bash
# Mirror filters live on the ingress/egress parents of eth2.
docker exec clab-ipsec-gw-a tc filter show dev eth2 ingress | grep mirred
docker exec clab-ipsec-gw-a tc filter show dev eth2 egress  | grep mirred

# Forensic tap.
docker exec clab-ipsec-gw-a tshark -i audit-tap0 -c 20

# Live XDP journal (falls back to generic/SKB mode on veth by design).
docker exec clab-ipsec-sensor /usr/sbin/xdp_monitor eth1 --json
```

> **Trap:** `tc filter show dev eth2` without `ingress`/`egress` lists only the
> root qdisc and shows nothing for `clsact` mirrors. `run.sh` and `status.sh`
> already check the correct parents.

### IPsec configuration

From `configs/gw-a/swanctl/conf.d/ipsec.conf` (GW-B mirrors it with swapped
addresses and IDs):

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

`start_action = trap` means the SA comes up when traffic triggers it. To
establish it explicitly:

```bash
docker exec clab-ipsec-gw-a swanctl --initiate --child lan-a-to-lan-b
docker exec clab-ipsec-gw-a swanctl --list-sas      # expect ESTABLISHED
```

### What `run.sh` verifies

1. All five containers are running.
2. `gw-a eth1/eth2/eth3`, `audit-tap0`, and `sensor eth1` exist.
3. At least one `mirred` action per direction on `gw-a eth2`.
4. `swanctl --list-sas` reports `ESTABLISHED` for `lan-a-to-lan-b`.
5. XFRM states and outbound tunnel policies are installed.
6. `host-a → host-b` and `host-b → host-a` ping with 0% loss.
7. Mirrored packet counts on `gw-a eth2` and `sensor eth1` match.
8. `audit-tap0` sees live ESP frames.
9. `sensor ip_forward=0` and the sensor is absent from `br-wan`.
10. XDP ESP events on `sensor eth1` (generic/SKB) — non-fatal if absent.

### Known dataplane quirk, by design

Both gateways forward LAN traffic through the tunnel **and** drop a plaintext
copy onto the WAN, because static `main`-table routes coexist with strongSwan's
policy-route table 220. Receivers discard the plaintext at XFRM ingress, so
connectivity metrics stay exact. The plaintext copy is faithfully mirrored to
the sensor (surfacing as `OTHER` for ICMP). This is **not** a defect introduced
by the observation work and should not be "fixed" as one.

---

## Running the analysis services

Copy the example environment first; it contains no secrets and every value is
safe by default.

```bash
cp .example.env .env
```

### Analytics API

```bash
python -m correlation.api.app --phase10            # binds 127.0.0.1:8081 by default
```

Environment-first configuration: `ANALYTICS_API_HOST`, `ANALYTICS_API_PORT`,
`ANALYTICS_API_ALLOWED_ORIGINS`, `ANALYTICS_API_CAPTURE_FEED`. CLI flags
`--host` / `--port` / `--allowed-origins` win over the environment. Port 8081 is
the default so it can run alongside the control plane on 8000.

### Advisory explanation service

```bash
python -m correlation.ai.service                     # binds 127.0.0.1:8082
```

Every question is classified by a deterministic scope gate before anything else
happens. Out-of-scope questions are refused with a reason; terminology questions
are answered from the built-in glossary; in-scope questions are answered from a
grounded template and *may* be passed to an OpenAI-compatible provider when one
is configured. The service never changes an assessment, score, finding, piece of
evidence, or the journal.

### Testbed control plane

```bash
uvicorn controller.api:app --host 127.0.0.1 --port 8000
```

`controller/api.py` defines the app but deliberately contains no `__main__` and
never calls `uvicorn` itself.

### Both services at once

`scripts/serve-backend.sh` is the supported entry point that starts the analytics
API (`127.0.0.1:8081`, `--phase10 --no-static`) and the control plane
(`127.0.0.1:8000`) together, owns their PIDs, and stops them cleanly. The testbed
lifecycle scripts deliberately do not stop servers.

### Dashboard

```bash
cd sentinel-frontend
npm ci
npm run dev          # or: npm run build && npm run preview
npm run typecheck
npm run verify       # full smoke-harness suite
```

`sentinel-frontend/` is the current dashboard. `frontend/` is the superseded
vanilla-JS UI that `controller/api.py` still serves at `/` and `/static`.

### Demo without the lab

The committed fixture lets the analytics surface be exercised with no Docker, no
root, and no network:

```bash
./scripts/init-demo-data.sh          # copy demo/analytics/ -> results/, verify, prove the store builds
./scripts/init-demo-data.sh --verify # verify only, copy nothing
./scripts/serve-backend.sh           # analytics API + control plane
```

Verify the fixture's integrity directly at any time:

```bash
cd demo && sha256sum -c MANIFEST.sha256
```

For the managed live-traffic demo against a real frontend stack,
`scripts/e2e-live-demo.sh` manages the whole flow:

```bash
./scripts/e2e-live-demo.sh up          # analytics :8081 + control :8000 + vite :5173
./scripts/e2e-live-demo.sh health      # readiness, CORS, and feed verdict probes
./scripts/e2e-live-demo.sh demo-start  # switch to an actively-appended live journal
./scripts/e2e-live-demo.sh demo-stop   # switch back to the recorded baseline
./scripts/e2e-live-demo.sh down        # stop only the servers this script started
```

It refuses to start a second server on an occupied port and never kills a
process it did not start.

---

## HTTP API reference

All three services are **read-only with respect to assessments**. The analytics
and AI services expose exactly one `POST` (`/ai/explain`), which is a question
that mutates nothing.

### Analytics API — Phase-8 surface (`correlation/api/routes.py`)

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/health` | Store health. |
| `GET` | `/api/assessments` | Assessment list; supports pagination query parameters. |
| `GET` | `/api/assessments/{assessment_id}` | One assessment bundle. |
| `GET` | `/api/assessments/{assessment_id}/{sub-resource}` | One of `expected`, `observed`, `correlation`, `risk`, `xai`, `ml`, `evidence`, `ipsec-state`. |

### Analytics API — `/api/v1` observable surface (`correlation/api/v1.py`, `openapi.py`)

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/health` | Component health plus the effective CORS policy. |
| `GET` | `/api/v1/metrics` | Prometheus text exposition. |
| `GET` | `/api/v1/traffic-generator` | Traffic generator status. |
| `GET` | `/api/v1/capture/events` | Live capture event tail (experiment-gated). |
| `GET` | `/api/v1/evidence` | Evidence registry listing. |
| `GET` | `/api/v1/evidence/{evidence_id}` | One evidence record with integrity status. |
| `GET` | `/api/v1/evidence/{evidence_id}/pcap` | Digest-verified PCAP stream. |
| `GET` | `/api/v1/runs` | Dataset run discovery. |
| `GET` | `/api/v1/runs/{run_id}` | One run. |
| `GET` | `/api/v1/runs/{run_id}/evidence` | Evidence bound to one run. |
| `GET` | `/api/v1/runs/{run_id}/audit` | Audit events for one run. |
| `GET` | `/api/v1/audit/events` | Journal events; filterable and pageable. |
| `GET` | `/api/v1/audit/events/{event_id}` | One journal event. |
| `GET` | `/api/v1/audit/events/{event_id}/evidence` | Evidence backing one journal event. |
| `GET` | `/api/v1/audit/runs` | Runs as seen by the journal. |
| `GET` | `/api/v1/audit/runs/{run_id}` | One journal run. |
| `GET` | `/api/v1/governance` | Governance events. |
| `GET` | `/api/v1/governance/{event_id}` | One governance event. |
| `GET` | `/api/v1/assessments` | Assessment listing with provenance. |
| `GET` | `/api/v1/assessments/{id}` | One assessment. |
| `GET` | `/api/v1/assessments/{id}/findings` | Findings for one assessment. |
| `GET` | `/api/v1/assessments/{id}/drift` | Drift comparison for one assessment. |
| `GET` | `/api/v1/assessments/{id}/findings/{finding_id}/explanation` | Chain of custody for the `(assessment, finding)` pair. |
| `GET` | `/api/v1/findings` | Cross-assessment finding listing. |
| `GET` | `/api/v1/findings/{finding_id}/explanation` | Convenience form; refuses to guess the assessment. |
| `GET` | `/api/v1/drift` | Drift overview. |
| `GET` | `/api/v1/drift/baselines` | Validated drift baselines. |
| `GET` | `/api/v1/responses/{recommendation_id}/evidence` | Evidence behind a planned response. |
| `GET` | `/api/v1/openapi.json` | The maintained OpenAPI description. |
| `GET` | `/api/v1/docs` | Human-readable route index. |

`POST`, `PUT`, `PATCH`, and `DELETE` return `405` with an `Allow: GET, HEAD,
OPTIONS` header on every path.

### Advisory AI service (`correlation/ai/service.py`)

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/ai/health` | Engine state and whether a provider is configured. |
| `GET` | `/ai/glossary` | Built-in terminology dictionary. |
| `POST` | `/ai/explain` | Answer one grounded question. Bounded question length; advisory only. |

### Testbed control plane (`controller/api.py`, `controller/dataset_api.py`)

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/` | Serves the legacy static dashboard. |
| `GET` | `/health` | Liveness. |
| `GET` | `/experiments/configurations` | Modes, address families, and supported algorithm sets. |
| `POST` | `/experiments` | Start one manual experiment. |
| `GET` | `/experiments/{job_id}` | Experiment status. |
| `GET` | `/dataset-runs/settings` | Configured sample ceiling. |
| `POST` | `/dataset-runs` | Create and start a dataset run. `409` if the testbed is busy. |
| `GET` | `/dataset-runs/{dataset_run_id}` | Run state and progress. |
| `POST` | `/dataset-runs/{dataset_run_id}/resume` | Resume after a pause. Refuses a changed plan fingerprint. |
| `GET` | `/dataset-runs/{dataset_run_id}/results` | Final dataset artifacts. |
| `GET` | `/dataset-runs/{dataset_run_id}/download` | Artifact download. |

Dataset runs and manual experiments share a single testbed reservation lock, so
the two can never execute concurrently.

---

## Feature and model contract

* Schema version `v2`, **59 declared features**, order and int/float split frozen
  in `correlation/ml/feature_contract.py`.
* Missing values are **never** imputed with zeros; the adapter fails fast.
  `NaN`/`inf`, booleans, strings, extra keys, and missing keys are all rejected.
* The ML model consumes **57** features: `burst_packet_ratio` and
  `ike_packet_count` are constant across every recorded sample (1.0 and 4) and are
  excluded, with the exclusion recorded in the training report.
* An artifact's `feature_names` must equal the canonical order before inference
  builds its input vector, so a reordered or stale model fails instead of
  silently predicting nonsense.
* ML never sets severity. `rule_ml_classification_disagreement` contributes a
  finding only when a documented policy threshold is crossed.

---

## Deterministic scoring

Each enabled finding contributes its severity weight; duplicates are removed
**before** scoring; a per-category cap bounds any single finding theme; a global
cap bounds the total; the total maps to exactly one severity through disjoint
bands.

| Severity | Weight |
| --- | --- |
| `INFO` | 0 |
| `LOW` | 6 |
| `MEDIUM` | 12 |
| `HIGH` | 25 |
| `CRITICAL` | 40 |

Per-category cap: `30`. Global cap: `100`.

A mismatch becomes a finding **only** for variables whose security relevance is
explicitly registered in `MISMATCH_FINDING_SPECS`. `UNKNOWN` and
`NOT_APPLICABLE` never become vulnerabilities by default; `INSUFFICIENT_EVIDENCE`
is produced only when policy enables it.

---

## Recorded results

These numbers come from the committed artifacts and reports in this repository.
They are **lab results on synthetic traffic**, not production benchmarks.

### Traffic classifier

From `demo/analytics/ml/train_report.json`:

| Property | Value |
| --- | --- |
| Samples | 300 (`212` train / `42` validation / `46` test) |
| Split strategy | grouped, stratified, greedy by `configuration_id` (70/15/15, seed 7) |
| Source runs | `dataset-20260923-221430`, `dataset-20260924-003710` (SHA-256 fingerprinted) |
| Classes | `voip, video, messaging, email, web, icmp` |
| Model | RandomForestClassifier, `n_estimators=500`, `random_state=7`, OOB enabled |
| OOB score | `1.0` |
| 5-fold CV accuracy / macro-F1 | `1.0` / `1.0` |

**These perfect scores are expected and are not evidence of generalisation.**
Each class comes from a deterministic generator with a distinct, well-separated
packet-size and inter-arrival signature, and there are only six classes across
two runs. The value here is the reproducible pipeline and the provenance chain,
not the accuracy. Do not cite this as a detection result.

### End-to-end recorded path

From `docs/verification/FINAL_VERIFICATION_REPORT.md`: 44 windows, 308 audit
events, 44 distinct per-window evidence IDs, all seven pipeline stages carrying
real PCAP evidence on 44/44 windows, and a digest-verified PCAP served from the
registry (out-of-root requests refused).

### Test-suite size

107 test modules. The custody work alone added 63 tests (1349 passed / 7 skipped
at the commit it was written). **Tests were not executed during this README
revision**; treat the counts above as recorded history, not as a fresh run.

---

## Known limitations

These are real and are not worked around anywhere in the code:

1. **Passive observation cannot read negotiated crypto.** Cipher, integrity
   algorithm, DH group, PFS, IKE version, and tunnel mode are `UNKNOWN` from the
   WAN side. Expected-state comparison still works — it compares what was planned
   against what is *observable*, and reports the rest as unobservable.
2. **Drift compares three fields.** `address_family`, `esp.presence`,
   `ah.presence`. No real observed drift exists in the recorded data, so drift is
   demonstrated on a controlled fixture and the real IPv4/IPv6 pair only.
3. **Drift is not scoped to an endpoint pair.** A comparison is not attributed to
   a specific endpoint interface.
4. **The drift-origin chain of custody is self-contradictory** (known defect,
   documented in `NOVEL_FEATURE_ACCEPTANCE_REPORT.md` §7).
5. **Two served custody fields violate their own OpenAPI contract** in both
   branches (same report).
6. **XDP does not traverse IPv6 extension headers**, so ESP behind one is
   classified `OTHER`.
7. **Native/driver XDP is unavailable on veth**; generic/SKB mode is the verified
   path. This is a virtualisation limitation, not a code defect.
8. **Both gateways leak a plaintext copy onto the WAN** by design (see the
   dataplane quirk above).
9. **Response execution is dry-run only.** The only executor type is `dry-run`;
   production execution is disabled by default and requires explicit
   configuration.
10. **Kafka streaming is off by default**; the in-memory transport is the
    supported default.
11. **SHAP is offline-only** and is deliberately absent from the API and UI.
12. **`ml.anomaly` has no anomaly classifier behind it**; the rule is registered
    but has no signal source.
13. **Mission asset profiles are operator declarations**, not measurements.
14. **No authentication, authorization, or rate limiting anywhere.** See below.
15. **No license file.** See below.
16. **`scripts/start-live-analytics.sh` is not a portable entry point.** It
    hardcodes an audit-journal path and a log path under `/tmp/opencode/` and
    binds `0.0.0.0` by default. Use `scripts/serve-backend.sh` or invoke
    `python -m correlation.api.app` directly instead.
17. **`scripts/init-demo-data.sh` points at a `demo/README.md` that does not
    exist**, so the fixture's provenance and selection audit are undocumented in
    this checkout.

---

## Security considerations

* **There is no authentication or authorization.** Any process that can reach a
  bound port can read every assessment, finding, evidence record, audit event,
  and governance event, and can start testbed experiments through the control
  plane. Bind to loopback and treat port access as full disclosure.
* **The control API sets `allow_origins=["*"]` with all methods and headers.**
  Do not expose it on a shared or routable interface.
* **Evidence PCAPs may contain captured payload.** Downloads are digest-verified
  and confined to the evidence root, but the bytes themselves are sensitive.
* **The AI service sends question text and grounded context to a third-party
  provider when one is configured.** Keep it disabled, or scope the context,
  before using it with real captures.
* **`.env` may hold provider credentials.** Copy `.example.env`, never commit a
  populated `.env`.
* **The testbed runs privileged containers and mirrors traffic.** Isolate it from
  any network you care about.

---

## Documentation

Start with **[`docs/verification/FINAL_VERIFICATION_REPORT.md`](docs/verification/FINAL_VERIFICATION_REPORT.md)**
for current scope, architecture, what was verified, and known limitations. The
full index is **[`docs/README.md`](docs/README.md)**.

| Document | What it answers |
| --- | --- |
| [`docs/verification/FINAL_VERIFICATION_REPORT.md`](docs/verification/FINAL_VERIFICATION_REPORT.md) | What the repository is, and what was verified end to end. |
| [`NOVEL_FEATURE_ACCEPTANCE_REPORT.md`](NOVEL_FEATURE_ACCEPTANCE_REPORT.md) | Independent, code-re-read acceptance of drift, mission context, and custody — including the defects. |
| [`CHAIN_OF_CUSTODY_EXPLAINABILITY_REPORT.md`](CHAIN_OF_CUSTODY_EXPLAINABILITY_REPORT.md) | Custody contract, the two routes, and why a finding id is not a key. |
| [`DRIFT_AWARE_ASSESSMENT_REPORT.md`](DRIFT_AWARE_ASSESSMENT_REPORT.md) | Drift design and its real-data limits. |
| [`MISSION_CONTEXT_REPORT.md`](MISSION_CONTEXT_REPORT.md) | Mission profiles and risk contextualization. |
| [`END_TO_END_ASSESSMENT_REPORT.md`](END_TO_END_ASSESSMENT_REPORT.md) | End-to-end assessment walkthrough. |
| [`docs/development/REPOSITORY_GUIDE.md`](docs/development/REPOSITORY_GUIDE.md) | Repository conventions and the committed-fixture policy. |
| [`docs/architecture/SCHEMA.md`](docs/architecture/SCHEMA.md) | Domain schemas. |
| [`docs/architecture/STATE_CONSTRUCTION.md`](docs/architecture/STATE_CONSTRUCTION.md) | How observed state is constructed. |
| [`docs/architecture/MULTI_SA_CORRELATION.md`](docs/architecture/MULTI_SA_CORRELATION.md) | Multi-SA correlation design. |
| [`docs/architecture/ML_CORRELATION_BOUNDARY.md`](docs/architecture/ML_CORRELATION_BOUNDARY.md) | Why ML cannot set severity. |
| [`docs/reports/ANALYTICS_API_FRONTEND_CONTRACT.md`](docs/reports/ANALYTICS_API_FRONTEND_CONTRACT.md) | The API contract the browser client codes against. |

---

## Contributing and scope

This is a research testbed, not a product. Changes should preserve these
invariants, each of which has a tripwire test:

1. Passive observation stays passive.
2. `UNKNOWN` never becomes a vulnerability.
3. Every finding carries an evidence reference.
4. Scoring stays deterministic and documented in `RiskPolicy`, not in the engine.
5. The analytics API stays read-only and answers `405` for every mutating verb.
6. Real crypto parameters are never inferred from passive metadata.

---

## License

**No `LICENSE` file exists in this repository.** Until one is added, the code is
unlicensed and no rights are granted. Do not redistribute or build on it until
licensing is resolved.

