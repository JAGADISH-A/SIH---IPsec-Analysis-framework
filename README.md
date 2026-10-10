# IPsec Sentinel

## AI-Powered Drift-Aware Security Assessment System for Government VPN Infrastructure

<div align="center">

![Python](https://img.shields.io/badge/Python-3.14-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.141-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-7-646CFF?logo=vite&logoColor=white)
![strongSwan](https://img.shields.io/badge/strongSwan-6.0.3-5B8DEF)
![eBPF/XDP](https://img.shields.io/badge/eBPF%2FXDP-Verified-8A2BE2)
![TShark](https://img.shields.io/badge/TShark-Verified-2E8B57)
![Zeek](https://img.shields.io/badge/Zeek-Verified-1E90FF)
![scikit-learn](https://img.shields.io/badge/scikit-learn-1.9-FF9900?logo=scikit-learn&logoColor=white)
![SHAP](https://img.shields.io/badge/SHAP-0.52-000000)
![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178C6?logo=typescript&logoColor=white)
![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-4.1-06B6D4?logo=tailwindcss&logoColor=white)

</div>

## Project Description

IPsec Sentinel is a passive IPsec observability and security-assessment framework for government-grade VPN estates. It continuously watches live IPsec tunnels, compares what it observes against an approved configuration baseline, and turns encrypted-traffic evidence into measurable security findings, drift verdicts, and analyst-ready explanations.

**Purpose.** Large government VPN estates use IPsec to protect sensitive traffic, but the tunnels themselves are hard to audit: they span heterogeneous gateways, negotiate complex cryptographic settings, and the traffic they carry is encrypted. IPsec Sentinel exists to answer operational security questions without ever touching the data path:

- Is each observed tunnel consistent with its approved configuration and cryptographic policy?
- Are cryptographic parameters (algorithms, lifetimes, SPIs) drifting from the expected baseline?
- Are the traffic patterns and states consistent with the declared mission of each gateway?
- Can findings be explained to an analyst with evidence and reasoning, not just a score?

**Why it exists.** Traditional approaches are manual, periodic, and analyst-dependent; they inspect configuration files rather than live behaviour, they cannot tell you *now* whether a tunnel has drifted, and they rely on deep packet inspection that is unavailable for encrypted traffic. IPsec Sentinel is deliberately **passive**: it receives a mirror copy of the WAN-side IPsec stream and reads tunnel metadata, so it observes real encryption behaviour (IKE handshakes, ESP SAs, SPI/sequence/counters) without decrypting payloads, modifying packets, or sitting inline in the network path.

**Impact.** For a security operations team, the impact is a shift from *auditing after the fact* to *continuous posture awareness*:

- **Continuous drift detection** — observed state is compared against a validated, integrity-sealed baseline, so a renegade cipher or a misconfigured gateway is surfaced as a finding instead of a latent risk.
- **Evidence-backed findings** — every finding points at the specific observed values behind it, with security-association, metadata, and crypto-evidence analysis attached.
- **Explainability** — ML classification is paired with SHAP attribution and natural-language reasoning, so findings are defensible in review and reproducible.
- **Auditability** — every recorded observation carries chain-of-custody and provenance metadata, satisfying the traceability demands of government compliance reviews.

---

## System Architecture

The system is designed as a layered pipeline. Each layer consumes the output of the one before it and produces the input for the next, ending in an interactive dashboard and reports.

```mermaid
flowchart LR
    A["IPsec Testbed (traffic generation)"]
    B["Observation & Evidence Capture"]
    C["State / Feature Normalization"]
    D["Correlation & Baseline Comparison"]
    E["Risk Assessment & Findings"]
    F["ML & Explainability"]
    G["Audit & Chain of Custody"]
    H["Backend Services"]
    I["Dashboard & Reports"]
    A --> B --> C --> D --> E --> F --> G --> H --> I
```

### Layer 1 — IPsec Testbed (traffic generation)

| | |
| --- | --- |
| **Layer technologies** | Containerlab, Docker, strongSwan 6 / swanctl, IKEv2, ESP (AES-GCM-256), XFRM, Linux netns / bridge / veth, `tc`/`mirred`, iproute2 |
| **Input** | Containerlab topologies (`topology/`), strongSwan `swanctl` configurations (`configs/`), mission/asset profiles (`configs/mission/`) |
| **Output** | A live, real IPsec tunnel (`Host-A → GW-A ⇄ GW-B → Host-B`) with an established IKE SA + CHILD SA, installed XFRM state and policy, and a WAN-side stream of IKE and ESP frames |

The lab produces genuinely encrypted traffic on purpose: strongSwan negotiates real IKEv2 sessions and encrypts real ESP payloads, so every downstream layer sees authentic tunnel behaviour rather than synthetic logs.

### Layer 2 — Observation & Evidence Capture

| | |
| --- | --- |
| **Layer technologies** | GW-A authoritative passive mirror (mirrored `eth2` → in-gateway audit tap + dedicated sensor feed), eBPF/XDP `xdp_monitor` (BPF ring buffer), TShark audit tap, Zeek offline replay, PCAP, JSONL journals |
| **Input** | Mirrored WAN traffic (UDP ports 500/4500, ESP/protocol 50, AH/protocol 51) delivered to a passive sink that never forwards packets |
| **Output** | Per-packet XDP events (IKE / IKE-NATT / ESP / ESP-NATT / AH, SPI, sequence, addresses, timestamps) streamed to a live JSONL journal, duplicate TShark capture at the audit tap, and durable PCAP/replay evidence |

Observation is performed at the gateway's WAN interface for a reason: that is the single point that sees **both** IKE negotiation and ESP data in both directions. The sensor is never a path element — `net.ipv4.ip_forward` stays `0` — and the mirror is copy-only, so capture cannot degrade or modify live traffic.

### Layer 3 — State / Feature Normalization

| | |
| --- | --- |
| **Layer technologies** | Python, NumPy, PyArrow, `ipsec_state_builder`, 100 ms window aggregator, XFRM / strongSwan state readers, Parquet / JSONL datasets |
| **Input** | XDP event journal, XFRM state/policy snapshots, strongSwan SA state |
| **Output** | A normalized `ObservedState` snapshot (per-SPI direction, counters, timestamps, sequence progression) and fixed-schema feature rows (59 features per 100 ms window) in reusable dataset form |

Raw events are not directly comparable to a baseline, so this layer normalizes them into a single canonical schema. That one contract is shared by the ML layer, the correlation layer, and the drift layer — there is exactly one way a window of traffic is represented anywhere downstream.

### Layer 4 — Correlation, Baseline Comparison & Drift Detection

| | |
| --- | --- |
| **Layer technologies** | Python comparison engine and rule set, discrepancy model, canonical-state adapter, baseline registry with integrity seal, drift comparison model |
| **Input** | Normalized `ObservedState` + the registered expected-state baseline (validated record from a `BaselineRegistry`) |
| **Output** | Per-attribute comparison records, drift verdicts (each stamped *compared* or honestly reported as *not configured* when no baseline exists), and discrepancy sets for the risk layer |

The layer is strict about standards: a baseline must be a **validated, registered** record before any comparison is made, and an absent baseline is reported as `not_configured` — never silently treated as "no drift". Observed honestly, an unstated comparison cannot look like a clean one.

### Layer 5 — Risk Assessment & Findings

| | |
| --- | --- |
| **Layer technologies** | Risk engine, scoring and policy modules, findings model, threat matrix, security-association / metadata / crypto-evidence analysis, report generator |
| **Input** | Drift verdicts and comparison records, enriched with security-association analysis (per-SPI state), metadata analysis, and crypto-evidence evaluation |
| **Output** | Structured findings with risk scores, a threat matrix, and analytical assessment reports for analyst review |

A clear principle separates facts from judgement: observation and analysis modules report **evidence state** only, and the risk engine — and only the risk engine — converts that evidence into a finding. An analyst can always inspect which observed value produced which judgement.

### Layer 6 — ML Classification & Explainability

| | |
| --- | --- |
| **Layer technologies** | scikit-learn (Random Forest) + deterministic nearest-centroid demo model, SHAP, strict feature contract and model metadata, Google Gemini (google-genai) explanation service with offline deterministic fallback |
| **Input** | Normalized feature rows, trained model artifacts, and completed assessment records |
| **Output** | Traffic-profile classifications, SHAP attribution explaining which features drove each classification, and natural-language technical explanations with a deterministic offline path when the AI provider is unavailable |

Model artifacts are JSON (never pickle), carry full provenance metadata, and are validated against the same fail-fast feature contract used at inference, so training and runtime can never disagree about feature ordering.

### Layer 7 — Audit, Chain of Custody & Response

| | |
| --- | --- |
| **Layer technologies** | Custody builder, evidence linkage, audit journal, response planner, policy-aware executor with gates and approvals |
| **Input** | Evidence records, findings, and their provenance/context |
| **Output** | Audit-ready evidence with hash-chained custody metadata, traceable recording of every analysis event, and policy-gated response plans/actions for a defence operation |

Everything that can be recorded is recorded with provenance, so a finding can always be reconstructed — what was observed, when, by which layer, and under which baseline — which is what makes the output defensible in a compliance review.

### Layer 8 — Backend Services

| | |
| --- | --- |
| **Layer technologies** | Python, FastAPI, Pydantic, Uvicorn — three independent services: a read-only **analytics** service, a mutating **control** service, and a read-only **AI explanation** service |
| **Input** | Read/control requests from the dashboard and CLI workflows |
| **Output** | JSON analytical products (assessments, findings, drift state, XAI output, evidence, asset criticality) and control operations for experiment/dataset runs |

Services are separated by responsibility and risk: reads never mutate, and the AI explanation process — the only component that can spend provider quota — is started explicitly and kept isolated so the rest of the system runs without it.

### Layer 9 — Dashboard & Reports

| | |
| --- | --- |
| **Layer technologies** | React 19, Vite 7, TypeScript, Tailwind CSS 4, Recharts 3, lucide-react |
| **Input** | JSON products served by the backend services |
| **Output** | Interactive dashboards for assessment overview, findings and risk, drift comparison, live screening, ML/XAI inspection, evidence and packet investigation, threat matrix, and generated reports |

The dashboard is the analyst's entry point: live screening for current posture, drill-down into any finding down to the packet evidence behind it, and side-by-side comparison of observed versus expected state.

### Why it is designed this way

| Design choice | Reason | Benefit |
| --- | --- | --- |
| **Passive observation** (mirror + sensor sink, never inline) | Encrypted gov traffic on the data path must not be modified or degraded | Zero impact on live tunnels; no single point of failure in the path |
| **eBPF/XDP in the kernel** | IPsec monitoring is high-packet-rate; userspace capture drops frames | Low-overhead, high-throughput capture of every IKE/ESP/AH frame |
| **TShark + Zeek as a second path** | Counters alone cannot prove what happened on the wire | Durable, replayable packet evidence alongside live statistics |
| **Fixed 59-feature normalization schema** | Multiple consumers (drift, ML, comparison) need one truth | A single shared contract prevents drift/ML disagreements |
| **Validated baseline registry** | Drift is meaningless without an approved reference | `not_configured` vs "no drift" are never confused |
| **Facts separated from judgements** | Observations must stay reviewable independent of scoring | Every finding can be traced to the exact observed value |
| **JSON-only model artifacts + feature contract** | Untrusted, unreproducible models are a governance risk | ML output is reproducible and verifiable end-to-end |
| **SHAP + AI explanation with offline fallback** | A score no one can explain cannot be defended | Analysts get evidence and reasoning, even without the AI provider |
| **Hash-chained custody/audit journal** | Government compliance demands provenance | Findings are reconstructible and audit-ready |
| **Separated read-only / control / AI services** | Read and write must not be conflated; AI quota is bounded | Fail-safe, isolated operations with a deliberate AI startup |
| **Containerised lab topology** | Real-world heterogeneity must be exercised | Deterministic, disposable labs (tunnel / transport / NAT / multi-SA) |

---

## Technology Stack

| Category | Technologies | Purpose |
| --- | --- | --- |
| VPN / IPsec | strongSwan 6, swanctl, IKEv2, ESP, AH, XFRM | Generate and manage real encrypted tunnels whose behaviour the system assesses |
| Lab / topology | Containerlab, Docker, Linux bridge/veth/netns | Run disposable multi-gateway VPN topologies (tunnel, transport, NAT, multi-SA) |
| Traffic capture | eBPF/XDP (`xdp_monitor`), TShark, Zeek, `tc`/`mirred`, PCAP | Capture mirrored WAN traffic passively, in kernel and at packet level |
| State/feature processing | Python 3.14, NumPy, PyArrow, `ipsec_state_builder`, window aggregator | Normalize raw events into observed state and fixed-schema feature datasets (Parquet/JSONL) |
| Correlation & analytics | Python comparison/rules engine, drift baseline registry, risk engine, SA/metadata/crypto analysis | Compare observed vs expected, score findings, and build analytical products |
| ML / XAI | scikit-learn (Random Forest + demo centroid model), SHAP, feature contract | Classify traffic profiles and explain each classification |
| AI explanation | Google Gemini (google-genai), deterministic templates | Generate analyst-readable technical explanations with an offline fallback |
| Audit / evidence | Chain-of-custody builder, evidence linkage, audit journal | Preserve provenance so every finding is reconstructible and traceable |
| Backend services | FastAPI, Pydantic, Uvicorn | Serve analytical products and control workflows to the dashboard and CLI |
| Frontend | React 19, Vite 7, TypeScript, Tailwind 4, Recharts 3 | Interactive dashboard, live screening, findings, and reports |
| Testing | pytest, frontend SSR smoke tests, shell verification scripts | Validate the repository and the deployed lab end-to-end |

---

## Installation on a Fresh Linux Host

The project ships its own installer and lifecycle scripts. From a fresh Linux host (e.g. Ubuntu/Debian), run the project commands in this order:

```bash
# 1. Host prerequisites
sudo apt update && sudo apt install -y docker.io iproute2 python3 python3-venv python3-yaml
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER" && newgrp docker
bash -c "$(curl -sL https://get.containerlab.dev)"      # Containerlab >= 0.79

# 2. Project environment
git clone <your-repository-url> ipsec-testbed && cd ipsec-testbed
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .example.env .env

# 3. Prepare the host (checks prerequisites, builds images, verifies the
#    committed eBPF artifact and the topology files) — the project's own installer
./scripts/install.sh

# 4. Deploy the IPsec testbed and verify the full stack
#    (mirrored observation, IPsec SA, connectivity, sensor, TShark audit tap, XDP)
./scripts/run.sh

# 5. Start the backend services (analytics + control; add --with-ai for the
#    AI explanation service, which needs GEMINI_API_KEY in .env)
./scripts/serve-backend.sh

# 6. Start the analyst dashboard
cd sentinel-frontend && npm install && npm run dev
# open http://localhost:5173
```

Operational scripts the project provides:

| Command | Purpose |
| --- | --- |
| `./scripts/install.sh` | One-step host preparation: prerequisites, eBPF artifact, container images, topology validation (idempotent) |
| `sudo ./scripts/run.sh` | Deploy/converge the testbed and verify the whole observation + IPsec + connectivity chain |
| `./scripts/status.sh` | Concise health report of the deployed lab |
| `./scripts/stop.sh` | Tear the testbed down |
| `./scripts/serve-backend.sh` | Start the backend services for dashboard work |
| `.venv/bin/python -m pytest -q` | Run the repository test suite |