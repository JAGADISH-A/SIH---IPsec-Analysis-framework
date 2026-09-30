# IPsec Analysis Framework Architecture

```text
┌─────────────────────────────┐
│      IPsec TESTBED          │
│ Containerlab • strongSwan   │
│ IKE / ESP / AH traffic      │
└──────────────┬──────────────┘
               │
      traffic + SA state + config
               │
 ┌─────────────┴─────────────┐
 │                           │
 ▼                           ▼
┌──────────────────────────┐  ┌──────────────────────────┐
│   LIVE OBSERVATION       │  │    EVIDENCE CAPTURE      │
│   eBPF / XDP             │  │    PCAP • TShark • Zeek  │
│   mirrored traffic       │  │    durable packet record │
└────────────┬─────────────┘  └────────────┬─────────────┘
             │                             │
             └──────────────┬──────────────┘
                            │
                    observed IPsec
                    events + metadata
                            │
                            ▼
              ┌───────────────────────────────┐
              │       IPsec STATE ENGINE      │
              │ IKE / SA / ESP / AH metadata  │
              └──────────────┬────────────────┘
                             │
                      normalized state
                             │
                             ▼
              ┌───────────────────────────────┐
              │       FEATURE / STATE ENGINE  │
              │     100-ms observation windows│
              └──────────────┬────────────────┘
                             │
                             ▼
╔══════════════════════════════════════════════════════════════════════╗
║              CORRELATION & ASSESSMENT CORE                           ║
║                                                                      ║
║  ┌────────────────┐      ┌──────────────────────────────┐           ║
║  │ OBSERVED STATE │─────►│ EXPECTED vs OBSERVED         │           ║
║  └────────────────┘      │ CORRELATION                  │           ║
║                          └──────────────┬───────────────┘           ║
║                                         │                           ║
║  ┌────────────────┐                     ▼                           ║
║  │   BASELINE     │────────────► DRIFT DETECTION                    ║
║  └────────────────┘                                                 ║
║                                         │                           ║
║                          ┌──────────────▼───────────────┐           ║
║                          │ FUNDAMENTAL IPsec ASSESSMENT │           ║
║                          └──────────────┬───────────────┘           ║
║                                         │                           ║
╚═════════════════════════════════════════╪═══════════════════════════╝
                                          │
                         security findings + evidence
                                          │
                     ┌────────────────────┴───────────────┐
                     │                                    │
                     ▼                                    ▼
          ┌──────────────────────┐             ┌──────────────────────┐
          │    ML / XAI ENGINE   │             │   MISSION CONTEXT    │
          │    RF • SHAP         │             │   asset / mission    │
          │    classification    │             │   profile            │
          └──────────┬───────────┘             └──────────┬───────────┘
                     │                                    │
                     └────────────────┬───────────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │ CROSS-SIGNAL            │
                         │ DISAGREEMENT            │
                         └────────────┬────────────┘
                                      │
                             contextualized risk
                                      │
                                      ▼
                    ┌────────────────────────────────┐
                    │     EVIDENCE / AUDIT LAYER     │
                    │ JSONL • hash chain • custody   │
                    └───────────────┬────────────────┘
                                    │
                             verified findings
                                    │
                    ┌───────────────┴────────────────┐
                    │                                │
                    ▼                                ▼
         ┌────────────────────┐           ┌────────────────────┐
         │ GEMINI / AI        │           │ RESPONSE / POLICY  │
         │ explanation        │           │ recommendations    │
         └──────────┬─────────┘           └──────────┬─────────┘
                    │                                │
                    └──────────────┬─────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │      SENTINEL DASHBOARD      │
                    │ traffic • findings • drift   │
                    │ evidence • recommendations   │
                    └──────────────────────────────┘
```

## Architecture Flow

1. The **IPsec testbed**, built with Containerlab and strongSwan, generates IKE, ESP, and AH traffic together with security-association state and configuration data.
2. Traffic is processed through two complementary paths:
   - **Live Observation:** eBPF/XDP captures mirrored traffic and real-time IPsec metadata.
   - **Evidence Capture:** PCAP, TShark, and Zeek provide a durable packet record for investigation and verification.
3. The live and evidence paths provide observed IPsec events and metadata to the **IPsec State Engine**.
4. The **IPsec State Engine** normalizes IKE, SA, ESP, and AH state.
5. The **Feature / State Engine** organizes normalized state into 100-millisecond observation windows.
6. The **Correlation & Assessment Core** combines observed state with configured baselines to perform:
   - Expected-versus-observed correlation
   - Drift detection
   - Fundamental IPsec security assessment
7. Security findings and supporting evidence are evaluated by the **ML / XAI Engine**, which uses random-forest classification and SHAP-based explanations.
8. **Mission Context** contributes asset and mission profiles so findings can be interpreted according to operational importance.
9. The **Cross-Signal Disagreement** component compares assessment signals and produces contextualized risk.
10. The **Evidence / Audit Layer** records verified findings, JSONL events, hash-chain integrity data, and chain-of-custody information.
11. **Gemini / AI** produces explanations, while the **Response / Policy** component generates recommended actions.
12. The **Sentinel Dashboard** presents traffic, findings, drift, evidence, explanations, and recommendations.
