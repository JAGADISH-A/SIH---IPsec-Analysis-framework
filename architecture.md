# IPsec Analysis Framework Architecture

```mermaid
flowchart TD
    A[Dataset Traffic] --> B[IPsec / StrongSwan Testbed]

    B --> C[Live Path]
    B --> D[Evidence Path]

    C --> E[eBPF / XDP]
    D --> F[PCAP]
    F --> G[TShark / Zeek]

    E --> H[IKE / ESP / AH]
    H --> I[IKE State]
    H --> J[ESP/AH Metadata]

    I --> K[IPsec State Engine]
    J --> K
    G --> L[Parser / Feature Engine]
    K --> L

    L --> M[100-ms Windows]
    M --> N[ML / AI Engine]

    N --> O[Traffic Type Classification]
    N --> P[Anomaly Detection]

    O --> Q[Expected vs Observed Correlation]
    P --> Q

    Q --> R[Risk Engine]
    Q --> S[XAI]

    R --> T[Audit Layer<br/>JSONL + Hash Chain]
    S --> T

    T --> U[Response / Policy]
    T --> V[Evidence<br/>PCAP Reference]

    U --> W[Analyst Approval]
    W --> X[XDP Action]
    X --> Y[Dashboard]
```

## Architecture Flow

1. **Dataset Traffic** enters the IPsec / StrongSwan testbed.
2. Traffic is processed through two paths:
   - **Live Path:** eBPF / XDP captures IKE, ESP, and AH information.
   - **Evidence Path:** PCAP data is analyzed using TShark and Zeek.
3. The live path extracts IKE state and ESP/AH metadata for the **IPsec State Engine**.
4. State and evidence data are combined by the **Parser / Feature Engine**.
5. Features are organized into **100-millisecond windows**.
6. The **ML / AI Engine** performs:
   - Traffic type classification
   - Anomaly detection
7. Results are compared through **Expected vs. Observed Correlation**.
8. The **Risk Engine** and **XAI** components support explainable risk assessment.
9. The **Audit Layer** records JSONL events with a hash chain for integrity.
10. The system generates response policies and evidence references.
11. An analyst approves the response before an **XDP Action** is applied.
12. Results and system status are displayed on the **Dashboard**.
