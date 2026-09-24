# ML / Correlation Boundary (evidence path hand-off)

Status: **boundary described here; correlation itself is implemented on a
separate branch and is out of scope for this repository run.**

## Where the evidence path hands off to ML/AI

The passive observation path produces, at a fixed 100 ms granularity, the
records that a downstream correlator consumes.  The boundary is the
`ebpf/xdp_window_aggregator.py` output (`window_aggr.jsonl`):

    events -> 100 ms fixed windows -> [window records] -> correlation/ML

Two window producers exist and are verified against the same recorded
PCAPs (see `results/e2e-verification/parser/`):

| producer | artifact | semantics |
| --- | --- | --- |
| `ebpf/xdp_window_aggregator.py` | `window_aggr.jsonl` | fixed 100 ms windows, byte + packet + SPI/seq-sm
 metrics, per-direction (A_TO_B/B_TO_A), bounded-late reordering |
| `controller/live_features.py` (`LiveFeatureExtractor`) | `windows.jsonl` | epoch feature vector with 100 ms-aligned `window_start_ns`/`window_end_ns` boundaries (feature-schema v2) |

Verified on real captures:

- `tunnel/tunnel_v4_gwa_eth2.pcap`           -> 205 windows over the ~20 s burst
- `tunnel/tunnel_v6inner_gwa_eth2.pcap`      -> 199 windows
- `transport/live-reverify/hostc_eth1_live.pcap` -> 1911 windows (IKE + idle
  span; 15 late-reorder events dropped by the lookback window, designed
  behaviour)

## Boundary contract

1. **Observable only.** The window/feature layer never decodes ESP payloads;
   it consumes outer metadata (SPI, sequence, sizes, timing, direction).
2. **No policy in the window layer.** Windows carry statistics; decisions
   (risk scoring, alerting, XDP action) are made downstream in the
   correlation/ML layer (separate branch).
3. **Timing discipline.** `window_start_ns = (first_ts_ns // 100ms) * 100ms`.
   Feature records are validated for schema parity between live XDP and
   offline PCAP replay by `controller/test_live_features.py` (15 tests).
4. **Lineage for the ML stage.** The spectral, size and rate fields shipped to
   the correlator carry the same `feature_schema_version` and are produced by
   the *same* `summarize_capture()` used for the dataset/ML training pipeline
   (`controller/features.py`), so offline training and live inference agree.

## Explicitly out of scope (this run)

- Correlator/ML model implementation and its audit/response wiring.
- XDP reaction policy driven by correlated state (live-path reaction stays a
  separate concern gated behind the analyst-approval stage of the
  architecture).
- Zeek/live-path deep detection integration (Zeek remains evidence-path only).