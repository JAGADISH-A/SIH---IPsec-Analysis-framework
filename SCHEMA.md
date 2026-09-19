# Dataset artifact schema (v2)

This document is the data contract for the Module 5 dataset artifacts. The
authoritative implementation is `controller/dataset_artifacts.py`; if any value
below disagrees with the code, the code wins and this file must be updated.

Versions:

- `dataset_schema_version = "v1"` — schema of one staged / finalized
  successful-sample record.
- `feature_schema_version = "v2"` — schema of the 59-column feature record.

Feature-schema history:

- **v1** (64 feature columns) added per-exchange IKE counts
  (`ike_sa_init_count`, `ike_auth_count`, `ike_create_child_sa_count`,
  `ike_informational_count`) and the observed `ike_version`. These five were
  removed in **v2**: the live WAN-side XDP sensor classifies IKE / IKE-NAT-T
  by transport port and exposes a per-packet length but never parses the IKE
  payload header, so those five columns are not reproducible from the live
  feed at inference time. Training features must be obtainable by the live
  passive sensor, so they are excluded from the ML feature vector. The size /
  count IKE statistics remain (live-producible). The exchange breakdown is
  still available as provenance from any stored PCAP via
  `controller/features.read_pcap_ike`.

## Directory layout (one finalized run)

```
results/<dataset_run_id>/
  state.json                  # engine-run state (Module 1/3/4, authoritative)
  manifest.json               # derived human-readable summary (Module 1)
  plan.json                   # Module 2 plan (assets/plan.json)
  finalization.json           # Module 5 artifact-finalization status
  README.txt                  # run-level artifact documentation
  features.parquet            # feature table (one row per successful sample)
  metadata.jsonl              # one full JSON record per successful sample
  staging/
    successful_samples.jsonl  # durable source (append + fsync)
    staging-orphans.jsonl     # archived non-committed records (diagnostics)
    plan.json
  captures/<sequence>/
    <experiment_id>.pcap      # PCAP evidence for the successful attempt
  failures/<experiment_id>/   # failed/interrupted attempt records (Module 3/4)
```

`successful_samples.jsonl` is the only append-written file; `features.parquet`
and `metadata.jsonl` are produced exactly once, atomically, at finalization
time and are never used as append logs.

## features.parquet

69 columns total: 10 linkage / ground-truth columns followed by the 59 feature
columns. Arrow types are `string`, `int32`, or `double`.

| # | column | type |
|---|--------|------|
| 1 | `dataset_run_id` | string |
| 2 | `sequence` | int32 |
| 3 | `experiment_id` | string |
| 4 | `attempt_number` | int32 |
| 5 | `traffic_profile` | string |
| 6 | `security_posture` | string |
| 7 | `configuration_id` | string |
| 8 | `captured_at` | string (ISO-8601 UTC) |
| 9 | `pcap_path` | string (relative to run dir) |
| 10 | `feature_schema_version` | string |

Feature columns (positions 11-69), all derived by `controller/features.py`:

Int32 (17): `packet_count`, `total_bytes`, `min_packet_size`,
`max_packet_size`, `unique_packet_size_count`, `outbound_packet_count`,
`inbound_packet_count`, `outbound_bytes`, `inbound_bytes`, `burst_count`,
`burst_count_10ms`, `burst_count_50ms`, `burst_count_200ms`,
`ike_packet_count`, `ike_datagram_bytes`, `ike_min_packet_size`,
`ike_max_packet_size`.

Double (42): `mean_packet_size`, `packet_size_std`, `packet_size_p10`,
`packet_size_p50`, `packet_size_p90`, `packet_size_p95`, `packet_size_p99`,
`packet_size_entropy`, `small_packet_ratio`, `large_packet_ratio`,
`mean_inter_arrival_time`, `inter_arrival_time_std`, `min_inter_arrival_time`,
`max_inter_arrival_time`, `packets_per_second`, `bytes_per_second`,
`flow_duration`, `outbound_packet_ratio`, `inbound_packet_ratio`,
`outbound_byte_ratio`, `inbound_byte_ratio`, `outbound_mean_packet_size`,
`inbound_mean_packet_size`, `outbound_packets_per_second`,
`inbound_packets_per_second`, `outbound_packet_size_p10`,
`outbound_packet_size_p50`, `outbound_packet_size_p90`,
`outbound_packet_size_p95`, `outbound_packet_size_p99`,
`inbound_packet_size_p10`, `inbound_packet_size_p50`,
`inbound_packet_size_p90`, `inbound_packet_size_p95`,
`inbound_packet_size_p99`, `mean_burst_packets`, `mean_burst_duration`,
`burst_packet_ratio`, `mean_burst_packets_10ms`, `mean_burst_packets_50ms`,
`mean_burst_packets_200ms`, `ike_mean_packet_size`.

### Size semantics (L2 vs L3)

All size statistics are **L3**: they are computed from the outer-IP **total
length** (`ip_total`) of the captured ESP/IKE frame, never from the PCAP
`incl_len`. On the WAN-side mirror (pcap linktype 1, Ethernet) the incl_len is
the full L2 frame, so for every captured frame `incl_len = ip_total + 14`.
This is pinned by the regression test in `controller/test_features.py` against
`controller/testdata/wan_side_esp_ike_sample.pcap` (a verbatim prefix of a real
run capture). Small/large packet thresholds (300 / 1400 bytes) and all byte
totals use `ip_total`. `total_bytes`, `bytes_per_second`, `outbound_bytes` and
`inbound_bytes` therefore exclude the 14-byte Ethernet header.

### IKE statistics

IKE frames (UDP 500/4500) are reported separately from ESP: count, datagram
bytes and min/max/mean packet size. The per-exchange-type counts and observed
IKE version are intentionally **not** part of the feature vector (see the v2
note above).

## Live v2 feature record (JSONL)

The live bridge (`controller/live_features.py`) turns the WAN-side XDP event
stream into one such object per observation epoch, emitted as a JSONL line:

```json
{
  "feature_schema_version": "v2",
  "window_start_ns": 7648000000000,
  "window_end_ns": 7760200000000,
  "features": { "<the 59 feature columns>" }
}
```

Semantics:

- `feature_schema_version` is the same constant as the parquet column
  (`FEATURE_SCHEMA_VERSION`).
- `window_start_ns` / `window_end_ns` bound the aligned 100 ms windows
  covering the first / last event of the epoch (`0`/`0` when no events were
  observed). They are observation geometry, not ML features.
- `features` holds exactly the 59 columns with the exact same values the
  training extractor would produce for the same frames: `LiveFeatureExtractor`
  and `controller/features.py.extract_features` share the single computation
  `summarize_capture`. Labels, ground truth and provenance never appear inside
  `features`.

Live-only conversions:

- **L2 → L3**: XDP `len` is the captured L2 frame length; feature sizes are
  L3 `ip_total`, so the live extractor subtracts the 14-byte Ethernet header.
- **Direction**: outer src == capture-point address ⇒ outbound; outer dst ==
  capture-point address ⇒ inbound (the same rule as the offline extractor).
- **Input types**: ESP and IKE / IKE-NAT-T events contribute; AH and OTHER
  contribute to no feature column.
- **Empty epochs** produce an all-zero, schema-complete feature dict.

No feature in the v2 vector depends on ESP SPI, sequence numbers or inferred
IPsec state; the auditor's observed-state builder (`ebpf/ipsec_state_builder.py`)
is a separate consumer of the same event stream. CLI: `python -m
controller.live_features --events <jsonl> --output - --capture-ip
192.168.100.1`.

Offline/live parity is enforced by `controller/test_live_features.py`, which
reconstructs XDP events from real captures and asserts exact equality with
`extract_features` for all 59 features (fixture plus every capture of the
completed run `dataset-20260916-231246`).

## metadata.jsonl record

One JSON object per line, one per successful sample. Shape:

```json
{
  "dataset_schema_version": "v1",
  "feature_schema_version": "v2",
  "status": "SUCCESS",
  "dataset_run_id": "<run id>",
  "sequence": 1,
  "experiment_id": "<run id>-exp-0001-attempt-01",
  "attempt_number": 1,
  "traffic_profile": "voip",
  "security_posture": "STRONG",
  "configuration_id": "<profile configuration id>",
  "mode": "tunnel",
  "address_family": "ipv4",
  "ike_version": 2,
  "ike_encryption": "aes128gcm16",
  "ike_integrity": "none",
  "ike_dh_group": "modp4096",
  "esp_encryption": "aes128gcm16",
  "esp_integrity": "none",
  "esp_dh_group": "modp4096",
  "pfs": true,
  "ipsec_configuration": { "mode": "...", "ike": {...}, "esp": {...} },
  "captured_at": "<ISO-8601 UTC>",
  "pcap_path": "captures/0001/<experiment_id>.pcap",
  "features": { "<59 feature columns>" }
}
```

Ground truth in a record (`security_posture`, `traffic_profile`,
`ipsec_configuration`) comes from the Module 2 plan sample for the record's
logical sequence; it is never recalculated from traffic. Flattened config
fields (`mode`, `address_family`, `ike_version`, `ike_encryption`,
`ike_integrity`, `ike_dh_group`, `esp_encryption`, `esp_integrity`,
`esp_dh_group`, `pfs`) are the experiment configuration (ground truth), not ML
input features. `ike_version` here is the **configured** IKE phase version
(e.g. `2`), a metadata field distinct from any observed-wire value.

## finalization.json

```json
{
  "dataset_run_id": "<run id>",
  "status": "COMPLETED | FAILED",
  "updated_at": "<ISO-8601 UTC>",
  "parquet_rows": 3,
  "metadata_records": 3
}
```

`status` records the artifact-finalization result only. On `FAILED`, an
`error` field carries the message and prior valid artifacts are preserved.
This file is separate from `state.json` (engine run status).

## Invariants enforced at finalization

- run status must be `COMPLETED`; `successful_samples == target_samples`.
- staged count == committed count == metadata/parquet row count.
- sequences are unique and cover exactly `1..target_samples`.
- every record matches its plan sample (posture, traffic profile,
  configuration id, full `ipsec_configuration`, flattened config fields).
- committed experiment ids and `pcap_path` references resolve to files.
- feature dict matches the 59-column schema exactly (types + keys).
- traffic and posture distributions match `traffic_quota` / `posture_planned`.
- the plan on disk still matches the run's stored `plan_fingerprint`.

Any violation writes `finalization.json` with status `FAILED` and leaves the
last valid `features.parquet` / `metadata.jsonl` untouched.