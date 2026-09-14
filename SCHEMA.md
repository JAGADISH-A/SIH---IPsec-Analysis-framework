# Dataset artifact schema (v1)

This document is the data contract for the Module 5 dataset artifacts. The
authoritative implementation is `controller/dataset_artifacts.py`; if any value
below disagrees with the code, the code wins and this file must be updated.

Versions:

- `dataset_schema_version = "v1"` — schema of one staged / finalized
  successful-sample record.
- `feature_schema_version = "v1"` — schema of the 54-column feature record.

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

64 columns total: 10 linkage / ground-truth columns followed by the 54 feature
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

Feature columns (positions 11-64), all derived by `controller/features.py`:

Int32 (14): `packet_count`, `total_bytes`, `min_packet_size`,
`max_packet_size`, `unique_packet_size_count`, `outbound_packet_count`,
`inbound_packet_count`, `outbound_bytes`, `inbound_bytes`, `burst_count`,
`burst_count_10ms`, `burst_count_50ms`, `burst_count_200ms`.

Double (40): `mean_packet_size`, `packet_size_std`, `packet_size_p10`,
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
`mean_burst_packets_200ms`.

## metadata.jsonl record

One JSON object per line, one per successful sample. Shape:

```json
{
  "dataset_schema_version": "v1",
  "feature_schema_version": "v1",
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
  "ike_version": "v2",
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
  "features": { "<54 feature columns>" }
}
```

Ground truth in a record (`security_posture`, `traffic_profile`,
`security_posture`, `ipsec_configuration`) comes from the Module 2 plan sample
for the record's logical sequence; it is never recalculated from traffic.

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
- feature dict matches the 54-column schema exactly (types + keys).
- traffic and posture distributions match `traffic_quota` / `posture_planned`.
- the plan on disk still matches the run's stored `plan_fingerprint`.

Any violation writes `finalization.json` with status `FAILED` and leaves the
last valid `features.parquet` / `metadata.jsonl` untouched.