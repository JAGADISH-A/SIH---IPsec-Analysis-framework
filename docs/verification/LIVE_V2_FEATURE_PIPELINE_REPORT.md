# Live v2 feature pipeline report

Status: **implemented and unit-verified**; short real-lab run pending (section 15).

## 1. Purpose and scope (TRAINING vs LIVE)

- **Training (offline)**: `controller/features.py::extract_features` computes the
  59-column v2 feature record from the per-sample PCAP of the dataset run
  (`results/datasets/dataset-20260916-231246/...`). Label/ground-truth columns
  (posture, traffic profile, crypto config, call metadata) are added at dataset
  finalization and are **never** part of the ML vector.
- **Live (inference-time)**: the WAN-side mirror feeds the XDP sensor
  (`ebpf/xdp_monitor.c`), which emits one passive event per ESP/IKE frame. This
  milestone delivers the **live feature extraction bridge** that turns that
  event stream into the *exact same* v2 record the training pipeline would
  produce for the same frames — without any XDP redesign, IKE header parsing,
  payload inspection, decryption, or label/posture knowledge.
- **No ML**: this milestone performs zero model training, selection or scoring.

Both sides share one computation (section 5), so there is no semantic drift to
tune or forgive.

## 2. Pipeline architecture

```
gw-a WAN mirror (passive)
   |
   v  ebpf/xdp_monitor.c        -- per-packet event JSONL (shape in section 6)
   |
   +--> ebpf/xdp_window_aggregator.py   -- 100 ms windows (monitoring / audit /
   |                                        state geometry; unchanged)
   +--> controller/live_features.py     -- LiveFeatureExtractor
                           |
                           v
        {"feature_schema_version":"v2","window_start_ns":...,
         "window_end_ns":...,"features":{59 columns}}
```

`ebpf/ipsec_state_builder.py` remains the auditor's observed-state layer; it is
a *separate* consumer of the same event stream and is documented to stay
unchanged (section 3). No v2 feature depends on SPI/sequence/state, so the
feature bridge does not consult it.

## 3. Change-control and scope boundary

Touched in this milestone (only):

- `controller/features.py` — **non-behavioral refactor**: the compute was moved
  verbatim into a pure `summarize_capture(packets, ike_sizes, ...)`;
  `extract_features` is now a thin PCAP-reading wrapper. Verified identity by
  re-running all extractor regressions (section 14).
- `controller/live_features.py` — new live bridge (new code).
- `controller/test_live_features.py` — new tests (new code).
- `SCHEMA.md` — appended the live-record section.
- `LIVE_V2_FEATURE_PIPELINE_REPORT.md` — this report.

Explicitly **not** modified: topology / TAP provisioning, XDP sensor
(`xdp_monitor.bpf.c`, `xdp_monitor.c`, `xdp_monitor_common.h`), window
aggregator, state builder, StrongSwan config, audit layer, frontend/backend,
dataset generator, dataset artifacts schema (`FEATURE_SCHEMA_VERSION` stays
`"v2"`). No label/posture/plaintext knowledge is needed or used by the bridge.

## 4. The v2 feature contract

The 59 column names and their types are **imported** from
`controller/dataset_artifacts.py` (`FEATURE_COLUMNS`, `INT_FEATURES`/`FLOAT_FEATURES`,
`FEATURE_SCHEMA_VERSION`) — they are never re-declared in `live_features.py`, so
a schema change cannot silently desynchronize the live bridge (a schema test in
`test_live_features.py` re-pins this). `assert_feature_keys` is invoked on every
emitted record. The five v1 columns removed in v2 (`ike_version`,
`ike_sa_init_count`, `ike_auth_count`, `ike_create_child_sa_count`,
`ike_informational_count`) are rejected by a dedicated no-reintroduction test.

## 5. Single source of computation

`summarize_capture` (pure, in `controller/features.py`) is the only
implementation of the feature math. Both `extract_features` and
`LiveFeatureExtractor.features()` call it. Consequently, offline/live parity is
**structural**: identical inputs ⇒ identical record. The live layer only has to
(a) map events to the same `(ts_s, incl_len, l3_len, src, dst)` tuple shape the
PCAP readers produce, and (b) implement the L2→L3 conversion.

## 6. Live event input contract and L2→L3 conversion

Event dicts match `xdp_monitor.c` JSON output / `PacketEvent.from_dict`:

- `ts` (bpf ktime, ns), `type` ∈ {IKE, IKE-NAT-T, ESP, AH, OTHER},
  `src`/`dst` IPv4, `proto`, `len` (**L2**), `spi`/`seq` (ESP/AH) or
  `sport`/`dport` (UDP-class).

Conversion: `l3_len = len - 14` (Ethernet). The constant 14 is pinned by
`controller/test_features.py` on a verbatim real-capture fixture: every ESP and
IKE frame satisfies `incl_len = ip_total + 14`. ESP and IKE/IKE-NAT-T events
contribute; AH and OTHER contribute to none of the 59 columns (the offline
readers likewise never parse AH). Only IPv4 frames carry `src`/`dst` (the BPF
program classifies non-IPv4 as OTHER/ignored), which is exactly what a
classifier needs.

## 7. Per-feature mapping (59 features, v2)

Disposition: **A** = directly reproducible from the live event fields;
**B** = deterministic aggregation of the live event set (documented offline
formula reused verbatim). There are no C-gap features and nothing is fabricated.
"live calc" is identical to "offline calc" applied to `l3_len` and
`ts_s = ts/1e9`; the table states the source fields for clarity.

| # | feature | type | meaning | offline calc (= live calc on L3/seconds) | source fields | disp |
|--:|---------|------|---------|-------------------------------------------|---------------|------|
| 1 | `packet_count` | int | ESP frames | `len(read_pcap)` | type=ESP | A |
| 2 | `total_bytes` | int | sum of ESP L3 lengths | `sum(ip_total)` | len (ESP) | A |
| 3 | `mean_packet_size` | float | mean ESP L3 size | `statistics.mean` | len (ESP) | B |
| 4 | `packet_size_std` | float | stdev of ESP sizes | `statistics.stdev` | len (ESP) | B |
| 5 | `min_packet_size` | int | smallest ESP frame (L3) | `min` | len (ESP) | A |
| 6 | `max_packet_size` | int | largest ESP frame (L3) | `max` | len (ESP) | A |
| 7 | `packet_size_p10` | float | 10th-percentile size | linear interpolation | len (ESP, sorted) | B |
| 8 | `packet_size_p50` | float | 50th-percentile size | " | " | B |
| 9 | `packet_size_p90` | float | 90th-percentile size | " | " | B |
| 10 | `packet_size_p95` | float | 95th-percentile size | " | " | B |
| 11 | `packet_size_p99` | float | 99th-percentile size | " | " | B |
| 12 | `unique_packet_size_count` | int | distinct sizes observed | `len(Counter(...))` | len (ESP) | A |
| 13 | `packet_size_entropy` | float | Shannon entropy of sizes (bits) | `-Σ p·log2 p` | len (ESP) | B |
| 14 | `small_packet_ratio` | float | fraction with size < 300 | count/size | len (ESP) | B |
| 15 | `large_packet_ratio` | float | fraction with size > 1400 | count/size | len (ESP) | B |
| 16 | `mean_inter_arrival_time` | float | mean gap between ESP frames (s) | `statistics.mean(diff(ts))` | ts (ESP) | B |
| 17 | `inter_arrival_time_std` | float | stdev of gaps (s) | `statistics.stdev` | ts (ESP) | B |
| 18 | `min_inter_arrival_time` | float | smallest gap (s) | `min` | ts (ESP) | B |
| 19 | `max_inter_arrival_time` | float | largest gap (s) | `max` | ts (ESP) | B |
| 20 | `packets_per_second` | float | ESP frame rate (1/s) | `count / duration` | ts, count | B |
| 21 | `bytes_per_second` | float | ESP throughput (B/s) | `total_bytes / duration` | ts, len | B |
| 22 | `flow_duration` | float | observation span (s) | `max(ts[-1]-ts[0], 1e-9)` | ts (ESP) | A |
| 23 | `outbound_packet_count` | int | frames with outer src == capture point | count(src==cap) | src | A |
| 24 | `inbound_packet_count` | int | frames with outer dst == capture point | count(dst==cap) | dst | A |
| 25 | `outbound_bytes` | int | outbound L3 bytes | sum(out sizes) | src, len | A |
| 26 | `inbound_bytes` | int | inbound L3 bytes | sum(in sizes) | dst, len | A |
| 27 | `outbound_packet_ratio` | float | outbound frame share | out/(out+in) | src, dst | B |
| 28 | `inbound_packet_ratio` | float | inbound frame share | in/(out+in) | src, dst | B |
| 29 | `outbound_byte_ratio` | float | outbound byte share | outB/(outB+inB) | src, dst, len | B |
| 30 | `inbound_byte_ratio` | float | inbound byte share | inB/(outB+inB) | src, dst, len | B |
| 31 | `outbound_mean_packet_size` | float | mean outbound ESP size | `statistics.mean(out)` | src, len | B |
| 32 | `inbound_mean_packet_size` | float | mean inbound ESP size | `statistics.mean(in)` | dst, len | B |
| 33 | `outbound_packets_per_second` | float | outbound frame rate | out/duration | src, ts | B |
| 34 | `inbound_packets_per_second` | float | inbound frame rate | in/duration | dst, ts | B |
| 35 | `outbound_packet_size_p10` | float | 10th-pct outbound size | interpolation | src, len | B |
| 36 | `outbound_packet_size_p50` | float | 50th-pct outbound size | " | " | B |
| 37 | `outbound_packet_size_p90` | float | 90th-pct outbound size | " | " | B |
| 38 | `outbound_packet_size_p95` | float | 95th-pct outbound size | " | " | B |
| 39 | `outbound_packet_size_p99` | float | 99th-pct outbound size | " | " | B |
| 40 | `inbound_packet_size_p10` | float | 10th-pct inbound size | interpolation | dst, len | B |
| 41 | `inbound_packet_size_p50` | float | 50th-pct inbound size | " | " | B |
| 42 | `inbound_packet_size_p90` | float | 90th-pct inbound size | " | " | B |
| 43 | `inbound_packet_size_p95` | float | 95th-pct inbound size | " | " | B |
| 44 | `inbound_packet_size_p99` | float | 99th-pct inbound size | " | " | B |
| 45 | `burst_count` | int | bursts under default gate (50 ms) | maximal runs separated by > gate | ts (ESP) | B |
| 46 | `mean_burst_packets` | float | mean packets per burst | `statistics.mean(run sizes)` | ts (ESP) | B |
| 47 | `mean_burst_duration` | float | mean burst length (s) | `statistics.mean(run spans)` | ts (ESP) | B |
| 48 | `burst_packet_ratio` | float | share of frames inside bursts | in-burst / count | ts (ESP) | B |
| 49 | `burst_count_10ms` | int | bursts gated at 10 ms | same algo, 0.01 s gate | ts (ESP) | B |
| 50 | `mean_burst_packets_10ms` | float | mean burst size, 10 ms gate | " | ts (ESP) | B |
| 51 | `burst_count_50ms` | int | bursts gated at 50 ms | same algo, 0.05 s gate | ts (ESP) | B |
| 52 | `mean_burst_packets_50ms` | float | mean burst size, 50 ms gate | " | ts (ESP) | B |
| 53 | `burst_count_200ms` | int | bursts gated at 200 ms | same algo, 0.2 s gate | ts (ESP) | B |
| 54 | `mean_burst_packets_200ms` | float | mean burst size, 200 ms gate | " | ts (ESP) | B |
| 55 | `ike_packet_count` | int | IKE frames (UDP 500 + 4500) | count of IKE datagrams | type ∈ {IKE,IKE-NAT-T} | A |
| 56 | `ike_datagram_bytes` | int | total IKE L3 datagram bytes | `sum(ip_total)` | len (IKE) | A |
| 57 | `ike_min_packet_size` | int | smallest IKE frame (L3) | `min` | len (IKE) | A |
| 58 | `ike_max_packet_size` | int | largest IKE frame (L3) | `max` | len (IKE) | A |
| 59 | `ike_mean_packet_size` | float | mean IKE frame size (L3) | `statistics.mean` | len (IKE) | B |

Notes: sizes are L3 throughout; burst semantics are as in
`controller/features.py::_burst_stats` (runs of ≥ 2 packets, gap ≤ gate).

## 8. Windowing and observation-epoch semantics

- The 100 ms window aggregator is unchanged and remains the monitoring/audit
  time base (`window_index = ts // window_ns`).
- The live feature bridge works at **epoch** granularity: `LiveFeatureExtractor`
  accumulates every event of the epoch and, on `snapshot()`/`reset()`, emits one
  record covering the whole epoch (equivalent to the offline per-capture
  record). `--emit-every N` provides a simple periodic boundary for live loops.
- `window_start_ns`/`window_end_ns` are the aligned 100 ms boundaries of the
  first/last epoch event (both `0` for an empty epoch) — observation geometry,
  not ML features. `nominal_duration`, when supplied, reuses the offline
  densest-window logic so a live epoch can mimic the 30 s training window.
- Empty epochs emit an all-zero, schema-complete record (silence is detectable).

## 9. Output record format (JSONL)

One object per line. `features` contains exactly the 59 keys; labels,
ground-truth and provenance stay outside it:

```json
{"feature_schema_version":"v2","window_start_ns":7648000000000,
 "window_end_ns":7760200000000,"features":{<59 keys>}}
```

CLI: `python -m controller.live_features --events <jsonl> --output - --capture-ip 192.168.100.1`

## 10. Direction semantics

Same rule as offline: outer `src == capture_ip` ⇒ outbound; `dst == capture_ip`
⇒ inbound. All five ground-truth runs used the gw-a WAN address
`192.168.100.1`. Frames whose source is neither endpoint are counted in the
totals but never attributed (directional fields stay zero), matching
`_directional_sizes`. Direction never uses SPI, so no state builder is
required.

## 11. IKE block semantics

IKE (UDP 500) and IKE-NAT-T (UDP 4500) events merge into the single IKE block;
ESP events never appear in it. This mirrors the offline reader. Known nuance:
`xdp_monitor.bpf.c` labels **any** UDP-4500 datagram as IKE-NAT-T. In this
testbed strongSwan carries ESP as IP protocol 50 (observed `proto=50` in the
live feed), so the UDP-4500 frames are genuine IKE under NAT-T; if ESP-in-UDP
were ever introduced the sensor's IKE-NAT-T label would need revisit — no
change was made here (out of scope, sensor untouched).

## 12. Offline/live parity methodology and per-feature parity rules

Method: for a given capture, `iterate_capture_as_live_events` reconstructs the
`xdp_monitor.c` event stream verbatim (L2 `len = incl_len`, integer-ns `ts`),
feeds `LiveFeatureExtractor`, and compares **all 59 features** against
`extract_features` on the same capture.

- **Exact equality (every feature)**: applies in the parity harness because both
  sides consume the *same* frames and the same (reconstructed) integer-ns clock.
  `l3 = len - 14` is exact; nothing is approximated. The comparison is
  `assertEqual(dicts)`.
- **Deterministic tolerated difference (real deployments, timing features)**: a
  live XDP `bpf_ktime_get_ns()` clock and a pcap epoch clock differ by unknown
  skew; gap-derived fields (`mean/std/min/max inter-arrival time`,
  `packets_per_second`, `bytes_per_second`, `flow_duration`, burst stats, and all
  per-second rates) are therefore equal only to the feature's rounding precision.
  All of these are rounded to ≥ 3 decimals (rates/sizes) or 6 decimals (IAT /
  durations) in the shared code; timestamp reconstruction error here is < 1 µs,
  far below that precision, so the tolerance is formally **zero at the emitted
  precision** and the harness asserts strict equality.
- **Size/count/entropy/directional and IKE-count features**: exact under both
  clocks (they depend on `len`/`src`/`dst`/classification only).

The harness runs on the 8-frame real fixture and on all five real captures of
`dataset-20260916-231246` (both with and without `nominal_duration=30.0`).

## 13. Schema validation and backward-compatibility tests

`controller/test_live_features.py` (15 tests):

- schema: exactly 59 features, no dupes, `features == FEATURE_KEYS`; v2 version;
  int/float type citizenship; `assert_feature_keys` passes incl. empty epoch;
- no labels/provenance inside `features`; v1 IKE columns never reintroduced;
- L2→L3 conversion; direction anchored to capture point; unknown-source frames
  un-attributed; IKE block (500+4500) vs ESP separation; AH/OTHER excluded;
- window-boundary alignment and `reset()` epoch isolation;
- offline/live parity (fixture, fixture+nominal, 5 real run captures);
- CLI end-to-end emits valid single JSONL record.

Backward-compatibility re-runs (unchanged behavior):

- `controller/test_features` (8), `controller/test_dataset_artifacts` (52),
  `ebpf/test_window_aggregator` (19), `ebpf/test_state_builder` (25), plus the
  dataset-generator/planner/run/reuse/timing/ipsec-events/audit/config suites
  (98). All green.

## 14. Verification results

| check | result |
|---|---|
| test_features + test_dataset_artifacts + test_live_features + ebpf tests | 119/119 OK |
| dataset-generator regression suites (planner/run/reuse/generator/timing/ipsec_events/audit/config) | 98/98 OK |
| parity on real fixture (8 frames) | exact, 59/59 features |
| parity on 5 real run captures (with 30 s nominal window) | exact, 59/59 features |
| bridge smoke test on recorded live feed (`live_events_wan_side_new.jsonl`) | 212 events → 196 feature frames (192 ESP + 4 IKE-NAT-T), 16 OTHER excluded, v2 record emitted |

Recorded-feed smoke details: `packet_count=192`, `total_bytes=26880` (192×140),
`ike_packet_count=4` (all UDP 4500), outbound/inbound = 96/96,
`mean_packet_size=140`, `flow_duration=112.12 s`, span `7648000000000 .. 7760200000000`
ns; the matched window file has 2064 windows (2039 empty, 17 with ESP activity,
1 with IKE-NAT-T), consistent with the emitted record.

## 15. Real-lab verification (executed 2026-09-19) and open items

Short controlled on-testbed run performed on the deployed topology (up 22 h,
IKE SA ESTABLISHED, CHILD SA `#11` INSTALLED, 0 packets prior). Observation
surface used unchanged: the already-attached mirror sensor on `sensor:eth1`
(`prog/xdp id 234 name xdp_pass`, `xdpgeneric`, mtu 9500; the established feed
is written container-side to `/repo/xdp_events.jsonl`). No topology, TAP, XDP,
audit, state-builder, or Generator component was modified.

Commands (bounded IKE/ESP flow, seconds of traffic, no dataset campaign):

```
# 1. baseline + feed-liveness probe (2 packets of ping → +10 feed events)
docker exec clab-ipsec-sensor sh -c 'wc -l /repo/xdp_events.jsonl'          # 436

# 2. short authorized traffic
docker exec clab-ipsec-host-a ping -c 4 -W 3 10.10.2.10        # ESP a->b, 0% loss
docker exec clab-ipsec-host-b ping -c 4 -W 3 10.10.1.10        # ESP b->a, 0% loss
docker exec clab-ipsec-gw-a swanctl --rekey --child lan-a-to-lan-b   # IKE-NAT-T (UDP 4500)
docker exec clab-ipsec-host-a ping -c 3 -W 3 10.10.2.10        # ESP on rekeyed SAs

# 3. capture the 30 appended events, then pipeline
docker exec clab-ipsec-sensor cat /repo/xdp_events.jsonl | tail -n +447 > lab_events.jsonl
python -m ebpf.xdp_window_aggregator --input lab_events.jsonl --output windows.jsonl
python -m controller.live_features --events lab_events.jsonl --output features_record.jsonl --capture-ip 192.168.100.1
python -m ebpf.ipsec_state_builder --events lab_events.jsonl --output state_events.jsonl
python -m ebpf.ipsec_state_builder --windows windows.jsonl --output state_windows.jsonl
```

Observed results and evidence (`results/observed-state/lab-verify-20260919-143813/`):

- **XDP mirror reception on gw-a WAN addrs**: 30 events, sources only
  `192.168.100.1`/`192.168.100.2`; `ts` are kernel `bpf_ktime_get_ns`
  timestamps, `len` = L2 frame length (incl. 14-byte Ethernet header).
- **Classification correct**: 22 ESP (proto 50, `spi`/`seq` present), 4 IKE-NAT-T
  (`sport=dport=4500`), 4 OTHER (mirrored non-ESP, no `src/dst`, excluded).
- **Rekey observed end-to-end**: new SPIs `cbbd3555`/`ce95413a` replace
  `cd055378`/`c16b3ead` (swanctl before/after in `sas_before.txt`/`sas_after.txt`);
  state builder snapshot lists all 4 SPIs with direction/first-last sequence.
- **100 ms windows emitted**: 171 windows, `window_start_ns`/`window_end_ns`
  aligned to 100 ms boundaries; 11 ESP windows, 3 IKE-NAT-T windows, 1 OTHER
  window, 156 empty; per-window `unique_esp_spi_count`, `esp_sequence_delta`,
  pps/bps correct (aggregator: `events_consumed=30 windows_emitted=171
  events_dropped_late=0`).
- **Live v2 record**: 1 record, `feature_schema_version=v2`, exactly 59 feature
  keys, 56 nonzero. Highlights: `packet_count=22`, `total_bytes=3080`
  (22×140 = `len`−14 → L3 `ip_total`, L2→L3 confirmed on live frames),
  `mean/min/max/p50/p95/p99_packet_size=140`, outbound/inbound 11/11 (ratios
  0.5), `ike_packet_count=4`, `ike_datagram_bytes=1232`, `flow_duration=17.03 s`.
- **No label/posture metadata**: record keys are only `feature_schema_version`,
  `window_start_ns`, `window_end_ns`, `features` (59) — no training labels,
  posture, or run metadata. No plaintext payload: events carry only
  `ts/type/src/dst/proto/len/spi/seq/(sport/dport)`; the pipeline never parses
  IKE payloads or extracts application data.
- **Audit path intact** (read-only status): gw-a `audit-tap0` up, 1 ingress +
  1 egress mirror filter each, ingress/egress mirrors actively sending
  (405 pkt / 207 pkt counters) — undisturbed.
- **State builder functional**: `packets_seen=30`, `spis=4`, endpoints
  `a=192.168.100.1 b=192.168.100.2`, `tunnel_seen=true`, `active=true`,
  `esp_seen/ike_nat_t_seen=true`, `ike_seen/ah_seen=false`, per-SPI sequence
  bookkeeping and transitions correct (events and windows paths).
- **Existing tests still green** after the lab run:
  - core: `controller.test_features`, `controller.test_live_features`,
    `controller.test_dataset_artifacts`, `ebpf.test_window_aggregator`,
    `ebpf.test_state_builder` — 119/119 OK;
  - dataset-generator regression (planner/run/reuse/generator/timing/
    ipsec_events/audit/config) — 98/98 OK.

Limitations (honest reporting):

- 30-event bounded window (4 pings ×2 + rekey + 3 pings); no bursty/loaded
  traffic pattern was exercised live, so burst features are small-scale
  (`burst_count=11`, `mean_burst_packets=2`). Parity for extreme-size patterns
  rests on the fixture/capture parity tests, not this run.
- Session-level feature records: the run produced one feature record (the
  extractor's epoch spans the whole capture). Periodic emission/multi-epoch
  alignment is covered by `--emit-every` and windowed consumption but was not
  re-validated on live seconds-to-minutes windows here.
- `sport=4500` IKE-NAT-T labelling applies to any UDP-4500 datagram on the
  mirror (fine for this testbed: ESP is protocol 50, no NAT-T-encapsulated ESP).
- Full `unittest discover` still hangs on lab-bound modules; suites are run
  explicitly by module (as above).

Open items:

1. decide the epoch/periodic emit policy for the live consumer (e.g. align to
   generator runs) — `--emit-every` provides the hook;
2. no C-gap features exist, so nothing is blocked by sensor capability;
3. future live runs should exercise larger/burstier authorized flows and an
   N-second windowed (non-single-epoch) emission to strengthen §15 evidence.