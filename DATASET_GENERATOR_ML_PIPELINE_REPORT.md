# Dataset Generator — ML Pipeline Validation Report

Date: 2026-09-19 · Branch `feature/testbed` @ `8b73af0` · No destructive live run performed.

This report validates the **Dataset Generator** as the labeled
training-data producer and resolves the open items left by
`DATASET_GENERATE_AUDIT_REPORT.md`. It is inspection + code-change only: no
Containerlab topology was destroyed or rebuilt, and the deployed WAN mirror /
XDP monitor context was left untouched. Evidence is drawn from the completed
runs `results/datasets/dataset-20260916-231246` (5 samples) and
`acc-eng-02` (2 samples), the live sensor diagnostics under
`results/observed-state/`, and the controller source.

## 1. Delivered decisions

| Item | Decision | Where |
|------|----------|-------|
| Feature schema | Authority = `controller/features.py`; declared schema = `controller/dataset_artifacts.py`; now **v2 = 59 columns** | `features.py:374`, `dataset_artifacts.py:84,115,182` |
| L2/L3 semantics | Training features are **L3** (`ip_total`); on the mirror `incl_len = ip_total + 14`; pinned by a regression test on real-capture evidence | `controller/test_features.py`, `controller/testdata/wan_side_esp_ike_sample.pcap` |
| IKE exchange features | **Removed** from the ML feature vector (`ike_version`, `ike_sa_init_count`, `ike_auth_count`, `ike_create_child_sa_count`, `ike_informational_count`) because the live XDP sensor cannot produce them | `features.py:479` (decision §3 below) |
| Labels / metadata | Ground truth (`security_posture`, `traffic_profile`, `configuration_id`) comes from the Module 2 plan; config fields stay in metadata, never in features | `dataset_artifacts.py:411` (no change needed) |
| SCHEMA.md | Rewritten to the authoritative v2 schema (was stale at 54 columns / v1) | `SCHEMA.md` |

## 2. Authoritative feature schema (v2)

- **59 feature columns** (17 int32 + 42 double), preceded by 10 linkage /
  ground-truth columns in `features.parquet` (69 columns total).
- Declared once in `FEATURE_COLUMNS`/`INT_FEATURES`; `FEATURE_KEYS` and
  `FLOAT_FEATURES` derive from them; `assert_feature_keys()` cross-checks
  every record against the live extractor output (`dataset_artifacts.py:238`),
  so the schema can never silently drift from the extractor.
- Verified against the real v1 parquet of `dataset-20260916-231246` (64
  feature columns at v1); all 5 rows are byte-level reproducible from their
  PCAPs with the extractor (see §9).

## 3. IKE feature fate — decision and evidence

**Decision: Option B (“remove from the ML feature schema”).**

Evidence gathered:

1. **Live sensor event schema** (`ebpf/xdp_monitor_common.h`,
   `ebpf/xdp_monitor.bpf.c`, and the real feed
   `results/observed-state/live_events_wan_side_new.jsonl`, 212 events):
   every event carries `timestamp, src, dst, spi, seq, sport, dport, len,
   type, proto`. `type` classifies IKE as UDP 500 and IKE-NAT-T as UDP 4500.
   Nothing parses the IKE payload header, so the observed IKE version and the
   per-exchange-type counts are **not obtainable** from the live feed.
2. **Training-v1 origin**: those five fields came from the training capture’s
   IKE header parse (`features.py` prior `_ike_summary`). Real captured IKE
   frames confirmed version=2 with SA_INIT on UDP 500 and AUTH on UDP 4500
   (strongSwan NAT-T hop), exactly 2 SA_INIT + 2 AUTH, and zero
   CREATE_CHILD_SA / INFORMATIONAL in every sample — near-zero ML variance.
3. **Extension cost**: producing the fields at inference would require adding
   IKE header parsing to the XDP path. That is a live-observation-path
   (sensor) change, which this milestone must not make: the WAN-side TAP /
   XDP architecture stays as deployed.

Consequence: `feature_schema_version` bumped **v1 → v2**; the five columns are
removed from `FEATURE_COLUMNS`, `INT_FEATURES`, `extract_features` output and
the parquet schema. All consumers were updated consistently
(`controller/features.py`, `controller/dataset_artifacts.py`,
`controller/test_dataset_artifacts.py`, `SCHEMA.md`). The exchange breakdown
remains recoverable from any stored PCAP via `read_pcap_ike`
(`features.py:154`) as provenance. The five remaining IKE statistics
(`ike_packet_count`, `ike_datagram_bytes`, `ike_min/max/mean_packet_size`) are
kept because they are derivable from the live feed (IKE/IKE-NAT-T window
counts + per-event `len`).

## 4. L2/L3 size semantics — verified and pinned

- All size features come from the **outer-IP total length** (`ip_total`):
  `_ipv4_fields`/`_ipv6_fields` read the IP length and total byte statistics
  are `sum(sizes)` of `ip_total` (`features.py:139,151,420-467`).
- On the WAN mirror (pcap linktype 1, Ethernet) every captured frame satisfies
  `incl_len = ip_total + 14`. Verified on all five real captures of
  `dataset-20260916-231246`: the `incl_len − ip_total` delta is exactly `14`
  for 100% of ESP and IKE frames (e.g. first ESP tuple
  `ts=1789580585.639280 incl=154 ip_total=140`).
- The live XDP `len` is the **L2** frame length (`data_end - data`); a real
  live ESP event shows `len:154`, i.e. the L2 counterpart of `ip_total=140`.
  A deploy-time live feature stage therefore normalizes with the +14 L2/L3
  relationship (next-milestone item; no training change needed because the
  training side already stores L3 totals and documents the wire relationship).
- **Regression test added** (`controller/test_features.py`, 8 tests): the
  fixture `controller/testdata/wan_side_esp_ike_sample.pcap` is a verbatim
  8-frame prefix of a real run capture. Tests pin `incl_len − ip_total = 14`
  for ESP and IKE, the exact known frame (`154`/`140`), that extracted features
  use L3 sizes (never `incl_len`), and direction anchoring.

## 5. Label / metadata separation (no leakage)

- ML input features = packet sizes, timings, counts, direction and IKE
  size/count of the **outer ESP+IKE stream** only. No plaintext payload, no
  inner IP, no process/generator identifiers.
- Ground-truth label = `security_posture` + `traffic_profile` (+
  `configuration_id`) resolved **from the Module 2 plan sample**, never
  recomputed from traffic (`dataset_artifacts.py:411-446`).
- Configuration provenance (`esp_encryption`, `esp_dh_group`, `pfs`, …) lives
  in `metadata.jsonl` and the parquet linkage columns and is **not** part of
  the ML vector. The metadata-level `ike_version` (configured IKE phase
  version, integer) is distinct from the removed observed-version feature.
- Verified on real records: label fields match the plan; the 5 v1 parquet
  rows trace to their metadata records and PCAP paths 1:1.

## 6. Dataset structure

- One finalized run produces (all inspected on the completed runs):
  `features.parquet` (atomic tmp+replace, produced once at finalization),
  `metadata.jsonl` (atomic), `captures/<seq>/<experiment_id>.pcap` (evidence),
  `staging/successful_samples.jsonl` (append+fsync durable source),
  `manifest.json`, `README.txt`, `finalization.json`.
- The dataset ZIP export contains exactly the four final artifacts
  (`dataset_artifacts.py:EXPORT_ARTIFACT_FILENAMES`); per-sample directories
  are provenance and excluded.
- 11 dataset runs exist under `results/datasets`; two are fully completed and
  were used as ground truth: `dataset-20260916-231246` (5 rows, all five
  posture bands, tunnel/ipv4) and `acc-eng-02` (2 rows, transport/ipv6,
  GOOD). A v2 end-to-end synthetic finalize was executed in a temp dir and
  produced a COMPLETED run with a 69-column `features.parquet` at
  `feature_schema_version = v2`.

## 7. Traffic classes

- Six profiles supported and emitted identically in `traffic.py` and
  `scripts/trafficgen.py`: `voip`, `video`, `messaging`, `email`, `web`,
  `icmp`; default duration 30 s (range 10–120 s); builtin and DITG backends.
- Real-run feature signatures are class-distinct (from the v1 parquet of
  `dataset-20260916-231246`):

| profile | packet size signature | direction (out/in pkt) |
|---|---|---|
| voip | uniform 244 B (1392+ ESP frames on wire) | 1.0 / 0.0 |
| video | uniform 1284 B | 1.0 / 0.0 |
| messaging | 108/192 B mix | 0.998 / 0.002 |
| email | bimodal 108/8300 B | 0.66 / 0.34 |
| web | 124/444 B | 0.60 / 0.40 |

  (The 5-sample run exercised voip/video/messaging/email/web; `icmp` is a
  first-class profile in the planner/catalogue.)

## 8. IPsec posture coverage

- Five deterministic bands via `posture_of_config` (`dataset_planner.py:85`):
  scoring = cipher family + key length + PFS + DH group →
  STRONG (≥11) / GOOD (≥9) / MEDIUM (≥6) / WEAK (≥4) / WORST (==3).
- The completed 5-sample run covered **all five bands**:
  STRONG `aes128gcm16 modp4096 pfs`, GOOD `modp3072`, MEDIUM `modp2048`,
  WEAK `modp2048 no-pfs`, WORST `aes128cbc+sha256 no-pfs`.
  `configuration_id` encodes `mode-family-encryption-integrity-dh-pfs`
  (`dataset_planner.py:108`). Runtime categories include `GCM null-integrity`
  vs `CBC+HMAC` frameworks.
- The planner is deterministic, posture-aware, rotates quotas per band and
  pins its output with a plan fingerprint that finalization re-validates.

## 9. Reproducibility and quality checks

- **Deterministic extraction**: `extract_features` is a pure function of the
  PCAP, `capture_ip` and `nominal_duration`. Verified on all 5 real samples of
  `dataset-20260916-231246`: re-running the extractor on the stored PCAPs
  reproduces the persisted feature rows exactly (64/64 keys at v1, 0 diffs).
  The 59 v2 common columns are computed identically.
- **Schema versioning for reproducibility**: the `feature_schema_version`
  linkage column distinguishes v1 (64-col) from v2 (59-col) artifacts; old
  runs remain readable and are not rewritten.
- **Quality checks** (`controller/quality.py` + finalization invariants in
  `validate_final_dataset`): frame mix is ESP-only or IKE+ESP; NaN/negative /
  zero-variance feature rejection; label==profile agreement; crypto-rule
  checks (GCM null-integrity vs CBC+HMAC); metadata–feature agreement; PASS-only
  aggregates; counts/sequences/plan-fingerprint/PCAP-reference invariants.
- Posture and traffic distributions are exposed by the API results endpoint.

## 10. Live-feed parity for the v2 vector

The v2 feature vector is the set that the live WAN-side sensor can produce in
principle:

| v2 feature group | live feed primitive |
|---|---|
| counts, bytes, size stats | per-window `esp_packets`, `ike_packets`, `ike_nat_t_packets`, `total_bytes`, min/max/avg size (100 ms windows, 2064 windows + 212 events observed in the live feed) |
| IKE count/size stats | IKE/IKE-NAT-T window counts + per-event `len` |
| direction | `packets_a_to_b` / `b_to_a`, `bytes_a_to_b` / `b_to_a` |
| timing / rates | `packets_per_second`, `bytes_per_second`, inter-event timestamps |
| burst structure | event timestamps gated at 10/50/200 ms (windows are 100 ms) |

The remaining work — a live feature stage that mirrors `extract_features` over
the XDP window/event stream with the +14 normalization and a defined
windowing policy — is a downstream deployment milestone, not a dataset
generator defect.

Caveats recorded (no action in this milestone): the live sensor classifies
UDP 4500 as IKE-NAT-T (which also covers ESP-in-UDP in real NAT deployments),
and it currently classifies only IPv4 outer frames; the retained IKE size/count
features and the direction features rely on those assumptions holding for
IPv4 tunnel/transport captures (the training side parses both IPv4 and IPv6).

## 11. Changes made in this milestone

- `controller/features.py` — `_ike_summary` emits no IKE version/exchange
  columns; removed the now-unused `IKEV2_EXCHANGE_*` constants; docstrings
  updated. Read `read_pcap_ike` still returns exchange provenance.
- `controller/dataset_artifacts.py` — `FEATURE_SCHEMA_VERSION = "v2"`;
  `FEATURE_COLUMNS` 64→59; `INT_FEATURES` 17; module/schema/validator
  docstrings updated.
- `controller/test_dataset_artifacts.py` — `feature_schema_version` assertions
  `v1→v2` (staged record + parquet row); `dataset_schema_version` stays `v1`.
- `controller/test_features.py` (new) + `controller/testdata/wan_side_esp_ike_sample.pcap`
  (new, verbatim 8-frame prefix of a real run capture) — L2/L3 and schema
  regression tests. 8/8 pass.
- `SCHEMA.md` — rewritten to the authoritative v2 contract (59 features, 10
  linkage columns, L2/L3 semantics, removed-column rationale, invariants).

## 12. Test evidence

- `controller.test_features`: 8 tests, OK.
- `controller.test_dataset_artifacts`: 52 tests, OK (includes v2 version
  assertions and end-to-end synthetic finalize).
- `controller.test_dataset_api` delegation/download/artifact subset: OK.
- `controller.test_dataset_planner`, `dataset_run`, `dataset_reuse`,
  `generator`, `dataset_timing`, `ipsec_events`, `audit`, `config`: 98 tests,
  OK.
- Manual end-to-end v2 finalize in a temp dir: COMPLETED, 3 rows,
  `features.parquet` = 69 columns, no removed IKE columns.
  (The full-controller `unittest discover` stalls on lab-bound modules in this
  environment — a pre-existing harness limitation unrelated to this change.)

## 13. Open items (next milestone, no change requested now)

1. Live feature-extractor stage mirroring `extract_features` over the XDP
   window/event stream, with the +14 L2/L3 normalization and a defined
   windowing policy.
2. Optionally recover observed IKE version/exchange at inference by parsing
   the IKE header in the (deploy-time) live stage; the training side already
   stores the exchange breakdown as PCAP provenance.
3. Schedule any new generation runs in a maintenance window (live generation
   destroys/redeploys the shared topology and holds `TESTBED_LOCK`), with
   target ≥ 25 samples for per-posture class balance.