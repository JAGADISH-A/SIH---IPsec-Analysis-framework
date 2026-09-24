# Dataset V2 Regeneration & Validation Report

- Date: 2026-09-23
- Scope: deterministic regeneration of the canonical ground-truth dataset
  `results/datasets/dataset-20260916-231246` (5 samples, one per security
  posture band) under the current **v2 / 59-column** feature schema, plus
  verification of the regenerated artifacts against both the offline
  `features.extract_features` path and the live `LiveFeatureExtractor` path.
- ML scope: **no model was implemented, trained, or run.** This is a
  dataset-integrity operation only.

## 1. Purpose

Module 1, as delivered, stored the dataset under the **v1** feature schema
(64 feature columns). The feature pipeline has since been re-specified to the
**v2** schema (59 columns: five v1 IKE-exchange columns were removed and the
remaining 59 retained). Because `normalize_feature_record` hard-enforces the
v2 schema on every `finalize_dataset` / validation path, the persisted dataset
was no longer in agreement with the live feature path. This report documents:

1. the in-place, deterministic regeneration of the dataset at v2,
2. per-sample equivalence against both feature paths, and
3. schema-shape verification of `metadata.jsonl` and `features.parquet`.

## 2. Decision: in-place regeneration from preserved PCAP evidence

The original run captured real Docker-in-containerlab topology traffic and
preserved the raw evidence in `results/datasets/<run>/captures/NNNN/<experiment_id>.pcap`.
A live lab re-run was therefore **not** required: every feature row is fully
derived from its PCAP plus

- capture IP anchor (direction of flow) = `capture_facing(mode, address_family)[1]`
  (tunnel/ipv4 -> `192.168.100.1`, the gw-a WAN address), and
- nominal duration = `traffic_model.duration` (30.0 s).

The regeneration re-finalized the **same run id** (instead of minting a new
run) because:

- `experiment_id`s embed the run id; changing run id would break the
  `parse_experiment_id(experiment_id) == (run.id, seq, attempt)` invariant
  enforced by `validate_final_dataset`,
- the Module 2 plan, labels, and committed IPsec configurations are unchanged,
- the staging log rewrite is a controlled, one-time migration (see 3.3).

## 3. Method

### 3.1 Rebuild tool

New module `controller/dataset_rebuild.py` (CLI `--run-id`, `--results-root`,
`--no-write`, `--verify-only`):

- `regenerate_run`: for every sample in the stored Module 2 plan, re-derives
  the 59 v2 features from the preserved PCAP, builds the full v2 record
  (`validate_final_dataset` in memory first), then persists via
  `rewrite_staging` + `finalize_dataset`.
- `verify_live_parity`: re-runs the **offline** feature path
  (`features.extract_features` with the per-sample capture IP and nominal
  duration) and the **live** feature path
  (`live_features.iterate_capture_as_live_events` -> `extract_record` with the
  same anchor/duration) for every row, and — when verifying materialized
  state — checks `features.parquet` shape and the `feature_schema_version`
  linkage column.

### 3.2 Review of extraction parameters

- Per-row capture IP: `capture.capture_facing("tunnel", "ipv4")[1]` =
  "192.168.100.1" (matches the pattern at `quality.py:341,346`).
- Per-row nominal duration: 30.0 s (constant across all five samples;
  `traffic_model.duration`).

### 3.3 Staging migration

`controller/dataset_artifacts.py` gained a public `rewrite_staging(run, records)`
(atomic tmp + fsync + replace) used by both the new rebuild tool and the
existing `_rewrite_staging_without` path. The staging log
`staging/successful_samples.jsonl` was migrated from v1 (64 cols) to v2 (59 cols)
so that any later `finalize_dataset` re-run stays converged on v2.

## 4. Plan snapshot (unchanged ground truth)

- Run: `dataset-20260916-231246`, planner v1, dataset schema v1 (kept).
- `target_samples = 5`, one per posture band; configuration seeds are unique
  per band (`posture_unique_configuration_count` = 1 each, `reuses = 0`).
- Catalogue (Module 2): 384 candidates -> 192 accepted across bands
  (STRONG 12, GOOD 44, MEDIUM 52, WEAK 48, WORST 36).
- Samples: mode tunnel / ipv4; IKEv2 aes256/sha256/modp2048; ESP varies
  by band (aes128gcm16 pfs4096 -> aes128cbc+sha256 no-pfs at WORST).
- Traffic (builtin `trafficgen.py`, deterministic, 30.0 s each): voip, video,
  messaging, email, web.

## 5. Before / after

| Artifact | Before | After |
|---|---|---|
| `metadata.jsonl` feature columns | 64 | 59 |
| `metadata.jsonl` `feature_schema_version` | v1 | v2 |
| `features.parquet` | 5 x 74 cols | 5 x 69 cols |
| `features.parquet` `feature_schema_version` col | v1 | v2 |
| `staging/successful_samples.jsonl` | v1 / 64 cols | v2 / 59 cols |
| IPsec configurations, postures, profiles | unchanged | unchanged |

Removed v1 columns (not part of v2): `ike_sa_init_count`,
`ike_auth_count`, `ike_create_child_sa_count`, `ike_informational_count`,
`ike_version`.

## 6. Per-sample parity (persisted == offline == live)

All regenerated rows were re-derived from the preserved PCAP and compared
byte-for-byte against (a) the persisted v2 metadata row and (b) the live
`LiveFeatureExtractor` record for the same frames.

| seq | posture | profile | esp pkts | ike pkts | cols | ver | offline | live | schema |
|---|---|---|---|---|---|---|---|---|---|
| 1 | STRONG | voip | 1499 | 4 | 59 | v2 | OK | OK | OK |
| 2 | GOOD | video | 7500 | 4 | 59 | v2 | OK | OK | OK |
| 3 | MEDIUM | messaging | 1607 | 4 | 59 | v2 | OK | OK | OK |
| 4 | WEAK | email | 237 | 4 | 59 | v2 | OK | OK | OK |
| 5 | WORST | web | 600 | 4 | 59 | v2 | OK | OK | OK |

`offline` = `extract_features(pcap, capture_ip=192.168.100.1, nominal_duration=30.0)`
matches the persisted row exactly (59 features, exact key set, equal values).
`live` = `LiveFeatureExtractor` round-trip on the same pcap frames matches the
persisted row exactly.

## 7. Schema validation (materialized state)

- `metadata.jsonl`: 5 records; `feature_schema_version` = `v2` for each;
  feature dict keys are exactly the 59 `FEATURE_KEYS` for each.
- `features.parquet`: 5 rows x **69 columns** = 10 linkage id columns
  (`PARQUET_ID_COLUMNS`) + 59 feature columns; `feature_columns_present=True`;
  `feature_schema_version` column = `v2` for all rows; natural-
  and experiment-id linkage intact.
- `finalization.json`: status `COMPLETED`, `parquet_rows=5`,
  `metadata_records=5`.

## 8. Commands run

```
# dry-run (deterministic preview, nothing written; exit 0)
.venv/bin/python -m controller.dataset_rebuild --run-id dataset-20260916-231246 --no-write

# real regeneration (staging rewrite + re-finalization; exit 0)
.venv/bin/python -m controller.dataset_rebuild --run-id dataset-20260916-231246

# materialized-state verification (metadata + parquet vs live path; exit 0)
.venv/bin/python -m controller.dataset_rebuild --run-id dataset-20260916-231246 --verify-only
```

Pre-change state was captured before the write (v1 / 74-col parquet) and
post-change state verified after (v2 / 69-col parquet); see section 5.

## 9. Tests

Safe, non-lab suite (core + dataset-generator regression), all passing:

```
Ran 241 tests in 0.819s   OK
```

(`controller.test_features`, `controller.test_live_features`,
`controller.test_dataset_artifacts`, `ebpf.test_window_aggregator`,
`ebpf.test_state_builder`, `controller.test_dataset_planner`,
`controller.test_dataset_run`, `controller.test_dataset_reuse`,
`controller.test_dataset_reuse_decision`, `controller.test_generator`,
`controller.test_dataset_timing`, `controller.test_ipsec_events`,
`controller.test_audit`, `controller.test_config`.)

Note: `controller.test_dataset_executor` is lab-bound (one test drives the real
`reset_and_deploy` + `destroy`, which needs the lab/sudo) and is excluded from
the safe batch by design, as in prior reports.

## 10. Invariants / limitations

Invariants preserved:

- Per-row identity: `experiment_id`, `configuration_id`, `security_posture`,
  `traffic_profile`, attempt number, dataset run id, capture path.
- Labels are **never derived from traffic**; they come solely from the Module 2
  plan. Values were unchanged.
- Repeatability: regeneration is deterministic; the dry-run and the written run
  produced identical per-row parity results.

Limitations:

- Regeneration does not alter the Module 2 plan (`planner_version: v1`,
  `dataset_schema_version: v1`) and does not mint a new run; it migrates the
  feature representation of the same evidence in place.
- Verification re-derives rows from the preserved captures; a fresh live-lab
  re-capture was intentionally not performed (see section 2) and would anyway
  produce near-identical but not bit-identical feature values.
- `results/` and `*.pcap` are gitignored; regenerated artifacts remain
  untracked as before. No git objects were created.

## 11. Outputs / repo state

- Modified: `controller/dataset_artifacts.py` (added `rewrite_staging`).
- New: `controller/dataset_rebuild.py` (rebuild + parity verification tool).
- New: `ML_LAYER_AUDIT.md` (Phase 1 audit deliverable).
- Regenerated (untracked, gitignored `results/`):
  `results/datasets/dataset-20260916-231246/{metadata.jsonl, features.parquet,
  staging/successful_samples.jsonl, finalization.json}`.

Nothing was committed. No ML model code was added, modified, or executed.