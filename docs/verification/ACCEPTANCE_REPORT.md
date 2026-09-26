# Testbed Acceptance Report

Date: 2026-09-16
Scope: post-refactor audit, capture-filter ambiguity resolution, and a complete
testbed acceptance run covering manual + automated N experiments, tunnel/transport
modes, IPv4/IPv6, builtin/D-ITG traffic generators, and PCAP/encryption/recovery
evidence.

## 1. Audit findings and actions

### Capture-filter ambiguity (resolved)

Pre-refactor, multiple modules each carried their own capture-filter default.
`campaign` used `udp port 500 or udp port 4500 or esp or ah` (IKE incl.), while
`dataset_executor`, `experiment_runner`, `capture.start_capture`, `dataset`, and
`quality` fell back to `esp` only. This meant the dataset/engine path silently
captured a different packet set than the campaign path.

Resolution — one canonical constant owned by `controller/capture.py`:

```
DEFAULT_CAPTURE_FILTER = "udp port 500 or udp port 4500 or esp or ah"
```

All consumers reference the same object (identity verified at runtime):
`campaign` (re-export), `experiment_runner.RunOptions.capture_filter` (default),
`dataset_executor` (constant + CLI `--capture-filter` default + `load_attempt`
metadata fallback), `dataset.build_metadata` fallback, `quality` aggregation
fallback, and `capture.start_capture` default. ESP-only remains available as an
explicit per-run override. The dataset/engine default capture therefore now
includes IKE negotiation traffic exactly like the campaign path.

Supporting change: `quality.scan_frames` now returns a 5-tuple
`(total, esp, ike, non_esp, malformed)` and the plaintext audit flags only
unexpected (non-ESP, non-IKE) frames, matching `features`' first-class IKE
parsing (`read_pcap_ike`, `IKE_UDP_PORTS`).

### Other audit notes

- Engine step (prior): `controller/experiment_runner.py` is a generic repeated-
  experiment engine; `controller/dataset_executor.py` is the dataset adapter.
- Deferred (explicitly out of scope for this acceptance, no behavior change):
  features.csv/`append_aggregate` deprecation, features→parser module placement,
  SCHEMA.md column-drift note (54 vs 64). No action taken.

## 2. Environment

- docker daemon 29.1.3, reachable unprivileged (`docker` + `clab_admins` groups).
- containerlab 0.79.0; `sudo -n containerlab` / `sudo -n docker` work
  (NOPASSWD limited; arbitrary `sudo` requires a password).
- Images: `ipsec-test-host:24.04`, `ipsec-test-gateway:6.0.3`.
- D-ITG: vendored `ITGSend`/`ITGRecv`/`ITGDec` binaries in `vendor/ditg/`.
- StrongSwan within gateways provides swanctl IPC for SA inspection.

## 3. Acceptance evidence

### 3.1 Manual runs — executor path, builtin generator (Phase 1)

Driver: `/tmp/opencode/manual_accept.py`. All 4 PASS, each with traffic PASS.

| mode | AF | traffic | result |
|------|----|---------|--------|
| tunnel | IPv4 | web | PASS |
| tunnel | IPv6 | voip | PASS |
| transport | IPv4 | web | PASS |
| transport | IPv6 | voip | PASS |

### 3.2 Automated campaign N experiments (Phase 2)

`campaigns/campaign-acceptance.json`, run `acc-camp-01`, 4 experiments x 20s, builtin.
4/4 PASS (`acc-camp-01-exp-0001..0004`). Captures verified with
`quality.scan_frames`: ESP 413/5012/1012/1000, IKE 4 per experiment (2
IKE_SA_INIT + 2 IKE_AUTH), unexpected plaintext = 0. Metadata
`capture_filter` = canonical full filter.

### 3.3 Engine repeated run N (builtin, Phase 3)

`acc-eng-01`, target = 6, mixed tunnel/transport x IPv4/IPv6, all 6 traffic
profiles, `RunOptions(duration=20)`: **COMPLETED 6/6**
(`successful=6`, `attempted=6`, `failed=0`), finalized COMPLETED,
`validate_final_dataset = true`.

Artifacts: `features.parquet` (25911 B), `metadata.jsonl` (6 rows),
`captures/0001..0006`. Per-sample ESP 1012/5012/1012/169/412/206, IKE 4 each,
unexpected = 0. Topology/E2E reuse pairs: (1,2) tunnel, (3,4) transport, (5,6)
tunnel.

### 3.4 Engine repeated run (D-ITG, Phase 4a)

`acc-eng-02`, target = 2 (tunnel/ipv4 voip STRONG aes128gcm16; transport/ipv6
video GOOD aes256cbc), `generator=ditg`: **COMPLETED 2/2**, finalized
COMPLETED. ESP 992/4305, IKE 4 each, unexpected = 0.

### 3.5 Builtin vs D-ITG parity, live transport lab (Phase 4b)

`scripts/validate_traffic_backends.py`, transport/ipv4, 25s. **All gated checks
PASSED**: voip/video/messaging equivalent at the ESP layer (packets and bytes
within tolerance); email byte-volume matches (TCP segmentation differs); web is
report-only (D-ITG tracks the 2 pps model; builtin echo loop over-generates).

### 3.6 Encryption evidence (Phase 5)

Live transport lab, live SA inspection:

- swanctl: IKE SA `ESTABLISHED` (IKEv2, AES_CBC-256/HMAC_SHA2_256_128 / PRF_
  HMAC_SHA2_256 / MODP_2048, UDP 4500) and CHILD `INSTALLED, TRANSPORT,
  ESP:AES_CBC-256/HMAC_SHA2_256_128`.
- Kernel `ip -s xfrm state`: two ESP SAs (SPIs `c9fcb8f5` in / `c4fa74e1` out),
  256-bit AES-CBC keys installed, mode transport.
- Live counters: 563907 bytes in / 15950833 bytes out — encrypted data flowed.
- Tunnel mode: engine run logs showed `#5 ... INSTALLED, TUNNEL,
  ESP:AES_CBC-128/...` with ESTABLISHED IKE SA.
- PCAP layer: every capture contains ESP frames + IKE (SA_INIT/AUTH) with zero
  unexpected plaintext.

### 3.7 Recovery semantics through the engine (Phase 6)

Driver: `/tmp/opencode/recovery_accept.py` (in-process, real engine +
persistence + artifact collector, schema-valid features).

- Transient failure: sequence 1 attempt 1 fails → attempt 2 succeeds → sample
  committed (`rec-a-exp-0001-attempt-02`), run COMPLETED 2/2,
  `attempts_per_sequence={'1': 2, '2': 1}`. PASS.
- Budget exhaustion: sequence 1 always fails → run FAILED after 5 attempts, 5
  persisted failure records, 0 committed samples, staging empty. PASS.
- Integrity check (negative result is a PASS): a successful outcome carrying a
  schema-invalid feature record is refused by the commit path (ArtifactError)
  and counted failed, never fabricated — "success is never fabricated" holds.

## 4. Final test-suite gate

359 tests green: `python -m unittest controller.test_*` (325 via discovery +
34 in the two relative-import reuse modules run as a package). Discovery-only
loading of `test_dataset_reuse*` uses `from . import reuse`, which requires
package execution — a harness artifact, not a test failure.

## 5. Results locations

- `results/acc-camp-01-exp-*` — campaign experiments.
- `results/datasets/acc-eng-01/`, `results/datasets/acc-eng-02/` — engine runs
  (captures/, staging/, features.parquet, metadata.jsonl, finalization.json).
- `/tmp/opencode/` — acceptance drivers + transient recovery stamps.
- `bin/`-style helpers: `scripts/validate_traffic_backends.py`.

## 6. Outstanding (for explicit authorization only)

- Deprecate `features.csv` / `append_aggregate` (parquet is canonical).
- Move `read_pcap_*` feature-parsing into a parser module.
- Update SCHEMA.md column-count note (features now 64).