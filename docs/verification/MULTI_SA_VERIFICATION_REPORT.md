# Multi-SA Passive Correlation — Verification Report

**Date:** 2026-09-27
**Branch:** `feature/security-assessment` (no commit made)
**Baseline preserved:** 1689 → 1726 passing tests, subtest count unchanged at 1708

---

## 1. Scope

Extend the testbed's correlation path so that a gateway holding several
simultaneous IPsec SAs — all riding the same UDP/4500 transport — keeps each SA's
observations, 100 ms windows, ML result, risk assessment and evidence separate
and individually attributable, while the existing single-SA behaviour stays
exactly as it was.

Explicitly out of scope: no retraining, no replacement of the committed model,
no new message bus, no evidence-store or audit redesign, no enforcement of any
kind. The whole path is passive.

## 2. What was built

| Component | File | Purpose |
|-----------|------|---------|
| `SaIdentity` model | `correlation/models/sa_identity.py` | One identity per observation: `RESOLVED` / `AMBIGUOUS` / `UNKNOWN`, with reason, candidates and evidence fields |
| Resolver | `correlation/sa_correlation.py` | Two-pass deterministic mapping from observed events to SA identities; also reads a PCAP keeping the SPI |
| Per-SA windowing | `controller/ml_inference.py` | `iter_window_records(..., sa_scoped=True)` buckets by `(window, sa_group_id)` |
| Per-SA observed state | `correlation/ml/live_correlation.py` | `observed_states_per_sa()` builds one `ObservedState` per SA from the same state engine |
| SA view in state | `ebpf/ipsec_state_builder.py` | Additive `sa_snapshots`, `sa_groups`, `outer_endpoint_pairs`, `spi_less_esp_packets` |
| Identity propagation | `LiveFeatureWindow`, `MLResult`, `CorrelationIdentity`, `EvidenceRef` | Optional SA fields, omitted when unset |
| NAT-T capture reader | `controller/features.py` | `read_pcap_esp_with_spi()` decodes UDP/4500 + LINUX_SLL2 and extracts the SPI |
| Real testbed | `topology/multi-sa/`, `scripts/multi-sa-testbed.sh` | 3 strongSwan gateways, 2 simultaneous SAs, one shared UDP/4500 socket |
| Verification driver | `scripts/multi-sa-verify.py` | Runs the path over a real capture and prints per-SA vs blended |
| PCAP reader tests | `controller/test_pcap_esp_reader.py` | Native/NAT-T ESP decoding incl. the RFC 3948 non-ESP marker |

## 3. Design decisions and why

**Group by tunnel, not by directional SPI.** A NAT-T SA has one SPI per
direction, so keying windows by SPI would split one tunnel in two and halve the
traffic each RF window sees. `sa_group_id` is the bidirectional relationship, so
one window contains both directions — matching the distribution the committed
model was trained on. The per-direction child SA stays available as `sa_id`.

**The SPI selects per destination, not globally.** RFC 4303 makes an SPI unique
for a given destination. One SPI observed on two peers is therefore
`AMBIGUOUS` with both candidate `sa_id`s listed, never resolved to whichever peer
happened to be indexed first.

**IKE is a context, not an SA.** IKE carries no SPI, so its identity is
peer-level, with `kind=IKE_CONTEXT`, `joins_spi=false` and reason
`ike_carries_no_spi`. A report can never present a negotiation as an
established SA.

**Identity from evidence only.** The resolver never reads the plan, the
configuration or the expected state. UDP ports are recorded as
`transport_port` and never enter an identity. A peer is derived from the
observed capture point; when that is unknown the group falls back to the whole
canonical endpoint pair rather than guessing a side.

**Uncertainty gets its own bucket.** `AMBIGUOUS` and `UNKNOWN` never join a
resolved SA's window or observed state. They are counted and reported, because
silently attributing them is worse than admitting the gap.

**No retraining.** Every SA-scoped window is produced by the existing
`LiveFeatureExtractor` over that one SA's events. The committed artifact
(`traffic_rf_v1`, SHA-256
`1f31b76ebb56cba8ca91229fd1d83e3d374d4dae359c97f885c1f849d52cb938`) is used
unchanged, and the per-SA feature vectors are ordinary v2 vectors.

## 4. Real scenario

Plain Docker, because the containerlab topology needs root and
`sudo -n true` fails in this environment. The scenario itself is real: three
strongSwan 6.0.3 gateways, real IKEv2 negotiation, real ESP, real XFRM SAs.

```
msa-wan   192.168.100.0/24   gw-a .1   gw-b .2   gw-c .3
msa-lan-a 10.10.1.0/24       gw-a .1   host-a .10
msa-lan-b 10.10.2.0/24       gw-b .1   host-b .10
msa-lan-c 10.10.3.0/24       gw-c .1   host-c .10
```

`gw-a` terminates two SAs (`gw-a↔gw-b`, `gw-a↔gw-c`), both with `encap = yes`,
so both children are `TUNNEL-in-UDP` on one shared `0.0.0.0:4500` charon socket.

Verified SA state on `gw-a`:

```
gw-a-to-gw-b: #3, ESTABLISHED, IKEv2  local 'gw-a' @ 192.168.100.1[4500]
                                       remote 'gw-b' @ 192.168.100.2[4500]
  lan-a-to-lan-b: #1, INSTALLED, TUNNEL-in-UDP, ESP:AES_GCM_16-256
    in  c4fa158f   out c050903e   local 10.10.1.0/24  remote 10.10.2.0/24
gw-a-to-gw-c: #2, ESTABLISHED, IKEv2  local 'gw-a' @ 192.168.100.1[4500]
                                       remote 'gw-c' @ 192.168.100.3[4500]
  lan-a-to-lan-c: #3, INSTALLED, TUNNEL-in-UDP, ESP:AES_GCM_16-256
    in  c608aa91   out c70f5f96   local 10.10.1.0/24  remote 10.10.3.0/24
```

Traffic was generated concurrently through both tunnels with deliberately
different profiles: small regular ICMP toward `host-b`, large 1200-byte UDP
datagrams toward `host-c`. Both children carried traffic simultaneously
(516 / 494 packets observed in the SA counters).

## 5. Evidence

| Artifact | SHA-256 | Size |
|----------|---------|------|
| `results/observed-state/multi-sa/multi-sa.pcap` | `e4c1dbd4f767f6ba11ebfa31d376328322b64a4ecb8085eba0f1401196525d13` | 6,925,064 bytes |
| `results/observed-state/multi-sa/verification.json` | (regenerated by the script) | 1,098 bytes |
| `results/datasets/acc-eng-02/staging/plan.json` | existing, unmodified | 1,875 bytes |
| RF artifact | `1f31b76ebb56cba8ca91229fd1d83e3d374d4dae359c97f885c1f849d52cb938` | unchanged |

Capture taken on the monitored gateway with
`tcpdump -i any -s 0 -U -w /tmp/multi-sa.pcap 'udp port 4500 or udp port 500'`.
12,624 ESP frames; `results/` is git-ignored and was not modified or committed.

Decoded SPIs — four child SAs across two peers, all on UDP/4500:

| Source | Destination | SPI | Frame len | Packets |
|--------|-------------|-----|-----------|---------|
| 192.168.100.1 | 192.168.100.2 | `0xc68118c9` | 168 | 4288 |
| 192.168.100.2 | 192.168.100.1 | `0xcb424e6e` | 168 | 4288 |
| 192.168.100.1 | 192.168.100.3 | `0xc054b297` | 1312 | 4004 |
| 192.168.100.3 | 192.168.100.1 | `0xce568814` | 660 | 44 |

These match the strongSwan SA counters exactly.

## 6. Result — per-SA resolution

```
sa:esp:192.168.100.2   spis=[0xc68118c9, 0xcb424e6e]  packets=8576
sa:esp:192.168.100.3   spis=[0xc054b297, 0xce568814]  packets=4048
indexed_sa_count=4  peer_protocol_groups=2  unique_spis=4  unidentifiable_events=0
```

Both directions of each tunnel collapsed into one group, the two tunnels stayed
separate, and no frame was left unattributable.

## 7. Result — windows and packet accounting

| | Count |
|---|---|
| SA-scoped windows | **841** |
| Merged windows (single-SA path) | 446 |
| `sa:esp:192.168.100.2` | 446 windows, 8576 packets |
| `sa:esp:192.168.100.3` | 395 windows, 4048 packets |
| **Attributed / captured** | **12624 / 12624** |

Per-SA attribution accounts for every packet exactly once — nothing lost,
nothing double-counted, and the blended window count is strictly lower than the
sum of the per-SA counts, which is the blending itself.

## 8. Result — ML per SA, model unchanged

Committed `traffic_rf_v1`, not retrained, `authoritative=false` retained:

| SA group | Windows | RF class |
|----------|---------|----------|
| `sa:esp:192.168.100.2` (ICMP traffic) | 446 | `icmp` |
| `sa:esp:192.168.100.3` (bulk traffic) | 395 | `video` |

0 ML errors. Each SA is classified 100% consistently, and the two classes
differ.

**The counterfactual.** The same capture through the pre-existing single-SA path
(446 merged windows):

| Class | Windows |
|-------|---------|
| `video` | 210 |
| `web` | 185 |
| `icmp` | 51 |

The blend reports no class consistently, and invents `web` — a class present
in neither tunnel. This is the concrete harm the feature removes.

## 9. Negative and ambiguity coverage

`tests/test_sa_correlation.py`, 37 tests. Behaviours pinned:

| Case | Result |
|------|--------|
| SPI `0` (parity harness / failed parse) | `UNKNOWN no_spi_available`; no SPI state created |
| Missing outer endpoints | `UNKNOWN no_outer_endpoints`, `kind=UNRESOLVED` |
| One SPI on two peers | `AMBIGUOUS spi_reused_across_peers`, 2 candidates, no `sa_id` |
| No-SPI traffic, 2 SAs on one peer | `AMBIGUOUS multiple_sas_on_peer`, 2 candidates |
| Ambiguous / unknown traffic in a window | own record; never merged into a resolved SA |
| SPI reused across peers | its own observed state; the resolved SA does not claim it |
| UDP/4500 in identity | never present in `sa_id` / `sa_group_id`; kept as `transport_port` |
| IKE | `kind=IKE_CONTEXT`, `joins_spi=false`, `spi=None` |
| IKE vs ESP group | never the same group |
| Capture point sorts higher than the peer | peer is still the far side |
| No capture point | `peer=None`, group falls back to the endpoint pair, no guess |
| Same capture bound to two SAs | two distinct `evidence_id`s |
| Cross-SA leakage | SA-A's observed state contains none of SA-B's SPIs or counts |
| Bridge/controller contract | SA never enters the strict controller RF record |
| Record without `sa_identity` | loads as `UNKNOWN` |
| Bare identity round-trip | `SaIdentity.from_dict(x.to_dict()) == x` |
| State engine legacy keys | flat `spis` and every existing snapshot key unchanged |

NAT-T capture decoding, `controller/test_pcap_esp_reader.py`:

| Case | Result |
|------|--------|
| Native ESP, IPv4 and IPv6 | SPI read |
| UDP/4500, **no** non-ESP marker (strongSwan) | SPI read |
| UDP/4500, **with** RFC 3948 marker (other peers) | same SPI — regression test for §10.2 |
| UDP/500 and other ports | not decoded as ESP |
| `LINUX_SLL2` (276), raw IPv4 (101), raw IPv6 (127) | decoded |
| Unsupported link type | `ValueError` |
| Truncated ESP header | frame kept, `spi=None` — never a fabricated value |
| Non-ESP traffic | skipped, not reported |
| Records out of file order | returned in time order |

## 10. Defects found and fixed

Two real defects were found while building this, both of which would have caused
silent, plausible-looking wrong answers rather than loud failures. They are
recorded here because the character of each one is the reason the surrounding
tests were written the way they are.

### 10.1 Audit payload renumbering (backward-compatibility regression)

The first implementation emitted the new `sa_group_id` / `sa_id` keys
unconditionally. Because an `EvidenceRef` travels inside the audit event payload
and the audit `event_id` is derived from that payload, this renumbered every
reference recorded before SA correlation existed. A valid journal then failed
its own integrity check:

```
event_id 'audit-1919b1c91f2363707e0395634bd7241d' does not match the event
content (expected 'audit-a858b0226e9a483af493f9be60dcc611')
```

Fix: the SA keys are emitted **only when set** — in
`EvidenceRef.to_dict`, in `EvidenceRef.identity_payload`, and in
`CorrelationIdentity.to_identity_payload`. `_ml_ref` and `_observed_ref` already
enumerated their fields and were never affected.

Result: a pre-SA identity keeps its original `event_id`, a pre-SA reference
keeps its original `evidence_id`, and a persisted audit chain still verifies.
This is now pinned by tests.

### 10.2 RFC 3948 non-ESP marker misread (silent SA failure)

`read_pcap_esp_with_spi` decoded UDP/4500 but read the SPI at a fixed offset
directly after the UDP header, even though its own comment said the non-ESP
marker must be skipped — it built the payload slice and then ignored it:

```python
# A non-ESP marker precedes the header on a NAT-T datagram; skip it.
payload = data[udp_offset + 8:]
return ip_total, src, dst, _esp_spi(payload, 0)   # <-- offset 0, marker not skipped
```

RFC 3948 §4.2 allows a four-byte zero marker before the ESP header on a
UDP/4500 datagram. It is optional and peers differ: the strongSwan in this
testbed omits it, several other implementations emit it.

The failure mode is the reason this mattered. For a marker-emitting peer every
frame is read as **SPI 0**, which `SaIdentity` treats as *no SPI evidence*, so
the entire tunnel degrades to `UNKNOWN no_spi_available` and the multi-SA
resolution this feature exists for quietly does not happen. No exception, no
log line — just an unresolved SA and a report that looks normal. The module's
pre-existing IKE reader already handled the marker correctly on the same
transport, so the ESP path was also simply inconsistent with its own convention.

Fix: `_natt_esp_start()` detects the marker (a zero first word) and skips it,
mirroring `_ike_udp_common`. Coverage: `controller/test_pcap_esp_reader.py`,
16 tests. The three marker tests were confirmed to fail against the pre-fix
reader and pass after it.

Backward compatibility of the fix was verified against the real capture: strongSwan
omits the marker, so all 12,624 frames decode to byte-identical SPIs with zero
SPI-0 values, unchanged by the patch.

## 11. Test results

| Suite | Result |
|-------|--------|
| New: `tests/test_sa_correlation.py` | **37 passed** |
| New: `controller/test_pcap_esp_reader.py` | **16 passed** |
| `controller/` + `ebpf/` | 574 passed, 15 skipped, 576 subtests |
| `tests/test_live_correlation_seam.py` + `test_audit_layer.py` | 107 passed, 78 subtests |
| `tests/test_governance_journal.py` + `test_audit_api.py` + `test_audit_layer.py` | 176 passed, 1132 subtests |
| **Full suite** | **1742 passed, 22 skipped, 10 warnings, 1708 subtests** (801 s) |

Baseline was 1689 passed / 22 skipped / **1708 subtests**. The subtest count is
unchanged, which is the evidence that no existing test or behaviour moved: the
53 extra passes are exactly the 37 SA-correlation tests plus the 16 PCAP-reader
tests.

## 12. Reproduction

```bash
# 1. real two-SA gateway (plain Docker; no root required)
scripts/multi-sa-testbed.sh up
scripts/multi-sa-testbed.sh status
scripts/multi-sa-testbed.sh traffic
scripts/multi-sa-testbed.sh capture
scripts/multi-sa-testbed.sh down

# 2. correlate the real capture, per SA vs blended
python scripts/multi-sa-verify.py \
    --pcap results/observed-state/multi-sa/multi-sa.pcap \
    --capture-ip 192.168.100.1 \
    --plan results/datasets/acc-eng-02/staging/plan.json \
    --endpoints a=192.168.100.1,b=192.168.100.2

# 3. tests
python -m pytest -q tests/test_sa_correlation.py
python -m pytest -q controller/test_pcap_esp_reader.py
python -m pytest -q
```

## 13. Limitations

1. **Single capture point.** Two gateways on opposite ends of one tunnel each
   report their own view; the two are never cross-checked. A disagreement
   between the two ends is not detected.
2. **Outer-address-based grouping.** A gateway whose peers present identical
   outer addresses cannot be separated by observation alone; such traffic is
   reported ambiguous rather than guessed.
3. **Rekeying rotates SPIs.** A long capture yields more child `sa_id`s while
   `sa_group_id` stays stable, so raw window counts are not comparable across a
   rekey without grouping.
4. **Identity is per-capture, not durable.** It is rebuilt from each capture
   and is not persisted across restarts.
5. **AH is implemented but not exercised in the real scenario.** The resolver
   and identity model handle `KIND_AH_SA` and there is no AH path in this
   topology; AH coverage is unit tests only.
6. **Evidence binding is by identity, not enforced by a cross-check.** SA
   scoping makes SA-A's and SA-B's references distinct ids, but the pipeline
   does not yet assert that a supplied reference's SA matches the window it is
   attached to. A caller passing a mismatched reference is not rejected today.
7. **Risk and XAI run per SA, but the policy is still global.** Findings are
   computed against the same plan-derived expectation for every SA, so a plan
   describing one tunnel will report the other as unmatched rather than
   evaluating it against its own expectation.
8. **`window_index` remains sequential per run**, not the absolute time bucket.
   It is deterministic and replay-stable, but it is not the bucket number, and
   two SA-scoped windows in the same bucket get different indices.
9. **The real scenario is IPv4/NAT-T only.** IPv6 and native (non-encapsulated)
   ESP are covered by unit tests and the existing parity harness, not by this
   Docker scenario.

## Files touched

**New**
- `correlation/models/sa_identity.py`
- `correlation/sa_correlation.py`
- `tests/test_sa_correlation.py`
- `controller/test_pcap_esp_reader.py`
- `scripts/multi-sa-testbed.sh`
- `scripts/multi-sa-verify.py`
- `topology/multi-sa/gw-{a,b,c}/swanctl/`
- `docs/architecture/MULTI_SA_CORRELATION.md`
- `docs/verification/MULTI_SA_VERIFICATION_REPORT.md`

**Modified**
- `controller/ml_inference.py`, `controller/features.py`
- `correlation/ml/live_correlation.py`, `correlation/ml/controller_bridge.py`
- `correlation/models/{features,identity,evidence,ml,__init__}.py`
- `correlation/audit.py`
- `ebpf/ipsec_state_builder.py`
- `docs/README.md`

No commit was made.
