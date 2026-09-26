# Milestone Report — IPsec Observed-State Construction Layer

Scope: **state construction only**. No ML, anomaly detection, classification,
risk scoring, XAI, expected-vs-observed correlation, response, mitigation,
policy enforcement, or backend/dashboard/audit integration was added.

The final output of this milestone is **OBSERVED IPSEC STATE**, not a score,
classification or prediction.

---

## 1. Files changed

New (state-construction layer):

| File | Purpose |
|------|---------|
| `ebpf/ipsec_state_builder.py` | Core observed-state model + thin JSONL CLI |
| `ebpf/test_state_builder.py` | 25 synthetic unit tests for the state model |

Reviewed / reused unchanged as inputs (already present, not redesigned):

| File | Role |
|------|------|
| `ebpf/xdp_monitor_common.h` | XDP ring-buffer event struct (unchanged) |
| `ebpf/xdp_monitor.bpf.c` | XDP classifier/observer (unchanged) |
| `ebpf/xdp_monitor.c` | userspace reader / `--json` mode (unchanged) |
| `ebpf/xdp_window_aggregator.py` | existing 100 ms aggregator + `PacketEvent` (unchanged) |

Runtime evidence (gitignored, under `results/observed-state/`):

- `live_events_pre_rekey.jsonl`, `live_events_full.jsonl`
- `live_windows_pre_rekey.jsonl`, `live_windows_full.jsonl`
- `live_state_from_events_{pre_rekey,full}.jsonl`
- `live_state_from_windows_{pre_rekey,full}.jsonl`

Only functional edit made to an existing state-layer file: added the explicit
`tunnel_seen` boolean to the snapshot (see §2).

## 2. State model / schema

`IPsecStateBuilder.snapshot()` emits one JSON object:

```
timestamp_ns, endpoints{a,b}, tunnel_seen,
active, observation_start_ns, last_packet_timestamp_ns, active_timeout_ms,
packets_seen, bytes_seen, packets_a_to_b, packets_b_to_a,
bytes_a_to_b, bytes_b_to_a,
ike_seen, ike_nat_t_seen, esp_seen, ah_seen,
observed_ike_activity,
last_ike_timestamp_ns, last_ike_nat_t_timestamp_ns,
last_esp_timestamp_ns, last_ah_timestamp_ns,
spis[], transitions[]
```

Per-SPI entry (`SpiState.snapshot`):

```
spi, direction, active,
first_seen_ns, last_seen_ns, packet_count,
first_sequence, last_sequence, highest_sequence, sequence_delta
```

Endpoints are configured once (`DEFAULT_ENDPOINTS` in `xdp_window_aggregator.py`)
and overridable via `IPsecStateBuilder(endpoints=...)` or `--endpoints`. The IP
addresses are not scattered through the code.

## 3. State transition model

Explicit, description-only labels (never verdicts):

```
NO_TRAFFIC (initial)  --IPSEC_TRAFFIC_OBSERVED-->  traffic observed
existing SPI set      --SPI_OBSERVED-->            new SPI observed
traffic continues     --ACTIVE-->                  recently active
no recent traffic     --INACTIVE-->                silent (no alert emitted)
```

Transitions are appended to `snapshot()["transitions"]` with timestamps;
`SPI_OBSERVED` carries the new SPI, its direction and the cumulative
`known_spis` set so a later layer can reason about rekey context.

## 4. How packet events / windows feed the builder

- `consume_event(PacketEvent)` — authoritative. Updates aggregate counters,
  protocol flags **and** per-SPI ESP state (SPI, direction, timestamps, packet
  count, sequence state).
- `consume_window(dict)` — aggregate only. Updates counters, direction totals
  and observed protocol flags. It deliberately does **not** derive per-SPI data
  from `unique_esp_spi_count`; the SPI list is left untouched (no invented data).
- Both call the same internal update helpers, so there is no duplicate logic.
- Core logic is transport/CLI independent: `.consume_event()`, `.consume_window()`,
  `.snapshot()`, `.reset()`. `main()` is a thin JSONL shell only, so recorded
  events can be replayed offline with no live XDP process.

## 5. SPI handling

- Map keyed by integer SPI (`dict[int, SpiState]`), no fixed/assumed value.
- Supports many SPIs concurrently. A new SPI never automatically deactivates or
  reclassifies an old one; old and new coexist (verified across a real rekey).
- Direction is inferred from the outer source endpoint and recorded per SPI.
- `active` per SPI is derived from `last_seen_ns` vs the configurable timeout.

## 6. Sequence handling

- 32-bit safe: `sequence_delta = (last - first) mod 2**32`, so one wraparound is
  a small forward step, not a huge jump.
- Per-SPI state is independent; a new SPI starting at 1 does **not** inherit the
  previous SPI's sequence. A reset on a newly observed SPI is not treated as an
  error.
- Only observations are stored (`first/last/highest_sequence`, `sequence_delta`)
  for later analysis. No gap/repeat/reset *detection* is implemented.

## 7. Active / inactive handling

- `STATE_ACTIVE_TIMEOUT_MS = 1000` by default; configurable in the constructor
  and via `--active-timeout-ms`. Never hard-coded at use sites.
- `active = (now_ns - last_packet_timestamp_ns) <= timeout`.
- Inactive is recorded as state/transition only; **no alert** is generated.

## 8. Unit-test results

Synthetic, no live network required:

```
$ .venv/bin/python -m unittest ebpf.test_state_builder ebpf.test_window_aggregator
Ran 44 tests in 0.005s
OK
```

25 state-builder tests cover all 18 required cases (empty state, first ESP,
A→B / B→A, IKE-NAT-T, ESP, AH, SPI first observation, repeated SPI, multiple
SPIs, rekey/SPI change, sequence progression, wraparound, no sequence
inheritance by a new SPI, active timeout, inactive/reactivation, no false
IKE-SA claim, no crypto inference, JSON serialization) plus window-only input,
event/window parity, custom endpoints and reset.

## 9. Live verification results

Pipeline run on the running lab: sensor `eth1` mirror → XDP (`--json`) → JSONL
events → 100 ms aggregator → state builder.

- Monitor: `xdp_monitor eth1 --json` attached to `sensor:eth1` (generic/SKB XDP;
  native driver XDP is unavailable over the 9500-MTU veth). XDP is `XDP_PASS`.
- Traffic: `host-a ping -c 10 10.10.2.10`, `host-b ping -c 10 10.10.1.10`
  (0% loss both ways), plus a rekey in the same capture.
- Pre-rekey capture: 45 events, 2 SPIs.
  - `0xcda30093` A_TO_B, seq 7→26, 21 pkt
  - `0xccae52e3` B_TO_A, seq 7→26, 20 pkt
- Aggregator: `events_consumed=45 windows_emitted=58 events_dropped_late=0`.
- State (from events): 45 packets / 6482 bytes, A→B 21, B→A 20, `esp_seen=true`,
  `tunnel_seen=true`, 2 SPIs with progressing sequences.
- Full capture: 93 events (81 ESP, 4 IKE-NAT-T, 8 mirrored OTHER/ARP),
  `events_consumed=93 windows_emitted=710 events_dropped_late=0`.
- State (from windows, aggregate only): identical totals
  (93 pkt / 14098 B, A→B 43, B→A 42, `ike_nat_t_seen=true`) and `spis=[]`,
  confirming the window path never fabricates per-SPI data.

Lifecycle (transport-independent driver): `active=true` at and up to the
timeout boundary, `active=false` one ns past it, then re-activation on a new
packet; observed transition order
`IPSEC_TRAFFIC_OBSERVED, SPI_OBSERVED×4, ACTIVE, INACTIVE, ACTIVE`.

## 10. Rekey verification

Normal StrongSwan rekey issued with the existing mechanism and **no config
change**: `swanctl --rekey --child lan-a-to-lan-b` → `rekey completed
successfully`.

StrongSwan state before → after:

```
#6 DELETED   in ccae52e3  out cda30093
#7 INSTALLED in ca1a0913  out c88574ca
```

Post-rekey traffic captured 4 IKE-NAT-T packets (UDP 4500 rekey) turning on
`ike_nat_t_seen` / `observed_ike_activity`, then ESP on the new SPIs.

Final observed state (from events, cross-checked against `swanctl --list-sas`):

| SPI | dir | active | packets | first→last seq |
|-----|-----|--------|---------|----------------|
| `0xc88574ca` | A_TO_B | true | 20 | 1→20 |
| `0xca1a0913` | B_TO_A | true | 20 | 1→20 |
| `0xccae52e3` | B_TO_A | false | 20 | 7→26 |
| `0xcda30093` | A_TO_B | false | 21 | 7→26 |

The new SPIs started at sequence 1 (fresh state, no inheritance); the old SPIs
were retained as inactive with their full history. The rekey SPI change is only
recorded as an observed transition — not labelled malicious or an anomaly.

## 11. No ML / detection / risk / mitigation added

Confirmed: no scoring, classification, anomaly detection, XAI, correlation,
blocking, policy enforcement or response of any kind. The only outputs are
observed counters, observed protocol activity, per-SPI observations and
descriptive transition labels. IKE is reported as `observed_ike_activity`
(never `ike_sa_established`); no algorithms/ciphers/strength/authentication are
inferred. Tests 16 and 17 assert this.

## 12. Untouched components

Confirmed unchanged:

- containerlab topology and gateway configs
- passive TAP/mirror (observation point migrated to the GW-A WAN side: the live
  XDP sensor now receives copy-only mirred copies of the WAN-facing peer of
  `gw-a:eth2` — ingress (A → B) + egress (B → A) on `br-wan:eth1` → `br-wan:eth3`
  → `sensor:eth1`; the old middle-link mirror on both dataplane members is gone;
  the sensor member is isolated with floods/learning disabled so it sees only
  the explicit mirror copies; mirror stats show 0 drops. The existing gw-a
  audit tap is a separate observation path and is unaffected)
- StrongSwan configuration
- existing XDP classifier and ring-buffer event struct (`xdp_monitor_common.h`,
  `xdp_monitor.bpf.c`, `xdp_monitor.c`)
- existing 100 ms aggregator behavior
- existing offline parser, audit layer, backend and dashboard

Infrastructure re-verified after the run:

- XDP attached only on `sensor:eth1` (none on `eth0`, none anywhere in the host
  root netns / other lab interfaces).
- Sensor remains non-forwarding: `net.ipv4.ip_forward=0`, no IPv4 on `eth1`,
  no `charon`.
- End-to-end connectivity after rekey: 0% packet loss in both directions.
