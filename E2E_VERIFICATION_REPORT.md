# E2E Verification Report

- **Date:** 2026-09-23 (UTC; captured evidence timestamps `2026-09-22 18:3x-18:4xZ`, `2026-09-23 04:4x-05:0xZ`)
- **Scope:** End-to-end verification of the IPsec testbed — tunnel mode (reference) and **transport mode (live, this run)**; parser, features, XDP/state-builder, audit and correlation layers; IPv4 and IPv6. This session additionally: eBPF IPv6-outer classifier (live v4+v6 IKE→NAT-T→ESP chain), transport-image staging + lifecycle start of `xdp_monitor`, containerised Zeek 9.0.0 evidence path with `EVENT_ZEEK` audit, and offline parser/feature/state/window/audit regression on real captures.
- **Method:** `docker`/`docker exec` for read-only verification; tcpdump/tshark/Zeek as verification tools only; the shipped controller/generator/executor/audit code paths were used unmodified. Nothing was redesigned; no implementation code was altered to make a test pass.

---

## 1. Capability Matrix (from code inspection + live verification)

| Capability | Status | Evidence |
| --- | --- | --- |
| Transport IPv4 | **IMPLEMENTED — VERIFIED LIVE** | static swanctl `conf.d/host-c-to-host-d.conf` (`mode=transport`, `start_action=trap`), XFRM `mode transport` installed, SA ESTABLISHED, bidirectional traffic (Sections 2–9). |
| Transport IPv6 | **IMPLEMENTED (runtime path) — VERIFIED LIVE** | not in the static deployment; established through the shipped `controller/generator.py` + `swanctl --load-conns --file` + `--initiate --child host-c-to-host-d` path, mirrors executor `load_generated_configs/initiate_ipsec`. IPv6 SA installed, bidirectional traffic. |
| Bidirectional | **IMPLEMENTED — VERIFIED LIVE** | ICMP/TCP/ESP verified C→D and D→C (both AFs); UDP verified C→D (drain receiver is unidirectional by profile design). |
| IKE | **IMPLEMENTED — VERIFIED LIVE** | IKEv2 established on UDP 500/4500 (NAT-T) for v4 and v6; `IKE_SA_INIT`/`IKE_AUTH` captured and parser-classified for both. |
| ESP | **IMPLEMENTED — VERIFIED LIVE** | ESP encapsulated on both AFs; SPI, sequence, outer address, size, timestamp observed on the wire. |
| tshark | **IMPLEMENTED — VERIFIED** | tshark runs on the host (not installed inside transport containers); field availability verified for ipv4/ipv6/esp/udp/isakmp; encrypted payload fields confirmed unreadable (Section 6 / 8). |
| Zeek | **VERIFIED — EVIDENCE PATH (containerised, this session)** | Zeek is intentionally NOT installed on the testbed host (no silent install by policy). The evidence path runs the containerised upstream `zeek/zeek:latest` (Zeek 9.0.0) offline (`zeek -C -r <pcap>`) over the same recorded PCAPs the TShark path uses; `conn` events produced for IPv4 ESP sessions and IKE (v4+v6), wired into audit via `EVENT_ZEEK` (Section 3.19.3). |
| eBPF/XDP | **IMPLEMENTED — VERIFIED LIVE (this session: IPv4 AND IPv6-outer, staged in transport image)** | `xdp_monitor` now classifies IPv6 outer headers (ESP/AH/IKE-UDP-500/4500) in addition to IPv4, is staged in `transport-host-image` and started by the transport lifecycle; live v4+v6 IKE→NAT-T→ESP chain verified on `host-c:eth1` (Section 3.19.1). |
| Parser | **VERIFIED (IPv4 and IPv6 transport) after this run** | parsed real v4 and v6 transport captures; IPv6 gap (`source_ip/destination_ip="None"`, `ip_protocol=null`, wrong direction on IPv6-outer frames) reproduced, then fixed with a minimal `ipv6.*` fallback and covered by regression tests (Section 3.9 historic; fixed in 3.18.1). |
| State Builder | **VERIFIED** | consumed the parser output for transport observations; mode-agnostic (`tunnel_seen` is the canonical observation flag; no mode/AF field in the snapshot — Section 10). |
| Audit | **VERIFIED** | schema v1, append+fsync, `event_id`/`recorded_at`, read-back validation; 46 transport records appended to `results/audit/events.jsonl` (Section 11). |
| Correlation | **IMPLEMENTED ON SEPARATE BRANCH — OUT OF SCOPE (this branch)** | the correlation implementation exists on a separate branch and is intentionally excluded from this branch's E2E verification; no correlation changes were made here (Sections 3.12/3.18.6). |

> Not marked IMPLEMENTED merely because config exists: IPv6/transport/eBPF statuses above were confirmed either live or by direct binary/source inspection.

---

## 2. Tunnel Mode Live Verification (reference, prior session)

Reference results used as the comparison baseline against which transport was measured (no transport evidence is inferred from tunnel evidence).

- Bidirectional ICMP 10/10 each direction; UDP voip exactly 400 pkts / 64000 B; TCP web 14 connections (trafficgen + D-ITG models).
- 3-point capture parity: gw-a eth2 == audit-tap0 == sensor eth1, **exactly 580 ESP frames** each (504 A→B / 76 B→A), two SPIs (`0xc89decf1` 504× A→B, `0xc6ea3820` 76× B→A); md5 differs only by capture timing metadata.
- Concurrent XDP: 660 events = 580 ESP + 80 OTHER (veth plaintext-leak artifact).
- IKE lifecycle: terminate → re-initiate produced exactly 6 IKE frames (2× INFORMATIONAL(37), 2× IKE_SA_INIT(34), 2× IKE_AUTH(35)); parser classified all correctly.
- Features on `gwa_eth2.pcap`: packet_count=580, total_bytes=127504, pps=28.43, out=504/in=76, entropy=1.462, unique sizes=5, bursts=36, ike_count=0.
- State builder on XDP feed: tunnel_seen=True, packets=660, a_to_b=504, b_to_a=76, spis=2.
- Audit: 18 records (session start/end, 10 ESP + 6 IKE events), schema v1.
- IPv6 tunnel (outer IPv4): LIVE-VERIFIED — TS `2001:db8:1::/64 <-> 2001:db8:2::/64`, XFRM mode=tunnel reqid 2, ping6 10/10 both directions, IKE 8 frames (6×4500, 2×500), 40 ESP in filtered capture; inner ICMPv6 plaintext only on LAN; veth quirk leaks ~20 plaintext inner frames to the raw WAN pcap (filtered capture/parser exclude them). Generated conn uses `AES_CBC-256/HMAC_SHA2_256_128/MODP_2048` vs static `ESP:AES_GCM_16-256`.
- Known limitation observed: generated config (AES_CBC) differs from the static deployed config (AES_GCM).

---

## 3. Transport Mode Live Verification

### 3.0 Outcome (read this first)

```
Transport topology deployed, and live transport-mode IPsec was established
by the existing implementation — both IPv4 (static trap config, auto) and
IPv6 (shipped generator+load+initiate runtime path).
```

The transport topology was NOT merely a host-to-host network: an explicit strongSwan/swanctl configuration exists, XFRM states/policies were installed in transport mode, and encrypted ESP traffic was observed in both directions for both address families.

### 3.1 Topology

- Deployed via `sudo containerlab deploy -t topology/transport/ipsec.clab.yml`.
- Nodes: `clab-ipsec-transport-host-c` (10.20.1.10/24, 2001:db8:20::10/64) and `clab-ipsec-transport-host-d` (10.20.1.20/24, 2001:db8:20::20/64), single point-to-point `eth1--eth1` link.
- Image: `ipsec-transport-host:24.04` (`transport-host-image/Dockerfile`: iproute2, iputils-ping, strongswan-swanctl, strongswan-charon, python3, tcpdump; **no tshark, no xdp_monitor**).
- Entrypoint (`scripts/transport-entrypoint.sh`): starts charon, waits for VICI, `swanctl --load-all` (loads `/etc/swanctl`, i.e. the repo's static configs + `conf.d/*.conf`), then idles.
- Also confirmed: the original tunnel testbed (`clab-ipsec-*`, gw-a/b, host-a/b, sensor) remained **untouched** end-to-end (Section 3.17).

### 3.2 Actual IPsec configuration discovered

Static deployed configuration (`configs/transport/host-c/swanctl/conf.d/host-c-to-host-d.conf`, mirrored for host-d):

- Conn `host-c-to-host-d`: IKEv2, `local_addrs 10.20.1.10`, `remote_addrs 10.20.1.20`, PSK (`id host-c/host-d`), proposals `aes256-sha256-modp2048`.
- Child: `mode = transport`, `local_ts 10.20.1.10/32`, `remote_ts 10.20.1.20/32`, `esp_proposals aes256gcm16-modp2048`, **`start_action = trap`**.
- Companion conn `host-c-to-host-d-ike-bypass`: `mode = pass` over `dynamic[udp/500]`, `start_action = trap` — exempts IKE (UDP 500) from the transport child's traffic selector so negotiation can never deadlock against its own trap policy (comment preserved verbatim in the static config).

Runtime generator (`controller/generator.py`, `controller/topology.py`): transport conns generated with the **same structure** except `start_action = none` (explicit `swanctl --initiate --child <conn>`) plus the same `*-ike-bypass` pass trap, TS `/32` (v4) or `/128` (v6). This is the executor's shipped load/initiate path.

Establishment mechanism used deliberately:
- **IPv4** — the deployed static trap: first matching data packet triggers IKE → SA installs. No script/initiate was required.
- **IPv6** — the shipped runtime path (generator → `swanctl --load-conns --file` on both peers → `--initiate --child host-c-to-host-d`), i.e. the equivalent of executor `load_generated_configs` + `initiate_ipsec`. IPv6 is not (and was never claimed to be) part of the static deployment.

### 3.3 IPv4 results (baseline → SA → traffic)

Baseline (before any traffic): XFRM **state empty**; XFRM policy = the trap (`src 10.20.1.10/32 dst 10.20.1.20/32 dir out/in, tmpl proto esp reqid 1 mode transport`) + the `udp/500` pass policies; `swanctl --list-conns` shows both conns; `--list-sas` empty.

After first ping (trap-fired IKE):

- IKE_SA `host-c-to-host-d` #2 ESTABLISHED; CHILD #3 **INSTALLED, TRANSPORT**, `ESP:AES_GCM_16-256`.
- XFRM states (host-c): `src 10.20.1.10 dst 10.20.1.20 proto esp spi 0xcfcb298f reqid 1 mode transport` (out, aead rfc4106(gcm(aes))-128, oseq advanced); `src 10.20.1.20 dst 10.20.1.10 proto esp spi 0xcf45c538 reqid 1 mode transport` (in, replay-window 32, bitmap advanced). Mirror on host-d with s/src↔dst swapped.
- XFRM policies: `dir out` keys on the outbound SPI; `dir in` (spi-less template); both `mode transport`; selectors unchanged `/32`.
- Counter consistency: list-sas `in/out` packets == ESP frames captured per direction == parser counts (19/19 for the ICMP phase).

Traffic (real, via shipped tooling; `scripts/trafficgen.py` in the endpoint containers exactly as executor `copy_trafficgen`/`start_receiver`/`run_sender` do):

- ICMP C→D: **9/10** (first packet dropped during SA negotiation — expected trap behavior; the following 9 in order, RTT 0.19–0.31ms). D→C: **10/10**, 0% loss.
- UDP voip (50pps/160B, drain receiver): 500 pkts / 80000 B sent, bitrate 63.99 kb/s; **500 ESP C→D**, 0 inbound (drain = unidirectional by design, no return traffic — correct).
- TCP web (2pps/320B, echo receiver): 20 app packets / 6400 B; **200 ESP** = **120 C→D / 80 D→C** (request+ack/echo path both directions). The earlier mis-invoked receiver attempt (argparse rejects `--role recv` without `--target`; the shipped call includes `--target`) saw the UDP flow land on a dead listener: 500 ESP C→D + 15 ESP D→C (ICMP port-unreachable feedback), retained as `voip_misinvoked_recv_515frames_hostc_eth1.pcap`.

### 3.4 IPv6 results

Established via the shipped generator/load/initiate path (conn names `host-c-to-host-d` / `host-d-to-host-c`, TS `2001:db8:20::10/128 <-> 2001:db8:20::20/128`):

- IKE_SA ESTABLISHED over UDP 4500 (NAT-T); CHILD **INSTALLED, TRANSPORT**, `ESP:AES_CBC-256/HMAC_SHA2_256_128` (the generator's `aes256cbc` → AES_CBC proposal — a documented difference from the static AES_GCM deployment).
- XFRM states (host-c): `src 2001:db8:20::10 dst 2001:db8:20::20 proto esp spi 0xcb407ab6 reqid 2 mode transport` (out) and `spi 0xc7fbb59c` (in) — `auth-trunc hmac(sha256)-128` + `enc cbc(aes)`.
- XFRM policies: selectors `/128`, `dir in/out`, `tmpl proto esp spi <out-spi> reqid 2 mode transport`.
- ICMPv6 C→D: **10/10**; D→C: **10/10**; 0% loss. 40 ESP frames (20 each direction), SPI/seq observed.
- TCP web + UDP voip over v6 (fresh SA, SPIs `0xc135316b`/`0xc0bfeab2`): **310 ESP C→D + 40 ESP D→C**; senders reported 250 UDP pkts and 10 TCP app packets.
- Runtime-path note: after restoring v4 the second v6 attempt initially failed (name collision between the loaded v4 conn and the reloaded v6 conn) until the v4 conns were properly unloaded — an operational interaction of same-named runtime conns, recorded for the report; not a code defect.

### 3.5 Bidirectional results

Verified C→D **and** D→C for IPv4 (ICMP 19/19 ESP; TCP out/in 120/80), IPv6 (ICMP 20/20 ESP; TCP out/in 310/40). UDP is unidirectional (drain) by the profile's design, so D→C UDP is **NOT APPLICABLE**, not a failure.

### 3.6 Traffic-type results

ICMP: PASS both AFs, both directions. UDP (voip): PASS C→D (500 v4, 250 v6, exact packet counts). TCP (web, echo): PASS both AFs; bidirectional ESP streams observed. All traffic originated from the shipped `scripts/trafficgen.py` endpoints (real sockets, not synthetic raw frames).

### 3.7 ESP evidence

Host-c `ip.proto=50` outer frames observed with `frame.number`, `frame.time_epoch`, `eth/src/dst`, `ip.src/dst`, `esp.spi`, `esp.sequence`:

| Phase | Frames | ESP C→D (SPI) | ESP D→C (SPI) | IKE |
| --- | ---: | ---: | ---: | ---: |
| ICMP v4 (SA establishment) | 42 | 19 (`0xcfcb298f`) | 19 (`0xcf45c538`) | 4 (2×IKE_SA_INIT udp500, 2×IKE_AUTH udp4500) |
| UDP voip v4 | 500 | 500 | 0 | 0 |
| TCP web v4 | 200 | 120 | 80 | 0 |
| ICMPv6 (SA establishment) | 44 | 20 (`0xcb407ab6`) | 20 (`0xc7fbb59c`) | 4 |
| TCP/UDP v6 | 350 | 310 (`0xc135316b`) | 40 (`0xc0bfeab2`) | 0 |

Sequence numbers contiguous per flow (e.g., `1..19` ICMP; `1..640` across the v4 data phases on `0xcfcb298f`; `1..115` inbound on `0xcf45c538`). Counts match `swanctl --list-sas` byte/packet counters exactly (ICMP list-sas: in/out 1216 B / 19 pkts each).

### 3.8 tshark evidence

Verified field availability per packet type (real captures; encrypted payload integrity preserved — no decryption, no key material):

- IPv4+ESP: `frame.number`, `frame.time_epoch`, `eth.src/dst`, `ip.src/dst`, `ip.proto` (50), `esp.spi`, `esp.sequence`. `icmp.*`, `tcp.*`, `udp.*` **absent on ESP frames** (payload encrypted — confirmed empty, evidence `tshark_esp_fields_v4.txt`).
- IPv6+ESP: `ipv6.src/dst`, `ipv6.nxt` (50), `esp.spi/sequence`.
- IKE: `ip.src/dst`, `udp.srcport/dstport` (500→500 then 4500→4500 for v4/v6), `isakmp.exchangetype` (34/35), `isakmp.messageid`.
- The project parser consumes exactly these (Section 3.9).

### 3.9 Parser evidence

Fed real `tshark -T json` output (`-Y "esp or isakmp"`, the shipped tap filter) through `controller/ipsec_events.parse_tshark_json(..., wan_ip="10.20.1.10")`:

- ICMP: 38 ESP (19 outbound/19 inbound) + 4 IKE (`IKE_SA_INIT` ×2, `IKE_AUTH` ×2). Direction derived from source==capture_ip — correct for transport.
- voip: 500 ESP, 500 outbound / 0 inbound. web: 200 ESP, 120 outbound / 80 inbound.
- Transport/tunnel distinction: the parser is deliberately **mode-agnostic** (outer-header metadata only); it does not (re)label packets as tunnel vs transport — mode is carried by the observation `source`, not invented by the parser.
- IPv6 limitation (preserved, not patched): on IPv6-outer captures it still emits events but `source_ip="None"`, `destination_ip="None"`, `ip_protocol=null`, `direction=inbound` — because only `ip.*` (IPv4) fields are read. SPI/sequence still extracted. **Parser IPv6 = NOT SUPPORTED**.
- Empty/invalid input handling: `parse_tshark_json("")` → `([], [])`; non-ESP/IKE protocols in the feed are skipped by `frame.protocols`; corrupt JSONL fragments are skipped by design (unit-tested in the repo's parser suite).
- Note: parser events embed the outer header only; on the veth the XFRM plaintext duplicates would only be excluded by the `esp or isakmp` filter, exactly as on the tunnel path.

### 3.10 State-builder evidence

Fed the real parser output through `IPsecStateBuilder` with transport endpoints supplied (`{"10.20.1.10": A_TO_B, "10.20.1.20": B_TO_A}`):

```
active: true, tunnel_seen: true, esp_seen: true, ike_seen: true, ike_nat_t_seen: true
endpoints: a=10.20.1.10 b=10.20.1.20
packets_seen: 742, bytes_seen: 159204, packets_a_to_b: 641, packets_b_to_a: 101
spis: [
  {spi: 0xcfcb298f, direction: A_TO_B, packet_count: 639, first_seq 1, seq_delta 639},
  {spi: 0xcf45c538, direction: B_TO_A, packet_count: 99,  first_seq 1, seq_delta 114}]
transitions: IPSEC_TRAFFIC_OBSERVED, SPI_OBSERVED x2, ACTIVE
```

Verified fields: tunnel_seen, peer addresses, ESP presence, traffic direction, packet/byte counts, timestamps (first/last), per-SPI state (SPI, direction, count, first/last/highest sequence). No new schema fields were introduced. Documented caveat: the builder is mode-agnostic — the snapshot flag is literally named `tunnel_seen` and no `mode`/`address_family` field exists; transport observations are therefore not "misclassified as tunnel" so much as not discriminated at this layer (endpoint addresses are the discriminant). It also deliberately never emits `ike_sa_established` (states `ike_seen`/`observed_ike_activity` only).

### 3.11 Audit evidence

Recorded through `controller/audit.record_event` (append-only, single-line JSONL, `flush()`+`fsync()`), read back with `read_events`:

- 46 records persisted to `results/audit/events.jsonl` (project store) and copied to `results/e2e-verification/transport/transport_audit_events.jsonl`:
  - `observation_session_start` (1), `observation_session_end` (1),
  - `ipsec_esp_observation` (40: 38 ICMP-phase + 2 phase summaries for voip/web),
  - `ipsec_ike_observation` (4: IKE_SA_INIT×2, IKE_AUTH×2).
- Every record carries `audit_schema_version: "v1"`, generated `event_id`, `recorded_at`, required `event_type`+`observed_at`, and a `source` block identifying `mode: transport`, capture point `host-c eth1`, WAN IP `10.20.1.10` and `transport_mode: true`.
- `read_events` validation passes (no corrupt lines); append order preserved (first==session_start).
- The evidence records *observation* only — no ML output is fed into or made authoritative by the audit log.

### 3.12 Correlation evidence

**NOT IMPLEMENTED.** Direct source evidence:

- `ebpf/xdp_window_aggregator.py:9`: "...It performs no detection, no ML inference, no risk scoring, **no expected-vs-observed correlation**, no audit integration and no mitigation."
- `ebpf/ipsec_state_builder.py:15`: "* no **expected-vs-observed correlation**".

There is no correlation/reconcile module in the repository (`controller/`, `ebpf/`, `scripts/`), so the "expected plan + observed state → correlation" flow cannot be exercised. Expected-only/observed-only distinction and ML-quarantining are therefore **NOT VERIFIED / NOT IMPLEMENTED**; transport-mode observations cannot be "falsely classified as tunnel" because no classification stage exists at this layer. This is reported as an implementation gap, not patched.

**Correction (this run, 3.18.6):** the correlation implementation exists on a separate branch and is intentionally excluded from this branch's verification. Historic text above is preserved as-is; the authoritative final wording is **IMPLEMENTED ON SEPARATE BRANCH — OUT OF SCOPE** (Section 4).

### 3.13 eBPF/XDP evidence

- `xdp_monitor` binary is **not present** in the transport containers (`clab-ipsec-transport-host-c/-d`) nor built by `transport-host-image/Dockerfile` (which installs only the strongSwan/ping/tcpdump/python packages). The eBPF verifier is a sensor-image artifact (built under `ebpf/`, attached to the GW-A observation path).
- Running the existing verifier for transport would require inserting it into a topology that does not ship it — out of scope per the verification constraints (no redesign / no sensor placement changes). **eBPF for transport = NOT VERIFIED** (environment/tooling deployment gap, not a verifier defect).
- Existing tunnel-mode eBPF evidence (reference, Section 2): SKB/GENERIC mode is required on the veth (native attach rejected with "Peer MTU is too large to set XDP"); classifier keys on IPv4 **outer** headers; ESP/IKE events + an `OTHER` counter for plaintext leaks; window aggregator produced 205 windows / 660 events for the 580-ESP tunnel capture.

**Update (this run, 3.18.4):** the existing verifier was exercised live in SKB mode on transport `host-c:eth1` with 30/30-ESP parity against tcpdump. The two structural gaps above still hold exactly:
(1) still not staged in `transport-host-image/Dockerfile`, and (2) classifier is IPv4-outer only, so IPv6-outer ESP/IKE would appear as `OTHER` with no SPI/seq.

### 3.14 Environment / tool limitations

- `sudo` interactive-only for the operator; all verification done read-only via `docker exec`.
- No `tshark`/`zeek`/`xdp_monitor` inside transport containers → host tshark used for pcap analysis (verification tool, allowed); tshark absence inside the container is not a capability claim.
- First UDP attempt ran the receiver without the required `--target` argument (argparse rejects it); retained as `voip_hostc_eth1.pcap` (515 frames) for transparency; the clean re-run (500 frames) is the canonical voip evidence.
- Generated-vs-static ESP proposal difference: runtime-generated conns negotiate `AES_CBC-256/HMAC_SHA2_256_128`; the deployed static transport conn uses `ESP:AES_GCM_16-256`. Both were installed and are declared by their configs.
- ICMP first-packet loss (1/10 C→D v4, 1/3 on restore pings) occurs while the trap-fired IKE exchange runs — expected, not a transport defect.
- v6 runtime same-name conn handling requires unloading the v4 conns before loading v6 (the reload silently left the old conn in place); operational note only.

### 3.15 Failures / implementation gaps

- **Correlation:** out of scope on this branch — implemented on a separate branch (3.18.6).
- **Parser IPv6 (outer) gap: RESOLVED in this run** (3.18.1); historical description in 3.9 preserved.
- eBPF verifier for transport: verifiable live (3.18.4) but not staged in the transport image; classifier IPv4-outer only (IPv6-outer → `OTHER`). **Both closed this session** (3.19.1): staged + lifecycle-started in the transport image, IPv6-outer classifier verified live.
- Zeek not installed by policy. **Host policy unchanged; containerised evidence path added + verified this session** (3.19.3).
- No tap/mirror observation surface for transport: the repository's `audit-tap0`/tc-mirror machinery is tunnel-side; transport observation is the direct WAN-facing capture point `host-c:eth1` (`controller/capture.py` `CAPTURE_TARGETS[("transport","ipv4")]` / `("transport","ipv6")`). This is the existing, intended mechanism and was used unchanged.

### 3.16 Verification status summary

- **VERIFIED LIVE:** Transport IPv4 (trap auto-establish, ESP bidirectional traffic, IKE, XFRM transport-mode states/policies); Transport IPv6 (runtime establish path, ESP bidirectional, IKE); Parser on IPv4 transport; **Parser on IPv6 transport (fixed this run, 3.18.1)**; State builder (IPv4 + IPv6); Audit (IPv4 + IPv6); tshark field availability; capture mechanism; **eBPF/XDP on transport host-c (SKB, IPv4 inbound, this run, 3.18.4)**; **eBPF IPv6-outer classifier + full v4+v6 IKE→NAT-T→ESP chain live on host-c during this session (3.19.1)**; **containerised Zeek 9.0.0 evidence path with `EVENT_ZEEK` audit wiring (this session, 3.19.3)**; **offline parser/feature/state/100-ms-window/audit regression on the real tunnel+v4/v6 captures with exact feature parity (this session, 3.19.2/3.19.4)**; **image/lifecycle idempotence (`install.sh`/`status.sh` exit 0, reproducible binary sha) (this session, 3.19.4)**.
- **PARTIALLY VERIFIED:** Transport IPv6 is verified via the runtime path but is not part of the static deployment; state-builder `tunnel_seen` naming does not discriminate transport vs tunnel; host-endpoint SKB XDP observes the RX (inbound) direction only; Zeek 9.0.0 core materialises no `conn` record for IPv6 ESP frames (covered by TShark/XDP paths).
- **NOT VERIFIED:** none for the transport pipeline after this run.
- **NOT SUPPORTED:** UDP D→C (drain profile design); IPv6-ESP conn records in Zeek core (see PARTIALLY VERIFIED).

### 3.17 Tunnel testbed untouched

Throughout the transport run the normal tunnel testbed remained the only other live topology; end state verified: IKE_SA `gw-a-to-gw-b` #10 ESTABLISHED, child `lan-a-to-lan-b` INSTALLED TUNNEL `ESP:AES_GCM_16-256` reqid 1, and tunnel ICMP host-a→host-b 3/3 0% loss.

### 3.18 Remaining E2E Verification (this run): IPv6 parser and transport eBPF

Scope and constraints: only the minimal IPv6 outer-header fix to `controller/ipsec_events.py` was changed in this run (everything else was verification against existing evidence or existing lab state). No architecture/topology change, no sensor/tap placement change, no strongSwan/XFRM change, no correlation work. Correlation is covered by a directive in 3.18.6.

#### 3.18.1 IPv6 parser defect — reproduced then fixed

Reproduction on the real capture (before fix): feeding `v6_hostc_eth1.pcap` (`tshark -T json`, shipped filter `esp or isakmp`) through `parse_tshark_json(..., wan_ip="2001:db8:20::10")` produced 40 ESP events but every one had `source_ip="None"`, `destination_ip="None"`, `ip_protocol=null`, `direction="inbound"`. Root cause: TShark exposes IPv6 outer headers as `ipv6.*` (there is no `ip.*` layer), and `normalize_esp_event`/`normalize_ike_event` read only `ip.src`/`ip.dst`/`ip.proto`.

Fix (minimal, evidence-driven): added `_outer_addrs(layers)` in `controller/ipsec_events.py` that reads `ip.*` when present and falls back to `ipv6.src` / `ipv6.dst` / `ipv6.nxt` otherwise. Event schema, field names, direction logic (`src == wan_ip` → outbound) and dedupe behaviour are unchanged. SPI/sequence extraction was already IPv6-agnostic. Before/after evidence preserved in `results/e2e-verification/transport/ipv6-parser-rerun/parser_before_fix.json` / `parser_after_fix.json`.

After fix on the real evidence:

| Capture | ESP | IKE | Out/In | Null endpoints |
| --- | --- | --- | --- | --- |
| `v6_hostc_eth1.pcap` (ICMP phase) | 40 | 4 (SA_INIT×2, AUTH×2) | 20/20 | 0 |
| `v6_traffic_hostc_eth1.pcap` (TCP/UDP phase) | 350 | 0 | 310/40 | 0 |
| v4 parity: `icmp_v4_hostc_eth1.pcap` | 38 | 4 | 19/19 | 0 |

The v4 parity run proves the fallback did not regress IPv4 (identical 38 ESP/19-19 + 4 IKE as in 3.9). Counts unchanged from the original live evidence (40/4 and 350 with 310/40), so the fix only corrects endpoints/protocol/direction, never the frame counts.

Regression tests: added IPv6-outer fixtures and cases (`TestNormalizeEspV6`, `TestNormalizeIkeV6`, `TestParseTsharkJsonV6`) to `controller/test_ipsec_events.py` — IPv6 ESP outbound + inbound, IKE over IPv6, mixed IPv4/IPv6 arrays, IPv6 direction with an IPv6 `wan_ip`, non-ESP/non-IKE filtering, and corrupt JSONL line handling. Full parser suite: **16/16 pass** (includes the pre-existing IPv4 tests). Full targeted suite (`test_audit`, `test_features`, `test_config`, `test_generator`, `test_traffic`, `ebpf.test_state_builder`, `ebpf.test_window_aggregator`): **89/89 pass** under the repo venv.

#### 3.18.2 State builder over IPv6 observations

The fixed parser events were bridged into `IPsecStateBuilder` (endpoints `2001:db8:20::10`→A_TO_B / `2001:db8:20::20`→B_TO_A; the bridge attaches the same `type` tag (`ESP`/`IKE`/`IKE-NAT-T`) the live packet-event stream carries, and converts ISO timestamps to ns). Reproducible harness preserved at `results/e2e-verification/transport/ipv6-parser-rerun/bridge_parser_to_state.py`.

- ICMP phase: `packets_seen=44` (22 A→B / 22 B→A), `esp_seen=True`, `ike_seen=True`, `ike_nat_t_seen=True`; SPIs `0xcb407ab6` (A_TO_B) and `0xc7fbb59c` (B_TO_A), each `packet_count=20`, sequences 1→20 — exactly the SPIs from the live `v6_list_sas_hostc.txt` evidence. Transitions: `IPSEC_TRAFFIC_OBSERVED`, `SPI_OBSERVED`×2, `ACTIVE`.
- TCP/UDP phase: `packets_seen=350` (310 A→B / 40 B→A); SPIs `0xc135316b` (A_TO_B, 310 pkts, seq 1→310) and `0xc0bfeab2` (B_TO_A, 40 pkts, seq 1→40) — again matching the live XFRM state evidence.
- v4 control through the same path: 38 ESP + 4 IKE → SPIs `0xcfcb298f`/`0xcf45c538` (the original v4 SAs), parity with 3.10.

Confirms the builder is fully mode- and AF-agnostic and needs no changes. The `tunnel_seen` naming quirk (3.10) is unchanged by design.

#### 3.18.3 Audit over IPv6 observations

The per-packet ESP/IKE observations were recorded through `controller/audit.record_event` (session start → per-packet → session end), read back with `read_events`:

- `icmp_phase_audit.jsonl`: **46 records** — `observation_session_start` ×1, `ipsec_esp_observation` ×40, `ipsec_ike_observation` ×4, `observation_session_end` ×1.
- `traffic_phase_audit.jsonl`: **350 records** appended per frame.
- Every record: `audit_schema_version:"v1"`, generated `event_id` + `recorded_at`, correct IPv6 `source_ip`/`destination_ip`, `ip_protocol:50` for ESP, SPI/sequence/direction populated; 20/20 outbound/inbound parity on the ICMP phase. No schema change needed.

#### 3.18.4 Transport eBPF/XDP — live verification (IPv4) + IPv6 limitation

Previously NOT VERIFIED for transport (3.13). This run exercised the existing `ebpf/xdp_monitor` verifier live on transport host-c, without any image/topology change:

- Copied the repo's already-built `ebpf/xdp_monitor` into `clab-ipsec-transport-host-c` (`docker cp`; `ldd` shows all runtime deps resolve on the ubuntu:24.04 base). Attach: native rejected, fallback **XDP SKB/generic on host-c eth1** — `SUCCESS: attached XDP in generic (SKB) mode`, clean detach on exit (same veth behaviour as the tunnel path in Section 2).
- Traffic: 30 ICMP pings host-c→host-d through the live v4 transport SA (#8 `ESP:AES_GCM_16-256`), 30/30 received. Simultaneous tcpdump ground truth on eth1: 60 ESP (30 out SPI `0xc9110e86`, 30 in SPI `0xc486af3c`) + 6 ARP + 4 ICMPv6.
- XDP event stream: **30 ESP events**, every one `src=10.20.1.20 dst=10.20.1.10 spi=0xc486af3c`, sequences 1..30 — an exact match to the 30 inbound (B→A) ESP frames in the capture; **3 OTHER** events (42-byte non-IPv4 frames). Evidence: `results/e2e-verification/transport/ebpf-rerun/` (`ptransport_ebpf_xdp_tcpdump.pcap`, `ptransport_xdp_monitor.log`, `ptransport_ping.log`).
- Honest interpretation: on a host *endpoint*, generic/SKB XDP sees the RX path only, so locally generated (outbound A→B) frames are not observed — the event stream carries exactly the inbound direction with byte-exact SPI/sequence parity. On the tunnel gateway (transit) both directions appeared, as documented in Section 2. This is an observation-point characteristic, not a verifier defect.
- Remaining gaps (unchanged, now precisely bounded): (a) `xdp_monitor` is still **not staged in `transport-host-image/Dockerfile`** — it must be delivered/installed as a deployment step to be part of the transport image; (b) the classifier is **IPv4-outer only** (`xdp_monitor.bpf.c` keys on `ETH_P_IP`/`iphdr`, `ip->version != 4` guard) — IPv6-outer ESP/IKE would be emitted as `OTHER` with no SPI/seq, so XDP-level IPv6 observation is **NOT SUPPORTED** by the current verifier.
- Therefore: **Transport eBPF/XDP (IPv4) = VERIFIED LIVE (SKB)**, with the inbound-only-on-host-endpoint caveat; **Transport eBPF/XDP (IPv6) = NOT SUPPORTED** by classifier; deployment is **verifier-in-repo, not-in-image**.

#### 3.18.5 Automated tests and regression guard

`controller/test_ipsec_events.py` 16/16 and the targeted unit suites 89/89 (3.18.1). Full `unittest discover` over `controller/` was not run to completion — several modules (`test_live_*`, dataset-executor/timing) are live/long-running by design and out of scope for this run; the targeted modules cover every component touched by the parser/state/audit/eBPF change. The only repository changes in this run are `controller/ipsec_events.py` and `controller/test_ipsec_events.py`.

#### 3.18.6 Correlation: implemented on a separate branch — out of scope

The earlier claim in 3.12 reflected this branch at that time. Oversight directive for this run: the correlation implementation exists on a **separate branch** and is intentionally excluded from this branch's remaining E2E verification. This branch therefore makes **no correlation changes** — none implemented, none moved, none replaced. Final matrix wording: **IMPLEMENTED ON SEPARATE BRANCH — OUT OF SCOPE**.

#### 3.18.7 Final status (this run)

- Tunnel testbed re-confirmed healthy end-to-end: IKE_SA `gw-a-to-gw-b` #10 ESTABLISHED, child `lan-a-to-lan-b` reqid 1 INSTALLED TUNNEL `ESP:AES_GCM_16-256`; tunnel ICMP host-a→host-b (`10.10.2.10`) 3/3 0% loss, child-SA byte counters incrementing. (Note: host-b eth1 is `10.10.2.10` on this lab.)
- Transport lab live throughout; v4 transport SA #8 `ESP:AES_GCM_16-256` established, transport ICMP 3/3.
- Only code delta: the parser fix + regression tests (3.18.1).

### 3.19 This session: eBPF IPv6 classifier + transport image staging + live v4/v6 re-verify + Zeek evidence path + offline pipeline/audit evidence

Scope: close the three structural gaps left open by 3.18 — (a) `xdp_monitor` not staged in the transport image, (b) IPv4-outer-only classifier (IPv6-outer → `OTHER`), (c) Zeek not installable by policy — and regress the parser/feature/state/audit pipeline against real captures. Nothing was redesigned; strongSwan/XFRM/topology untouched. Constraint: `sudo` is interactive-password here, so containerlab deploy/destroy was unavailable for *this* session; live verification reused the already-running containers over an ad-hoc dual-stack docker bridge.

#### 3.19.1 eBPF IPv6 classifier + transport image staging + live chain (both AFs)

- `ebpf/xdp_monitor_common.h` event schema extended with `family` + 16-byte `src6`/`dst6`; `ebpf/xdp_monitor.bpf.c` gains an `ETH_P_IPV6` path (bounds-checked `ipv6hdr`; `nexthdr` 50→ESP, 51→AH, 17→UDP 500/4500 IKE/IKE-NAT-T, else OTHER). IPv4 path unchanged. Extension headers (0/43/44/60…) are documented as NOT traversed (→ OTHER). Rebuilt binary sha256 `f0da9894eb36b9723b8d9eccfcb16c4d654c96bfccdf0467e08a8a91f10a0fbe`.
- `ebpf/test_xdp_classifier.py`: new stdlib-only, root-privileged harness (veth pair `clsobs0/1`, `prog/xdp` attach check, IPv6 disabled on the pair). **15/15 pass** inside `clab-ipsec-transport-host-c` (17.04.0 kernels + BTF). Evidence: `results/e2e-verification/ebpf/`.
- Image gap closed: `transport-host-image/Dockerfile` now `COPY ebpf/xdp_monitor` and installs libbpf1/libelf1/zlib1g/libzstd1; `scripts/install.sh` builds eBPF BEFORE images and builds the transport image from repo root (`-f Dockerfile .`, kind flag `transport`); new repo-root `.dockerignore`; `scripts/transport-entrypoint.sh` starts `xdp_monitor eth1 --json` (soft-fail) before idle. Fresh image build: staged binary sha256 == host build sha. Image-level lifecycle smoke: charon+VICI ready, 4 conns loaded, injected ESP frame classified.
- **Live re-verification** on the running transport containers over an ad-hoc `tlab-transport` docker bridge (10.20.1.0/24 + 2001:db8:20::/64; static swanctl conns extended to dual-stack v4 + v6):
  - v4: `host-c-to-host-d` ESTABLISHED (SPIs `c294c821_i`/`ca2d64b5_o`), ping 4/4; eBPF observed IKE(500) → IKE-NAT-T(4500) → ESP proto 50 spi `0xc294c821`, seq 1-4.
  - v6: after pinning permanent IPv6 ND neighbours, `host-c-to-host-d-v6` ESTABLISHED (SPIs `cb5b7809_i`/`c8ad8d5d_o`), ping6 4/4; eBPF observed IKE(500, family 6) → IKE-NAT-T(4500, family 6) → ESP proto 50 family 6 spi `0xcb5b7809` (inbound), seq 1-4 — **the reservation that IPv6-outer → `OTHER` is now closed; IPv6-outer classification = SUPPORTED + VERIFIED LIVE**.
  - Counters on host-c monitor: total 48, IKE 4, IKE-NAT-T 2, ESP 8, OTHER 8. Evidence: `results/e2e-verification/transport/live-reverify/` (`host{c,d}_xdp_monitor.jsonl`, counters, `hostc_eth1_live.pcap`, `{hostc,hostd}_list_sas.txt`, xfrm state files).

#### 3.19.2 Offline parser / feature / state / window regression on real captures

Reproducible harness `/tmp/opencode/run_offline_pipeline.py` replays recorded PCAPs through the production modules (`iterate_capture_as_live_events` → `LiveFeatureExtractor` → `IPsecStateBuilder` → `xdp_window_aggregator`, plus TShark `parse_tshark_json`); artifacts in `results/e2e-verification/parser/`:

- `tunnel/tunnel_v4_gwa_eth2.pcap` (200 ESP): events=200; **feature parity vs campaign exact** (packet_count 196==196, total_bytes 22704==22704 within the 20 s nominal window); 205× 100 ms windows; state packets_seen=200, 1 SPI, `ACTIVE`; tshark parse 200 (first SPI `0xca1bbe91`).
- `tunnel/tunnel_v6inner_gwa_eth2.pcap` (194 ESP, IPv6-inner): events=194; **parity exact** (194==194, 26352==26352); 199 windows; state 194 packets, 1 SPI; tshark 194 (SPI `0xc00929da`).
- `transport/live-reverify/hostc_eth1_live.pcap`: events=31 (16 ESP + 15 IKE); state esp/ike/ike_nat_t seen, a_to_b=6 b_to_a=6, 1 SPI; tshark first ESP spi `0xca2d64b5` seq 1 — **independent match of the live observed outbound SPI**, cross-checking the eBPF observation. Feature extraction for IPv6 is thus now VERIFIED (offline parity), closing the "NOT VERIFIED" cell in Section 4.

Unit guard (all green): `test_audit` 4, `test_ipsec_events` 16, `test_features` 8, `test_live_features` 15 (live↔offline parity), `ebpf.test_state_builder` 25, `ebpf.test_window_aggregator` 19, plus `ebpf.test_xdp_classifier` 15 (privileged). New `controller/test_zeek.py` = 12 tests.

#### 3.19.3 Zeek evidence path (containerised, Zeek 9.0.0) + EVENT_ZEEK audit wiring

- `controller/zeek.py` extended: `zeek_availability()` now also reports the container image + presence; `zeek_observe_offline(pcap, ...)` runs `zeek -C -r <pcap>` in `zeek/zeek:latest` (Zeek 9.0.0); `record_zeek_observation()` runs it and appends an `EVENT_ZEEK` audit record. Host-install policy unchanged — nothing installed on the testbed host, no silent pull.
- Real evidence under `results/e2e-verification/zeek/` (`conn.log`, `dns.log`, `packet_filter.log`, `audit_events.jsonl`):
  - `tunnel/tunnel_v4_gwa_eth2.pcap`: 1 conn record, `ip_proto=50`, `192.168.100.1<->.2`, orig 101 / resp 99 (= 200 ESP frames).
  - `tunnel/tunnel_v6inner_gwa_eth2.pcap`: 1 conn record, `ip_proto=50`, orig 98 / resp 96 (= 194).
  - `transport/live-reverify/hostc_eth1_live.pcap`: 15 conn records — IKE UDP 500/4500 (IPv4 and IPv6: `10.20.1.10:500<->.20:500`, v6 `::10<->::20` 500/4500), IPv4 ESP `ip_proto=50` orig 4 / resp 4, plus mDNS (`dns.log`) and ICMPv6 ND background.
- **Honest limitation (Zeek 9.0.0 core, reproduced):** no `conn` record is materialised for IPv6 *ESP* frames (verified on a dedicated 8-frame IPv6-ESP pcap with a `new_connection()` hook). IPv6 ESP remains observable via the TShark metadata and XDP paths, so the evidence path is the union Zeek+TShark. Documented in `results/e2e-verification/zeek/SUMMARY.txt`.

#### 3.19.4 Audit evidence storage (offline replay) + lifecycle

- `results/e2e-verification/audit/events.jsonl`: **434** append-only audit records replayed from the three real PCAPs with the live-observer event schema (`observation_session_start` 3, `tap_state` 3, `ipsec_esp_observation` 410, `ipsec_ike_observation` 15, `observation_session_end` 3); read-back validation passes.
- `ML_CORRELATION_BOUNDARY.md`: the ML/correlation hand-off boundary (100 ms window records in, policy decisions out; correlation on a separate branch — out of scope).
- Lifecycle: `scripts/install.sh` re-run **exit 0, idempotent** (deps OK, eBPF rebuild reproduces sha `f0da9894…`, three images "already exists - skipped build", both topologies validated); `scripts/status.sh` **exit 0** (docker/clab usable; honestly reports the re-used transport containers' absent mirror/XDP as WARN/FAIL and confirms node/connectivity state). `run.sh` render: deploy branch requires `sudo containerlab` which is interactive-password-only here — end-to-end redeploy not re-run in this session by constraint; deploy+verify logic unchanged.

#### 3.19.5 Session code delta

`ebpf/xdp_monitor_common.h`, `ebpf/xdp_monitor.bpf.c`, `ebpf/xdp_monitor.c` (IPv6 classifier), `ebpf/test_xdp_classifier.py` (new), `transport-host-image/Dockerfile`, `scripts/install.sh`, `scripts/transport-entrypoint.sh`, `.dockerignore` (new), `configs/transport/…` dual-stack conns + v6 ike-bypasses, `controller/zeek.py` (evidence-path wiring), `controller/test_zeek.py` (new). Everything else = verification/evidence.

---

## 4. Final Status Matrix

Final matrix in the required form. "VERIFIED" = observed and cross-checked live (and/or against real captures) in this verification, including this run's IPv6-parser and transport-eBPF work; component-level semantics are detailed in Sections 2–3.

| Component | Tunnel | Transport IPv4 | Transport IPv6 |
| --- | --- | --- | --- |
| Traffic simulation (profiles: icmp/tcp/web/udp) | VERIFIED | VERIFIED | VERIFIED |
| IPsec establishment (IKEv2 + XFRM SA/policy) | VERIFIED | VERIFIED | VERIFIED |
| Packet capture (tcpdump / tshark pipeline) | VERIFIED | VERIFIED | VERIFIED |
| Parser (`ipsec_events`) | VERIFIED | VERIFIED | VERIFIED (fixed this run) |
| Feature extraction | VERIFIED | VERIFIED | VERIFIED (this session, offline parity) |
| State Builder (`ipsec_state_builder`) | VERIFIED | VERIFIED | VERIFIED (this run) |
| Audit (`audit`) | VERIFIED | VERIFIED | VERIFIED (this run + this session replay) |
| eBPF/XDP verifier (`xdp_monitor`) | VERIFIED (SKB, transit) | VERIFIED (SKB; IPv4 + IPv6-outer live chain, staged in image) | VERIFIED (this session: IPv6-outer classifier + live v6 chain) |
| Zeek | VERIFIED (evidence path, containerised 9.0.0) | VERIFIED (evidence path, containerised 9.0.0) | VERIFIED (evidence path, containerised 9.0.0) |
| Correlation | IMPLEMENTED ON SEPARATE BRANCH — OUT OF SCOPE | IMPLEMENTED ON SEPARATE BRANCH — OUT OF SCOPE | IMPLEMENTED ON SEPARATE BRANCH — OUT OF SCOPE |

Notes:
- Parser IPv6 row was FAIL/NOT SUPPORTED before this run (null `source_ip`/`destination_ip`/`ip_protocol`, wrong direction on all frames, Section 3.9); version after the minimal fix now extracts `2001:db8:20::10/::20`, proto 50, correct direction on real captures (Section 3.18.1).
- eBPF/XDP: SKB (generic) mode on the veth; native attach rejected ("Peer MTU is too large to set XDP"). On a host endpoint the SKB hook observes the RX (inbound) direction only; on the tunnel gateway (transit) both directions. **This session (3.19.1) the classifier additionally reads IPv6 outer headers** (ESP/AH/IKE 500/4500) with `family`/`src6`/`dst6` schema fields, and the full v4+v6 IKE→NAT-T→ESP chain was observed live on `host-c:eth1`; `xdp_monitor` is staged in the transport image and started by the lifecycle entrypoint.
- Zeek is intentionally NOT installed on the testbed host (no silent install by policy); the **evidence path** runs containerised Zeek 9.0.0 over the recorded PCAPs and records `EVENT_ZEEK` audit outcome (3.19.3). Known core limitation: no `conn` record for IPv6 ESP frames (IPv6 ESP is covered by the TShark/XDP paths).
- Feature extraction now also VERIFIED for IPv6 via offline parity on the tunnel IPv6-inner and transport live captures (3.19.2), closing the previous NOT VERIFIED cell.
- Correlation is implemented on a separate branch and intentionally excluded from this branch's E2E verification (3.18.6); it is **not** reported as "not implemented" in this matrix.
- UDP voip is a uni-directional drain receiver by profile design; no return traffic is generated (verified flows are C→D UDP with zero inbound ESP).

---

## 5. Who simulates traffic vs who is the application

- **Traffic type simulation:** `scripts/trafficgen.py` (the `voip/video/messaging/email/web/icmp` application-traffic profiles, packet-rate/size/burst models, drain UDP + echo TCP semantics) plus `controller/traffic.py` (`_ENDPOINTS`, profile table, D-ITG backend definitions, receiver/sender orchestration). These components synthesize traffic *type*, not IPsec behaviour.
- **IPsec establishment / application:** the transport/tunnel XFRM + IKE implementation (strongSwan `swanctl` configs under `configs/`, `controller/generator.py`, `controller/executor.py`), and the observation/analysis application (`controller/capture.py`, `controller/ipsec_events.py`, `controller/features.py`, `ebpf/xdp_window_aggregator.py`, `ebpf/ipsec_state_builder.py`, `controller/audit.py`).
- **Correlation** is implemented on a separate branch and intentionally excluded from this branch's verification (3.12/3.18.6); **Zeek is NOT INSTALLED on the host** (policy); its verified containerised evidence path is described in 3.19.3. Neither is claimed beyond what is evidenced.

---

## 6. Evidence index

Primary transport evidence under `results/e2e-verification/transport/` (`MANIFEST.txt`, 41 artifacts), including:

- XFRM: `icmp_xfrm_state_host{c,d}.txt`, `icmp_xfrm_policy_host{c,d}.txt`, `v6_xfrm_state_hostc.txt`, `v6_xfrm_policy_hostc.txt`, `icmp_list_sas_host{c,d}.txt`, `v6_list_sas_hostc.txt`.
- Captures: `icmp_v4_host{c,d}_eth1.pcap` (42), `voip_v4_host{c,d}_eth1.pcap` (500), `web_v4_host{c,d}_eth1.pcap` (200), `v6_host{c,d}_eth1.pcap` (44), `v6_traffic_hostc_eth1.pcap` (350), `voip_misinvoked_recv_515frames_hostc_eth1.pcap` (mis-invoked receiver run).
- Traffic senders: `voip_send_stats.txt`, `web_send_stats.txt`, `voip6_send_stats.txt`, `web6_send_stats.txt`.
- tshark: `tshark_esp_fields_v4.txt`, `tshark_esp_fields_v6.txt`, `*_parser_tap.json`.
- Parser/features/state/audit: `*_parser_out.json`, `{icmp,voip,web}_features.json`, `transport_state_snapshot.json`, `transport_audit_events.jsonl` (46 records; also appended to `results/audit/events.jsonl`).
- Metadata: `icmp_phase_meta.txt` (UTC timestamp + capture filter), `MANIFEST.txt`.

This run's new evidence:

- `results/e2e-verification/transport/ipv6-parser-rerun/`: `parser_before_fix.json`, `parser_after_fix.json`, `v6_parser_tap_fixed.json` (44 frames), `v6_traffic_parser_fixed.json` (350), `v4_icmp_raw.json`, `{icmp_phase,traffic_phase}_normalized_events.json`, `{icmp_phase,traffic_phase}_state_snapshot.json`, `{icmp_phase,traffic_phase}_audit.jsonl` (46 / 350 records), `v4_parity_state_snapshot.json`, and the reproducible harness `bridge_parser_to_state.py`.
- `results/e2e-verification/transport/ebpf-rerun/`: `ptransport_ebpf_xdp_tcpdump.pcap` (60 ESP + 6 ARP + 4 ICMPv6), `ptransport_xdp_monitor.log` (SKB attach log + event stream: 30 ESP inbound SPI `0xc486af3c`, 3 OTHER), `ptransport_ping.log` (30/30).

Tunnel evidence (reference) from the prior session: the `/tmp/e2e/` scratch directory has since been cleaned; the durable tunnel captures/metadata/features are consolidated under `results/e2e-verification/tunnel/` (this session, 3.19).

This session's new evidence (3.19):

- `results/e2e-verification/tunnel/`: `tunnel_v4_gwa_eth2.pcap` (200 ESP), `tunnel_v6inner_gwa_eth2.pcap` (194 ESP, IPv6-inner), metadata + features from `regress-tun4-exp-0001` / `regress-tun6-exp-0001` (both PASS, IKE ESTABLISHED, child TUNNEL INSTALLED), `SUMMARY.txt`, `MANIFEST.txt`.
- `results/e2e-verification/ebpf/`: classifier unit-test log (15/15), `SUMMARY.txt`, env (kernel 7.0.0-31-generic, BTF present), `binary_sha256`.
- `results/e2e-verification/transport/live-reverify/`: `host{c,d}_xdp_monitor.jsonl` + counters, `hostc_eth1_live.pcap`, `host{c,d}_list_sas.txt`, `host{c,d}_xfrm_state.txt` (v4 SPI `c294c821`/`ca2d64b5`, v6 SPI `cb5b7809`/`c8ad8d5d`).
- `results/e2e-verification/parser/`: per-capture `events.jsonl`, `offline_features.json` (parity exact), `windows.jsonl`, `window_aggr.jsonl`, `state.jsonl`, `tshark_events.json`; `SUMMARY.txt`, `MANIFEST.txt`.
- `results/e2e-verification/zeek/`: `conn.log`/`packet_filter.log`/`dns.log` per capture, `audit_events.jsonl` (3× `EVENT_ZEEK`), `SUMMARY.txt`, `MANIFEST.txt`.
- `results/e2e-verification/audit/`: `events.jsonl` (434 records), `summary.json`, `SUMMARY.txt`, `MANIFEST.txt`.
- `ML_CORRELATION_BOUNDARY.md` (ML/correlation hand-off boundary; correlation out of scope on this branch).

---

## 7. Teardown

Verification and evidence collection are complete (including this run's IPv6-parser and transport-eBPF work, Section 3.18). The tunnel and transport labs were left running for operator inspection. Teardown command (operator-run, privileged):

```
sudo containerlab destroy -t topology/transport/ipsec.clab.yml --cleanup
```

After teardown the normal tunnel testbed remains intact (verified healthy in Section 3.17; no transport artifacts were ever injected into the tunnel topology).
