# IPsec VPN Testbed — Observation & Analysis Framework

A reproducible **five-container** IPsec VPN testbed built with **Containerlab**, **strongSwan 6.0.3** and
eBPF/XDP monitoring, in which **GW-A is the authoritative observation point**.

```text
                    IPsec VPN (ESP)
╭─LAN-A─────────╮  ╭──────WAN──────╮  ╭─LAN-B─────────╮
│               │  │               │  │               │
│  Host-A ───── GW-A ───── br-wan ───── GW-B ───── Host-B │
│  10.10.1.10   │ eth2    eth2     │  10.10.2.10      │
│               │  │               │  │               │
│               │  eth3    eth1    │                     sensor (passive)
│               │    ╰── mirror ──╯╯  ip_forward=0, NOT on br-wan
│               │  audit-tap0         eBPF/XDP eth1      │
╰───────────────╯  (in-gw-a tap)                         │
```

There are **five** containers (tunnel topology):

| Node     | Role              | Address                            |
| -------- | ----------------- | ---------------------------------- |
| `host-a` | LAN-A host        | `10.10.1.10/24`                    |
| `gw-a`   | IPsec gateway (observation point) | `10.10.1.1/24`, `192.168.100.1/24` |
| `gw-b`   | IPsec gateway     | `192.168.100.2/24`, `10.10.2.1/24` |
| `host-b` | LAN-B host        | `10.10.2.10/24`                    |
| `sensor` | Passive observation node | mirror feed on `eth1`          |

Architecture notes (verified behaviour — do not "fix"):

* The WAN is a root-namespace bridge named **`br-wan`** carrying **only** the two gateway
  members (`gw-a eth2`, `gw-b eth2`). The sensor is **not** a member and has
  `net.ipv4.ip_forward=0`.
* GW-A mirrors **both directions** of its `eth2` traffic using `tc`/`clsact` `mirred`
  actions. The mirror feeds (**a**) an in-gw-a `tap` device `audit-tap0` (forensic surface,
  readable with `tshark`) and (**b**) `gw-a eth3` → `sensor eth1`.
* `br-wan` must exist **before** `containerlab deploy`; the deploy wrapper handles this.
  Always deploy/teardown through the wrapper — never a bare `containerlab deploy`.

---

## Quick Start (one-step lifecycle)

Everything is scripted. From the repository root:

```bash
./scripts/install.sh   # 1) host prereqs + images + ebpf build + topology validation
./scripts/run.sh       # 2) deploy (or converge) + full verification
./scripts/status.sh    # 3) concise health report, any time
./scripts/stop.sh      # 4) teardown (reuses the deployment destroy path)
```

`run.sh` and `stop.sh` recreate `br-wan` and run Containerlab, so they require root
(`sudo ./scripts/run.sh`); `install.sh` and `status.sh` run unprivileged.

### Output conventions

| Tag      | Meaning                                             |
| -------- | --------------------------------------------------- |
| `[OK]`   | check passed                                        |
| `[WARN]` | non-fatal observation (e.g. optional XDP sampling)  |
| `[FAIL]` | required check failed → the script exits non-zero   |

`install.sh` exits non-zero if a **required** prerequisite is missing. It will not fail
because native XDP cannot attach (native/DRV XDP is a known veth/MTU limitation; the
verified mode is **generic/SKB** — see §XDP).

### Idempotency

* `install.sh`: existing images and the built `ebpf/xdp_monitor` are reused.
* `run.sh`: if the lab is already deployed and observation-mirror healthy, it **converges**
  (skips redeploy) and re-verifies the full stack; otherwise it redeploys through the
  deploy wrapper (`--reconfigure`-based), which is safe on a running lab.

---

## Requirements

Run the testbed inside the Ubuntu VM:

* Ubuntu (Linux), Docker (daemon running), Containerlab,
* build toolchain for the eBPF monitor: `clang`/`llvm`, `bpftool`, `libbpf`/`libelf`/`libz`, `make`,
* `python3` with `pyyaml` (used for topology validation).

`install.sh` checks all of these and prints per-item `[OK]/[WARN]/[FAIL]`; fix any
`[FAIL]`, then re-run it. It does **not** install system packages — only reports them.

Artifacts:

```text
ebpf/xdp_monitor          built by `make -C ebpf` (installed/run inside the sensor)
```

---

## Project Structure

```text
ipsec-testbed/
├── controller/                    # sensor side: capture, deploy, dataset, features, RF
├── correlation/                   # analysis side: state, comparison, risk, XAI, audit, API
├── ebpf/
│   └── xdp_monitor.c ...          # eBPF/XDP monitor (CLI: <iface> [--json])
├── frontend/                      # static dashboard assets
├── tests/                         # analysis-side test suite + committed fixtures
├── docs/                          # all documentation (see docs/README.md)
│   ├── architecture/              # schema, design, boundary contracts
│   ├── verification/              # verification reports + final verification report
│   ├── reports/                   # implementation/change reports
│   └── development/               # repository guide
├── gateway-image/   host-image/   transport-host-image/    # Dockerfiles
├── configs/gw-a/swanctl           configs/gw-b/swanctl     # strongSwan
├── topology/
│   ├── tunnel/ipsec.clab.yml      # verified tunnel architecture
│   └── transport/ipsec.clab.yml   # transport (host-d) topology
├── campaigns/                     # named experiment plans (--campaign)
├── campaign.json  campaign-quality.json                   # default campaign inputs
├── scripts/
│   ├── install.sh                 # one-step preparation
│   ├── run.sh                     # deploy + verify
│   ├── status.sh                  # health report
│   ├── stop.sh                    # teardown
│   ├── gateway-entrypoint wrappers (gw-entrypoint.sh, audit-tap-setup.sh,
│   │                              transport-entrypoint.sh)
│   └── deploy-ipsec.sh            # authoritative deploy/destroy wrapper (br-wan + clab)
├── results/                       # LOCAL generated evidence — not committed
└── README.md
```

Git-ignored: `results/` and `out/` (local generated evidence), `topology/*/clab-*/`
(Containerlab state), `controller/generated/`, Python caches, `.env`.
The one committed capture is `controller/testdata/*.pcap`, which three test modules
require — see [docs/development/REPOSITORY_GUIDE.md](docs/development/REPOSITORY_GUIDE.md).

## Documentation

Start with **[docs/verification/FINAL_VERIFICATION_REPORT.md](docs/verification/FINAL_VERIFICATION_REPORT.md)**
for current scope, architecture, what was verified, and known limitations.
The full documentation index is [docs/README.md](docs/README.md).

---

## Building the Images (done by install.sh)

```bash
docker build -t ipsec-test-gateway:6.0.3  ./gateway-image
docker build -t ipsec-test-host:24.04     ./host-image
docker build -t ipsec-transport-host:24.04 ./transport-host-image
```

The gateway image is based on `openeuler/strongswan:6.0.3-oe2403sp4` and adds `tcpdump`,
`tshark`, and the observation helpers.

---

## How the Sensor/Monitoring Works

On GW-A the container entrypoint provisions the observation path:

```text
gw-a eth2 (ingress + egress) ── tc mirred (mirror-dev, 2 chained actions)
        ├──> bridge tap "audit-tap0"           (tshark -i audit-tap0)
        └──> eth3 ── veth ──> sensor eth1       (tcpdump, eBPF/XDP)
```

Verify the mirror filters (they live on the `ingress`/`egress` parents of `eth2`):

```bash
docker exec clab-ipsec-gw-a tc filter show dev eth2 ingress | grep mirred
docker exec clab-ipsec-gw-a tc filter show dev eth2 egress  | grep mirred
```

> Trap: the bare `tc filter show dev eth2` form lists the root qdisc only and returns
> nothing for clsact mirrors. Always check `... ingress` and `... egress` explicitly.
> (`run.sh`/`status.sh` already implement this correctly.)

### cBPF/audit tap readout (in gw-a)

```bash
docker exec clab-ipsec-gw-a tshark -i audit-tap0 -c 20        # ESP frames live
docker exec clab-ipsec-host-a  ping -c 3 10.10.2.10 &          # generate traffic
```

### eBPF/XDP monitor on the sensor

The sensor runs `xdp_monitor` (non-terminating, JSON events per packet). The veth/MTU
combination rejects **native (driver)** XDP (`veth: Peer MTU is too large to set XDP`);
the monitor automatically falls back and runs in **generic (SKB) mode**, which is verified
working on this testbed. `install.sh` never fails on this limitation.

```bash
docker cp ebpf/xdp_monitor clab-ipsec-sensor:/usr/sbin/xdp_monitor
docker exec clab-ipsec-sensor /usr/sbin/xdp_monitor eth1 --json   # live stream
```

Useful XDP fields: `type` (`ESP`/`AH`/`IKE`/`IKE-NAT-T`/`OTHER`), `spi`, `seq`, `src`/`dst`.

---

## IPsec Configuration

```text
IKE v2, PSK (shared), GW-A ID gw-a, GW-B ID gw-b
TS GW-A local 10.10.1.0/24, remote 10.10.2.0/24
CHILD_SA: lan-a-to-lan-b — TUNNEL, ESP:AES_GCM_16-256
```

Initiate/re-establish from GW-A:

```bash
docker exec clab-ipsec-gw-a swanctl --initiate --child lan-a-to-lan-b
```

`run.sh` does this automatically and waits for `ESTABLISHED`.

---

## Verification Reference (what run.sh checks)

1. **Nodes**: all five containers running.
2. **Interfaces**: `gw-a eth1/eth2/eth3`, `audit-tap0`, `sensor eth1`.
3. **Observation mirror**: ≥1 `mirred` action per direction on `gw-a eth2`.
4. **IPsec**: `swanctl --list-sas` → `ESTABLISHED` + CHILD `lan-a-to-lan-b`.
5. **XFRM**: ESP states present, outbound tunnel policy installed.
6. **Connectivity**:

   ```bash
   docker exec clab-ipsec-host-a ping -c 5 10.10.2.10          # expect 0% loss
   docker exec clab-ipsec-host-b ping -c 5 10.10.1.10          # reverse direction
   ```

7. **Sensor mirror**: live capture during a ping burst — `gw-a eth2` and `sensor eth1`
   counts match (high watermark, then stable).
8. **Audit tap**: live `tshark` sample on `audit-tap0` sees ESP.
9. **Sensor posture**: `ip_forward=0`; sensor not on `br-wan` (`br-wan` members remain
   exactly the two gateway `eth2`s).
10. **XDP (optional, non-fatal)**: `xdp_monitor` on `sensor eth1` receives ESP events in
    generic/SKB mode.

### Known dataplane quirk (by design)

Both gateways forward LAN traffic through the tunnel **and** drop a plaintext copy onto
the WAN (static `main`-table routes coexist with strongSwan's policy-route table 220).
Receivers discard the plaintext at XFRM ingress, so ping stays exact. It is faithfully
mirrored to the sensor (appears as `OTHER` in XDP when ICMP) and is **not** caused by —
and must not be "fixed" by — the observation work.

---

## Teardown / Recovery

```bash
sudo ./scripts/stop.sh        # destroys the lab and removes br-wan (via the wrapper)
./scripts/run.sh              # redeploy + full re-verify any time
```

Recovery rule of thumb inherited from the wrapper: to recreate the Containerlab dataplane
links, use the wrapper's `destroy`/`deploy` (a bare `docker restart` does not restore
`eth1/eth2/eth3`). Health checks and first-run provisioning live in `deploy-ipsec.sh`.

---

## Final Validation Checklist

```text
[ ] install.sh exits 0 (idempotent across re-runs)
[ ] five containers running
[ ] GW-A observation ready: eth2 ing+eg mirror -> audit-tap0 + eth3 -> sensor
[ ] br-wan members = gw-a eth2, gw-b eth2 (sensor NOT a member)
[ ] sensor ip_forward=0
[ ] charon running on both gateways, configs loaded
[ ] IKEv2 SA + CHILD_SA lan-a-to-lan-b ESTABLISHED (ESP:AES_GCM_16-256)
[ ] XFRM state/policy present, counters advance
[ ] Host-A → Host-B ping 0% packet loss (and reverse)
[ ] ESP mirrored 1:1 from gw-a eth2 to sensor eth1
[ ] audit-tap0 sees ESP in gw-a
[ ] xdp_monitor captures ESP on sensor eth1 (generic/SKB mode)
[ ] run.sh on an already-healthy lab converges (no blind redeploy)
[ ] stop.sh tears down cleanly; next run.sh redeploys and passes fully
```

This is the validated observation-aware IPsec testbed for the project.