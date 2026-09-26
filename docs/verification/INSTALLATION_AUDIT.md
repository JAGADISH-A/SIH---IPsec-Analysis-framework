# INSTALLATION_AUDIT — IPsec Testbed

**Phase 1 — analysis only.** No implementation changes made. Every conclusion cites the
repository files/commands that support it. Verified environment facts (this machine):
Ubuntu 26.04.1 LTS, kernel 7.0.0-31-generic, Docker server 29.1.3, Containerlab 0.79.0,
clang 21.1.8, bpftool v7.7.0, libbpf 1.6, GCC 15.2.0, Make 4.4.1, pyyaml 6.0.3.
Working tree = HEAD `64ce174`.

> **Critical git-state fact (read first):** the repository HEAD commit does **not** contain
> `scripts/install.sh`, `scripts/run.sh`, `scripts/status.sh`, `scripts/stop.sh`,
> `.dockerignore`, or the eBPF staging in `transport-host-image/Dockerfile`
> (`git cat-file -e HEAD:scripts/install.sh` → NO; `git show HEAD:transport-host-image/Dockerfile
> | grep -c COPY` → 0). These live only in the **working tree** as untracked/modified files.
> A fresh `git clone` of HEAD today would have **no installation script at all**. Closing this
> is a prerequisite for "another developer can set it up" (see §13, item 0).

---

## 1. Current installation flow

`scripts/install.sh` (338 lines) — the only installation/preparation entry point. Lifecycle
traced start to finish:

```text
scripts/install.sh
  │ 0. resolve SCRIPT_DIR/ROOT_DIR, cd $ROOT_DIR          (install.sh:27-29)
  │ 1. Host prerequisites                                  (install.sh:53-151)
  │    OS (Linux uname) ── Docker CLI+daemon usable ── Containerlab ── sudo/root posture
  │    clang ── llvm-config ── bpftool ── libbpf/libelf/libz (ldconfig) ── make+cc
  │    python3 (+pyyaml, optional-by-label)
  │    fail_count>0 → exit 1                                (install.sh:147-151)
  │ 2. eBPF build:  make -C ebpf                            (install.sh:157-180)
  │    requires ebpf/Makefile; artifact must be -x ebpf/xdp_monitor
  │ 3. Container images (build missing, skip existing)      (install.sh:185-229)
  │    ipsec-test-gateway:6.0.3   ctx=gateway-image/
  │    ipsec-test-host:24.04      ctx=host-image/
  │    ipsec-transport-host:24.04 ctx=repo-root (kind=transport, stages ebpf/xdp_monitor)
  │ 4. Topology validation (tunnel + transport)             (install.sh:236-320)
  │    file presence → YAML parse (guarded first pass) → image-ref presence vs docker
  │    → dir writable → no-op notes on br-wan
  │ exit 0 / exit 1
```

Nothing beyond preparation: `install.sh` never deploys, never touches `br-wan`, never runs
containerlab `deploy`. It closes with pointers to `run.sh` / `status.sh` / `stop.sh`
(install.sh:333-337).

Rendering loop on this machine (verified, recorded in `results/e2e-verification/MANIFEST.txt`):
`install.sh` exit 0, idempotent, eBPF rebuild reproduces sha `f0da9894…`, three images
"already exists - skipped build", both topologies validate.

## 2. Existing implementation inventory

| Artifact | What it implements | File:line |
| --- | --- | --- |
| `scripts/install.sh` | one-step prereq check + eBPF build + image build + topology validation | whole file |
| `scripts/run.sh` | deploy (converge via `deploy-ipsec.sh deploy`) + full runtime verification | whole file |
| `scripts/status.sh` | read-only health report | whole file |
| `scripts/stop.sh` | `deploy-ipsec.sh destroy` + hang-over check | whole file |
| `scripts/deploy-ipsec.sh` | `br-wan` ensure + `containerlab deploy --reconfigure` / `destroy --cleanup` | deploy-ipsec.sh:51-64,96-111 |
| `scripts/gw-entrypoint.sh` | charon + VICI wait + `swanctl --load-all` + observation provisioning | whole file |
| `scripts/transport-entrypoint.sh` | charon + load + **starts `xdp_monitor eth1 --json`** (soft-fail) | transport-entrypoint.sh:32-45 |
| `scripts/audit-tap-setup.sh` | idempotent `tc mirred` mirror (eth2 → audit-tap0 + eth3) | whole file |
| `ebpf/Makefile` | clang/bpftool/cc build of `xdp_monitor` (SKB/generic verified mode) | whole file |
| `ebpf/xdp_monitor.{c,bpf.c,common.h}` + committed `vmlinux.h/.skel.h/.bpf.o/xdp_monitor` | IPv4+IPv6 ESP/AH/IKE/IKE-NAT-T classifier + monitor | xdp_monitor.bpf.c:147-208 (IPv6) |
| `transport-host-image/Dockerfile` | stages `ebpf/xdp_monitor` into `/usr/sbin/xdp_monitor` + runtime libs | Dockerfile:26 |
| `gateway-image/Dockerfile` / `host-image/Dockerfile` | strongSwan 6.0.3 + tshark/tcpdump; plain ubuntu host | whole files |
| `.dockerignore` | keeps root build context lean, keeps `ebpf/` + image dirs | whole file |
| `topology/tunnel/ipsec.clab.yml` | 5-node verified architecture; repo-relative binds `../../scripts/…` | lines 28-31,45-47 |
| `topology/transport/ipsec.clab.yml` | 2-node transport lab; `../../scripts/transport-entrypoint.sh` bind | lines 10-13,24-27 |
| `README.md` | quick start, requirements, artifacts, verification reference | lines 42-54,77-92 |

## 3. Missing implementation

1. **`pyyaml` at install time** — install.sh:141 flags pyyaml as a non-fatal `[WARN]`, and the
   first heredoc guards `import yaml` (install.sh:255-264), but the **second heredoc
   hard-imports `yaml` unguarded** (install.sh:286: `import sys, yaml`). On a host without
   python3-yaml, install.sh crashes with an unhandled `ImportError` at the topology-image
   step (`[$FAIL] topology syntax validation failed`), directly contradicting the WARN.
   *Evidence of latent failure, not testable here (pyyaml installed = the failure is masked).*
2. **python3 is effectively required but flagged WARN** — install.sh:144 warns "topology
   validation limited" when python3 is absent, yet install.sh:247 and install.sh:286 invoke
   `python3` unconditionally. Missing python3 → crash at section 4, not the promised graceful
   degradation.
3. **Containerlab minimum version not checked** — `--reconfigure` behavior is described as
   "since containerlab 0.79" (deploy-ipsec.sh:23-32). install.sh only checks presence
   (install.sh:76-86). An older containerlab would install cleanly then fail at deploy-time.
4. **Host `ip`/`bridge` (iproute2) not checked** — `ensure_bridge()` needs `ip link add type
   bridge` (deploy-ipsec.sh:54-57) and containerlab wiring needs `bridge`; neither is checked
   by install.sh. On a minimal server this installs fine but deploy fails.
5. **eBPF staging invariant not enforced when the transport image already exists** —
   install.sh:205-208 skips the build wholesale when `ipsec-transport-host:24.04` is present.
   If the repo's `ebpf/xdp_monitor` is later recompiled (different classifier), the stale
   image keeps the old binary and install.sh never notices. Invariant enforcement exists only
   at image-create time (install.sh:210-216), never at image-present time.
6. **Dev-header prerequisites not checked** — only runtime `.so` presence is verified via
   ldconfig (install.sh:122-128). A genuine `make clean && make -C ebpf` also needs
   `<bpf/libbpf.h>`, `<bpf/bpf_helpers.h>` (libbpf-dev) and `<linux/if_link.h>`
   (linux-libc-dev). Missing → build fails on an otherwise "OK" prereq report.
7. **Installation artifacts are not committed** (see git-state fact above). No fresh
   developer can obtain `install.sh`/`run.sh`/`status.sh`/`stop.sh`/`.dockerignore` or the
   staged transport Dockerfile from git.

## 4. Partial implementation

1. **eBPF toolchain checks are over-strict for a fresh clone** — all of
   `ebpf/xdp_monitor`, `.bpf.o`, `.skel.h`, `vmlinux.h` are committed (verified:
   `git ls-files ebpf/`). A fresh clone therefore builds via a `make` no-op
   (verified: `make -C ebpf` → "Nothing to be done for 'all'"), *and the committed binary is
   fully loadable* (runtime libs `libbpf.so.1/libelf.so.1/libz.so.1/libzstd.so.1` satisfied
   inside the image; `ldd` verified identical host vs image). Yet install.sh **hard-FAILs**
   without clang/llvm/bpftool/`make`. The toolchain is genuinely only needed to *rebuild*
   from source; a friend who only wants to run the testbed is needlessly blocked.
2. **`bpftool` check has a redundant/dead branch** — install.sh:114-120 does
   `if command -v bpftool … elif command -v bpftool … || ls /usr/sbin/bpftool …`. The first
   `elif` arm repeats the `if` condition; the effective behavior (PATH then `/usr/sbin/bpftool`)
   works but the code is confusing.
3. **`python3`/`pyyaml` labelling** — labelled optional, actually required (§3 items 1-2).
4. **Docker fallback is passwordless-sudo-only** — install.sh:69 `sudo -n docker info`; a user
   with password-protected sudo and no docker-group membership hits the hard FAIL at
   install.sh:73 even though they could legitimately build images via a sudoed docker.
5. **README/requirements** — correctly document the toolset (README.md:77-92) but do not
   document the pyyaml/py3 inconsistency or the containerlab-version floor.

## 5. Portability issues

| # | Issue | Evidence | Impact |
| --- | --- | --- | --- |
| P1 | Installation scripts & staging Dockerfile not in HEAD | git-state fact | fresh clone cannot install |
| P2 | Committed build artifacts (`vmlinux.h` 3.5 MB, `.o/.skel.h/binary`) mean `make` is a no-op on a pristine clone; sha `f0da9894…` is only reproducible with the same clang/libbpf combo | `make -C ebpf` no-op; report §3.19.4 | rebuild determinism ≠ cross-machine; acceptable but must be documented, and image-staging invariant must be "bit-identical to repo binary" not "sha X" |
| P3 | All paths repo-relative (good): scripts use `SCRIPT_DIR/…/..`; topology binds are `../../scripts/…` resolved by containerlab against the topology file location | install.sh:27-29; topology/tunnel/ipsec.clab.yml:29-31 | portable — no `$HOME`, absolute path, or username anywhere (`grep`)
| P4 | `stat -c %s` (GNU) and `ldconfig -p` assumed | install.sh:173,123 | fine on any Linux/GNU distro; not on macOS (already rejected at install.sh:55) |
| P5 | Docker base pulls needed at first install (openeuler/strongswan, ubuntu:24.04) + gateway `dnf install` network fetch | gateway-image/Dockerfile:3-6 | first install requires internet |
| P6 | Build context for transport image = repo root; `.dockerignore` keeps it lean (`.git`, `.venv`, `results`, `__pycache__`) and is present only untracked | .dockerignore; install.sh:216 | works; but root context also ships `vendor/` (440 K) — harmless |
| P7 | Containerlab/pip/venv tooling for the *controller* is runtime, not install | requirements.txt; `controller/` | correctly out of install scope |

## 6. Privilege issues

| Step | Root? | Docker/sudo? | Evidence | Assessment |
| --- | --- | --- | --- | --- |
| install.sh prereq checks | no | docker group OR passwordless sudo for `$DOCKER` | install.sh:67-74 | correct; hardening: password-sudo users blocked (§4.4) |
| eBPF `make -C ebpf` | no | none | install.sh:165 | correct |
| `docker build …` | no | docker group / sudoed docker | install.sh:205-228 | correct |
| topology validation | no | docker inspect for image refs | install.sh:301-307 | correct |
| run.sh deploy | **yes** (br-wan + containerlab) | plain `docker` calls assume docker group | run.sh:22-26,65-87; deploy-ipsec.sh:54-64 | documented — run.sh/stop.sh require root; install.sh/status.sh do not (README.md:53-54) |
| stop.sh destroy | **yes** | — | stop.sh:13-27 | correct |
| status.sh | read-only | docker group | status.sh:31-36 | correct |

Installation steps that actually need root: **none**. Runtime deployment steps (br-wan +
containerlab) need root — correctly separated into `run.sh`/`stop.sh`/`deploy-ipsec.sh`, not
mixed into installation. The privilege model is sound.

## 7. Idempotency analysis (two consecutive `install.sh` runs)

| Step | Second-run behavior | Verdict |
| --- | --- | --- |
| prereq checks | re-run; pure reads | SAFE |
| `make -C ebpf` | no-op if artifacts present; rebuilds only if sources newer | SAFE / not repeated uselessly |
| `docker image inspect` loop | each existing image → "skipped build" | SAFE, RELEASED as intended |
| transport image staging | not re-verified (stale-staging risk, §3.5) | SAFE but not self-healing |
| topology validation | pure reads/parses | SAFE |
| Overall | exit 0; verified twice this session (report §3.19.4: "install.sh re-run exit 0, idempotent … eBPF rebuild reproduces sha f0da9894…") | SAFE / IDEMPOTENT |

`run.sh` second-run: converges (skips redeploy) when lab healthy (run.sh:81-94); otherwise
redeploys via `--reconfigure` which is safe on a running lab (deploy-ipsec.sh:23-32).
`stop.sh` clears so a later `run.sh` redeploys. No step FAILS on a second run; no step writes
outside the repo except containerlab state under `topology/*/` (git-ignored).

## 8. Dependency matrix

| Dependency | State | Evidence | Gap | Required change |
| --- | --- | --- | --- | --- |
| OS: Linux (uname) | IMPLEMENTED | install.sh:55-59 | none | none |
| Docker CLI + daemon usable | IMPLEMENTED | install.sh:61-74 | password-sudo edge (§4.4) | optional: prompt/sudo fallback hardening |
| Containerlab present | IMPLEMENTED | install.sh:76-86, status.sh:41-45 | no min-version check (§3.3) | add `>=0.79` check |
| clang | IMPLEMENTED | install.sh:102-106 | over-strict for no-op build (§4.1) | document committed-binary no-op path |
| llvm (`llvm-config`) | IMPLEMENTED | install.sh:108-112 | same as clang | same |
| bpftool | IMPLEMENTED | install.sh:114-120 | dead `elif` arm (§4.2) | simplify condition |
| libbpf/libelf/libz runtime `.so` | IMPLEMENTED | install.sh:122-128 | headers not checked (§3.6) | optional: add dev-header check |
| libbpf-dev / linux-libc-dev headers | MISSING | — | only `.so` checked | add for `make clean` path |
| make + cc | IMPLEMENTED | install.sh:130-134 | none | none |
| python3 | PARTIAL | install.sh:136-145 vs 247/286 | flagged WARN but hard-required (§3.2) | FAIL when absent |
| pyyaml | PARTIAL | install.sh:138-141 vs guarded heredoc vs 286 | unguarded 2nd heredoc (§3.1) | guard 2nd heredoc |
| kernel headers + kernel BTF | NOT REQUIRED at install | committed `vmlinux.h`; `vmlinux.h` rule only fires if file missing (Makefile:13-16); `/sys/kernel/btf/vmlinux` regen path never hit on clone | none | none (runtime BTF needs are container-side) |
| tshark / tcpdump on host | NOT REQUIRED | installed only inside images (gateway-image/Dockerfile:3-8; transport-host-image/Dockerfile:10-16) | none | none |
| iproute2 (`ip`/`bridge`/`tc`) | MISSING check | deploy-ipsec.sh:51-57 | host may lack on minimal server (§3.4) | add WARN |
| sudo / root | IMPLEMENTED | install.sh:88-98; run.sh:22-26 | none | none |
| git | NOT REQUIRED by install | needed only to obtain repo | none | none |
| eBPF runtime kernel support (veth XDP, ringbuf) | NOT REQUIRED by install | runtime concern of sensor/transport containers (privileged) | none | none |

## 9. Docker/image matrix

| Image | Tag | Build context | Dockerfile | Base | Built when missing | Staged eBPF | Order |
| --- | --- | --- | --- | --- | --- | --- | --- |
| gateway | ipsec-test-gateway:6.0.3 | `gateway-image/` | gateway-image/Dockerfile | `openeuler/strongswan:6.0.3-oe2403sp4` (pulled) | yes | no | after eBPF (n/a) |
| host | ipsec-test-host:24.04 | `host-image/` | host-image/Dockerfile | `ubuntu:24.04` (pulled) | yes | no | after eBPF (n/a) |
| transport | ipsec-transport-host:24.04 | **repo root** | transport-host-image/Dockerfile:26 | `ubuntu:24.04` (pulled) | yes | **copies `ebpf/xdp_monitor`** | **must be after eBPF build** — enforced (install.sh:210-216) |

- Existing-images-on-this-machine: gateway (built 09-17), host (09-12), transport (09-23,
  contains staged binary sha == host build sha `f0da9894…`, verified §10).
- Skip-existing: install.sh:205-208. Rebuild never forced; no drift detection (§3.5).
- First install on a fresh machine: all three built; base images + gateway `dnf install`
  require network (P5).
- Idempotency of the step: SAFE (§7). Unnecessary rebuilds: **none**.

## 10. eBPF build/staging matrix

| Stage | Current | Evidence | Gap / change |
| --- | --- | --- | --- |
| Source | `ebpf/xdp_monitor.bpf.c` + `_common.h` (IPv4+IPv6 classifier; ringbuf + counters map) | xdp_monitor.bpf.c:147-208 (IPv6 outer) | none |
| Build | `make -C ebpf` via clang→skel→cc (`-lelf -lz -lbpf`); generic/SKB is the verified attach mode | ebpf/Makefile:1-24; install.sh:165 | toolchain strictly required while committed artifacts make it a no-op (§4.1) |
| Binary | committed `ebpf/xdp_monitor` (62,176 B; sha256 `f0da9894…` on this toolchain) | `sha256sum ebpf/xdp_monitor`; `stat -c %s` | sha is toolchain-dependent (P2) |
| Verification | install.sh only checks presence/`-x` + reports byte size | install.sh:172-180 | add in-place `sha256sum` + staged-image compare (§3.5) |
| Transport image staging | Dockerfile `COPY ebpf/xdp_monitor /usr/sbin/xdp_monitor`; runtime libs `libbpf1 libelf1 zlib1g libzstd1`; image built from repo root AFTER the build | transport-host-image/Dockerfile:26,10-22; install.sh:210-216 | enforced only at image-create (§3.5) |
| Invariant in env | **host `ebpf/xdp_monitor` sha == staged `/usr/sbin/xdp_monitor` sha = `f0da9894…`** (verified live) | `sha256sum` both | preserved; add enforcement at image-present |

## 11. Installation vs deployment boundary

```text
INSTALLATION      install.sh                prereq checks + eBPF build + images + topology validation
   ↓
BUILD/PREPARE     install.sh §2-3           eBPF binary + 3 images (eBPF before transport image)
   ↓
DEPLOYMENT        run.sh / stop.sh          br-wan + containerlab deploy/destroy (root)
   ↓
RUNTIME VERIFY    run.sh §2-9               nodes/interfaces/mirror/IPsec/XFRM/connectivity/sensor/audit/XDP
   ↓
EVIDENCE VERIFY   E2E_VERIFICATION_REPORT   results/e2e-verification/* (offline captures, parser, zeek, audit)
```

Correctly placed: install.sh does **preparation only** — it never deploys, never builds
`br-wan`, never runs containerlab `deploy`, never claims runtime verification (README.md:53-54;
deploy-ipsec.sh:51-64). Deploy(root), verify, evidence are in their own layers. Nothing is in
the wrong layer. The only boundary smell is install.sh's hard dependency on a runnable Docker
daemon + containerlab merely to *validate* topology YAML and image refs — acceptable and
unchanged (a "prepared testbed host" assumption already documented in install.sh:64,85).

## 12. Fresh-machine walkthrough

Developer: fresh Ubuntu clone, no images, no eBPF toolchain, docker installed+group,
sudo, internet. `git clone … && cd ipsec-testbed`:

1. **`ls`** → no `install.sh` (it is untracked in the workspace). **FAILS to even start.**
2. (After artifacts are committed) `./scripts/install.sh`:
   - prereq: docker OK; containerlab required (must pre-install `containerlab`, version floor
     unenforced); **clang/llvm/bpftool/make all required — absent → hard FAIL**, even though the
     committed binary makes a build unnecessary (§4.1). Installing the full eBPF toolchain
     unblocks it but is real friction.
   - `make -C ebpf` → no-op (artifacts committed).
   - docker builds: pulls `ubuntu:24.04` + `openeuler/strongswan:6.0.3-oe2403sp4` (internet),
     gateway `dnf install` fetches more (internet), transport image stages the committed
     binary → invariant holds trivially.
   - topology validation with pyyaml present → OK. (Without pyyaml → unhandled ImportError, §3.1.)
3. `sudo ./scripts/run.sh`:
   - needs `ip`/`bridge`/`iproute2` on host (unchecked, §3.4 — present on Ubuntu server images).
   - deploy + full verify. Works if containerlab ≥ 0.79 (unchecked — older silently breaks).
4. `./scripts/status.sh` read-only; `sudo ./scripts/stop.sh` teardown.

Success points: scripted flow, repo-relative paths, idempotent install, deterministic binary
staging when images are freshly built.
Failure points: (a) install scripts not committed → cannot clone-and-install; (b) over-strict
toolchain, (c) latent pyyaml crash, (d) no clab min-version / iproute2 checks, (e) stale
transport image never re-verified after the repo binary changes.

## 13. Exact recommended changes (Phase 2 candidates — smallest, preserving verified behavior)

| # | Change | Justification | Risk |
| --- | --- | --- | --- |
| 0 | Commit the installation artifacts (`install.sh`, `run.sh`, `status.sh`, `stop.sh`, `.dockerignore`, `E2E_VERIFICATION_REPORT.md`, `ML_CORRELATION_BOUNDARY.md`, updated `transport-host-image/Dockerfile`/`transport-entrypoint.sh`/configs/tests). *(Requires an explicit user request — never commit unasked.)* | HEAD lacks all installation entry points; without this no fresh developer can install | low (documentation/repo hygiene) |
| 1 | Guard the second topology heredoc against missing `yaml` (reuse the first heredoc's structural-check fallback) | fixes latent install crash (§3.1,§4.3) | low |
| 2 | Make python3 a hard `[FAIL]` rather than `[WARN]` | it is used unconditionally (§3.2) | low |
| 3 | When `ipsec-transport-host:24.04` already exists, compare staged `/usr/sbin/xdp_monitor` sha256 vs `ebpf/xdp_monitor`; `[WARN]` on mismatch with a one-line rebuild hint. Keep the existing create-time enforcement. | closes the stale-staging gap (§3.5) without forcing rebuilds; preserves the verified invariant contract "image binary == repo binary" | low (`docker run --rm --entrypoint sha256sum` on existing image) |
| 4 | Add a containerlab minimum-version check (`>= 0.79`) at install.sh:76 | required by `--reconfigure` (deploy-ipsec.sh:23-32) (§3.3) | low |
| 5 | Add a `[WARN]` (not FAIL) when host `ip`/`bridge` are absent | needed at deploy time (§3.4) | low |
| 6 | Simplify the `bpftool` dead `elif` arm (install.sh:114-120) | clarity only (§4.2) | negligible |
| 7 | OPTIONAL — document that on a pristine clone the eBPF build is a no-op over committed artifacts and the toolchain is only needed for `make clean`/rebuild; keep checks as-is (honest) or add an explicit rebuild flag | resolves the over-strictness complaint without redesigning the build (§4.1, P2) | low |
| 8 | OPTIONAL — dev-header check (`libbpf.h`, `linux/if_link.h`) for the `make clean` path | completes the build story (§3.6) | low |

## Dependency matrix — component summary

| Component | Current state | Evidence | Gap | Required change |
| --- | --- | --- | --- | --- |
| Docker detection | IMPLEMENTED | install.sh:61-74 | password-sudo edge | optional hardening |
| Containerlab | IMPLEMENTED | install.sh:76-86 | no min-version | add ≥0.79 check (#4) |
| clang / llvm / bpftool / make | IMPLEMENTED | install.sh:102-134 | over-strict for no-op build; dead elif | doc / simplify (#6,#7) |
| libbpf/libelf/libz `.so` | IMPLEMENTED | install.sh:122-128 | headers unverified (§3.6) | optional dev-header check (#8) |
| eBPF build | IMPLEMENTED | ebpf/Makefile; install.sh:165 | no forced rebuild / no sha verify | in-place sha + doc (#7) |
| transport image staging | IMPLEMENTED (create-time) | install.sh:210-216; Dockerfile:26 | not re-verified at image-present (§3.5) | staged-sha compare (#3) |
| topology validation | PARTIAL | install.sh:247-316 | unguarded 2nd heredoc; hard py3 | guard + harden (#1,#2) |
| python3 / pyyaml | PARTIAL | install.sh:136-145,247,286 | labelling vs actual | FAIL / guard (#1,#2) |
| iproute2 host tools | MISSING check | deploy-ipsec.sh:54-57 | unchecked | WARN (#5) |
| host tshark/tcpdump | NOT REQUIRED | images only | none | none |
| kernel headers/BTF | NOT REQUIRED (committed vmlinux.h) | ebpf/Makefile:13-16 | none | none |
| sudo/root model | IMPLEMENTED | install.sh:88-98; run.sh:22-26 | none | none |

---

## Session summary (what's complete / partial / missing)

- **Already complete:** a working, idempotent one-step `install.sh` (prereqs → eBPF build →
  image build → topology validation); a correct installation/deployment boundary; a verified
  eBPF→image staging invariant at **image-create time** (sha `f0da9894…` host == staged);
  all repo-relative paths (no `$HOME`/absolute-path/username dependencies); three images that
  build-from-scratch on a fresh machine; full deploy/verify/teardown lifecycle scripts.
- **Partially complete:** python3/pyyaml are labelled optional but actually required, with an
  unguarded `yaml` import that would crash a fresh install without python3-yaml; the eBPF
  toolchain checks are over-strict given the committed, loadable artifacts; the staging
  invariant is not re-verified when the transport image already exists.
- **Actually missing:** commitment of the installation entry points to git (without it a fresh
  clone cannot install at all); containerlab minimum-version check; host `ip`/`bridge` check;
  eBPF dev-header check for the rebuild path; an explicit, documented "committed-binary no-op
  build / rebuild with `make clean -C ebpf`" path on the README.
- **Implement next (Phase 2, after review):** items 0→3→1→2→4→5→6 in §13, then test:
  1. fresh-install path as far as the environment permits;
  2. second/idempotent install; 3. eBPF build; 4. image creation; 5. binary/image invariants;
  6. existing regression suites. Privilege-limited steps (e.g. containerlab redeploy with
  password-sudo) are marked `ENVIRONMENT-BLOCKED`, never faked.

**Phase 1 complete — analysis only; nothing modified except this audit file.**

---

## Phase 2 — Implementation report (post-review)

Gaps from §13 implemented in `scripts/install.sh` (no other source file changed; install/deploy
boundary preserved). Final status labels: `IMPLEMENTED` / `PARTIALLY IMPLEMENTED` /
`ENVIRONMENT-BLOCKED` / `REMAINING`.

### Files changed
- `scripts/install.sh` — the only modified file (5 edit groups). Nothing else touched.

### Gap-by-gap resolution (map to §13 item numbers)
| # | Gap | Resolution | Status |
|---|-----|-----------|--------|
| 0 | install scripts / `.dockerignore` absent from git HEAD | Files exist and are intended to be committed, but **not committed** per explicit instruction. Committed next time the user asks for a commit. | `PARTIALLY IMPLEMENTED` (commit held intentionally) |
| 1 | python3/pyyaml optional-but-required + latent `yaml` crash | Both are now hard prerequisites: `[FAIL]` (not WARN) if python3 or `import yaml` missing; the topology-validation heredocs are therefore guaranteed safe. | `IMPLEMENTED` |
| 2 | over-strict eBPF toolchain checks on committed-artifact path | Two-path logic: `ebpf_rebuild` probes `make -q -C ebpf` (fallback: no `make` → no-op iff committed `ebpf/xdp_monitor` exists and is executable). Toolchain chain (make/cc, clang, llvm-config, bpftool with `/usr/sbin/bpftool` fallback, libbpf/libelf/libz via `ldconfig`, dev-header compile probe for `bpf/libbpf.h`+`linux/if_link.h`, `bpf/bpf_helpers.h` existence) is checked **only** on the rebuild path; no-op path logs "build toolchain NOT required". | `IMPLEMENTED` |
| 3 | staging invariant not re-verified for existing transport image | New `staged_sha()` (`docker run --entrypoint sha256sum`) + `EBPF_SHA` (host `sha256sum ebpf/xdp_monitor`). Existing transport image → compare; **mismatch = `[FAIL]` + exact rebuild command (`docker build -t <img> -f <ctx>/Dockerfile .`) + `exit 1`**. Post-build verification of a freshly built transport image also enforced. | `IMPLEMENTED` |
| 4 | containerlab min-version missing | `CLAB_MIN_VERSION="0.79.0"` + numeric `version_at_least()` (main/major/minor/patch), ANSI-stripped parse of `containerlab version`. Older version → `[FAIL]` naming `deploy-ipsec.sh '--reconfigure'`; unparseable → `[WARN]` (fail-closed only at deploy? no — version string that fails to parse warns, then proceed: containerlab was at least runnable). | `IMPLEMENTED` |
| 5 | host `ip`/`bridge` missing | Deploy-reflecting `[WARN]` checks (root-namespace `br-wan` is created/deployed by `deploy-ipsec.sh` via `ip link add … type bridge` and `bridge link`; WARN mirrors current fail-soft behavior; install never alters the bridge). No arbitrary deps added. | `IMPLEMENTED` |
| 6 | dead `elif` in bpftool check | Removed; bpftool now resolved once with `/usr/sbin/bpftool` fallback → `BPFTOOL_OVERRIDE` for `make`. | `IMPLEMENTED` |
| — | idempotency / no unnecessary rebuild | Second install verified: no-op path, `make -q` returns 0, existing transport image staged sha matches → "skipped build"; wrong staged sha → fail, never silently accepted. | `IMPLEMENTED` |
| 7 | documentation of the two-path behavior | Documented in the install header, section 1b, and §2 runtime output; this report records it. README spot-note not yet added. | `PARTIALLY IMPLEMENTED` |

### Verification run on this host (all real, none fabricated)
- Normal install → exit 0; no-op eBPF path; `f0da9894…` sha; existing `ipsec-transport-host:24.04`
  staged sha matches → skipped build; `containerlab 0.79.0 (>= 0.79.0)`; `ip`/`bridge` present;
  pyyaml OK; both topologies validated. Second run identical → idempotency confirmed.
- `containerlab` shim reporting `0.78.1` → `[FAIL]` + upgrade guidance + exit 1. ✔
- python3 shim lacking `import yaml` → `[FAIL]` "apt install python3-yaml" + exit 1. ✔
- PATH hiding `/usr/sbin` → `ip` still found at `/usr/bin/ip` (OK), `bridge` `[WARN]`, exit 0. ✔
- Scratch stale transport image (different staged binary) → `[FAIL]` showing staged vs host sha +
  rebuild command + exit 1. Real image untouched. ✔
- Rebuild-path harness (isolated `ebpf/` copy with artifacts removed) → rebuild detected; clang,
  llvm 21.1.8, bpftool (override), libbpf/libelf/libz, dev-header compile probe, `bpf/bpf_helpers.h`
  all OK; `make` build succeeded; sha printed; exit 0. Determinism: same-dir rebuild reproduces the
  same sha. ✔
- `version_at_least` unit: 7/7 cases (equal/above/below on each component). ✔
- Regressions: 55 controller + 44 eBPF state/window + 15 privileged `test_xdp_classifier`
  (real BPF load in `clab-ipsec-transport-host-c`) — all green. ✔

### Cross-directory rebuild note (documents the reported sha delta)
A fresh `make -C ebpf` from `/tmp/…` produced sha `04b1473d…` vs committed `f0da9894…`. Root cause:
`CFLAGS=-g` embeds the DWARF compilation directory into the binary (confirmed via
build-id + `strings` showing the two different `comp_dir`s), so the same sources rebuild
byte-identically **only from the repository directory**. Consequence: the staging invariant is
enforced against the *current host artifact* (as implemented), not a fixed global sha — rebuilding
from a different directory then producing a new sha is correctly flagged as a stale-image mismatch
until the transport image is rebuilt, which is the designed, fail-closed behaviour.

### Limitations / remaining
- `ENVIRONMENT-BLOCKED` (password-sudo): containerlab `deploy --reconfigure` (fresh deployment),
  `run.sh` deploy branch, `stop.sh`, host `apt` installs, deletion/re-tag of the in-use transport
  image. The install-deploy boundary is preserved; deploy behavior is unchanged this session.
- `REMAINING`: git commit of the install artifacts (awaiting explicit instruction); README
  spot-note documenting the two-path install behavior.
- Old containerlab `0.7x` deploy-path test beyond the CLI shim is `ENVIRONMENT-BLOCKED` (cannot
  downgrade clab). Logic is exercised via the version-parse/compare shim.
- No demo/privileged `ip`/`bridge` absence test on a real non-iproute2 host; the branch was verified
  via PATH restriction.
- **No git commit was made.**

## Final status labels
| Gap | Status |
|-----|--------|
| 0 install artifacts present & commit-ready | `PARTIALLY IMPLEMENTED` (commit held by instruction) |
| 1 python3/pyyaml hard prereq | `IMPLEMENTED` |
| 2 eBPF two-path (no-op vs rebuild) | `IMPLEMENTED` |
| 3 transport staging SHA invariant (incl. existing image) | `IMPLEMENTED` |
| 4 containerlab ≥ 0.79 | `IMPLEMENTED` |
| 5 host `ip`/`bridge` checks | `IMPLEMENTED` |
| 6 dead `elif` removal | `IMPLEMENTED` |
| 7 two-path documentation | `PARTIALLY IMPLEMENTED` (README spot-note) |
| 8 install/deploy boundary | `IMPLEMENTED` (unchanged, preserved) |
| 9 idempotency | `IMPLEMENTED` |
| 10 tests | `IMPLEMENTED` (env-blocked variants marked, none faked) |
| 11 final report with labels | `IMPLEMENTED` (this section) |
