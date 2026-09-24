#!/usr/bin/env bash
#
# install.sh - one-step installation/preparation for the IPsec testbed.
#
# Responsibilities (installation/preparation ONLY - it never deploys the lab):
#   1. Host prerequisite checks (Docker, Containerlab >= 0.79, python3/pyyaml,
#      sha256sum, host networking tools; the eBPF build toolchain only when a
#      rebuild of ebpf/xdp_monitor is actually required).
#   2. eBPF/xdp_monitor - committed-artifact (no-op) path OR make rebuild path;
#      the host artifact sha256 is recorded for image-staging verification.
#   3. Container image preparation (build missing images; verify the transport
#      image stages the exact host ebpf/xdp_monitor binary sha256 - including
#      for an already-existing image, where a stale staged binary is a hard
#      error with the rebuild command printed).
#   4. Containerlab topology validation (tunnel + transport).
#
# Bring the testbed up with:
#   ./scripts/run.sh
#
# Check its health with:
#   ./scripts/status.sh
#
# Stop it with:
#   ./scripts/stop.sh
#
# Idempotent: safe to run repeatedly; existing images and built artifacts are
# reused.  The GW-A observation architecture (GW-A is the authoritative
# observation point; sensor receives a passive mirror via gw-a:eth3) is
# packaged as-is - installation does not redesign the topology.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR" || exit 1

OK="[OK]"
WARN="[WARN]"
FAIL="[FAIL]"

fail_count=0

ok()   { printf '%s %s\n' "$OK"   "$*"; }
warn() { printf '%s %s\n' "$WARN" "$*"; }
fail() { printf '%s %s\n' "$FAIL" "$*" >&2; fail_count=$((fail_count + 1)); }

section() { printf '\n=== %s ===\n' "$*"; }

CLAB_MIN_VERSION="0.79.0"

# version_at_least "cur" "min" -> 0 if cur >= min, 1 otherwise.
# Numeric, dot-separated (major.minor.patch). Containerlab's banner prints ANSI
# art plus a "version: X.Y.Z" line; the caller pre-strips ANSI.
version_at_least() {
    _cv_cur="$1"
    _cv_min="$2"
    _cv_ca="${_cv_cur%%.*}"; _cv_rest="${_cv_cur#*.}"
    _cv_cb="${_cv_rest%%.*}"; _cv_cc="${_cv_rest#*.}"
    _cv_ma="${_cv_min%%.*}"; _cv_rest="${_cv_min#*.}"
    _cv_mb="${_cv_rest%%.*}"; _cv_mc="${_cv_rest#*.}"
    [ "${_cv_ca:-0}" -gt "${_cv_ma:-0}" ] && return 0
    [ "${_cv_ca:-0}" -lt "${_cv_ma:-0}" ] && return 1
    [ "${_cv_cb:-0}" -gt "${_cv_mb:-0}" ] && return 0
    [ "${_cv_cb:-0}" -lt "${_cv_mb:-0}" ] && return 1
    [ "${_cv_cc:-0}" -ge "${_cv_mc:-0}" ]
}

echo "=========================================================================="
echo " IPsec testbed - installation / preparation"
echo "=========================================================================="
echo "Working directory: $ROOT_DIR"

DOCKER="docker"

# ---------------------------------------------------------------------------
# 1. Host prerequisites
# ---------------------------------------------------------------------------
section "1. Host prerequisites"

if [ "$(uname -s)" != "Linux" ]; then
    fail "unsupported OS '$(uname -s)'; Linux is required (this testbed uses netns/bridge features)."
else
    ok "host OS: Linux ($(uname -r))"
fi

if command -v docker >/dev/null 2>&1; then
    ok "Docker installed ($(docker --version 2>/dev/null | tr -d '\n'))"
else
    fail "Docker is not installed. Install Docker (e.g. get.docker.com) or run this setup on a prepared testbed host."
fi

if $DOCKER info >/dev/null 2>&1; then
    ok "Docker daemon is running and usable by the current user."
elif [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && sudo -n docker info >/dev/null 2>&1; then
    warn "Docker daemon requires sudo for the current user; 'sudo docker' will be used for image steps."
    DOCKER="sudo docker"
else
    fail "Docker daemon is not usable. Start Docker (systemctl start docker) and/or add the user to the 'docker' group."
fi

if command -v containerlab >/dev/null 2>&1; then
    if containerlab version >/dev/null 2>&1; then
        ok "Containerlab executable is runnable."
    else
        fail "Containerlab binary present but not runnable; check its permissions/install."
    fi
    clab_ver="$(containerlab version 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    if [ -n "$clab_ver" ]; then
        if version_at_least "$clab_ver" "$CLAB_MIN_VERSION"; then
            ok "Containerlab $clab_ver (>= $CLAB_MIN_VERSION - required by deploy-ipsec.sh '--reconfigure')."
        else
            fail "Containerlab $clab_ver is OLDER than the required $CLAB_MIN_VERSION - deploy-ipsec.sh relies on 'containerlab deploy --reconfigure'. Upgrade Containerlab and re-run."
        fi
    else
        warn "Containerlab version could not be parsed; cannot verify the >= $CLAB_MIN_VERSION requirement (an old release may fail at deploy time)."
    fi
else
    fail "Containerlab is not installed. Install Containerlab >= $CLAB_MIN_VERSION (github.com/srl-labs/containerlab) or run this setup on a prepared testbed host."
fi

if [ "$(id -u)" -eq 0 ]; then
    ok "running as root - privileged deploy steps will not need sudo."
elif command -v sudo >/dev/null 2>&1; then
    if sudo -n true >/dev/null 2>&1; then
        ok "passwordless sudo available for privileged deploy steps."
    else
        warn "sudo requires an interactive password here; ./run.sh and ./stop.sh will prompt for it."
    fi
else
    warn "no sudo available; ./run.sh and ./stop.sh require root to create the external 'br-wan' bridge and run containerlab."
fi

for net_tool in ip bridge; do
    if command -v "$net_tool" >/dev/null 2>&1; then
        ok "host tool: $net_tool"
    else
        warn "'$net_tool' not found on the host - deploy-ipsec.sh creates the root-namespace 'br-wan' bridge with 'ip link add type bridge' and inspects it with 'bridge link' (deploy-time requirement; apt install iproute2)."
    fi
done

if command -v sha256sum >/dev/null 2>&1; then
    ok "sha256sum available (eBPF image-staging verification)."
else
    fail "sha256sum not found (coreutils); required to verify the transport image stages the exact host eBPF artifact."
fi

if command -v python3 >/dev/null 2>&1; then
    ok "python3: $(python3 --version 2>&1 | tr -d '\n')"
else
    fail "python3 is required (topology validation). apt install python3."
fi
if python3 -c "import yaml" >/dev/null 2>&1; then
    ok "python3: pyyaml available (topology validation)."
else
    fail "python3 module 'yaml' (pyyaml / python3-yaml package) is required by the topology validation; apt install python3-yaml."
fi

section "1b. eBPF prerequisites (committed-artifact vs rebuild path)"

# The repository commits the eBPF build artifacts (vmlinux.h, .bpf.o, .skel.h,
# xdp_monitor).  On a fresh clone `make` has nothing to do, so the full
# clang/llvm/bpftool/libbpf development toolchain is NOT required to install or
# run the testbed.  The toolchain is only mandatory when sources/artifacts are
# actually out of date and a rebuild is required (e.g. after `make clean` or
# editing the classifier).
ebpf_rebuild=0
if [ ! -f ebpf/Makefile ]; then
    fail "ebpf/Makefile missing; cannot build xdp_monitor."
    exit 1
elif command -v make >/dev/null 2>&1 && make -q -C ebpf >/dev/null 2>&1; then
    ok "committed eBPF artifacts are up-to-date (make -q: nothing to rebuild) - build toolchain NOT required."
elif ! command -v make >/dev/null 2>&1; then
    if [ -x ebpf/xdp_monitor ]; then
        ok "committed ebpf/xdp_monitor present; 'make' absent so up-to-date probing is skipped."
    else
        fail "make is not installed and ebpf/xdp_monitor is missing (committed artifact OR make + toolchain required)."
        ebpf_rebuild=1
    fi
else
    ok "eBPF rebuild path active (sources/artifacts out of date) - full build toolchain required."
    ebpf_rebuild=1
fi

if [ "$ebpf_rebuild" -eq 1 ]; then
    if command -v make >/dev/null 2>&1 && command -v cc >/dev/null 2>&1; then
        ok "build tools: make + $(cc --version 2>/dev/null | head -1 | grep -o 'gcc\|clang' || echo cc)"
    else
        fail "make/cc are not installed (required to build ebpf/xdp_monitor)."
    fi

    if command -v clang >/dev/null 2>&1; then
        ok "clang ($(clang --version 2>/dev/null | head -1 | awk '{print $NF}') )"
    else
        fail "clang is not installed. apt install clang (required to build ebpf/xdp_monitor)."
    fi

    if command -v llvm-config >/dev/null 2>&1; then
        ok "llvm ($(llvm-config --version 2>/dev/null | tr -d '\n'))"
    else
        fail "llvm-config is not installed. apt install llvm (required to build ebpf/xdp_monitor)."
    fi

    if command -v bpftool >/dev/null 2>&1; then
        ok "bpftool ($(command -v bpftool))"
        BPFTOOL_OVERRIDE=""
    elif [ -x /usr/sbin/bpftool ]; then
        ok "bpftool (/usr/sbin/bpftool - not on PATH; make will be told its location)."
        BPFTOOL_OVERRIDE="/usr/sbin/bpftool"
    else
        fail "bpftool is not installed. apt install linux-tools-common linux-tools-generic (required to build ebpf/xdp_monitor)."
    fi

    for lib in libbpf libelf libz; do
        if ldconfig -p 2>/dev/null | grep -q "$lib\.so"; then
            ok "library: $lib"
        else
            fail "library '$lib' not found (ldconfig). apt install libbpf-dev libelf-dev zlib1g-dev."
        fi
    done

    # Development headers are only needed for an actual (re)build; verify them
    # with a compile probe (user-space libbpf + kernel UAPI) plus the BPF-side
    # helper header shipped by libbpf-dev.
    if printf '#include <bpf/libbpf.h>\n#include <linux/if_link.h>\nint main(void){return 0;}\n' | cc -x c - -o /dev/null >/dev/null 2>&1; then
        ok "dev headers: bpf/libbpf.h + linux/if_link.h (compile probe OK)."
    else
        fail "eBPF development headers missing. apt install libbpf-dev linux-libc-dev (headers needed only for a rebuild)."
    fi
    if [ ! -f /usr/include/bpf/bpf_helpers.h ]; then
        fail "bpf/bpf_helpers.h not found (part of libbpf-dev; needed to rebuild the BPF program)."
    else
        ok "dev header: bpf/bpf_helpers.h"
    fi
else
    ok "build toolchain checks skipped on the committed-artifact (no-op) path."
fi

if [ "$fail_count" -gt 0 ]; then
    echo
    printf '%s %s prerequisite problem(s) - fix them, then re-run this installer.\n' "$FAIL" "$fail_count"
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. eBPF / xdp_monitor  (prepared BEFORE the images: the transport image
#    stages ebpf/xdp_monitor into every transport host.  On the committed-
#    artifact path the binary is reused; on the rebuild path it is compiled.)
# ---------------------------------------------------------------------------
section "2. eBPF / xdp_monitor"

if [ "$ebpf_rebuild" -eq 1 ]; then
    echo "[~~] building xdp_monitor (ebpf/) ..."
    if [ -n "${BPFTOOL_OVERRIDE:-}" ]; then
        if make -C ebpf --no-print-directory BPFTOOL="$BPFTOOL_OVERRIDE" >/dev/null 2>&1; then
            ok "ebpf build completed."
        else
            printf '%s %s\n' "$FAIL" "ebpf/xdp_monitor build failed (check clang/llvm/bpftool/libbpf/headers above)."
            exit 1
        fi
    else
        if make -C ebpf --no-print-directory >/dev/null 2>&1; then
            ok "ebpf build completed."
        else
            printf '%s %s\n' "$FAIL" "ebpf/xdp_monitor build failed (check clang/llvm/bpftool/libbpf/headers above)."
            exit 1
        fi
    fi
else
    ok "using committed ebpf/xdp_monitor artifact (no-op path, no rebuild required)."
fi

if [ -x ebpf/xdp_monitor ]; then
    ok "artifact ebpf/xdp_monitor ($(stat -c %s ebpf/xdp_monitor 2>/dev/null) bytes)."
    echo "    NOTE: XDP generic/SKB mode is the verified monitoring mode on the testbed's"
    echo "          veth/MTU combination. Native (driver) XDP is a known optional limitation"
    echo "          and is NOT part of any hard installation requirement."
else
    fail "ebpf/xdp_monitor binary is not present (build path did not produce it)."
    exit 1
fi

EBPF_SHA="$(sha256sum ebpf/xdp_monitor | awk '{print $1}')"
ok "ebpf/xdp_monitor sha256: $EBPF_SHA"

# ---------------------------------------------------------------------------
# 3. Container images
# ---------------------------------------------------------------------------
section "3. Container images"

# name:build-context[:transport] of the images the topologies reference.  The
# transport image is built from the repository ROOT as context (so it can COPY
# ebpf/xdp_monitor) and is therefore marked with the "transport" kind flag.
# For a transport image the staged /usr/sbin/xdp_monitor sha256 MUST equal the
# host artifact sha256 ($EBPF_SHA) - enforced both for freshly built images and
# for an image that already exists (mismatch = hard error with rebuild command).
IMAGES=( "ipsec-test-gateway:6.0.3|gateway-image|"
         "ipsec-test-host:24.04|host-image|"
         "ipsec-transport-host:24.04|transport-host-image|transport" )

# staged_sha <image> : sha256 of /usr/sbin/xdp_monitor baked inside the image.
staged_sha() {
    $DOCKER run --rm --entrypoint sha256sum "$1" /usr/sbin/xdp_monitor 2>/dev/null | awk '{print $1}'
}

for entry in "${IMAGES[@]}"; do
    img="${entry%%|*}"
    rest="${entry#*|}"
    ctx="${rest%%|*}"
    kind="${rest#*|}"

    if [ ! -f "$ctx/Dockerfile" ]; then
        fail "image build context missing: $ctx/Dockerfile (image '$img'). Check the repository layout."
        continue
    fi

    if $DOCKER image inspect "$img" >/dev/null 2>&1; then
        if [ "$kind" = "transport" ]; then
            existing_staged="$(staged_sha "$img")"
            if [ -n "$existing_staged" ] && [ "$existing_staged" = "$EBPF_SHA" ]; then
                ok "image $img already exists - staged eBPF sha256 matches the host artifact (${EBPF_SHA:0:16}...); skipped build."
            else
                printf '%s %s\n' "$FAIL" "image $img exists but its staged /usr/sbin/xdp_monitor sha256 ('${existing_staged:-unavailable}') differs from the current host artifact '$EBPF_SHA'."
                echo "    The transport image bakes in ebpf/xdp_monitor at build time, so the existing"
                echo "    image carries a stale/different eBPF binary. Rebuild it from the repository root:"
                echo "        $DOCKER build -t $img -f $ctx/Dockerfile ."
                echo "    then re-run this installer."
                exit 1
            fi
        else
            ok "image $img already exists - skipped build."
        fi
        continue
    fi

    if [ "$kind" = "transport" ]; then
        if [ ! -x ebpf/xdp_monitor ]; then
            fail "transport image needs ebpf/xdp_monitor but it is missing (eBPF build in section 2 failed)."
            exit 1
        fi
        echo "[~~] building $img from repo root with $ctx/Dockerfile (stages ebpf/xdp_monitor) ..."
        build_log="$($DOCKER build -t "$img" -f "$ctx/Dockerfile" . 2>&1)"
    else
        echo "[~~] building $img from $ctx/ (base images auto-pulled) ..."
        build_log="$($DOCKER build -t "$img" "$ctx" 2>&1)"
    fi

    if $DOCKER image inspect "$img" >/dev/null 2>&1; then
        if [ "$kind" = "transport" ]; then
            new_staged="$(staged_sha "$img")"
            if [ -n "$new_staged" ] && [ "$new_staged" = "$EBPF_SHA" ]; then
                ok "image $img built - staged eBPF sha256 matches the host artifact (${EBPF_SHA:0:16}...)."
            else
                printf '%s %s\n' "$FAIL" "image $img built but its staged /usr/sbin/xdp_monitor sha256 ('${new_staged:-unavailable}') does not match the host artifact '$EBPF_SHA'."
                exit 1
            fi
        else
            ok "image $img built."
        fi
    else
        printf '%s %s\n' "$FAIL" "image $img failed to build."
        printf '%s\n' "$build_log" | tail -15 >&2
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# 4. Topology validation
# ---------------------------------------------------------------------------
section "4. Containerlab topology validation"

TOPO_FILE_TUNNEL="topology/tunnel/ipsec.clab.yml"
TOPO_FILE_TRANSPORT="topology/transport/ipsec.clab.yml"

for topo in "$TOPO_FILE_TUNNEL" "$TOPO_FILE_TRANSPORT"; do
    if [ ! -f "$topo" ]; then
        fail "topology file missing: $topo"
        continue
    fi
    ok "topology present: $topo"
done

python3 - "$TOPO_FILE_TUNNEL" "$TOPO_FILE_TRANSPORT" <<'PY'
import os
import sys

files = sys.argv[1:]

try:
    import yaml
except ImportError:
    yaml = None

for f in files:
    if yaml is None:
        import re
        text = open(f).read()
        if not re.search(r"^name:", text, re.M) or not re.search(r"^topology:", text, re.M):
            sys.exit(f"basic structural check failed for {f}")
        continue
    try:
        data = yaml.safe_load(open(f))
    except Exception as exc:
        sys.exit(f"YAML parse failed for {f}: {exc}")
    if not isinstance(data, dict) or not data.get("name") or not isinstance(data.get("topology"), dict):
        sys.exit(f"invalid structure in {f}: missing 'name'/'topology'")
    if not (data.get("topology") or {}).get("nodes"):
        sys.exit(f"no nodes defined in {f}")
    if not os.access(os.path.dirname(f) or ".", os.W_OK):
        sys.exit(f"topology directory not writable: {f}")

print("parsed: ok")
PY
py_rc=$?

if [ "$py_rc" -ne 0 ]; then
    fail "topology syntax validation failed."
    exit 1
fi

echo "[~~] checking images referenced by the topologies ..."
topo_images="$(python3 - "$TOPO_FILE_TUNNEL" "$TOPO_FILE_TRANSPORT" <<'PY'
import sys, yaml
def collect(f):
    d = yaml.safe_load(open(f))
    return {n.get("image") for n in (d.get("topology") or {}).get("nodes", {}).values() if isinstance(n, dict) and n.get("image")}
out = set()
for f in sys.argv[1:]:
    out |= collect(f)
for img in sorted(out):
    print(img)
PY
)"

missing=0
for img in $topo_images; do
    if $DOCKER image inspect "$img" >/dev/null 2>&1; then
        ok "topology image $img available."
    else
        fail "topology image $img NOT available (create it via this installer's image step first)."
        missing=1
    fi
done

for topo in "$TOPO_FILE_TUNNEL" "$TOPO_FILE_TRANSPORT"; do
    d="$(dirname "$topo")"
    if [ -w "$d" ]; then
        ok "topology directory writable: $d/ (containerlab state dirs can be created)."
    else
        warn "topology directory not writable: $d/ (containerlab deploy will fail without write access)."
    fi
done

echo "    NOTE: 'br-wan' is an externally-managed root-namespace bridge. deploy-ipsec.sh"
echo "          ensures it exists before 'containerlab deploy'; install/run never alter it."
echo "          The bridge carries ONLY the two gateway members (WAN/IPsec dataplane)."

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
section "Summary"

if [ "$fail_count" -gt 0 ]; then
    printf '%s %s required check(s) failed. Re-run %s after fixing them.\n' "$FAIL" "$fail_count" "$0"
    exit 1
else
    echo "Installation/preparation complete."
    echo
    echo "Next steps:"
    echo "    ./scripts/run.sh      # deploy the tunnel testbed + verify observation/IPsec/connectivity"
    echo "    ./scripts/status.sh   # concise health report"
    echo "    ./scripts/stop.sh     # tear the testbed down (reuses deployment destroy)"
    exit 0
fi