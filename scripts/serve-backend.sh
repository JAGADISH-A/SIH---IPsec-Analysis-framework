#!/usr/bin/env bash
#
# serve-backend.sh - start the two Sentinel HTTP backends for frontend work.
#
# There is no single entry point for the API layer anywhere else in the
# repository: the README documents the *testbed* lifecycle (run.sh / status.sh
# / stop.sh) but never the servers, and `controller/api.py` has no __main__ and
# never calls uvicorn itself.  This script is that missing entry point, and
# nothing more: it starts the two applications that already exist, waits until
# each answers HTTP, prints where to look, and shuts both down on Ctrl-C.
#
# It does NOT deploy the containerlab lab.  Assessment data comes from the
# recorded artifacts under results/; starting a *new* experiment needs the lab,
# which is `sudo ./scripts/run.sh`.
#
#   1. Analytics API  (Server A, read-only)  default 0.0.0.0:8081
#        python -m correlation.api.app --phase10
#        assessments, risk, findings, evidence, XAI, drift, metrics.
#        The --phase10 flag is REQUIRED: without it every /api/v1 route
#        answers 503 phase10_unavailable.  (The phase-8 /api/ routes work
#        without it, but the v1 routes and the per-finding explanation do not.)
#
#   2. Control API    (Server B, mutating)   default 0.0.0.0:8000
#        uvicorn controller.api:app
#        configurations, create/run experiments, dataset runs, /static.
#
# Usage:
#   ./scripts/serve-backend.sh                     # both, stay in foreground
#   ./scripts/serve-backend.sh --analytics-only
#   ./scripts/serve-backend.sh --control-only
#   CONTROL_PORT=8001 ./scripts/serve-backend.sh
#
# Bind addresses
#   Both servers default to 0.0.0.0 because the frontend is opened from a
#   second machine (the browser under test reaches Vite on the VM's LAN
#   address), and a listener bound to 127.0.0.1 alone refuses that.  CORS is
#   not a substitute: the browser cannot even send the request.  0.0.0.0 still
#   accepts http://localhost:<port>, so the on-VM workflow is unchanged.  Set
#   ANALYTICS_HOST=127.0.0.1 CONTROL_HOST=127.0.0.1 to keep either service
#   loopback-only.
#
# Environment (all optional):
#   ANALYTICS_HOST / ANALYTICS_PORT   analytics bind address (default 0.0.0.0:8081)
#   CONTROL_HOST  / CONTROL_PORT     control bind address (default 0.0.0.0:8000)
#   FRONTEND_ORIGIN                   browser origin the Vite dev server is
#                                    reached at.  It is added to the analytics
#                                    CORS allow-list automatically, so a LAN
#                                    origin works without hand-editing anything
#                                    (default http://localhost:5173).
#   ANALYTICS_API_ALLOWED_ORIGINS     set this to take full control of the
#                                    analytics CORS allow-list; when it is set,
#                                    FRONTEND_ORIGIN is ignored so an operator
#                                    always wins.
#   ANALYTICS_DRIFT_BASELINE          JSONL baseline registry passed through as
#                                    --drift-baseline, with
#                                    ANALYTICS_DRIFT_BASELINE_ID as
#                                    --baseline-id.  Defaults to the repository
#                                    artifact results/drift-demo/baselines.jsonl
#                                    and its registered id, which is the
#                                    validated transport+IPv4 baseline; the app
#                                    refuses to start if either is absent, so
#                                    drift is never silently not_configured.
#   ANALYTICS_ASSET_ID                asset this store describes, passed as
#                                    --asset-id, so the operator-supplied
#                                    mission profile (and therefore asset
#                                    criticality) resolves instead of reporting
#                                    not_configured.  Default gw-b, the
#                                    operational-communications gateway in
#                                    configs/mission/asset_mission_profiles.json.
#   ANALYTICS_MISSION_PROFILES        override the mission profile file path.
#
# The live experiment-boundary gate defaults ON across the analytics API and the
# capture feed defaults to the live XDP journal the sensor actually writes.
# ANALYTICS_MODE=recorded serves the RECORDED baseline (results/observed-state/
# live_events_full.jsonl) instead and opts the replay server back into the legacy
# mode that serves recorded history as it is on disk.
export ANALYTICS_CAPTURE_EXPERIMENT_GATED="${ANALYTICS_CAPTURE_EXPERIMENT_GATED:-1}"
if [ "${ANALYTICS_MODE:-live}" = "recorded" ]; then
    export ANALYTICS_CAPTURE_EXPERIMENT_GATED=0
    export ANALYTICS_API_CAPTURE_FEED="${ANALYTICS_API_CAPTURE_FEED:-results/observed-state/live_events_full.jsonl}"
else
    export ANALYTICS_API_CAPTURE_FEED="${ANALYTICS_API_CAPTURE_FEED:-results/observed-state/xdp/live_events.jsonl}"
fi
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR" || exit 1

OK="[OK]"
WARN="[WARN]"
FAIL="[FAIL]"

ok()   { printf '%s %s\n' "$OK"   "$*"; }
warn() { printf '%s %s\n' "$WARN" "$*"; }
fail() { printf '%s %s\n' "$FAIL" "$*" >&2; }

section() { printf '\n=== %s ===\n' "$*"; }

# ---------------------------------------------------------------------------
# Port-occupancy helpers.
#
# The classic failure this guards against: an operator starts the same backend
# twice, the second bind dies with EADDRINUSE while the FIRST instance keeps
# answering health checks, and the script then "verifies" the wrong server --
# whose CORS policy predates FRONTEND_ORIGIN -- so it prints a correct
# allow-list and then [FAIL] cors against a server that never saw it.
#
# Rule: never silently start a second server on an occupied port. Detect it,
# identify the owner, and either reuse the running instance (when it already
# satisfies exactly the probes this script would guarantee) or fail with the
# explicit stop/restart command for the operator.
# ---------------------------------------------------------------------------

# connect_host <bind-address> -> an address urllib can actually reach
connect_host() {
    case "$1" in
        0.0.0.0|"::"|"::0"|"") printf '127.0.0.1' ;;
        *) printf '%s' "$1" ;;
    esac
}

# port_pid <host> <port> -> who owns the listener, or "" when the port is free.
# `ss -ltnp` hides the PID of a socket owned by another user, so PID_HIDDEN is
# reported as the owner string -- "in use" is the fact that matters.
port_pid() {
    local host="$1" port="$2" out pid owner
    out="$(ss -ltn 2>/dev/null | awk -v port=":${port}$" '$4 ~ port{print}' | head -1)"
    if [ -z "$out" ]; then
        return 0   # no listener -> port free
    fi
    pid="$(ss -ltnp 2>/dev/null | awk -v port=":${port}$" '$4 ~ port && /pid=/{print}' | head -1 \
        | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)"
    if [ -n "$pid" ]; then
        owner="$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')"
        printf '%s (user %s)\n' "$pid" "${owner:-?}"
    else
        printf 'PID_HIDDEN (owned by another user; use sudo ss -ltnp to see it)\n'
    fi
}

probe_status() {
    # probe_status <url> -> 200 / <http error> / ERR
    "$PYTHON" - "$1" <<'PY' 2>/dev/null
import sys, urllib.request, urllib.error
try:
    print(urllib.request.urlopen(sys.argv[1], timeout=4).status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception:
    print("ERR")
PY
}

probe_cors_origin() {
    # probe_cors_origin <url> <origin> -> Access-Control-Allow-Origin echo or ERR.
    "$PYTHON" - "$1" "$2" <<'PY' 2>/dev/null
import sys, urllib.request, urllib.error
url, origin = sys.argv[1], sys.argv[2]
req = urllib.request.Request(url, headers={"Origin": origin})
try:
    r = urllib.request.urlopen(req, timeout=4)
    print(r.headers.get("Access-Control-Allow-Origin", ""))
except urllib.error.HTTPError as e:
    print(e.headers.get("Access-Control-Allow-Origin", ""))
except Exception:
    print("ERR")
PY
}

# analytics_usable <dest> <port> <required_origin> -> exit 0 when the HTTP
# service already on the port is a --phase10 analytics API that this script
# could treat as "started and verified": /api/health 200, /api/v1/health 200
# (phase-10 attached), and CORS answers with <required_origin> verbatim.
analytics_usable() {
    local dest="$1" port="$2" required="$3" base
    base="http://$dest:$port"
    [ "$(probe_status "$base/api/health")" = "200" ] || return 1
    [ "$(probe_status "$base/api/v1/health")" = "200" ] || return 1
    [ "$(probe_cors_origin "$base/api/health" "$required")" = "$required" ] || return 1
    return 0
}

PYTHON=".venv/bin/python"
UVICORN=".venv/bin/uvicorn"
# 0.0.0.0, not 127.0.0.1: the frontend under test is opened from a second
# machine, so the browser must be able to open a TCP connection to these two
# services on the VM's LAN address. A loopback listener cannot be reached from
# there at all -- the browser fails before CORS is ever consulted -- and 0.0.0.0
# still serves http://localhost:<port>, so nothing on the VM changes. Both stay
# overridable, so a loopback-only deployment is one variable away.
ANALYTICS_HOST="${ANALYTICS_HOST:-0.0.0.0}"
ANALYTICS_PORT="${ANALYTICS_PORT:-8081}"
CONTROL_HOST="${CONTROL_HOST:-0.0.0.0}"
CONTROL_PORT="${CONTROL_PORT:-8000}"
# The explanation service is a third process. It was previously never started,
# so the frontend's "Explain with AI" had nothing to reach on 8082 and every
# request degraded to the offline path.
AI_HOST="${AI_HOST:-127.0.0.1}"
AI_PORT="${AI_PORT:-8082}"

# ---------------------------------------------------------------------------
# Drift baseline: passed through to the analytics API, never re-derived.
#
# The drift layer defines exactly one way to establish a baseline -- a validated
# record already present in a BaselineRegistry file -- and the analytics API
# refuses to start with a registry but no named baseline (and vice versa),
# because an unstated baseline is not a baseline. `start-live-analytics.sh`
# already spells this out; this script previously omitted both flags entirely,
# which is why the store answered `not_configured` and the Drift surface in the
# UI could only ever report that no comparison had been made.
#
# The defaults are the repository's own artifact and its own registered id --
# the same validated transport+IPv4 baseline. Nothing is generated here: the
# file is read and its integrity seal verified by the app exactly as it is for
# any other deployment. Override either variable to compare against a different
# registered baseline.
ANALYTICS_DRIFT_BASELINE="${ANALYTICS_DRIFT_BASELINE:-results/drift-demo/baselines.jsonl}"
ANALYTICS_DRIFT_BASELINE_ID="${ANALYTICS_DRIFT_BASELINE_ID:-baseline-transport-ipv4}"

# ---------------------------------------------------------------------------
# Asset mission context: which asset this store describes, and its profile file.
#
# Criticality is an operator declaration (configs/mission/
# asset_mission_profiles.json), never inferred from traffic, so the store can
# only resolve it when it is told which asset it is describing. Without
# --asset-id every asset surface reports not_configured. gw-b is the
# operational-communications gateway in the shipped profile file; the profile
# path and asset id both stay overridable and are never written into the
# application.
ANALYTICS_ASSET_ID="${ANALYTICS_ASSET_ID:-gw-b}"
ANALYTICS_MISSION_PROFILES="${ANALYTICS_MISSION_PROFILES:-configs/mission/asset_mission_profiles.json}"

drift_args=()
if [ -f "$ANALYTICS_DRIFT_BASELINE" ]; then
    drift_args=(--drift-baseline "$ANALYTICS_DRIFT_BASELINE" --baseline-id "$ANALYTICS_DRIFT_BASELINE_ID")
    drift_summary="baseline=$ANALYTICS_DRIFT_BASELINE_ID from $ANALYTICS_DRIFT_BASELINE"
else
    # Reported, not worked around and not faked: a missing artifact means no
    # comparison, and inventing one would make the Drift surface claim a
    # longitudinal fact that was never established.
    drift_summary="none -- no baseline artifact at $ANALYTICS_DRIFT_BASELINE"
    warn "drift baseline artifact not found: $ANALYTICS_DRIFT_BASELINE"
    warn "  (relative to the repo root; set ANALYTICS_DRIFT_BASELINE to point at"
    warn "   an existing registry file). Every drift surface will report"
    warn "   not_configured -- that is NOT the same as 'no drift detected'."
fi

# ---------------------------------------------------------------------------
# CORS allow-list for the analytics plane.
#
# The analytics API is served by a stdlib HTTP server with a deliberate,
# narrow default allow-list: loopback dev origins only.  That default is the
# right security posture (the API is unauthenticated), but it means a browser
# reaching the Vite dev server over the LAN -- http://192.168.182.128:5173 --
# gets a 200 response with no `Access-Control-Allow-Origin` header, so the
# browser blocks the read and the frontend reports Analytics as offline even
# though the API is healthy and reachable.
#
# The fix belongs here, in the launch configuration, not in application logic:
# nothing about the decision should depend on a hardcoded address in code.  We
# therefore synthesise an allow-list from the loopback defaults plus the origin
# the frontend is actually served from, and only when the operator has not
# already expressed an explicit policy.
FRONTEND_ORIGIN="${FRONTEND_ORIGIN:-http://localhost:5173}"

LOOPBACK_DEV_ORIGINS="http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000,http://127.0.0.1:8000"

# The frontend is served on this machine and opened from another one, so the
# origin the browser actually uses is this host's LAN address, which is
# discovered here rather than written down anywhere. It is a *launch*
# configuration value, not an application one: the API still decides per
# request against whatever list it is given, and the operator can override
# everything below. Discovered by asking the kernel which address it would use
# to reach the outside world, which needs no network access and no scraping.
lan_origin() {
    local ip
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)"
    [ -n "$ip" ] || return 0
    printf 'http://%s:%s' "$ip" "${VITE_PORT:-5173}"
}

if [ -n "${ANALYTICS_API_ALLOWED_ORIGINS:-}" ]; then
    # Operator set it explicitly: pass through untouched, do not second-guess.
    CORS_MODE="explicit (ANALYTICS_API_ALLOWED_ORIGINS)"
else
    ANALYTICS_API_ALLOWED_ORIGINS="${LOOPBACK_DEV_ORIGINS},${FRONTEND_ORIGIN}"
    # Permit the LAN origin too, so a browser opened on http://<lan-ip>:5173 is
    # not blocked while the loopback workflow keeps working unchanged.
    LAN_ORIGIN="$(lan_origin)"
    if [ -n "$LAN_ORIGIN" ]; then
        case ",${ANALYTICS_API_ALLOWED_ORIGINS}," in
            *",${LAN_ORIGIN},"*) ;;
            *) ANALYTICS_API_ALLOWED_ORIGINS="${ANALYTICS_API_ALLOWED_ORIGINS},${LAN_ORIGIN}" ;;
        esac
    fi
    export ANALYTICS_API_ALLOWED_ORIGINS
    CORS_MODE="derived (loopback dev origins + FRONTEND_ORIGIN=${FRONTEND_ORIGIN}${LAN_ORIGIN:+, LAN_ORIGIN=${LAN_ORIGIN}})"
fi

# The startup CORS preflight has to probe an origin that is *supposed* to be
# allowed. Under an explicit policy, FRONTEND_ORIGIN is ignored entirely, so
# probing it unconditionally would fail the check for a perfectly valid
# allow-list. Probe FRONTEND_ORIGIN when the effective list permits it, and
# otherwise probe the first permitted origin, naming which one was tested.
FIRST_ALLOWED_ORIGIN="${ANALYTICS_API_ALLOWED_ORIGINS%%,*}"
CORS_PROBE_ORIGIN="$FRONTEND_ORIGIN"
CORS_PROBE_IS_FRONTEND=1
case ",${ANALYTICS_API_ALLOWED_ORIGINS}," in
    *",${FRONTEND_ORIGIN},"*) ;;
    *)
        CORS_PROBE_ORIGIN="$FIRST_ALLOWED_ORIGIN"
        CORS_PROBE_IS_FRONTEND=0
        ;;
esac

START_ANALYTICS=1
START_CONTROL=1
# Off by default: it is the only process that can spend the Gemini quota, so
# starting it should be a deliberate choice rather than a side effect of
# "start the backend". `npm run dev:full` and the smoke target set
# AI_ACTION=start themselves.
START_AI=0
case "${1:-}" in
    --analytics-only) START_CONTROL=0; START_AI=0 ;;
    --control-only)   START_ANALYTICS=0; START_AI=0 ;;
    --with-ai)        START_AI=1 ;;
    "")               ;;
    *) fail "unknown option '$1' (use --analytics-only, --control-only or --with-ai)"; exit 2 ;;
esac
AI_ACTION="${AI_ACTION:-start}"
if [ "$START_AI" -eq 1 ] && [ "$AI_ACTION" != "start" ]; then
    fail "AI_ACTION=$AI_ACTION but --with-ai was given; use one or the other"
fi

section "preflight"

if [ ! -x "$PYTHON" ]; then
    fail "$PYTHON not found."
    fail "Create the virtualenv and install requirements.txt first:"
    fail "    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
    exit 1
fi
ok "python: $("$PYTHON" --version 2>&1)"

if [ "$START_CONTROL" -eq 1 ] && [ ! -x "$UVICORN" ]; then
    fail "$UVICORN not found; the control plane needs uvicorn (requirements.txt)."
    exit 1
fi

if [ "$START_ANALYTICS" -eq 1 ]; then
    if ! "$PYTHON" -c "import correlation.api.app" >/dev/null 2>&1; then
        fail "cannot import correlation.api.app from the repository root."
        exit 1
    fi
    if [ ! -d results ]; then
        warn "results/ is absent: the analytics store will report no assessments."
        warn "It is gitignored (.gitignore:21) - regenerate it before expecting data."
    fi
fi

# ---------------------------------------------------------------------------
# Occupancy preflight: decide before starting anything whether each required
# port is free, already running a service this script may reuse, or occupied by
# something else. Never start a second server on an occupied port.
# ---------------------------------------------------------------------------
ANALYTICS_DEST="$(connect_host "$ANALYTICS_HOST")"

ANALYTICS_ACTION="start"
if [ "$START_ANALYTICS" -eq 1 ]; then
    owner="$(port_pid "$ANALYTICS_HOST" "$ANALYTICS_PORT")"
    if [ -n "$owner" ]; then
        warn "port $ANALYTICS_HOST:$ANALYTICS_PORT is already in use: pid $owner"
        warn "  inspect:  ss -ltnp | grep -E ':$ANALYTICS_PORT'  ;  ps -fp <pid>"
        if analytics_usable "$ANALYTICS_DEST" "$ANALYTICS_PORT" "$CORS_PROBE_ORIGIN"; then
            ok "the process on $ANALYTICS_PORT is a usable --phase10 analytics API "
            ok "  (readiness 200, v1 200, CORS $CORS_PROBE_ORIGIN allowed) -- reusing it"
            ANALYTICS_ACTION="reuse"
        else
            fail "port $ANALYTICS_HOST:$ANALYTICS_PORT is occupied but the service is NOT usable:"
            fail "  it does not pass readiness / phase-10 / CORS ($CORS_PROBE_ORIGIN) probes"
            fail "  (this is what happens when the running instance predates the"
            fail "  allow-list you set, e.g. it was started before FRONTEND_ORIGIN)"
            fail "  stop that process and re-run this script:"
            fail "       kill ${owner%% *}    # pid owning $ANALYTICS_PORT"
            fail "       $0"
            exit 1
        fi
    fi
fi

CONTROL_DEST="$(connect_host "$CONTROL_HOST")"
CONTROL_ACTION="start"
if [ "$START_CONTROL" -eq 1 ]; then
    owner="$(port_pid "$CONTROL_HOST" "$CONTROL_PORT")"
    if [ -n "$owner" ]; then
        warn "port $CONTROL_HOST:$CONTROL_PORT is already in use: pid $owner"
        warn "  inspect:  ss -ltnp | grep -E ':$CONTROL_PORT'  ;  ps -fp <pid>"
        if [ "$(probe_status "http://$CONTROL_DEST:$CONTROL_PORT/health")" = "200" ]; then
            ok "the process on $CONTROL_PORT answers /health -- reusing it"
            CONTROL_ACTION="reuse"
        else
            fail "port $CONTROL_HOST:$CONTROL_PORT is occupied but /health does not answer 200."
            fail "  stop that process and re-run this script:"
            fail "       kill ${owner%% *}    # pid owning $CONTROL_PORT"
            fail "       $0"
            exit 1
        fi
    fi
fi

analytics_pid=""
control_pid=""
ai_pid=""

cleanup() {
    printf '\n'
    section "shutting down"
    for pid in "$analytics_pid" "$control_pid" "$ai_pid"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null && ok "stopped pid $pid"
    done
    wait 2>/dev/null
    exit 0
}
trap cleanup INT TERM EXIT

wait_for_http() {
    # wait_for_http <url> <label> <tries>
    local url="$1" label="$2" tries="${3:-60}" i
    for ((i = 0; i < tries; i++)); do
        if "$PYTHON" - "$url" <<'PY' >/dev/null 2>&1
import sys, urllib.request
try:
    urllib.request.urlopen(sys.argv[1], timeout=2).read()
except Exception:
    sys.exit(1)
PY
        then
            ok "$label is answering: $url"
            return 0
        fi
        sleep 0.5
    done
    fail "$label did not answer within ~$((tries / 2))s: $url"
    return 1
}

# ---------------------------------------------------------------------------
if [ "$START_ANALYTICS" -eq 1 ]; then
    section "analytics API (read-only, Server A)"
    if [ "$ANALYTICS_ACTION" = "start" ]; then
        "$PYTHON" -m correlation.api.app \
            --host "$ANALYTICS_HOST" --port "$ANALYTICS_PORT" --phase10 --no-static \
            --audit-journal "${ANALYTICS_AUDIT_JOURNAL:-/tmp/opencode/analysis-events.jsonl}" \
            "${drift_args[@]}" \
            --asset-id "$ANALYTICS_ASSET_ID" \
            --mission-profiles "$ANALYTICS_MISSION_PROFILES" &
        analytics_pid=$!
        wait_for_http "http://$ANALYTICS_DEST:$ANALYTICS_PORT/api/health" \
            "analytics API" 60
    fi
fi

# ---------------------------------------------------------------------------
if [ "$START_CONTROL" -eq 1 ]; then
    section "control plane (mutating, Server B)"
    if [ "$CONTROL_ACTION" = "start" ]; then
        "$UVICORN" controller.api:app \
            --host "$CONTROL_HOST" --port "$CONTROL_PORT" --log-level info &
        control_pid=$!
        wait_for_http "http://$CONTROL_DEST:$CONTROL_PORT/health" "control plane" 60
    fi
fi

# ---------------------------------------------------------------------------
if [ "$START_AI" -eq 1 ]; then
    section "explanation service (read-only, Server C)"
    if [ "$AI_ACTION" = "start" ]; then
        # ANALYTICS_API_URL so the assistant reads live-registered assessments
        # through the read-only v1 surface rather than rebuilding the store.
        # CONTROL_API_URL is what lets "why did this fail?" be answered from
        # the controller's recorded root cause instead of inferred from the
        # finding; without it the assistant says root cause was not recorded,
        # which is the honest answer rather than a guess.
        "$PYTHON" -m correlation.ai.service \
            --host "$AI_HOST" --port "$AI_PORT" \
            --analytics-url "http://$ANALYTICS_HOST:$ANALYTICS_PORT" \
            --control-url "http://$CONTROL_HOST:$CONTROL_PORT" &
        ai_pid=$!
        wait_for_http "http://$AI_HOST:$AI_PORT/ai/health" "explanation service" 60
    fi
fi

# ---------------------------------------------------------------------------
section "verify (exactly what a frontend should be able to call)"

check() {
    # check <label> <url>
    local code
    code=$("$PYTHON" - "$2" <<'PY' 2>/dev/null
import sys, urllib.request, urllib.error
try:
    r = urllib.request.urlopen(sys.argv[1], timeout=5)
    print(r.status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception as e:
    print(f"ERR {type(e).__name__}")
PY
)
    if [ "$code" = "200" ]; then
        ok "$1 -> $code"
    else
        fail "$1 -> $code"
    fi
}

report_state() {
    # report_state <base-url>
    #
    # Print the backend's own verdict for the two surfaces the Sentinel UI
    # reads, so the startup output states the fact instead of leaving the
    # operator to infer it. These are read-only GETs against the store that is
    # already running; nothing is computed, defaulted or second-guessed here --
    # `configured: false` is reported as exactly that, never as "clean".
    "$PYTHON" - "$1" <<'PY' 2>/dev/null || true
import json, sys, urllib.request
base = sys.argv[1].rstrip("/")
for label, path in (("drift", "/api/v1/drift"), ("assets", "/api/v1/assets")):
    try:
        with urllib.request.urlopen(base + path, timeout=5) as response:
            body = json.loads(response.read().decode("utf-8"))
    except Exception:
        print(f"  {label:<8} : unavailable")
        continue
    if label == "drift":
        state = "configured" if body.get("configured") else "NOT CONFIGURED"
        detail = (f"baseline={body.get('baseline_id')} "
                  f"assessments={body.get('assessment_count')} "
                  f"compared={body.get('compared_count')} "
                  f"drift_detected={body.get('drift_detected_count')}")
    else:
        state = "configured" if body.get("configured") else "NOT CONFIGURED"
        detail = f"asset={body.get('store_asset_id')} declared={body.get('total')}"
        criticality = None
        for asset in body.get("assets") or []:
            if isinstance(asset, dict) and asset.get("asset_id") == body.get("store_asset_id"):
                profile = asset.get("profile") or {}
                criticality = profile.get("criticality")
        if criticality:
            detail += f" criticality={criticality}"
    print(f"  {label:<8} : {state} ({detail})")
PY
}

check_cors() {
    # check_cors <url>
    #
    # Reproduce exactly what the browser does: send Origin and look for
    # Access-Control-Allow-Origin. A plain curl succeeding proves nothing here,
    # because curl ignores CORS entirely -- a 200 with no ACAO header is
    # precisely the failure that makes the frontend show Analytics as offline.
    local header
    header=$("$PYTHON" - "$1" "$CORS_PROBE_ORIGIN" <<'PY' 2>/dev/null
import sys, urllib.request, urllib.error
url, origin = sys.argv[1], sys.argv[2]
req = urllib.request.Request(url, headers={"Origin": origin})
try:
    r = urllib.request.urlopen(req, timeout=5)
    print(r.headers.get("Access-Control-Allow-Origin", ""))
except urllib.error.HTTPError as e:
    print(e.headers.get("Access-Control-Allow-Origin", ""))
except Exception:
    print("ERR")
PY
)
    if [ "$header" = "$CORS_PROBE_ORIGIN" ]; then
        if [ "$CORS_PROBE_IS_FRONTEND" -eq 1 ]; then
            ok "cors       $CORS_PROBE_ORIGIN is allowed"
        else
            ok "cors       $CORS_PROBE_ORIGIN is allowed (first entry of the allow-list)"
            warn "cors       FRONTEND_ORIGIN=$FRONTEND_ORIGIN is NOT in the allow-list;"
            warn "           a browser served from it will be blocked. Either add it to"
            warn "           ANALYTICS_API_ALLOWED_ORIGINS or set FRONTEND_ORIGIN to match."
        fi
    else
        fail "cors       $CORS_PROBE_ORIGIN is NOT allowed -- the browser will block every read"
        fail "           fix: put that origin in ANALYTICS_API_ALLOWED_ORIGINS, or set FRONTEND_ORIGIN"
    fi
}

if [ "$START_ANALYTICS" -eq 1 ]; then
    A="http://$ANALYTICS_HOST:$ANALYTICS_PORT"
    check "readiness  GET /api/health"                "$A/api/health"
    check "assessments GET /api/assessments"          "$A/api/assessments"
    check "openapi    GET /api/v1/openapi.json"       "$A/api/v1/openapi.json"
    check "v1 health  GET /api/v1/health"             "$A/api/v1/health"
    check "v1 findings GET /api/v1/findings"          "$A/api/v1/findings"
    check "v1 drift   GET /api/v1/drift"              "$A/api/v1/drift"
    check "v1 assets  GET /api/v1/assets"            "$A/api/v1/assets"
    check_cors "$A/api/health"
    report_state "http://$ANALYTICS_DEST:$ANALYTICS_PORT"
fi

if [ "$START_CONTROL" -eq 1 ]; then
    C="http://$CONTROL_HOST:$CONTROL_PORT"
    check "health      GET /health"                   "$C/health"
    check "configs     GET /experiments/configurations" "$C/experiments/configurations"
    check "dataset     GET /dataset-runs/settings"    "$C/dataset-runs/settings"
    check "openapi     GET /openapi.json"             "$C/openapi.json"
fi

if [ "$START_AI" -eq 1 ]; then
    I="http://$AI_HOST:$AI_PORT"
    check "health    GET /ai/health"                   "$I/ai/health"
    check "glossary  GET /ai/glossary"                 "$I/ai/glossary"
    check_cors "$I/ai/health"
fi

section "where to look"
if [ "$START_AI" -eq 1 ]; then
    printf '  Explanation API   : http://%s:%s/ai/health\n' "$AI_HOST" "$AI_PORT"
fi
if [ "$START_ANALYTICS" -eq 1 ]; then
    printf '  Analytics OpenAPI : http://%s:%s/api/v1/openapi.json\n' "$ANALYTICS_HOST" "$ANALYTICS_PORT"
    printf '  Analytics Swagger : http://%s:%s/api/v1/docs\n' "$ANALYTICS_HOST" "$ANALYTICS_PORT"
    printf '  Drift             : %s\n' "$drift_summary"
    printf '  Asset criticality : %s via %s\n' "$ANALYTICS_ASSET_ID" "$ANALYTICS_MISSION_PROFILES"
fi
if [ "$START_CONTROL" -eq 1 ]; then
    printf '  Control OpenAPI   : http://%s:%s/openapi.json\n' "$CONTROL_HOST" "$CONTROL_PORT"
    printf '  Control Swagger   : http://%s:%s/docs\n' "$CONTROL_HOST" "$CONTROL_PORT"
fi

cat <<EOF

Both backends stay up until you press Ctrl-C.

Where they are reachable
------------------------
  analytics : http://${ANALYTICS_HOST}:${ANALYTICS_PORT}
  control   : http://${CONTROL_HOST}:${CONTROL_PORT}

Both bind 0.0.0.0 by default so the frontend can also be opened from another
machine (http://<this-host>:5173). 0.0.0.0 still serves http://localhost, so
the on-VM workflow is unchanged. To keep either service loopback-only:

  ANALYTICS_HOST=127.0.0.1 CONTROL_HOST=127.0.0.1 ./scripts/serve-backend.sh

Drift and asset context
-----------------------
  drift       : ${drift_summary}
  asset       : ${ANALYTICS_ASSET_ID} via ${ANALYTICS_MISSION_PROFILES}

These are passed straight through to the analytics API, which reads and
integrity-checks the baseline file itself.  Nothing is generated here, so a
not_configured verdict on the drift surface means the comparison genuinely was
not made -- it is not a clean comparison.

Frontend CORS
-------------
The control plane allows any origin in development, which is why Control works
from a browser on the LAN while Analytics does not. The analytics API keeps a
narrow allow-list, so a browser reaching Vite over the LAN needs that origin
permitted explicitly.

  policy in use : ${CORS_MODE}
  allow-list    : ${ANALYTICS_API_ALLOWED_ORIGINS}

The preflight above already verified this by sending Origin and checking for
Access-Control-Allow-Origin, which is the only test that reflects what a
browser actually does.

To serve the frontend from a different host or port:

  FRONTEND_ORIGIN=http://192.168.182.128:5173 ./scripts/serve-backend.sh

Or take full control of the allow-list (then FRONTEND_ORIGIN is ignored):

  ANALYTICS_API_ALLOWED_ORIGINS=http://192.168.182.128:5173,http://localhost:5173 \\
      ./scripts/serve-backend.sh

No authentication is configured on either server, and they now bind every
interface by default so a remote browser can reach them. Do not run this on a
shared or untrusted network.

Press Ctrl-C to stop.
EOF

wait
