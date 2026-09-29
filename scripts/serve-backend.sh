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
#   1. Analytics API  (Server A, read-only)  default 127.0.0.1:8081
#        python -m correlation.api.app --phase10
#        assessments, risk, findings, evidence, XAI, drift, metrics.
#        The --phase10 flag is REQUIRED: without it every /api/v1 route
#        answers 503 phase10_unavailable.  (The phase-8 /api/ routes work
#        without it, but the v1 routes and the per-finding explanation do not.)
#
#   2. Control API    (Server B, mutating)   default 127.0.0.1:8000
#        uvicorn controller.api:app
#        configurations, create/run experiments, dataset runs, /static.
#
# Usage:
#   ./scripts/serve-backend.sh                     # both, stay in foreground
#   ./scripts/serve-backend.sh --analytics-only
#   ./scripts/serve-backend.sh --control-only
#   CONTROL_PORT=8001 ./scripts/serve-backend.sh
#
# Environment (all optional):
#   ANALYTICS_HOST / ANALYTICS_PORT   analytics bind address (default 127.0.0.1:8081)
#   CONTROL_HOST  / CONTROL_PORT     control bind address (default 127.0.0.1:8000)
#   FRONTEND_ORIGIN                   browser origin the Vite dev server is
#                                    reached at.  It is added to the analytics
#                                    CORS allow-list automatically, so a LAN
#                                    origin works without hand-editing anything
#                                    (default http://localhost:5173).
#   ANALYTICS_API_ALLOWED_ORIGINS     set this to take full control of the
#                                    analytics CORS allow-list; when it is set,
#                                    FRONTEND_ORIGIN is ignored so an operator
#                                    always wins.
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
ANALYTICS_HOST="${ANALYTICS_HOST:-127.0.0.1}"
ANALYTICS_PORT="${ANALYTICS_PORT:-8081}"
CONTROL_HOST="${CONTROL_HOST:-127.0.0.1}"
CONTROL_PORT="${CONTROL_PORT:-8000}"

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

if [ -n "${ANALYTICS_API_ALLOWED_ORIGINS:-}" ]; then
    # Operator set it explicitly: pass through untouched, do not second-guess.
    CORS_MODE="explicit (ANALYTICS_API_ALLOWED_ORIGINS)"
else
    ANALYTICS_API_ALLOWED_ORIGINS="${LOOPBACK_DEV_ORIGINS},${FRONTEND_ORIGIN}"
    export ANALYTICS_API_ALLOWED_ORIGINS
    CORS_MODE="derived (loopback dev origins + FRONTEND_ORIGIN=${FRONTEND_ORIGIN})"
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
case "${1:-}" in
    --analytics-only) START_CONTROL=0 ;;
    --control-only)   START_ANALYTICS=0 ;;
    "")               ;;
    *) fail "unknown option '$1' (use --analytics-only or --control-only)"; exit 2 ;;
esac

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

cleanup() {
    printf '\n'
    section "shutting down"
    for pid in "$analytics_pid" "$control_pid"; do
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
            --audit-journal "${ANALYTICS_AUDIT_JOURNAL:-/tmp/opencode/analysis-events.jsonl}" &
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
    check_cors "$A/api/health"
fi

if [ "$START_CONTROL" -eq 1 ]; then
    C="http://$CONTROL_HOST:$CONTROL_PORT"
    check "health      GET /health"                   "$C/health"
    check "configs     GET /experiments/configurations" "$C/experiments/configurations"
    check "dataset     GET /dataset-runs/settings"    "$C/dataset-runs/settings"
    check "openapi     GET /openapi.json"             "$C/openapi.json"
fi

section "where to look"
if [ "$START_ANALYTICS" -eq 1 ]; then
    printf '  Analytics OpenAPI : http://%s:%s/api/v1/openapi.json\n' "$ANALYTICS_HOST" "$ANALYTICS_PORT"
    printf '  Analytics Swagger : http://%s:%s/api/v1/docs\n' "$ANALYTICS_HOST" "$ANALYTICS_PORT"
fi
if [ "$START_CONTROL" -eq 1 ]; then
    printf '  Control OpenAPI   : http://%s:%s/openapi.json\n' "$CONTROL_HOST" "$CONTROL_PORT"
    printf '  Control Swagger   : http://%s:%s/docs\n' "$CONTROL_HOST" "$CONTROL_PORT"
fi

cat <<EOF

Both backends stay up until you press Ctrl-C.

Frontend CORS
-------------
The control plane allows any origin in development, which is why Control works
from a browser on the LAN while Analytics does not. The analytics API keeps a
narrow loopback-only allow-list, so a browser reaching Vite over the LAN needs
that origin permitted explicitly.

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

No authentication is configured on either server. Both bind loopback by
default; do not expose them on a shared network without adding auth.

Press Ctrl-C to stop.
EOF

wait
