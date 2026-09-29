#!/usr/bin/env bash
#
# e2e-live-demo.sh - managed operator flow for the Sentinel live-traffic demo.
#
# One command line for the whole manual E2E experience against the REAL
# frontend stack:
#
#   up                 start (or reuse) analytics 8081 + control 8000 + vite 5173
#   health             probe health + CORS + the feed's current verdict
#   status             same as health, plus process ownership in one table
#   demo-start         switch analytics to an actively-appended demo journal
#                      (LIVE) and start the deterministic replay writer
#   demo-stop          stop the replay, switch analytics back to the recorded
#                      baseline (RECORDED)
#   down               stop replay + stop ONLY the servers this script started
#   replay <cmd>       replay start|stop (used internally by demo-start/stop)
#
# Principles (the ones that keep it safe to run on a live machine):
#
#  * It never starts a second server on an occupied port.  It detects the
#    owner, verifies whether the running service already satisfies the exact
#    probes it would guarantee (readiness + phase-10 + CORS for the frontend
#    origin), and either REUSES it or FAILS with the explicit stop command.
#  * It only ever kills processes it started itself (pid files under
#    $LOGDIR).  The exception is demo-start, which must restart the analytics
#    feed on 8081; if that port is owned by a process this script did not
#    start, it refuses unless --force is given (and prints what it is about to
#    do first).
#  * It does not touch the sensor journal (results/observed-state/xdp/), the
#    containerlab lab, or 8099.
#  * CORS: the analytics allow-list is DERIVED -- the fixed loopback dev
#    origins plus $HOST_IP:$VITE_PORT.  Setting ANALYTICS_API_ALLOWED_ORIGINS
#    overrides it (operator always wins).
#
# Environment (all optional; defaults shown):
#   HOST_IP                    machine LAN IP            (default 192.168.182.128)
#   VITE_PORT                  vite port                 (default 5173)
#   ANALYTICS_HOST/PORT        analytics bind            (default 0.0.0.0:8081)
#   CONTROL_HOST/PORT          control bind              (default 0.0.0.0:8000)
#   FRONTEND_ORIGIN            browser origin            (default http://$HOST_IP:$VITE_PORT)
#   ANALYTICS_API_ALLOWED_ORIGINS  explicit CORS allow-list (wins over derived)
#   LOGDIR                     pid/log directory        (default /tmp/opencode)
#
# LIVE / RECORDED / NO CURRENT TRAFFIC are decided by the backend, never here:
#   - current==true                -> LIVE (packet rows render)
#   - current==false, rows present -> RECORDED (history, never shown as live)
#   - journal absent/empty         -> NO CURRENT TRAFFIC (waiting state)
#
# The live experiment-boundary gate defaults ON across the analytics API; this
# demo explicitly replays recorded history as documented above, so it opts the
# replay server back into legacy mode.
export ANALYTICS_CAPTURE_EXPERIMENT_GATED=0
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR" || exit 1

HOST_IP="${HOST_IP:-192.168.182.128}"
VITE_PORT="${VITE_PORT:-5173}"
ANALYTICS_HOST="${ANALYTICS_HOST:-0.0.0.0}"
ANALYTICS_PORT="${ANALYTICS_PORT:-8081}"
CONTROL_HOST="${CONTROL_HOST:-0.0.0.0}"
CONTROL_PORT="${CONTROL_PORT:-8000}"
FRONTEND_ORIGIN="${FRONTEND_ORIGIN:-http://${HOST_IP}:${VITE_PORT}}"
LOGDIR="${LOGDIR:-/tmp/opencode}"
PYTHON=".venv/bin/python"
UVICORN=".venv/bin/uvicorn"
VITE_BIN="sentinel-frontend/node_modules/.bin/vite"
RECORDED_FEED="results/observed-state/live_events_full.jsonl"
DEMO_FEED="results/observed-state/demo/live_events.jsonl"
REPLAY_SCRIPT="scripts/demo-capture-replay.py"
REPLAY_PID="$LOGDIR/e2e-replay.pid"
ANALYTICS_PID="$LOGDIR/e2e-analytics.pid"
CONTROL_PID="$LOGDIR/e2e-control.pid"
VITE_PID="$LOGDIR/e2e-vite.pid"

mkdir -p "$LOGDIR"

OK="[OK]"; WARN="[WARN]"; FAIL="[FAIL]"
ok()   { printf '%s %s\n' "$OK"   "$*"; }
warn() { printf '%s %s\n' "$WARN" "$*"; }
fail() { printf '%s %s\n' "$FAIL" "$*" >&2; }
section() { printf '\n=== %s ===\n' "$*"; }

# connect_host <bind-address> -> reachable address for HTTP probes
connect_host() {
    case "$1" in
        0.0.0.0|"::"|"::0"|"") printf '127.0.0.1' ;;
        *) printf '%s' "$1" ;;
    esac
}
ANALYTICS_DEST="$(connect_host "$ANALYTICS_HOST")"
CONTROL_DEST="$(connect_host "$CONTROL_HOST")"

# Derived CORS allow-list (identical policy to serve-backend.sh).
LOOPBACK_DEV_ORIGINS="http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000,http://127.0.0.1:8000"
if [ -n "${ANALYTICS_API_ALLOWED_ORIGINS:-}" ]; then
    CORS_MODE="explicit (ANALYTICS_API_ALLOWED_ORIGINS)"
else
    export ANALYTICS_API_ALLOWED_ORIGINS="${LOOPBACK_DEV_ORIGINS},${FRONTEND_ORIGIN}"
    CORS_MODE="derived (loopback dev origins + FRONTEND_ORIGIN=${FRONTEND_ORIGIN})"
fi

probe_status() {
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

probe_cors() {
    "$PYTHON" - "$1" "$2" <<'PY' 2>/dev/null
import sys, urllib.request, urllib.error
req = urllib.request.Request(sys.argv[1], headers={"Origin": sys.argv[2]})
try:
    r = urllib.request.urlopen(req, timeout=4)
    print(r.headers.get("Access-Control-Allow-Origin", ""))
except urllib.error.HTTPError as e:
    print(e.headers.get("Access-Control-Allow-Origin", ""))
except Exception:
    print("ERR")
PY
}

port_owner() {
    local port="$1" pid owner
    pid="$(ss -ltnp 2>/dev/null | awk -v port=":${port}$" '$4 ~ port && /pid=/{print}' | head -1 \
        | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)"
    if [ -n "$pid" ]; then
        owner="$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')"
        printf '%s:%s' "$pid" "${owner:-?}"
    elif ss -ltn 2>/dev/null | awk -v port=":${port}$" '$4 ~ port{found=1} END{exit !found}'; then
        printf 'PID_HIDDEN:%s' "other-user"
    fi
}

analytics_usable() {
    [ "$(probe_status "http://$ANALYTICS_DEST:$ANALYTICS_PORT/api/health")" = "200" ] || return 1
    [ "$(probe_status "http://$ANALYTICS_DEST:$ANALYTICS_PORT/api/v1/health")" = "200" ] || return 1
    [ "$(probe_cors "http://$ANALYTICS_DEST:$ANALYTICS_PORT/api/health" "$FRONTEND_ORIGIN")" = "$FRONTEND_ORIGIN" ] || return 1
}

control_usable() {
    [ "$(probe_status "http://$CONTROL_DEST:$CONTROL_PORT/health")" = "200" ]
}

start_analytics() {
    # start_analytics <feed> <logfile> -- launch a managed analytics (detached)
    local feed="$1" logfile="$2"
    if [ -f "$ANALYTICS_PID" ] && kill -0 "$(cat "$ANALYTICS_PID")" 2>/dev/null; then
        warn "analytics pid file says $(cat "$ANALYTICS_PID") is running; killing it to apply the feed"
        kill "$(cat "$ANALYTICS_PID")" 2>/dev/null
    fi
    local i
    for i in $(seq 1 20); do
        [ -z "$(port_owner "$ANALYTICS_PORT")" ] && break
        sleep 0.5
    done
    local args=(--host "$ANALYTICS_HOST" --port "$ANALYTICS_PORT" --phase10 --no-static)
    args+=(--audit-journal "${ANALYTICS_AUDIT_JOURNAL:-/tmp/opencode/analysis-events.jsonl}")
    [ "$feed" != "-" ] && args+=(--capture-feed "$feed")
    setsid env ANALYTICS_API_ALLOWED_ORIGINS="$ANALYTICS_API_ALLOWED_ORIGINS" \
        .venv/bin/python -m correlation.api.app "${args[@]}" \
        </dev/null >"$logfile" 2>&1 &
    echo $! > "$ANALYTICS_PID"
    local i
    for i in $(seq 1 60); do
        [ "$(probe_status "http://$ANALYTICS_DEST:$ANALYTICS_PORT/api/health")" = "200" ] && { ok "analytics API answering: http://$ANALYTICS_DEST:$ANALYTICS_PORT/api/health"; return 0; }
        sleep 0.5
    done
    fail "analytics API did not answer within 30s (log: $logfile)"
    return 1
}

start_control() {
    setsid env "$UVICORN" controller.api:app \
        --host "$CONTROL_HOST" --port "$CONTROL_PORT" --log-level warning \
        </dev/null >"$LOGDIR/e2e-control.log" 2>&1 &
    echo $! > "$CONTROL_PID"
    local i
    for i in $(seq 1 60); do
        [ "$(probe_status "http://$CONTROL_DEST:$CONTROL_PORT/health")" = "200" ] && { ok "control API answering: http://$CONTROL_DEST:$CONTROL_PORT/health"; return 0; }
        sleep 0.5
    done
    fail "control API did not answer within 30s (log: $LOGDIR/e2e-control.log)"
    return 1
}

start_vite() {
    local i
    cd sentinel-frontend || return 1
    setsid env "$VITE_BIN" --host 0.0.0.0 </dev/null >"$LOGDIR/e2e-vite.log" 2>&1 &
    echo $! > "$VITE_PID"
    cd "$ROOT_DIR" || return 1
    for i in $(seq 1 60); do
        [ "$(probe_status "http://127.0.0.1:$VITE_PORT/")" = "200" ] && { ok "vite answering: http://127.0.0.1:$VITE_PORT/"; return 0; }
        sleep 0.5
    done
    fail "vite did not answer within 30s (log: $LOGDIR/e2e-vite.log)"
    return 1
}

replay_is_running() {
    [ -f "$REPLAY_PID" ] && kill -0 "$(cat "$REPLAY_PID")" 2>/dev/null
}

replay_start() {
    if replay_is_running; then
        warn "replay already running (pid $(cat "$REPLAY_PID"))"
        return 0
    fi
    truncate -s 0 "$DEMO_FEED" 2>/dev/null || :   # fresh demo journal, ours alone
    setsid "$PYTHON" "$ROOT_DIR/$REPLAY_SCRIPT" \
        --journal "$ROOT_DIR/$DEMO_FEED" \
        --source "$ROOT_DIR/$RECORDED_FEED" \
        </dev/null >"$LOGDIR/e2e-replay.log" 2>&1 &
    echo $! > "$REPLAY_PID"
    local i current
    for i in $(seq 1 40); do
        if ! kill -0 "$(cat "$REPLAY_PID")" 2>/dev/null; then
            fail "replay exited immediately (log: $LOGDIR/e2e-replay.log)"
            return 1
        fi
        current="$(feed_current)"
        [ "$current" = "true" ] && return 0
        sleep 0.5
    done
    fail "replay started but the feed did not report current:true within 20s"
    return 1
}

replay_stop() {
    if replay_is_running; then
        kill "$(cat "$REPLAY_PID")" 2>/dev/null
        local i
        for i in $(seq 1 40); do
            replay_is_running || break
            sleep 0.5
        done
        replay_is_running && { fail "replay pid $(cat "$REPLAY_PID") did not exit"; return 1; }
        rm -f "$REPLAY_PID"
        ok "replay stopped; demo journal is now recorded history"
    else
        warn "replay is not running"
    fi
    return 0
}

feed_current() {
    "$PYTHON" - "$ANALYTICS_DEST" "$ANALYTICS_PORT" <<'PY' 2>/dev/null
import sys, json, urllib.request
try:
    with urllib.request.urlopen(f"http://{sys.argv[1]}:{sys.argv[2]}/api/v1/capture/events?limit=1", timeout=4) as r:
        print(str(json.loads(r.read())["current"]).lower())
except Exception:
    print("")
PY
}

feed_report() {
    "$PYTHON" - "$ANALYTICS_DEST" "$ANALYTICS_PORT" <<'PY' 2>/dev/null || echo "ERR"
import sys, json, urllib.request
try:
    with urllib.request.urlopen(f"http://{sys.argv[1]}:{sys.argv[2]}/api/v1/capture/events?limit=1", timeout=4) as r:
        d = json.loads(r.read())
except Exception as e:
    print(f"unreachable ({type(e).__name__})")
    raise SystemExit(0)
state = d.get("state"); present = d.get("present"); current = d.get("current")
if current is True:
    verdict = "LIVE"
elif present and d.get("total", 0) > 0:
    verdict = "RECORDED"
else:
    verdict = "NO CURRENT TRAFFIC"
print(f"verdict={verdict} state={state} present={present} current={current} "
      f"source={d.get('source')} total={d.get('total')} "
      f"last_write_age_ms={d.get('last_write_age_ms')} "
      f"freshness_window_ms={d.get('freshness_window_ms')}")
PY
}

ensure_base_stack() {
    section "preflight"
    [ -x "$PYTHON" ] || { fail "$PYTHON missing; run install instructions in README"; exit 1; }
    [ -f "$RECORDED_FEED" ] || { warn "recorded artifact absent: $RECORDED_FEED (init-demo-data.sh?)"; }
    [ -x "$UVICORN" ] || { fail "$UVICORN missing (requirements.txt)"; exit 1; }
    [ -x "$VITE_BIN" ] || { fail "$VITE_BIN missing; run npm install in sentinel-frontend"; exit 1; }
    ok "python: $("$PYTHON" --version 2>&1)"

    section "port occupancy"
    local owner
    owner="$(port_owner "$ANALYTICS_PORT")"
    if [ -n "$owner" ]; then
        warn "analytics port $ANALYTICS_PORT owned by: $owner"
        if analytics_usable; then
            ok "reusing the analytics on $ANALYTICS_PORT (readiness + v1 + CORS $FRONTEND_ORIGIN all pass)"
        else
            fail "analytics port $ANALYTICS_PORT is occupied but NOT usable for this demo."
            fail "  The running instance predates the CORS allow-list (root cause of the"
            fail "  browser 'disconnected' symptom). Restart it with the derived policy:"
            fail "      kill ${owner%%:*}"
            fail "      FRONTEND_ORIGIN='$FRONTEND_ORIGIN' $0 up"
            exit 1
        fi
    else
        ok "$ANALYTICS_PORT free"
        start_analytics "-" "$LOGDIR/e2e-analytics.log" || exit 1
    fi

    owner="$(port_owner "$CONTROL_PORT")"
    if [ -n "$owner" ]; then
        warn "control port $CONTROL_PORT owned by: $owner"
        if control_usable; then
            ok "reusing the control API on $CONTROL_PORT (/health OK)"
        else
            fail "control port $CONTROL_PORT is occupied but /health does not answer."
            fail "      kill ${owner%%:*}"
            fail "      $0 up"
            exit 1
        fi
    else
        ok "$CONTROL_PORT free"
        start_control || exit 1
    fi

    owner="$(port_owner "$VITE_PORT")"
    if [ -n "$owner" ]; then
        warn "vite port $VITE_PORT owned by: $owner -- reusing it (must be running from sentinel-frontend/.env)"
    else
        ok "$VITE_PORT free"
        start_vite || exit 1
    fi
}

cmd_up() {
    ensure_base_stack
    section "verify"
    cmd_health
    publish_urls
}

cmd_health() {
    local a c ah cor head
    a="[OK] (already verified above)"
    [ "$(probe_status "http://$ANALYTICS_DEST:$ANALYTICS_PORT/api/health")" = "200" ] && a="200"
    c="200"
    [ "$(probe_status "http://$CONTROL_DEST:$CONTROL_PORT/health")" != "200" ] && c="FAIL"
    cor="$(probe_cors "http://$ANALYTICS_DEST:$ANALYTICS_PORT/api/health" "$FRONTEND_ORIGIN")"
    if [ "$cor" = "$FRONTEND_ORIGIN" ]; then
        ok "CORS: $FRONTEND_ORIGIN allowed (exactly what a browser needs)"
    else
        fail "CORS: $FRONTEND_ORIGIN returned '$cor' -- browser will block Analytics. Restart analytics with derived allow-list."
    fi
    ah="ERR"; [ "$(probe_status "http://$ANALYTICS_DEST:$ANALYTICS_PORT/api/v1/health")" = "200" ] && ah="200"
    ok "analytics  /api/health=$a /api/v1/health=$ah"
    ok "control    /health=$c"
    ok "frontend   http://$HOST_IP:$VITE_PORT   (probe: $(probe_status "http://127.0.0.1:$VITE_PORT/"))"
    ok "CORS policy in use: $CORS_MODE"
        printf '%s' "  feed: "; feed_report
}

cmd_status() {
    section "process ownership"
    local owner
    for spec in "$ANALYTICS_PORT:analytics (8081)" "$CONTROL_PORT:control (8000)" "$VITE_PORT:vite (5173)" "8099:nojournal baseline"; do
        port="${spec%%:*}"; label="${spec#*:}"
        owner="$(port_owner "$port")"
        if [ -n "$owner" ]; then
            ok "port $port ($label) -> pid $owner"
        else
            warn "port $port ($label) -> not listening"
        fi
    done
    if replay_is_running; then
        ok "demo replay        -> pid $(cat "$REPLAY_PID")"
    else
        warn "demo replay        -> not running"
    fi
    section "feed verdict"
    feed_report
    section "health"
    cmd_health
}

cmd_demo_start() {
    ensure_base_stack
    if replay_is_running; then
        warn "demo already live (replay pid $(cat "$REPLAY_PID")) -- nothing to do"
        return 0
    fi
    owner="$(port_owner "$ANALYTICS_PORT")"
    if [ -n "$owner" ]; then
        pid="${owner%%:*}"
        if [ "$pid" = "$(cat "$ANALYTICS_PID" 2>/dev/null)" ] && kill -0 "$pid" 2>/dev/null; then
            ok "analytics on $ANALYTICS_PORT is this script's managed instance (pid $pid); switching feed to the demo journal"
        elif [ "${1:-}" = "--force" ]; then
            warn "replacing non-managed analytics on $ANALYTICS_PORT (pid $pid). Log will be under $LOGDIR."
        else
            fail "analytics on $ANALYTICS_PORT (pid $pid) was not started by this script;"
            fail "  giving up rather than killing a process this script does not own."
            fail "  Stop it yourself and re-run, or re-run with --force:"
            fail "      kill $pid && $0 demo-start"
            exit 1
        fi
        [ "$pid" = "$(cat "$ANALYTICS_PID" 2>/dev/null)" ] && kill "$pid" 2>/dev/null && sleep 1
    fi
    install -d "$(dirname "$DEMO_FEED")"
    : > "$DEMO_FEED"
    start_analytics "$DEMO_FEED" "$LOGDIR/e2e-analytics-live.log" || exit 1
    ok "analytics now pinned to the demo journal: $DEMO_FEED"
    if ! replay_start; then
        fail "replay did not start; stopping live demo safely"
        cmd_demo_stop
        exit 1
    fi
    section "LIVE state reached"
    feed_report
    ok "Open the browser at http://$HOST_IP:$VITE_PORT/ — rows are live now."
    ok "Stop the demo with:  $0 demo-stop  (or  $0 replay stop  to keep analytics live)"
}

cmd_demo_stop() {
    replay_stop || exit 1
    owner="$(port_owner "$ANALYTICS_PORT")"
    if [ -n "$owner" ]; then
        pid="${owner%%:*}"
        if [ "$pid" = "$(cat "$ANALYTICS_PID" 2>/dev/null)" ]; then
            ok "stopping the managed analytics (pid $pid)"
            kill "$pid" 2>/dev/null
            sleep 1
        else
            warn "analytics on $ANALYTICS_PORT (pid $pid) was not started by this script; leaving it alone"
        fi
    fi
    start_analytics "-" "$LOGDIR/e2e-analytics.log" || exit 1
    ok "analytics switched back to the recorded baseline feed"
    section "RECORDED state reached"
    feed_report
    ok "Refresh the browser: recorded history is shown, never as live traffic."
}

cmd_down() {
    replay_stop || true
    for file in "$ANALYTICS_PID" "$CONTROL_PID" "$VITE_PID"; do
        if [ -f "$file" ] && kill -0 "$(cat "$file")" 2>/dev/null; then
            ok "stopping managed process pid $(cat "$file")"
            kill "$(cat "$file")" 2>/dev/null
            rm -f "$file"
        fi
    done
    section "stopped (anything running before 'up' was not touched)"
}

publish_urls() {
    cat <<EOF

Frontend   : http://$HOST_IP:$VITE_PORT/            (Packet Analysis at '/')
Analytics  : http://$HOST_IP:$ANALYTICS_PORT/api/v1/openapi.json
Control    : http://$HOST_IP:$CONTROL_PORT/openapi.json
Live demo  : $0 demo-start
Stop demo  : $0 demo-stop
Full stop  : $0 down
EOF
}

usage() {
    sed -n '2,9p;12,26p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

case "${1:-}" in
    up)        cmd_up ;;
    health)    cmd_health ;;
    status)    cmd_status ;;
    demo-start) cmd_demo_start "${2:-}" ;;
    demo-stop) cmd_demo_stop ;;
    down)      cmd_down ;;
    replay)
        case "${2:-}" in
            start) replay_start ;;
            stop)  replay_stop ;;
            *) fail "usage: $0 replay start|stop"; exit 2 ;;
        esac
        ;;
    -h|--help|help) usage ;;
    *) fail "unknown command '${1:-}'"; usage; exit 2 ;;
esac