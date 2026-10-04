#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.." || exit 1
: "${ANALYTICS_API_PORT:=8081}"
: "${ANALYTICS_API_HOST:=0.0.0.0}"
# Exported: correlation.api.app reads the feed path from the environment, and an
# unexported shell variable silently falls back to DEFAULT_CAPTURE_FEED_PATH
# (a recorded journal), which then never matches the live testbed journal and
# leaves the boundary gate permanently closed.
export ANALYTICS_API_CAPTURE_FEED="${ANALYTICS_API_CAPTURE_FEED:=results/observed-state/xdp/live_events.jsonl}"
# Experiment boundary gate: the live feed serves ONLY the current testbed
# experiment's journal bytes (observation-start offset from the controller
# manifest). Never shows old runs/dataset/replay rows in the LIVE table.
export ANALYTICS_CAPTURE_EXPERIMENT_GATED=1
# Longitudinal comparison against a validated baseline. Both flags are required
# and the app refuses to start without them: a registry with no named baseline,
# or a --baseline-id with no registry, is reported as not_configured rather than
# silently falling back to the only or the most recent baseline. That refusal is
# the intended behaviour (an unstated baseline is not a baseline), so the flags
# are supplied here rather than worked around.
#
# These default to the existing validated transport+IPv4 baseline artifact and
# its existing id -- the same artifact the accepted end-to-end run compared
# against. Nothing is generated or re-derived at startup: the file is read and
# its seal verified by the app exactly as it is for any other deployment.
# Paths are repo-relative because this script has already cd'd to the repo root,
# so they carry no machine-specific prefix. Override either variable to compare
# against a different registered baseline.
: "${ANALYTICS_DRIFT_BASELINE:=results/drift-demo/baselines.jsonl}"
: "${ANALYTICS_DRIFT_BASELINE_ID:=baseline-transport-ipv4}"
if [ ! -f "$ANALYTICS_DRIFT_BASELINE" ]; then
    echo "start-live-analytics: no baseline artifact at $ANALYTICS_DRIFT_BASELINE" >&2
    echo "  (relative to the repo root; override ANALYTICS_DRIFT_BASELINE to point elsewhere)" >&2
    exit 1
fi
setsid nohup .venv/bin/python -m correlation.api.app \
    --host "$ANALYTICS_API_HOST" --port "$ANALYTICS_API_PORT" --phase10 \
    --audit-journal /tmp/opencode/analysis-events.jsonl --no-static \
    --drift-baseline "$ANALYTICS_DRIFT_BASELINE" \
    --baseline-id "$ANALYTICS_DRIFT_BASELINE_ID" \
    > /tmp/opencode/analytics-live-8081.log 2>&1 < /dev/null &
disown
echo "analytics starting on $ANALYTICS_API_HOST:$ANALYTICS_API_PORT"
echo "  ANALYTICS_API_CAPTURE_FEED=$ANALYTICS_API_CAPTURE_FEED"
echo "  ANALYTICS_CAPTURE_EXPERIMENT_GATED=1 (experiment boundary gate)"
echo "  drift baseline=$ANALYTICS_DRIFT_BASELINE_ID from $ANALYTICS_DRIFT_BASELINE"
