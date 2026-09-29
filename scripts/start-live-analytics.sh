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
setsid nohup .venv/bin/python -m correlation.api.app \
    --host "$ANALYTICS_API_HOST" --port "$ANALYTICS_API_PORT" --phase10 \
    --audit-journal /tmp/opencode/analysis-events.jsonl --no-static \
    > /tmp/opencode/analytics-live-8081.log 2>&1 < /dev/null &
disown
echo "analytics starting on $ANALYTICS_API_HOST:$ANALYTICS_API_PORT"
echo "  ANALYTICS_API_CAPTURE_FEED=$ANALYTICS_API_CAPTURE_FEED"
echo "  ANALYTICS_CAPTURE_EXPERIMENT_GATED=1 (experiment boundary gate)"