#!/usr/bin/env bash
#
# init-demo-data.sh - materialise the demo assessment data a frontend needs.
#
# Why this exists
# ---------------
# The analytics server does not compute assessments at request time. It reads
# recorded artifacts from results/ once at startup, in memory, and serves those.
# results/ is gitignored (.gitignore:21) because it is where 2,000+ generated
# experiment outputs land. Until now that meant a fresh clone had no
# assessments, no findings and no evidence, and the analytics API answered
# "no assessments" even though the code was correct.
#
# So the artifacts the demo actually needs are tracked, curated and checksummed
# in demo/analytics/ (see demo/README.md for provenance and the audit that
# produced the selection). This script copies them into results/ at the exact
# paths correlation/artifacts.py expects, verifies their checksums, and then
# proves the analytics store builds and reports the documented counts.
#
# It is idempotent and non-destructive: it copies fixture files into place and
# leaves everything else in results/ alone. It never runs the testbed, never
# touches the network, and never needs root.
#
# Usage:
#   ./scripts/init-demo-data.sh            # copy fixture -> results/, then verify
#   ./scripts/init-demo-data.sh --verify   # verify only, copy nothing
#
# After this succeeds:
#   ./scripts/serve-backend.sh
# and GET http://127.0.0.1:8081/api/health reports the demo dataset.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR" || exit 1

OK="[OK]"
FAIL="[FAIL]"

ok()   { printf '%s %s\n' "$OK"   "$*"; }
fail() { printf '%s %s\n' "$FAIL" "$*" >&2; }

section() { printf '\n=== %s ===\n' "$*"; }

PYTHON=".venv/bin/python"
FIXTURE_DIR="demo/analytics"
MANIFEST="demo/MANIFEST.sha256"
MANIFEST_BASENAME="MANIFEST.sha256"
TARGET_DIR="results"

VERIFY_ONLY=0
case "${1:-}" in
    --verify)   VERIFY_ONLY=1 ;;
    "")         ;;
    *) fail "unknown option '$1' (use --verify)"; exit 2 ;;
esac

section "preflight"

if [ ! -x "$PYTHON" ]; then
    fail "$PYTHON not found."
    fail "Create the virtualenv and install requirements.txt first:"
    fail "    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
    exit 1
fi
ok "python: $("$PYTHON" --version 2>&1)"

if [ ! -d "$FIXTURE_DIR" ]; then
    fail "$FIXTURE_DIR is missing. The demo fixture is tracked in git, so this"
    fail "means the clone is incomplete. Re-clone the backend branch."
    exit 1
fi
if [ ! -f "$MANIFEST" ]; then
    fail "$MANIFEST is missing; the fixture cannot be checksummed."
    exit 1
fi
ok "fixture: $FIXTURE_DIR ($(find "$FIXTURE_DIR" -type f | wc -l) files, $(du -sh "$FIXTURE_DIR" | cut -f1))"

# ---------------------------------------------------------------------------
section "checksum"

# The manifest stores paths relative to the fixture directory, so verify there.
if ( cd "$FIXTURE_DIR" && sha256sum -c "../$MANIFEST_BASENAME" >/dev/null 2>&1 ); then
    ok "all $(wc -l < "$MANIFEST") fixture files match $MANIFEST"
else
    fail "fixture checksum mismatch; listing the files that differ:"
    ( cd "$FIXTURE_DIR" && sha256sum -c "../$MANIFEST_BASENAME" 2>&1 | grep -v ': OK$' ) >&2
    exit 1
fi

# ---------------------------------------------------------------------------
if [ "$VERIFY_ONLY" -eq 0 ]; then
    section "install into $TARGET_DIR/"

    mkdir -p "$TARGET_DIR" || exit 1
    # cp -a of a trailing '/.' copies the directory's contents, preserving the
    # layout under results/ that correlation/artifacts.py hard-codes.
    cp -a "$FIXTURE_DIR/." "$TARGET_DIR/" || exit 1
    ok "copied fixture into $TARGET_DIR/"
    ok "existing files in $TARGET_DIR/ that the fixture does not own are untouched"
else
    section "install into $TARGET_DIR/ (skipped: --verify)"
fi

# ---------------------------------------------------------------------------
section "verify the analytics store can build from this data"

# This is the check that matters: it exercises the same construction path the
# server uses, so a green run here means the demo works from a fresh clone.
if ! "$PYTHON" - <<'PY'
import sys
sys.path.insert(0, ".")
from correlation.api.store import AssessmentStore

store = AssessmentStore()
bundles = store.bundles
findings = store.overview.get("findings_total")

print("  assessments : %d" % len(bundles))
print("  findings    : %s" % findings)
print("  sources     : %d" % len(store.sources))

fail = []
if len(bundles) < 12:
    fail.append("expected >= 12 assessments, got %d" % len(bundles))
if not findings:
    fail.append("expected a non-zero finding count")
if not store.sources:
    fail.append("expected provenance sources")

if fail:
    for line in fail:
        print("  FAILED: %s" % line, file=sys.stderr)
    raise SystemExit(1)
PY
then
    fail "the analytics store did not build from the installed data."
    fail "Check the traceback above; re-run with ./scripts/init-demo-data.sh --verify"
    exit 1
fi

section "done"

cat <<EOF
The demo dataset is installed. Start the two backends with:

    ./scripts/serve-backend.sh

Then check readiness:

    curl -s http://127.0.0.1:8081/api/health

The full frontend contract is in docs/FRONTEND_API_CONTRACT.md.
Demo data provenance is in demo/README.md.

This data is recorded, sanitised evidence from a lab run: RFC1918 addresses
only, no credentials, no personal data. It is prototype/demo data for a
loopback-only development deployment, not production.
EOF
