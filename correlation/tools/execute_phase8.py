"""Phase 8 EXECUTE: run the dashboard store end-to-end (deterministic).

Builds the dashboard assessment store by running the REAL Phase-3/4/5/6/7
pipeline over the REAL recorded artifacts (the Phase-3 plan, ipsec_state_builder
snapshots, feature-schema-v2 windows and recorded RandomForest output), verifies
the whole pipeline is byte-identical across two runs (no time/random/network
inputs), and writes the full static snapshot for the dashboard demo mode:

    python -m correlation.tools.execute_phase8 [--plan <path>]
                                               [--output out/dashboard_snapshot.json]

The snapshot contains overview + headers + every full assessment bundle
(expected, observed, correlation, ml, risk, xai, evidence, ipsec-state) plus the
`sources` each assessment was built from, with each artifact's own digest.
"""

import argparse
import hashlib
import json
import os

from ..api.routes import serializable
from ..api.store import build_store

DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(__file__), "..", "..", "out", "dashboard_snapshot.json"
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", default=None)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)

    store = build_store(args.plan) if args.plan else build_store()
    snapshot = serializable(store)

    report = {
        "execute_tool": "correlation.tools.execute_phase8",
        "store_version": store.overview["store_version"],
        "plan": store.plan_path,
        "overview": dict(store.overview),
        "scenario_slots": sorted({h["slot"] for h in store.headers}),
        "history": [
            {
                "assessment_id": h["assessment_id"],
                "slot": h["slot"],
                "sequence": h["sequence"],
                "risk_score": h["risk_score"],
                "severity": h["severity"],
                "correlation_status": h["correlation_status"],
                "finding_count": h["finding_count"],
            }
            for h in store.headers
        ],
        "determinism": None,
    }

    # determinism: rebuild the whole store twice and byte-compare serialization
    first = json.dumps(serializable(build_store(store.plan_path)), sort_keys=True)
    second = json.dumps(serializable(build_store(store.plan_path)), sort_keys=True)
    digest = hashlib.sha256(
        json.dumps(snapshot, sort_keys=True).encode("utf-8")
    ).hexdigest()
    report["determinism"] = {
        "two_runs_identical": first == second,
        "snapshot_sha256": digest,
    }

    output = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, indent=2, sort_keys=True)
        handle.write("\n")

    print(json.dumps(report, indent=2, sort_keys=True))
    print("\nWROTE:", output)
    return report, output


if __name__ == "__main__":
    main()