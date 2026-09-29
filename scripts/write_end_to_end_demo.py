"""Write the end-to-end demonstration artifact from the real pipeline.

Run directly; not collected by pytest:

    .venv/bin/python scripts/write_end_to_end_demo.py

The artifact is generated, never hand-written, so it cannot drift from what the
pipeline actually produces. It is a demonstration of a controlled scenario, so
every record states which parts came from a real recorded capture and which part
was a declared fixture.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlation.api.custody_routes import (  # noqa: E402
    handle_assessment_finding_explanation,
)
from correlation.api.drift_routes import handle_drift  # noqa: E402
from correlation.api.store import (  # noqa: E402
    DriftCurrentObservation,
    build_store,
)
from correlation.artifacts import REPO_ROOT, load_observed_state  # noqa: E402
from correlation.drift import BaselineRegistry, validate_baseline  # noqa: E402
from correlation.mission import load_mission_profiles  # noqa: E402

BASELINE_STATE = "results/e2e-verification/parser/tunnel_v4/state.jsonl"
FIXTURE_STATE = "tests/fixtures/drift/ah_substitution_state.jsonl"
FIXTURE_PROVENANCE = "tests/fixtures/drift/ah_substitution_provenance.json"
OUTPUT = "results/end-to-end-assessment/accepted_drift_demo.json"

BASELINE_ID = "baseline-e2e-tunnel-v4"
BASELINE_VALIDATED_BY = "sec-ops@ipsec-testbed"
BASELINE_VALIDATED_AT = "2026-09-20T09:00:00Z"

DRIFT_ASSESSMENT = "dataset-20260924-003710:3:band-medium-drift"
PLAN_ASSESSMENT = "dataset-20260924-003710:3:band-medium"
FINDING = "RISK-DRIFT-ESP-PRESENCE"

#: Scenario 0 uses only recorded artifacts. ``tunnel-v6`` pairs the real
#: ``tunnel_v6inner`` state snapshot with an IPv6 plan sample, so the observed
#: outer address family genuinely disagrees with the plan -- a real finding from
#: real data, with no fixture anywhere in the chain.
REAL_ASSESSMENT = "dataset-20260924-003710:16:tunnel-v6"
REAL_FINDING = "RISK-ADDRESS-FAMILY-MISMATCH"

SCENARIO_LABEL = (
    "longitudinal comparison of a declared controlled current observation "
    "against the validated baseline built from the real recorded tunnel_v4 "
    "capture; the current state is a disclosed derived fixture, not a capture "
    "of a live device"
)


def build(asset_id):
    state, _ = load_observed_state(BASELINE_STATE)
    registry = BaselineRegistry()
    registry.register(validate_baseline(
        state,
        baseline_id=BASELINE_ID,
        validated_by=BASELINE_VALIDATED_BY,
        validated_at=BASELINE_VALIDATED_AT,
    ))
    current, record = load_observed_state(FIXTURE_STATE)
    provenance = json.loads(
        open(os.path.join(REPO_ROOT, FIXTURE_PROVENANCE)).read())
    return build_store(
        asset_id=asset_id,
        mission_profiles=load_mission_profiles(),
        baselines=registry,
        baseline_id=BASELINE_ID,
        drift_observations=[DriftCurrentObservation(
            slot="band-medium",
            observed=current,
            state_record=record,
            declared_provenance=provenance,
        )],
        drift_scenario_label=SCENARIO_LABEL,
    )


def main() -> int:
    low = build("gw-a")
    high = build("gw-b")

    state, _ = load_observed_state(BASELINE_STATE)
    registry = BaselineRegistry()
    registry.register(validate_baseline(
        state, baseline_id=BASELINE_ID, validated_by=BASELINE_VALIDATED_BY,
        validated_at=BASELINE_VALIDATED_AT))
    # The control: the same store with no declared current observation, so the
    # recorded capture is compared against its own baseline.
    control_no_drift = build_store(
        asset_id="gw-a", mission_profiles=load_mission_profiles(),
        baselines=registry, baseline_id=BASELINE_ID)

    chain_low = handle_assessment_finding_explanation(
        low, DRIFT_ASSESSMENT, FINDING)
    chain_high = handle_assessment_finding_explanation(
        high, DRIFT_ASSESSMENT, FINDING)

    # Scenario 0: a chain built from recorded artifacts only. No declared
    # observation, no baseline, no fixture -- the default store. This is the
    # scenario a demo can show without any disclosure caveat at all.
    real_only = build_store(asset_id="gw-b", mission_profiles=load_mission_profiles())
    chain_real = handle_assessment_finding_explanation(
        real_only, REAL_ASSESSMENT, REAL_FINDING)

    document = {
        "artifact": "end_to_end_acceptance_demonstration",
        "schema_version": "v1",
        "read_only": True,
        "what_this_is": (
            "One assessment traced end to end through the real pipeline: a "
            "validated IPsec baseline, a current observed state, a drift "
            "comparison, a drift finding, technical risk, declared mission "
            "context, a contextualized risk, and the chain of custody that "
            "explains all of it. Every value below was produced by the "
            "existing engines; none was written by hand."
        ),
        "data_status": {
            "real_recorded_capture": {
                "paths": [BASELINE_STATE],
                "role": (
                    "establishes the validated baseline, and is the live "
                    "capture the evidence references point at"
                ),
                "is_capture": True,
            },
            "controlled_fixture": {
                "paths": [FIXTURE_STATE, FIXTURE_PROVENANCE],
                "role": "the current observed state, declared as a declaration",
                "is_capture": False,
                "note": (
                    "No two recorded captures of the same asset in this "
                    "repository differ in a comparable security-state field: "
                    "all 10 usable real captures canonicalise to the same "
                    "state. One further recorded snapshot (the IPv6 parser "
                    "rerun) does canonicalise differently, but it describes a "
                    "different endpoint pair and is not admitted by the "
                    "loader. So the drifted side of this demonstration is a "
                    "disclosed derived fixture and is labelled as such "
                    "everywhere it appears."
                ),
            },
        },
        "scenarios": {
            "0_fully_real": "no fixture is involved anywhere in this scenario; "
                            "every input is a recorded artifact",
            "1_baseline_no_drift": "control_no_drift",
            "2_controlled_drift": "asset_contexts + comparison",
            "3_mission_comparison": "asset_contexts.gw-a vs asset_contexts.gw-b",
        },
        "baseline": {
            "baseline_id": BASELINE_ID,
            "validated_by": BASELINE_VALIDATED_BY,
            "validated_at": BASELINE_VALIDATED_AT,
            "source": BASELINE_STATE,
        },
        "drift_summary": handle_drift(low),
        "fully_real_chain": {
            "disclosure": (
                "recorded artifacts only; no controlled fixture and no declared "
                "observation takes part in this chain"
            ),
            "assessment_id": REAL_ASSESSMENT,
            "finding_id": REAL_FINDING,
            "uses_fixture": False,
            "chain": chain_real,
        },
        "asset_contexts": {
            "gw-a": {
                "role": "declared development asset",
                "chain": chain_low,
            },
            "gw-b": {
                "role": "declared operational asset",
                "chain": chain_high,
            },
        },
        "comparison": {
            "finding_id": FINDING,
            "assessment_id": DRIFT_ASSESSMENT,
            "finding_digest_gw_a": chain_low["finding_digest"],
            "finding_digest_gw_b": chain_high["finding_digest"],
            "finding_digest_identical": (
                chain_low["finding_digest"] == chain_high["finding_digest"]
            ),
            "technical_risk_identical": (
                chain_low["risk_score"] == chain_high["risk_score"]
            ),
            "contextualized_risk_gw_a":
                chain_low["mission_context"]["risk"]["contextualized_risk"],
            "contextualized_risk_gw_b":
                chain_high["mission_context"]["risk"]["contextualized_risk"],
        },
        "control_no_drift": {
            "description": (
                "The same store with the recorded capture compared against its "
                "own baseline. No drift finding is produced and no extra "
                "assessment is registered."
            ),
            "drift_summary": handle_drift(control_no_drift),
            "assessment_ids_include_drift_origin": (
                DRIFT_ASSESSMENT in control_no_drift.bundles
            ),
        },
    }

    path = os.path.join(REPO_ROOT, OUTPUT)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"wrote {OUTPUT}")
    print(f"  status        {chain_low['drift']['status']}")
    print(f"  finding       {chain_low['finding_id']}")
    print(f"  technical     {chain_low['risk_score']} {chain_low['risk_severity']}")
    print(f"  gw-a          {chain_low['mission_context']['risk']['contextualized_risk']}"
          f" {chain_low['mission_context']['risk']['contextualized_severity']}")
    print(f"  gw-b          {chain_high['mission_context']['risk']['contextualized_risk']}"
          f" {chain_high['mission_context']['risk']['contextualized_severity']}")
    print(f"  digests equal {document['comparison']['finding_digest_identical']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
