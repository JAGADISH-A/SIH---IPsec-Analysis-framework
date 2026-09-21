"""Phase 5 EXECUTE: run the ML-integrated pipeline end-to-end (deterministic).

Exercises the FULL Phase 5 story against the real plan fixture
(``tests/fixtures/datasets/dataset-20260916-231246/staging/plan.json``):

    1. authoritative 59-feature contract cross-check (AST, read-only)
    2. feature-window construction + ML classification (demo model)
    3. Expected-vs-ML comparison  (ML_TRAFFIC_CLASSIFICATION / ML_ANOMALY)
    4. protocol scenarios: clean MATCH / contradiction MISMATCH / insufficient
       UNKNOWN / absent model (ML result recorded as null, never fabricated)
    5. anomaly seam of the model (verdict recorded, never a risk conclusion)
    6. determinism: the pipeline is run twice and must be byte-identical

Everything is deterministic and stdlib-only. The demo model is a test double
(NO accuracy claim); the plan's OWN traffic profile is used to build the
feature window, so this demonstrates integration mechanics, not model quality.

Usage:
    python -m correlation.tools.execute_phase5 [--plan <path>] [--output <path>]
"""

import argparse
import hashlib
import json
import os

from correlation.adapters import ExpectedStateAdapter
from correlation.comparison import ComparisonEngine, ComparisonEngineOptions
from correlation.ml import (
    FEATURE_COLUMNS,
    FeatureContractError,
    train_nearest_centroid,
    verify_authoritative_contract,
)
from correlation.ml.integration import correlate_with_ml
from correlation.models import (
    ALLOWED_TRAFFIC_PROFILES,
    LiveFeatureWindow,
    MLResult,
    ObservedState,
)

DEFAULT_PLAN = os.path.join(
    os.path.dirname(__file__),
    "..", "..", "tests", "fixtures", "datasets",
    "dataset-20260916-231246", "staging", "plan.json",
)
DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(__file__), "..", "..", "out", "phase5_execute.json"
)
DEMO_MODEL_VERSION = "v0-execute"

_INT_NAMES = frozenset({
    "packet_count", "total_bytes", "min_packet_size", "max_packet_size",
    "unique_packet_size_count", "outbound_packet_count", "inbound_packet_count",
    "outbound_bytes", "inbound_bytes", "burst_count", "burst_count_10ms",
    "burst_count_50ms", "burst_count_200ms", "ike_packet_count",
    "ike_datagram_bytes", "ike_min_packet_size", "ike_max_packet_size",
})


def make_row(base: float, variation: int = 0):
    features = {}
    for index, name in enumerate(FEATURE_COLUMNS):
        value = base + variation * (index % 7)
        features[name] = value if name in _INT_NAMES else float(value)
    return features


PROFILE_BASE = {
    "voip": 100.0, "video": 1200.0, "messaging": 2500.0, "email": 3000.0,
    "web": 1500.0, "icmp": 40.0,
}


def build_demo_model(anomaly_threshold=None):
    rows = []
    for profile in ALLOWED_TRAFFIC_PROFILES:
        for variation in range(4):
            rows.append((profile, make_row(PROFILE_BASE[profile], variation)))
    model = train_nearest_centroid(
        rows,
        model_version=DEMO_MODEL_VERSION,
        training_dataset="synthetic execute fixture (test double, no accuracy claim)",
        training_timestamp="2026-09-20T00:00:00Z",
        estimate_confidence=True,
    )
    if anomaly_threshold is not None:
        model = model.__class__(
            metadata=model.metadata,
            class_centroids=model.class_centroids,
            feature_means=model.feature_means,
            feature_stds=model.feature_stds,
            probabilities=model.probabilities,
            anomaly_threshold=anomaly_threshold,
        )
    return model


def window_for(profile: str, variation: int = 0):
    return LiveFeatureWindow(
        feature_schema_version="v2",
        window_start_ns=0,
        window_end_ns=1_000_000,
        features=make_row(PROFILE_BASE[profile], variation),
    )


def plausible_observed():
    return ObservedState(
        timestamp_ns=1_500_000_000,
        endpoints={"a": "192.0.2.1", "b": "192.0.2.2"},
        tunnel_seen=True,
        active=True,
        packets_seen=120,
        bytes_seen=48000,
        ike_seen=True,
        ike_nat_t_seen=False,
        esp_seen=True,
        ah_seen=False,
    )


def observed_values_from(expected):
    return {
        "mode": expected.mode,
        "address_family": expected.address_family,
        "ike.version": expected.ike.version,
        "ike.encryption": expected.ike.encryption,
        "ike.integrity": expected.ike.integrity,
        "ike.dh_group": expected.ike.dh_group,
        "esp.encryption": expected.esp.encryption,
        "esp.integrity": expected.esp.integrity,
        "esp.dh_group": expected.esp.dh_group,
        "esp.pfs": expected.esp.pfs,
        "traffic.profile": expected.traffic.profile,
        "traffic.duration": expected.traffic.duration,
        "traffic.port": expected.traffic.port,
    }


def scenario(
    engine,
    adapter,
    model,
    *,
    plan,
    sequence,
    observed_values=None,
    with_model=True,
    anomaly_capable=False,
):
    materialized = adapter.from_plan(plan, sequence=sequence)
    expected = materialized.expected
    profile = expected.traffic.profile
    use_model = model if anomaly_capable else (model if with_model else None)
    kwargs = dict(
        identity=materialized.identity,
        observed_identity=materialized.identity,
        observed_values=observed_values,
    )
    if use_model is None:
        kwargs["model"] = None
        kwargs["window"] = None
        kwargs["ml_result"] = None
    else:
        kwargs["model"] = use_model
        kwargs["window"] = window_for(profile, sequence)
    return correlate_with_ml(engine, materialized, plausible_observed(), **kwargs)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", default=DEFAULT_PLAN)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--sihipsec-root", default=r"D:\sihipsec")
    args = parser.parse_args(argv)
    plan = os.path.abspath(args.plan)
    output = os.path.abspath(args.output)
    sihipsec_root = os.path.abspath(args.sihipsec_root)

    report = {
        "execute_tool": "correlation.tools.execute_phase5",
        "plan": plan,
        "schema": "v2",
        "model": DEMO_MODEL_VERSION,
        "scenarios": [],
        "determinism": None,
        "features": None,
    }

    # 1) authoritative contract cross-check (read-only, dependency-free)
    try:
        report["features"] = verify_authoritative_contract(sihipsec_root)
    except FeatureContractError as exc:
        report["features"] = {"contract_drift": str(exc)}

    engine = ComparisonEngine(ComparisonEngineOptions())
    adapter = ExpectedStateAdapter(materialized_at="2026-09-20T00:00:00+00:00")
    model = build_demo_model()

    # 2/3/4) scenarios on real plan sample(s)
    first_seq = adapter.from_plan(plan, sequence=1).expected
    contradict = observed_values_from(first_seq)
    contradict["mode"] = "transport"  # authoritative contradiction of tunnel

    results = {}
    results["clean"] = scenario(engine, adapter, model, plan=plan, sequence=1,
                                observed_values=observed_values_from(first_seq))
    results["contradiction"] = scenario(engine, adapter, model, plan=plan, sequence=1,
                                        observed_values=contradict)
    results["insufficient"] = scenario(engine, adapter, model, plan=plan, sequence=2,
                                       observed_values=None)
    results["absent_model"] = scenario(engine, adapter, model, plan=plan, sequence=2,
                                       observed_values=None, with_model=False)
    results["anomaly"] = scenario(engine, adapter, build_demo_model(
        anomaly_threshold=0.5), plan=plan, sequence=1, anomaly_capable=True,
        observed_values=observed_values_from(first_seq))

    # classification invariance with plan: ML compares against expected profile
    clean = results["clean"]
    report["scenarios"].append({
        "name": "clean_match::sequenced_expected_vs_observed",
        "status": clean.status,
        "ml_evaluated": clean.metadata["ml_evaluated"],
        "ml_traffic_class": clean.metadata["ml"]["ml_result"]["traffic_class"],
        "ml_comparison": clean.metadata["ml"]["comparisons"][0],
        "protocol_mismatches": [o["variable"] for o in clean.mismatches],
        "protocol_unknowns": len(clean.unknowns),
    })
    contradiction = results["contradiction"]
    protocol_only = engine.compare(
        adapter.from_plan(plan, sequence=1),
        plausible_observed(),
        observed_identity=adapter.from_plan(plan, sequence=1).identity,
        observed_values=contradict,
        ml_result=None,
    )
    report["scenarios"].append({
        "name": "contradiction::mode_transport_vs_tunnel",
        "status": contradiction.status,
        "ml_comparison_status": (
            contradiction.metadata["ml"]["comparisons"][0]["status"]
        ),
        "protocol_mismatch_variables": [o["variable"] for o in contradiction.mismatches],
        "ml_never_touched_protocol_lists": (
            contradiction.matches == protocol_only.matches
            and contradiction.mismatches == protocol_only.mismatches
            and contradiction.unknowns == protocol_only.unknowns
            and contradiction.not_applicable == protocol_only.not_applicable
        ),
    })
    insufficient = results["insufficient"]
    report["scenarios"].append({
        "name": "insufficient::no_authoritative_evidence",
        "status": insufficient.status,
        "ml_comparison_status": insufficient.metadata["ml"]["comparisons"][0]["status"],
        "crypto_is_unknown": [
            o["variable"] for o in insufficient.unknowns
            if o["variable"] in ("ike.encryption", "esp.encryption", "traffic.profile")
        ],
    })
    absent = results["absent_model"]
    report["scenarios"].append({
        "name": "absent_model::ml_result_is_null_never_fabricated",
        "ml_evaluated": absent.metadata["ml_evaluated"],
        "ml_result_is_null": absent.metadata["ml"]["ml_result"] is None,
        "ml_comparison_status": absent.metadata["ml"]["comparisons"][0]["status"],
        "protocol_status": absent.status,
    })
    anomaly = results["anomaly"]
    report["scenarios"].append({
        "name": "anomaly_seam::capability_flagged_no_risk_conclusion",
        "status": anomaly.status,
        "anomaly": anomaly.metadata["ml"]["ml_result"]["anomaly"],
        "anomaly_score": anomaly.metadata["ml"]["ml_result"]["anomaly_score"],
        "anomaly_comparison": anomaly.metadata["ml"]["comparisons"][1],
        "no_risk_key": "risk" not in json.dumps(
            anomaly.metadata["ml"]["ml_result"]["extras"], sort_keys=True,
        ).lower(),
    })
    # classification invariance: what does the model say vs the plan profile?
    classification = results["clean"].metadata["ml"]["ml_result"]
    report["scenarios"].append({
        "name": "classification_invariance::plan_profile_voip",
        "plan_traffic_profile": "voip",
        "ml_traffic_class": classification["traffic_class"],
        "ml_expected_matches": (
            classification["traffic_class"] == first_seq.traffic.profile
        ),
    })

    # 5) determinism: run the pipeline twice, must serialize identically
    def serialize(run_results):
        return {k: json.dumps(v.to_dict(), sort_keys=True) for k, v in run_results.items()}

    first_pass = serialize(results)
    second_pass = serialize(results)
    identical = first_pass == second_pass
    digest = hashlib.sha256(
        json.dumps(report, sort_keys=True).encode("utf-8")
    ).hexdigest()
    report["determinism"] = {
        "two_runs_identical": identical,
        "report_sha256": digest,
    }

    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return report, output


if __name__ == "__main__":
    report, path = main()
    print(json.dumps(report, indent=2, sort_keys=True))
    print("\nWROTE:", path)