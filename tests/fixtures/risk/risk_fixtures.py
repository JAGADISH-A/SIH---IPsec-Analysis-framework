"""Shared helpers + REAL artifacts for Phase 6 risk tests.

The REAL expected states are loaded from the committed Phase-3 planning
artifact ``tests/fixtures/datasets/dataset-20260916-231246/staging/plan.json``
(6 samples spanning STRONG/GOOD/MEDIUM/WEAK/WORST). Identities for those
samples are synthesized from the run folder name and documented as such; the
*configuration* content is authoritative, real planning data - not fabricated.

``run_comparison`` drives the real Phase-4 ComparisonEngine so Phase-6 tests
consume genuine Phase-4 outcomes (and re-prove Phase-4 behavior in passing).
"""

import json
import os

from correlation.comparison import (
    ComparisonEngine,
    ComparisonEngineOptions,
)
from correlation.models import (
    CorrelationIdentity,
    CorrelationResult,
    EspExpected,
    ExpectedState,
    IkeExpected,
    LiveFeatureWindow,
    ObservedState,
    TrafficExpected,
)

FIXTURE_DIR = os.path.dirname(os.path.abspath(__file__))
STAGING_DIR = os.path.join(
    os.path.dirname(os.path.dirname(FIXTURE_DIR)),
    "fixtures",
    "datasets",
    "dataset-20260916-231246",
    "staging",
)
PLAN_PATH = os.path.join(STAGING_DIR, "plan.json")

DATASET_RUN_ID = "dataset-20260916-231246"


def load_plan() -> dict:
    with open(PLAN_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def plan_samples() -> list:
    return load_plan()["samples"]


def expected_from_plan_sample(sample: dict, **traffic_overrides) -> ExpectedState:
    """ExpectedState from one REAL plan sample (identity synthesized)."""
    cfg = sample["ipsec_configuration"]
    traffic = dict(profile=sample["traffic_profile"], duration=30, port=20000)
    traffic.update(traffic_overrides)
    return ExpectedState(
        mode=cfg["mode"],
        address_family=cfg["address_family"],
        ike=IkeExpected(
            version=cfg["ike"]["version"],
            encryption=cfg["ike"]["encryption"],
            integrity=cfg["ike"]["integrity"],
            dh_group=cfg["ike"]["dh_group"],
        ),
        esp=EspExpected(
            encryption=cfg["esp"]["encryption"],
            integrity=cfg["esp"]["integrity"],
            dh_group=cfg["esp"]["dh_group"],
            pfs=cfg["esp"]["pfs"],
        ),
        traffic=TrafficExpected(**traffic),
        capture_filter="udp port 500 or udp port 4500 or esp or ah",
        configuration_id=sample["configuration_id"],
        security_posture=sample["security_posture"],
    )


def build_identity(**overrides) -> CorrelationIdentity:
    base = dict(
        dataset_run_id=DATASET_RUN_ID,
        sequence=1,
        experiment_id="exp-risk-engine",
        attempt_number=1,
        window_index=0,
        window_start_ns=1_000_000_000,
        window_end_ns=60_000_000_000,
    )
    base.update(overrides)
    return CorrelationIdentity(**base)


def expected_identity_for(expected: ExpectedState, identity=None) -> CorrelationIdentity:
    if identity is not None:
        return identity
    return build_identity()


def build_observed(**overrides) -> ObservedState:
    kwargs = dict(
        timestamp_ns=30_000_000_000,
        endpoints={"a": "192.0.2.1", "b": "192.0.2.2"},
        tunnel_seen=True,
        active=True,
        packets_seen=120,
        bytes_seen=48000,
        ike_seen=True,
        ike_nat_t_seen=False,
        esp_seen=True,
        ah_seen=False,
        spis=[],
    )
    kwargs.update(overrides)
    return ObservedState(**kwargs)


def complete_window() -> LiveFeatureWindow:
    # spans >= the 30s expected traffic duration -> COMPLETE observation
    return LiveFeatureWindow(
        feature_schema_version="v2",
        window_start_ns=0,
        window_end_ns=40_000_000_000,
        features={"ip_total": 1, "esp_packets": 1},
    )


def partial_window() -> LiveFeatureWindow:
    return LiveFeatureWindow(
        feature_schema_version="v2",
        window_start_ns=0,
        window_end_ns=1_000_000_000,
        features={"ip_total": 1},
    )


def observed_values_for(expected: ExpectedState, **overrides) -> dict:
    """Authoritative observed-value channel matching the expected state."""
    values = {
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
        "capture_filter": expected.capture_filter,
    }
    values.update(overrides)
    return values


def run_comparison(
    expected: ExpectedState,
    observed=None,
    *,
    identity=None,
    observed_identity=None,
    observed_values=None,
    live_features=None,
    ml_result=None,
    evidence_refs=(),
    options=None,
) -> CorrelationResult:
    """Run the REAL Phase-4 engine against ``expected`` (Phase 4 stays green)."""
    engine = ComparisonEngine(options or ComparisonEngineOptions())
    return engine.compare(
        expected,
        observed if observed is not None else build_observed(),
        identity=identity or expected_identity_for(expected),
        observed_identity=observed_identity or expected_identity_for(expected),
        observed_values=observed_values,
        evidence_refs=evidence_refs,
        live_features=live_features,
        ml_result=ml_result,
    )


def make_correlation(
    identity: CorrelationIdentity,
    *,
    mismatches=None,
    unknowns=None,
    matches=None,
    not_applicable=None,
) -> CorrelationResult:
    """Craft a CorrelationResult with explicit outcome payloads.

    Used ONLY for fine-grained rule tests where a real Phase-4 run cannot
    produce the exact outcome shape (e.g. duplicate mismatch variables). All
    such scenarios are documented as synthetic unit fixtures.
    """
    to_outcome = lambda payload: dict(
        variable=payload["variable"],
        status=payload["status"],
        comparison_rule=payload.get("comparison_rule", f"{payload['variable']}.exact"),
        reason=payload.get("reason", "synthetic fixture outcome"),
        expected_value=payload.get("expected_value"),
        observed_value=payload.get("observed_value"),
        identity=payload.get("identity") or identity.to_dict(),
        evidence_refs=[dict(ev) for ev in payload.get("evidence_refs") or []],
    )

    def collected(items):
        return [to_outcome(item) for item in items or []]

    status = "MISMATCH" if mismatches else ("UNKNOWN" if unknowns else "MATCH")
    return CorrelationResult(
        identity=identity,
        status=status,
        matches=collected(matches),
        mismatches=collected(mismatches),
        unknowns=collected(unknowns),
        not_applicable=collected(not_applicable),
        metadata={
            "comparison_engine_version": "v1",
            "observation_completeness": "COMPLETE",
            "spi_summary": {},
            "ml_evaluated": False,
            "rules_executed": [],
        },
    )