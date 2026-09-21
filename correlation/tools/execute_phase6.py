"""Phase 6 EXECUTE: run the risk engine end-to-end (deterministic).

Exercises the FULL Phase 6 story against the real plan fixture
(``tests/fixtures/datasets/dataset-20260916-231246/staging/plan.json``):

    1. real expected-state materialization (Phases 3)
    2. real deterministic comparison (Phase 4)
    3. risk assessment across every posture band of the real plan
       (STRONG/GOOD/MEDIUM/WEAK/WORST): clean config, configuration
       weakness, confirmed adversity, UNKNOWN discipline, ML-derived
       evidence, and the compounded CRITICAL band
    4. determinism: the whole pipeline is run twice and must be
       byte-identical (same score, severity, finding set, SHA-256)

Everything is deterministic and stdlib-only. SIH semantics are consumed
READ-ONLY; nothing here ever grades IKE, AES-128 key length, or unknown
observations. Evidence is never fabricated.

Usage:
    python -m correlation.tools.execute_phase6 [--plan <path>] [--output <path>]
"""

import argparse
import hashlib
import json
import os

from correlation.adapters import ExpectedStateAdapter
from correlation.comparison import ComparisonEngine, ComparisonEngineOptions
from correlation.models import MLResult, ObservedState
from correlation.risk import RiskEngine, RiskPolicy

DEFAULT_PLAN = os.path.join(
    os.path.dirname(__file__),
    "..", "..", "tests", "fixtures", "datasets",
    "dataset-20260916-231246", "staging", "plan.json",
)
DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(__file__), "..", "..", "out", "phase6_execute.json"
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


def _summary(assessment):
    return {
        "score": assessment.overall_score,
        "severity": assessment.severity,
        "findings": len(assessment.findings),
        "raw_sum": assessment.metadata["score_detail"]["raw_sum"],
        "rule_ids": sorted({finding.rule_id for finding in assessment.findings}),
        "categories": sorted({finding.category for finding in assessment.findings}),
        "sources": sorted({finding.source for finding in assessment.findings}),
        "risk_policy_version": assessment.risk_policy_version,
        "identity": assessment.identity.dataset_run_id,
    }


def run_scenario(engine, adapter, risk_engine, *, plan, sequence,
                 observed_values=None, mode_override=None, ml_result=None):
    materialized = adapter.from_plan(plan, sequence=sequence)
    expected = materialized.expected
    values = observed_values
    if mode_override is not None:
        values = dict(observed_values_from(expected))
        values["mode"] = mode_override
    comparison = engine.compare(
        materialized,
        plausible_observed(),
        observed_identity=materialized.identity,
        observed_values=values,
        ml_result=ml_result,
    )
    assessment = risk_engine.assess(
        expected=materialized.expected if materialized.identity is None
        else materialized,
        observed=plausible_observed(),
        correlation=comparison,
        ml_result=ml_result,
    )
    return materialized, comparison, assessment


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", default=DEFAULT_PLAN)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    plan = os.path.abspath(args.plan)
    output = os.path.abspath(args.output)

    report = {
        "execute_tool": "correlation.tools.execute_phase6",
        "plan": plan,
        "policy": RiskPolicy.default().policy_version,
        "scenarios": [],
        "determinism": None,
    }

    engine = ComparisonEngine(ComparisonEngineOptions())
    adapter = ExpectedStateAdapter(materialized_at="2026-09-20T00:00:00+00:00")
    risk_engine = RiskEngine(RiskPolicy.default())

    def add(name, materialized, comparison, assessment, context=None):
        record = {
            "name": name,
            "sample": {
                "sequence": materialized.identity.sequence,
                "traffic_profile": materialized.expected.traffic.profile,
                "security_posture": materialized.expected.security_posture,
            },
            "comparison_status": comparison.status,
            "mismatch_variables": [o["variable"] for o in comparison.mismatches],
            "unknown_variables": [o["variable"] for o in comparison.unknowns],
            "assessment": _summary(assessment),
        }
        if context:
            record.update(context)
        report["scenarios"].append(record)

    # every posture band of the real plan, clean evidence matching the plan
    for sequence in range(1, 7):
        materialized, comparison, assessment = run_scenario(
            engine, adapter, risk_engine, plan=plan, sequence=sequence,
            observed_values=observed_values_from(
                adapter.from_plan(plan, sequence=sequence).expected),
        )
        add("clean::posture_band_{}".format(sequence), materialized, comparison, assessment)

    # configuration weakness: WEAK sample (PFS disabled) -> MEDIUM finding
    materialized, comparison, assessment = run_scenario(
        engine, adapter, risk_engine, plan=plan, sequence=4,
        observed_values=observed_values_from(adapter.from_plan(plan, sequence=4).expected),
    )
    add("config::weak_plan_no_observed_flaw", materialized, comparison, assessment)

    # WORST sample alone (CBC family + PFS off) -> compounded HIGH, never CRITICAL
    materialized, comparison, assessment = run_scenario(
        engine, adapter, risk_engine, plan=plan, sequence=5,
        observed_values=observed_values_from(adapter.from_plan(plan, sequence=5).expected),
    )
    add("config::worst_plan_compounded", materialized, comparison, assessment)

    # confirmed adversity: tunnel plan observed in transport -> CONFIGURATION_MISMATCH
    materialized, comparison, assessment = run_scenario(
        engine, adapter, risk_engine, plan=plan, sequence=1, mode_override="transport",
    )
    add("adversity::confirmed_transport_vs_tunnel", materialized, comparison, assessment)

    # compounded evidence across categories -> CRITICAL band
    ml = MLResult(model_version="traffic-rf-v0-execute", anomaly=True, anomaly_score=0.9)
    materialized, comparison, assessment = run_scenario(
        engine, adapter, risk_engine, plan=plan, sequence=5, mode_override="transport",
        ml_result=ml,
    )
    add("compounded::worst+adversity+ml", materialized, comparison, assessment, context={
        "ml": {"model_version": ml.model_version, "anomaly": ml.anomaly,
               "anomaly_score": ml.anomaly_score},
    })

    # UNKNOWN discipline: no authoritative evidence, never a vulnerability
    materialized, comparison, assessment = run_scenario(
        engine, adapter, risk_engine, plan=plan, sequence=2, observed_values=None,
    )
    add("unknown::no_authoritative_evidence", materialized, comparison, assessment)

    # ML-derived evidence only (clean plan + anomaly verdict)
    materialized, comparison, assessment = run_scenario(
        engine, adapter, risk_engine, plan=plan, sequence=3, ml_result=ml,
        observed_values=observed_values_from(adapter.from_plan(plan, sequence=3).expected),
    )
    add("ml::anomaly_evidence_low", materialized, comparison, assessment, context={
        "ml": {"model_version": ml.model_version, "anomaly": ml.anomaly},
    })

    # determinism: whole pipeline twice, byte-identical
    def snapshot(seed):
        engine = ComparisonEngine(ComparisonEngineOptions())
        adapter = ExpectedStateAdapter(materialized_at="2026-09-20T00:00:00+00:00")
        risk_engine = RiskEngine(RiskPolicy.default())
        results = []
        for sequence, overrides in seed:
            m, c, a = run_scenario(engine, adapter, risk_engine, plan=plan,
                                   sequence=sequence, **overrides)
            results.append((sequence, c.to_dict(), a.to_json(sort_keys=True)))
        return json.dumps(results, sort_keys=True)

    seed = [
        (1, {"observed_values": observed_values_from(adapter.from_plan(plan, sequence=1).expected)}),
        (5, {"mode_override": "transport", "ml_result": ml}),
        (2, {"observed_values": None}),
    ]
    first_pass = snapshot(seed)
    second_pass = snapshot(seed)
    digest = hashlib.sha256(
        json.dumps(report, sort_keys=True).encode("utf-8")
    ).hexdigest()
    report["determinism"] = {
        "two_runs_identical": first_pass == second_pass,
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