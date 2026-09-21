"""PHASE 8 — Deterministic assessment store.

Builds the dashboard's assessment index by running the REAL Phase-3 -> Phase-7
pipeline over the committed Phase-3 planning fixture
(``tests/fixtures/datasets/dataset-20260916-231246/staging/plan.json``).

The store is DETERMINISTIC (fixed inputs -> fixed outputs; no time, random,
or network) and exposes the six required Phase-8 demo scenarios plus the six
clean posture bands (the risk trend uses only real pipeline values).

Demo-mode inputs (documented, not fabricated backend decisions):

* ``observed`` live-path snapshots, SPI observations and state transitions are
  testbed-telemetry stand-ins (what a real eBPF state builder would emit);
* ``ml_result`` acts as the Phase-5 model output the correlation layer
  consumes;
* ``evidence_refs`` are operator-supplied references (matching the documented
  ``results/datasets/<run_id>/captures/<seq>/<experiment_id>.pcap`` pattern)
  presented READ-ONLY by the dashboard.

Every score / severity / finding / explanation is produced by the real
Phase-6/7 engines consuming those inputs - never recomputed in the UI layer.
"""

import json
import os
from typing import Any, Dict, List, Optional, Tuple

from ..adapters import ExpectedStateAdapter
from ..comparison import ComparisonEngine, ComparisonEngineOptions
from ..models import EvidenceRef, MLResult, ObservedState, SpiObservation
from ..risk import RiskEngine, RiskPolicy
from ..xai import ExplainabilityEngine
from .adapters import (
    STORE_VERSION,
    assessment_bundle,
    evidence_to_view,
    header_view,
)

PLAN_PATH = os.path.join(
    os.path.dirname(__file__),
    "..", "..", "tests", "fixtures", "datasets",
    "dataset-20260916-231246", "staging", "plan.json",
)

# Dataset run id derived from the folder name (Phase-3 identity convention).
DATASET_RUN_ID = "dataset-20260916-231246"

MATERIALIZED_AT = "2026-09-20T00:00:00+00:00"

SCENARIO_SLOTS = (
    "strong-clean",
    "pfs-weak",
    "transport",
    "unknown",
    "ml-anomaly",
    "worst-ml",
)


def demo_observed(sequence: int) -> ObservedState:
    """Testbed-telemetry stand-in snapshot for the demo store (documented).

    Deterministic per sequence. SPI integers are derived by formula
    (``0x06000000 + sequence * 0x10000 + hop``) purely so the UI can exercise
    the SPI display; they carry no security meaning.
    """
    base_ns = 30_000_000_000
    spis = [
        SpiObservation(
            spi=(0x06000000 + sequence * 0x10000),
            direction="A_TO_B",
            active=True,
            first_seen_ns=1_000_000_000 + sequence * 100_000,
            last_seen_ns=base_ns,
            packet_count=120 + sequence * 10,
            first_sequence=1,
            last_sequence=120 + sequence * 10,
            highest_sequence=120 + sequence * 10,
            sequence_delta=119 + sequence * 10,
        ),
        SpiObservation(
            spi=(0x06000000 + sequence * 0x10000 + 1),
            direction="B_TO_A",
            active=True,
            first_seen_ns=1_500_000_000 + sequence * 100_000,
            last_seen_ns=base_ns,
            packet_count=115 + sequence * 10,
            first_sequence=1,
            last_sequence=115 + sequence * 10,
            highest_sequence=115 + sequence * 10,
            sequence_delta=114 + sequence * 10,
        ),
    ]
    return ObservedState(
        timestamp_ns=base_ns,
        endpoints={"a": "192.0.2.1", "b": "192.0.2.2"},
        tunnel_seen=True,
        active=True,
        packets_seen=240 + sequence * 20,
        bytes_seen=8_000_000 + sequence * 500_000,
        packets_a_to_b=120 + sequence * 10,
        packets_b_to_a=120 + sequence * 10,
        bytes_a_to_b=4_200_000 + sequence * 250_000,
        bytes_b_to_a=3_800_000 + sequence * 250_000,
        ike_seen=True,
        ike_nat_t_seen=False,
        esp_seen=True,
        ah_seen=False,
        observed_ike_activity=True,
        last_ike_timestamp_ns=base_ns - 2_000,
        last_esp_timestamp_ns=base_ns - 500,
        last_ah_timestamp_ns=None,
        spis=spis,
        transitions=[
            _transition("NO_TRAFFIC", sequence * 100_000),
            _transition("SPI_OBSERVED", 1_000_000_000 + sequence * 100_000),
            _transition("ACTIVE", 1_500_000_000 + sequence * 100_000),
        ],
    )


def _transition(name: str, offset: int) -> Dict[str, Any]:
    from ..models import TransitionObservation

    return TransitionObservation(name=name, timestamp_ns=1_000 + offset)


def complete_window():
    from ..models import LiveFeatureWindow

    return LiveFeatureWindow(
        feature_schema_version="v2",
        window_start_ns=0,
        window_end_ns=40_000_000_000,
        features={"ip_total": 1, "esp_packets": 1},
    )


def _evidence_for(slot: str, sequence: int, experiment_id: str) -> List[EvidenceRef]:
    """Operator-supplied evidence refs (demo mode). Empty where noted."""
    refs = {
        "strong-clean": [
            EvidenceRef(
                pcap_path=f"results/datasets/{DATASET_RUN_ID}/captures/{sequence}/{experiment_id}.pcap",
                capture_sequence=sequence,
                source="training_pcap",
            ),
            EvidenceRef(
                audit_event_reference=f"audit://tap-events.jsonl#0",
                source="audit_tap",
            ),
        ],
        "pfs-weak": [
            EvidenceRef(
                pcap_path=f"results/datasets/{DATASET_RUN_ID}/captures/{sequence}/{experiment_id}.pcap",
                capture_sequence=sequence,
                source="training_pcap",
            ),
            EvidenceRef(source="swanctl"),
        ],
        "transport": [
            EvidenceRef(
                audit_event_reference=f"audit://tap-events.jsonl#2048",
                source="audit_tap",
            ),
        ],
        "worst-ml": [
            EvidenceRef(
                pcap_path=f"results/datasets/{DATASET_RUN_ID}/captures/{sequence}/{experiment_id}.pcap",
                capture_sequence=sequence,
                source="training_pcap",
            ),
            EvidenceRef(source="live_xdp"),
        ],
    }
    return refs.get(slot, [])


def _ml_for(slot: str, expected) -> Optional[MLResult]:
    """Phase-5 model-output stand-in for ML scenarios (documented demo input)."""
    if slot in ("ml-anomaly", "worst-ml"):
        return MLResult(
            model_version="traffic-rf-v1-demo",
            traffic_class=expected.traffic.profile,
            classification_confidence=0.91,
            anomaly=True,
            anomaly_score=0.9,
        )
    if slot in ("strong-clean", "transport", "pfs-weak"):
        return MLResult(
            model_version="traffic-rf-v1-demo",
            traffic_class=expected.traffic.profile,
            classification_confidence=0.91,
            anomaly=False,
            anomaly_score=0.02,
        )
    return None


def _scenario_label(slot: str, sequence: int, posture: Optional[str]) -> str:
    labels = {
        "strong-clean": f"STRONG configuration, no findings (sequence {sequence}, {posture or 'STRONG'})",
        "pfs-weak": f"WEAK configuration, PFS disabled (sequence {sequence})",
        "transport": f"Confirmed mode mismatch (sequence {sequence})",
        "unknown": f"UNKNOWN observations, no authoritative evidence (sequence {sequence})",
        "ml-anomaly": f"ML anomaly evidence (sequence {sequence})",
        "worst-ml": f"Combined WORST + mismatch + ML anomaly (sequence {sequence})",
    }
    return labels.get(slot, f"clean posture band {sequence}")


def _observed_values_from(expected) -> Dict[str, Any]:
    """Authoritative evidence channel matching the expected state (Phase 4)."""
    esp_integrity = expected.esp.integrity
    return {
        "mode": expected.mode,
        "address_family": expected.address_family,
        "ike.version": expected.ike.version,
        "ike.encryption": expected.ike.encryption,
        "ike.integrity": expected.ike.integrity,
        "ike.dh_group": expected.ike.dh_group,
        "esp.encryption": expected.esp.encryption,
        "esp.integrity": esp_integrity,
        "esp.dh_group": expected.esp.dh_group,
        "esp.pfs": expected.esp.pfs,
        "traffic.profile": expected.traffic.profile,
        "traffic.duration": expected.traffic.duration,
        "traffic.port": expected.traffic.port,
        "capture_filter": expected.capture_filter,
    }


class AssessmentStore:
    """Deterministic in-memory index + bundles (built once, read-only)."""

    def __init__(self, plan_path: str = PLAN_PATH) -> None:
        self.plan_path = os.path.abspath(plan_path)
        self.bundles: Dict[str, Dict[str, Any]] = {}
        self.headers: List[Dict[str, Any]] = []
        self.overview: Dict[str, Any] = {}
        self.store: Dict[str, Any] = {}
        self._build()

    # -- lifecycle ----------------------------------------------------------

    def _run_pipeline(self, sequence: int, slot: str, *, mode_override=None,
                      ml_result=None, evidence_refs=(),
                      observed_values_supplied=True):
        """Run the real Phase 3 -> 4 -> 5/6 -> 7 pipeline for one scenario."""
        adapter = ExpectedStateAdapter(materialized_at=MATERIALIZED_AT)
        materialized = adapter.from_plan(self.plan_path, sequence=sequence)
        expected = materialized.expected
        identity = materialized.identity

        observed = demo_observed(sequence)
        values = None
        if observed_values_supplied:
            values = _observed_values_from(expected)
            if mode_override is not None:
                values = dict(values)
                values["mode"] = mode_override

        engine = ComparisonEngine(ComparisonEngineOptions())
        correlation = engine.compare(
            materialized,
            observed,
            observed_identity=identity,
            observed_values=values,
            live_features=complete_window(),
            ml_result=ml_result,
            evidence_refs=evidence_refs,
        )

        assessment = RiskEngine(RiskPolicy.default()).assess(
            expected=materialized,
            observed=observed,
            correlation=correlation,
            ml_result=ml_result,
            evidence_refs=evidence_refs,
        )

        xai = ExplainabilityEngine().explain(
            assessment,
            correlation=correlation,
            ml_result=ml_result,
            evidence_refs=evidence_refs,
        )
        return expected, observed, correlation, assessment, xai

    def _add(self, sequence: int, slot: str, *, mode_override=None,
             ml_result=None, evidence_refs=(), observed_values_supplied=True,
             scenario_label=None):
        expected, observed, correlation, assessment, xai = self._run_pipeline(
            sequence, slot, mode_override=mode_override, ml_result=ml_result,
            evidence_refs=evidence_refs,
            observed_values_supplied=observed_values_supplied,
        )
        assessment_id = f"{DATASET_RUN_ID}:{sequence}:{slot}"
        evidence_view = [evidence_to_view(ev) for ev in evidence_refs]
        bundle = assessment_bundle(
            assessment_id,
            identity=assessment.identity,
            expected=expected,
            observed=observed,
            correlation=correlation,
            ml=ml_result,
            assessment=assessment,
            xai=xai,
            slot=slot,
            scenario=scenario_label or _scenario_label(slot, sequence, expected.security_posture),
            evidence=evidence_view,
        )
        self.bundles[assessment_id] = bundle
        self.headers.append(header_view(bundle))
        return bundle

    def _build(self) -> None:
        # clean posture bands (real plan, authoritative evidence -> trend data)
        for sequence in range(1, 7):
            self._add(
                sequence,
                f"band-{sequence}",
                scenario_label=f"Clean posture band {sequence}",
                evidence_refs=_evidence_for("strong-clean" if sequence == 1 else "", sequence, f"exp-band-{sequence}"),
            )

        plan = self._load_plan_samples()
        expected_by_seq = {
            sample["sequence"]: self._materialize(sample)
            for sample in plan
        }

        for slot in SCENARIO_SLOTS:
            sequence, overrides, supplied = self._scenario(plan, expected_by_seq, slot)
            self._add(
                sequence, slot,
                mode_override=overrides.get("mode"),
                ml_result=overrides.get("ml"),
                evidence_refs=overrides.get("evidence", []),
                observed_values_supplied=supplied,
            )

        self._build_overview()

    # -- helpers ------------------------------------------------------------

    def _load_plan_samples(self) -> List[Dict[str, Any]]:
        with open(self.plan_path, "r", encoding="utf-8") as handle:
            return json.load(handle)["samples"]

    def _materialize(self, sample: Dict[str, Any]):
        adapter = ExpectedStateAdapter(materialized_at=MATERIALIZED_AT)
        sequence = sample["sequence"]
        return adapter.from_plan(self.plan_path, sequence=sequence).expected

    def _scenario(self, plan, expected_by_seq, slot):
        """Scenario definition -> (sequence, run overrides, observed_values flag)."""
        if slot == "strong-clean":
            return 1, {"evidence": _evidence_for(slot, 1, "exp-strong")}, True
        if slot == "pfs-weak":
            return 4, {"evidence": _evidence_for(slot, 4, "exp-pfs-weak")}, True
        if slot == "transport":
            return 1, {"mode": "transport", "evidence": _evidence_for(slot, 1, "exp-transport")}, True
        if slot == "unknown":
            return 2, {}, False
        if slot == "ml-anomaly":
            return 3, {"ml": _ml_for(slot, expected_by_seq[3])}, True
        if slot == "worst-ml":
            return 5, {
                "mode": "transport",
                "ml": _ml_for(slot, expected_by_seq[5]),
                "evidence": _evidence_for(slot, 5, "exp-worst-ml"),
            }, True
        raise ValueError(f"unknown scenario slot {slot!r}")

    def _build_overview(self) -> None:
        severities: Dict[str, int] = {}
        categories: Dict[str, int] = {}
        total_findings = 0
        unknown_observations = 0
        ml_anomalies = 0
        highest = None
        for header in self.headers:
            severities[header["severity"]] = severities.get(header["severity"], 0) + 1
            total_findings += header["finding_count"]
            bundle = self.bundles[header["assessment_id"]]
            for outcome in bundle["correlation"]["rows"]:
                if outcome["status"] == "UNKNOWN":
                    unknown_observations += 1
            if header["ml_present"] and header["ml_anomaly"] is True:
                ml_anomalies += 1
            if highest is None or header["risk_score"] > highest["risk_score"]:
                highest = header
        for header in self.headers:
            bundle = self.bundles[header["assessment_id"]]
            for finding in bundle["risk"]["findings"]:
                categories[finding["category"]] = (
                    categories.get(finding["category"], 0) + 1
                )
        severity_order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        self.overview = {
            "store_version": STORE_VERSION,
            "total_assessments": len(self.headers),
            "severity_counts": {s: severities.get(s, 0) for s in severity_order},
            "category_counts": dict(sorted(categories.items())),
            "findings_total": total_findings,
            "unknown_observations": unknown_observations,
            "ml_anomalies": ml_anomalies,
            "risk_policy_version": self.bundles[self.headers[0]["assessment_id"]][
                "risk"]["risk_policy_version"
            ],
            "xai_available": True,
            "source": "real Phase-3 plan fixture + Phase-4/5/6/7 pipeline (deterministic)",
            "highest_risk": highest["risk_score"] if highest else None,
            "highest_severity": highest["severity"] if highest else None,
        }
        self.store = {
            "api_schema_version": "v1",
            "overview": dict(self.overview),
            "headers": [dict(h) for h in self.headers],
        }


def build_store(plan_path: str = PLAN_PATH) -> AssessmentStore:
    return AssessmentStore(plan_path=plan_path)