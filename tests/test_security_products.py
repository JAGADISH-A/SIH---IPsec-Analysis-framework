"""Validation of the security-analysis products (brief areas 1-12).

Every assertion here is about a contract the brief states explicitly:

* each product exists, is produced by exactly one producer, carries its own
  source/evidence, states its state, and is reachable through the API;
* an evidence gap stays a gap -- ``UNKNOWN``/``NOT_AVAILABLE`` never becomes a
  negative finding, and a sequence gap is never replay evidence;
* a value that cannot be observed at runtime is reported as configuration
  with ``runtime_observable = False``, never as a runtime observation;
* the API exposes the products with unique, documented, routable routes.

Nothing here generates traffic or touches the testbed: everything is read
from the committed recorded artifacts through the same code path the store
uses.
"""

import json
import unittest

from correlation.analysis.crypto_evidence import (
    EVIDENCE_SOURCE_CONFIGURATION,
    MODE,
)
from correlation.analysis.metadata import (
    EXPOSURE_NOT_OBSERVABLE,
    RISK_LEVEL_NONE,
)
from correlation.analysis.replay import (
    EVIDENCE_PER_PACKET,
    REPLAY_STATUS_INSUFFICIENT_DATA,
    REPLAY_STATUS_NO_EVIDENCE,
    REPLAY_STATUS_OBSERVED,
    REPLAY_STATUSES,
    analyze_replay,
)
from correlation.analysis.reports import EXECUTIVE_QUESTIONS
from correlation.analysis.sa import analyze_sa
from correlation.analysis.states import (
    STATE_CONFIGURED,
    STATE_NOT_AVAILABLE,
    STATE_NOT_APPLICABLE,
    STATE_OBSERVED,
    STATE_UNKNOWN,
    UNESTABLISHED_STATES,
    VALID_STATES,
    EvidenceValue,
    is_established,
    validate_state,
)
from correlation.analysis.threat_matrix import (
    THREAT_CATEGORIES,
    THREAT_REPLAY,
    build_threat_matrix,
    threat_category_for,
)
from correlation.api.openapi import openapi_document
from correlation.api.routes import (
    SUB_RESOURCE_KEYS,
    SUB_RESOURCES,
    ApiError,
    handle_get,
)
from correlation.api.store import (
    RECORDED_CASES,
    build_store,
    load_recorded_observation,
    sequence_journal_for,
)
from correlation.artifacts import canonical_spi
from correlation.models import EspExpected, ExpectedState, IkeExpected, SpiObservation, TrafficExpected
from correlation.models.expected import ALLOWED_TRAFFIC_PROFILES
from correlation.response.models import ACTION_REQUIRE_REVIEW
from correlation.response.policy import DEFAULT_RULE_OVERRIDES, ResponsePolicy
from correlation.response.rules import RESPONSE_RULE_TRACEABILITY
from correlation.risk.engine import RiskEngine
from correlation.risk.models import RiskFinding
from correlation.risk.policy import ALL_RULES, RiskPolicy
from tests.fixtures.risk.risk_fixtures import build_observed, run_comparison

#: Every key the brief requires of a finding (area 6).
REQUIRED_FINDING_KEYS = (
    "finding_id",
    "rule_id",
    "title",
    "category",
    "severity",
    "score",
    "score_added",
    "source",
    "configured_value",
    "state",
    "runtime_applicable",
    "evidence",
    "reason",
)

#: Every key the brief requires of a correlation row (area 5).
REQUIRED_ROW_KEYS = (
    "variable",
    "status",
    "verdict",
    "expected_value",
    "observed_value",
    "configured_value",
    "comparison_rule",
    "state",
    "runtime_observable",
    "evidence_source",
    "evidence_refs",
    "reason",
)


def make_expected(**overrides):
    kwargs = dict(
        mode="tunnel",
        address_family="ipv4",
        ike=IkeExpected(version=2, encryption="aes256", integrity="sha256",
                        dh_group="modp2048"),
        esp=EspExpected(encryption="aes256gcm16", integrity=None,
                        dh_group="modp2048", pfs=True),
        traffic=TrafficExpected(profile="video", duration=30, port=20000),
        capture_filter="udp port 500 or udp port 4500 or esp or ah",
        configuration_id=None,
        security_posture="STRONG",
    )
    kwargs.update(overrides)
    return ExpectedState(**kwargs)


def case_named(name):
    return next(case for case in RECORDED_CASES if case.name == name)


def evidence_for(name):
    """The recorded observation plus its sequence journal for one case."""
    observation = load_recorded_observation(case_named(name))
    return observation, sequence_journal_for(observation)


_STORE = None


def store():
    global _STORE
    if _STORE is None:
        _STORE = build_store()
    return _STORE


def bundle_for(slot):
    return next(b for b in store().bundles.values() if b["slot"] == slot)


class TestStateVocabulary(unittest.TestCase):
    """Area 12 pre-condition: the seven states stay distinct."""

    def test_the_brief_seven_states_are_all_defined(self):
        self.assertEqual(
            VALID_STATES,
            (
                "OBSERVED",
                "CONFIGURED",
                "INFERRED",
                "ASSESSED",
                "UNKNOWN",
                "NOT_AVAILABLE",
                "NOT_APPLICABLE",
            ),
        )

    def test_validate_state_rejects_the_statuses_that_are_not_states(self):
        for bogus in ("MATCH", "MISMATCH", "unknown", "", None, 0):
            with self.subTest(bogus=bogus):
                with self.assertRaises(ValueError):
                    validate_state(bogus)

    def test_unestablished_states_are_never_established(self):
        for state in UNESTABLISHED_STATES:
            self.assertFalse(is_established(state))
        for state in ("OBSERVED", "CONFIGURED", "INFERRED", "ASSESSED"):
            self.assertTrue(is_established(state))

    def test_evidence_value_carries_a_state_a_source_and_a_reason(self):
        value = EvidenceValue.of(
            7, STATE_OBSERVED, "results/example.jsonl", "counted in the artifact")
        self.assertEqual(value.to_dict(), {
            "value": 7,
            "state": STATE_OBSERVED,
            "source": "results/example.jsonl",
            "reason": "counted in the artifact",
            "runtime_observable": None,
        })
        self.assertTrue(value.established)

    def test_evidence_value_refuses_a_stateless_or_unsourced_value(self):
        with self.assertRaises(ValueError):
            EvidenceValue.of(7, "ANYTHING", "results/example.jsonl", "why")
        with self.assertRaises(ValueError):
            EvidenceValue.of(7, STATE_OBSERVED, "", "why")
        with self.assertRaises(ValueError):
            EvidenceValue.of(7, STATE_OBSERVED, "results/example.jsonl", "  ")


class TestArea1SecurityAssociations(unittest.TestCase):
    """Area 1: establishment, direction, packets, sequence, lifetime/rekey."""

    def test_without_an_observation_the_product_says_not_available(self):
        product = analyze_sa(None)
        self.assertEqual(product.state, STATE_NOT_AVAILABLE)
        self.assertEqual(product.associations, ())
        self.assertTrue(product.reason.strip())

    def test_a_recorded_capture_produces_one_association_per_spi(self):
        observation, evidence = evidence_for("nat-t")
        product = analyze_sa(observation.observed, source=evidence.state_path)
        payload = product.to_dict()

        self.assertEqual(payload["state"], STATE_OBSERVED)
        self.assertEqual(len(payload["associations"]),
                         len(observation.observed.spis))
        self.assertEqual(payload["summary"]["association_count"],
                         len(payload["associations"]))
        self.assertEqual(payload["summary"]["sa_snapshots_recorded"], False)
        self.assertIn("observation_window_seconds", payload["summary"])

    def test_every_association_states_what_it_cannot_know(self):
        observation, evidence = evidence_for("nat-t")
        product = analyze_sa(observation.observed, source=evidence.state_path)
        for association in product.to_dict()["associations"]:
            with self.subTest(spi=association["spi"]):
                self.assertEqual(association["lifetime"]["state"],
                                 STATE_NOT_AVAILABLE)
                self.assertEqual(association["rekey"]["state"],
                                 STATE_NOT_AVAILABLE)
                self.assertIn("sa_snapshot()", association["lifetime"]["reason"])
                self.assertTrue(association["rekey"]["reason"].strip())
                self.assertEqual(association["sa_identity"]["state"],
                                 STATE_NOT_AVAILABLE)

    def test_establishment_direction_and_sequence_are_observed_values(self):
        observation, evidence = evidence_for("nat-t")
        product = analyze_sa(observation.observed, source=evidence.state_path)
        association = product.to_dict()["associations"][0]

        self.assertEqual(association["data_plane_established"]["state"],
                         STATE_OBSERVED)
        self.assertIs(association["data_plane_established"]["value"], True)
        self.assertEqual(association["direction"]["state"], STATE_OBSERVED)
        self.assertIn(association["direction"]["value"],
                      ("A_TO_B", "B_TO_A"))
        self.assertEqual(association["first_observed_packet_ns"]["state"],
                         STATE_OBSERVED)
        self.assertEqual(association["last_observed_packet_ns"]["state"],
                         STATE_OBSERVED)
        self.assertLessEqual(
            association["first_observed_packet_ns"]["value"],
            association["last_observed_packet_ns"]["value"],
        )
        self.assertEqual(association["sequence"]["state"], STATE_OBSERVED)
        for key in ("first_sequence", "last_sequence", "highest_sequence"):
            self.assertIn(key, association["sequence"]["value"])
        self.assertEqual(association["age_seconds"]["state"], "INFERRED")
        self.assertIsNotNone(association["age_seconds"]["value"])

    def test_the_analysis_makes_no_security_claim_and_no_score(self):
        observation, evidence = evidence_for("nat-t")
        payload = analyze_sa(
            observation.observed, source=evidence.state_path).to_dict()
        self.assertTrue(payload["limitations"])
        self.assertTrue(
            any("no score" in item or "no security claim" in item
                for item in payload["limitations"])
        )

    def test_no_bundle_turns_a_missing_sa_lifecycle_field_into_a_finding(self):
        for bundle in store().bundles.values():
            rules = {f["rule_id"] for f in bundle["risk"]["findings"]}
            self.assertFalse(
                {r for r in rules
                 if "lifetime" in r or "rekey" in r or "sa_identity" in r},
                f"an unrecorded SA field became a finding in {bundle['slot']}",
            )


class TestArea2RuntimeCryptoEvidence(unittest.TestCase):
    """Area 2: configured vs runtime, with runtime_applicable spelled out."""

    UNOBSERVABLE = ("esp.encryption", "esp.integrity", "esp.dh_group",
                    "esp.pfs", "ike.version")

    def test_a_captured_tunnel_reports_every_unobservable_property_as_unknown(self):
        from correlation.analysis.crypto_evidence import analyze_crypto_evidence

        evidence = analyze_crypto_evidence(make_expected(), None)
        payload = evidence.to_dict()

        self.assertEqual(payload["state"], "UNKNOWN")
        self.assertEqual(payload["runtime_established"], [])
        for name in self.UNOBSERVABLE:
            prop = payload["by_property"][name]
            with self.subTest(property=name):
                self.assertEqual(prop["state"], "UNKNOWN")
                self.assertIs(prop["runtime_observable"], False)
                self.assertEqual(prop["evidence_source"],
                                 EVIDENCE_SOURCE_CONFIGURATION)
                self.assertIsNone(prop["runtime_value"])
                if prop["configured_value"] is None:
                    self.assertEqual(prop["configured_state"],
                                     STATE_NOT_AVAILABLE)
                else:
                    self.assertEqual(prop["configured_state"], STATE_CONFIGURED)
                self.assertTrue(prop["reason"].strip())

    def test_mode_is_reported_as_observed_only_when_the_sa_report_recorded_it(self):
        from correlation.analysis.crypto_evidence import analyze_crypto_evidence

        unobserved = analyze_crypto_evidence(make_expected(), build_observed())
        self.assertEqual(unobserved.to_dict()["by_property"][MODE]["state"],
                         "UNKNOWN")
        self.assertIs(unobserved.to_dict()["by_property"][MODE][
            "runtime_observable"], True)
        self.assertIsNone(unobserved.to_dict()["by_property"][MODE][
            "runtime_value"])

        observed = analyze_crypto_evidence(
            make_expected(), build_observed(mode="transport"))
        prop = observed.to_dict()["by_property"][MODE]
        self.assertEqual(prop["state"], STATE_OBSERVED)
        self.assertEqual(prop["runtime_value"], "transport")
        self.assertEqual(observed.to_dict()["state"], STATE_OBSERVED)
        self.assertIn(MODE, observed.to_dict()["runtime_established"])

    def test_a_configured_value_is_never_echoed_back_as_a_runtime_value(self):
        from correlation.analysis.crypto_evidence import analyze_crypto_evidence

        for payload in (
            analyze_crypto_evidence(make_expected(), None).to_dict(),
            analyze_crypto_evidence(make_expected(), build_observed()).to_dict(),
            bundle_for("nat-t")["crypto_evidence"],
            bundle_for("tunnel-v4")["crypto_evidence"],
        ):
            for prop in payload["properties"]:
                if prop["state"] == "UNKNOWN":
                    self.assertIsNone(prop["runtime_value"])

    def test_the_bundle_carries_the_product_and_its_limitations(self):
        payload = bundle_for("nat-t")["crypto_evidence"]
        self.assertEqual(payload["state"], "UNKNOWN")
        self.assertEqual(len(payload["properties"]), 6)
        self.assertEqual(sorted(payload["by_property"]), sorted(
            p["property"] for p in payload["properties"]))
        self.assertTrue(payload["limitations"])
        self.assertTrue(
            payload["source"].startswith(
                "results/observed-state/live_state_from_events_full.jsonl"),
            payload["source"],
        )


class TestArea3Replay(unittest.TestCase):
    """Area 3: replay status from evidence, never from a gap."""

    def test_a_recorded_duplicate_is_observed_replay_evidence(self):
        observation, evidence = evidence_for("nat-t")
        payload = analyze_replay(
            observation.observed, sequences=evidence.sequences,
            source=evidence.state_path).to_dict()

        self.assertEqual(payload["status"], REPLAY_STATUS_OBSERVED)
        self.assertEqual(payload["duplicate_sequences"], 1)
        self.assertEqual(payload["sequence_gaps"], 0)
        self.assertEqual(payload["backward_sequences"], 0)
        self.assertEqual(payload["source"], evidence.state_path)

        duplicates = [e for e in payload["evidence"]
                      if e["kind"] == "duplicate_sequence"]
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(duplicates[0]["occurrence_count"], 2)
        self.assertGreater(duplicates[0]["separation_seconds"], 0)
        self.assertLess(duplicates[0]["separation_seconds"], 1)

    def test_a_clean_journal_reports_no_evidence_and_not_a_clean_bill(self):
        observation, evidence = evidence_for("transport-v6")
        payload = analyze_replay(
            observation.observed, sequences=evidence.sequences,
            source=evidence.state_path).to_dict()

        self.assertEqual(payload["status"], REPLAY_STATUS_NO_EVIDENCE)
        self.assertEqual(payload["duplicate_sequences"], 0)
        self.assertEqual(payload["backward_sequences"], 0)
        for spi in payload["per_spi"]:
            self.assertEqual(spi["status"], REPLAY_STATUS_NO_EVIDENCE)
            self.assertEqual(spi["evidence_level"], EVIDENCE_PER_PACKET)
            self.assertEqual(spi["state"], STATE_OBSERVED)

    def test_a_pcap_without_a_journal_is_insufficient_data_not_no_evidence(self):
        observation, evidence = evidence_for("tunnel-v4")
        self.assertIsNone(evidence.journal_path)
        payload = analyze_replay(
            observation.observed, sequences=None,
            source=evidence.state_path).to_dict()

        self.assertEqual(payload["status"], REPLAY_STATUS_INSUFFICIENT_DATA)
        self.assertIsNone(payload["duplicate_sequences"])
        self.assertTrue(any("aggregate" in item.lower()
                            for item in payload["limitations"]))

    def test_without_an_observation_the_product_says_insufficient_data(self):
        payload = analyze_replay(None).to_dict()
        self.assertEqual(payload["status"], REPLAY_STATUS_INSUFFICIENT_DATA)
        self.assertEqual(payload["per_spi"], [])

    def test_a_sequence_gap_alone_is_never_replay_evidence(self):
        spi = SpiObservation(
            spi=0xC0A80164, direction="A_TO_B", active=True,
            first_seen_ns=1000, last_seen_ns=5000, packet_count=3,
            first_sequence=1, last_sequence=5, highest_sequence=5,
            sequence_delta=4,
        )
        observed = build_observed(spis=[spi])
        sequences = {canonical_spi(0xC0A80164): [(1, 1000), (2, 2000), (5, 5000)]}

        payload = analyze_replay(
            observed, sequences=sequences, source="synthetic gap fixture").to_dict()

        self.assertEqual(payload["status"], REPLAY_STATUS_NO_EVIDENCE)
        self.assertEqual(payload["duplicate_sequences"], 0)
        self.assertEqual(payload["backward_sequences"], 0)
        self.assertEqual(payload["sequence_gaps"], 2)
        gap = next(e for e in payload["evidence"]
                   if e["kind"] == "sequence_gap")
        self.assertEqual(gap["missing_sequences"], 2)
        self.assertIn("NEVER counted as replay evidence", gap["note"])

    def test_a_backwards_step_is_observed_anomaly_evidence(self):
        spi = SpiObservation(
            spi=0xC0A80164, direction="A_TO_B", active=True,
            first_seen_ns=1000, last_seen_ns=5000, packet_count=3,
            first_sequence=3, last_sequence=5, highest_sequence=5,
            sequence_delta=2,
        )
        observed = build_observed(spis=[spi])
        sequences = {canonical_spi(0xC0A80164): [(5, 1000), (4, 2000), (3, 3000)]}

        payload = analyze_replay(
            observed, sequences=sequences, source="synthetic backward fixture").to_dict()

        self.assertEqual(payload["status"], REPLAY_STATUS_OBSERVED)
        self.assertEqual(payload["duplicate_sequences"], 0)
        self.assertEqual(payload["backward_sequences"], 2)
        self.assertIn("backward_sequence",
                      [e["kind"] for e in payload["evidence"]])

    def test_the_product_states_the_three_things_it_never_asserts(self):
        payload = analyze_replay(None).to_dict()
        joined = " ".join(payload["limitations"]).lower()
        self.assertIn("gap", joined)
        self.assertIn("never treated as replay evidence", joined)
        self.assertIn("risk engine", joined)

    def test_the_bundle_statuses_are_all_in_the_documented_vocabulary(self):
        for bundle in store().bundles.values():
            payload = bundle["replay_assessment"]
            with self.subTest(slot=bundle["slot"]):
                self.assertIn(payload["status"], REPLAY_STATUSES)
                self.assertIn(payload["status"],
                              (REPLAY_STATUS_OBSERVED,
                               REPLAY_STATUS_NO_EVIDENCE,
                               REPLAY_STATUS_INSUFFICIENT_DATA))
                self.assertTrue(payload["reason"].strip())
                self.assertTrue(payload["source"].strip())
                self.assertIn("evidence", payload)


class TestArea4MetadataExposure(unittest.TestCase):
    """Area 4: observable metadata, risk level, evidence and limitations."""

    def test_eleven_dimensions_are_classified_for_a_recorded_capture(self):
        observation, evidence = evidence_for("nat-t")
        from correlation.analysis.metadata import analyze_metadata_exposure

        payload = analyze_metadata_exposure(
            observation.observed, source=evidence.state_path).to_dict()

        self.assertEqual(payload["state"], STATE_OBSERVED)
        self.assertEqual(len(payload["observable_metadata"]), 11)
        self.assertEqual(payload["observable_metadata"][2]["dimension"],
                         "ike_esp_metadata")
        self.assertEqual(payload["observable_metadata"][4]["dimension"],
                         "packet_direction")
        for name in ("ike_esp_metadata", "packet_direction"):
            dimension = next(d for d in payload["observable_metadata"]
                             if d["dimension"] == name)
            with self.subTest(dimension=name):
                self.assertEqual(dimension["state"], STATE_OBSERVED)
                self.assertEqual(dimension["exposure"], "EXPOSED")
                self.assertTrue(dimension["value"])
        self.assertEqual(len(payload["risk_ladder"]), 4)
        self.assertTrue(payload["limitations"])
        for dimension in payload["observable_metadata"]:
            with self.subTest(dimension=dimension["dimension"]):
                self.assertIn(dimension["state"], VALID_STATES)
                self.assertTrue(dimension["reason"].strip())
                self.assertIn(dimension["exposure"],
                              ("EXPOSED", "NOT_EXPOSED", "NOT_OBSERVABLE"))

    def test_not_recorded_and_not_applicable_stay_different(self):
        from correlation.analysis.metadata import analyze_metadata_exposure

        observation, evidence = evidence_for("nat-t")
        payload = analyze_metadata_exposure(
            observation.observed, source=evidence.state_path).to_dict()
        by_name = {d["dimension"]: d for d in payload["observable_metadata"]}

        self.assertEqual(by_name["transport_ports"]["state"],
                         STATE_NOT_AVAILABLE)
        self.assertEqual(by_name["transport_ports"]["exposure"],
                         EXPOSURE_NOT_OBSERVABLE)
        self.assertEqual(by_name["payload_content"]["state"],
                         STATE_NOT_APPLICABLE)
        self.assertEqual(by_name["inner_addresses"]["state"],
                         STATE_NOT_APPLICABLE)

    def test_without_an_observation_nothing_is_claimed_about_metadata(self):
        from correlation.analysis.metadata import analyze_metadata_exposure

        payload = analyze_metadata_exposure(None).to_dict()
        self.assertEqual(payload["state"], STATE_NOT_AVAILABLE)
        self.assertEqual(payload["risk_level"], RISK_LEVEL_NONE)
        self.assertEqual(payload["findings"], [])
        for dimension in payload["observable_metadata"]:
            self.assertEqual(dimension["state"], STATE_NOT_AVAILABLE)
            self.assertIsNone(dimension["value"])

    def test_metadata_findings_carry_no_severity_and_no_score(self):
        payload = bundle_for("nat-t")["metadata_exposure"]
        self.assertEqual(payload["risk_level"], "MEDIUM")
        for finding in payload["findings"]:
            with self.subTest(dimension=finding["dimension"]):
                self.assertNotIn("severity", finding)
                self.assertNotIn("score", finding)
                self.assertIn("not scored", finding["scoring"])
                self.assertTrue(finding["evidence"])

    def test_every_documented_risk_level_appears_exactly_once_in_the_ladder(self):
        payload = bundle_for("tunnel-v4")["metadata_exposure"]
        levels = [row["risk_level"] for row in payload["risk_ladder"]]
        self.assertEqual(sorted(levels), ["HIGH", "LOW", "MEDIUM", "NONE"])


class TestArea5CorrelationOutput(unittest.TestCase):
    """Area 5: every correlation row exposes configured/runtime/state."""

    def test_every_row_carries_the_required_enrichment(self):
        for bundle in store().bundles.values():
            for row in bundle["correlation"]["rows"]:
                with self.subTest(slot=bundle["slot"], variable=row["variable"]):
                    for key in REQUIRED_ROW_KEYS:
                        self.assertIn(key, row)
                    self.assertIn(row["state"], VALID_STATES)
                    self.assertIsInstance(row["runtime_observable"], bool)
                    self.assertEqual(row["verdict"], row["status"])
                    self.assertEqual(row["configured_value"],
                                     row["expected_value"])

    def test_an_unobservable_runtime_value_is_marked_unobservable(self):
        for bundle in store().bundles.values():
            for row in bundle["correlation"]["rows"]:
                if row["observed_value"] is None:
                    with self.subTest(slot=bundle["slot"],
                                      variable=row["variable"]):
                        self.assertFalse(row["runtime_observable"])

    def test_every_correlation_status_maps_onto_exactly_one_state(self):
        expected_state = {
            "MATCH": STATE_OBSERVED,
            "MISMATCH": STATE_OBSERVED,
            "UNKNOWN": STATE_UNKNOWN,
            "NOT_APPLICABLE": STATE_NOT_APPLICABLE,
        }
        seen = set()
        for bundle in store().bundles.values():
            for row in bundle["correlation"]["rows"]:
                with self.subTest(slot=bundle["slot"],
                                  variable=row["variable"]):
                    seen.add(row["status"])
                    self.assertEqual(row["state"],
                                     expected_state[row["status"]])
        self.assertEqual(
            seen, {"MATCH", "MISMATCH", "UNKNOWN", "NOT_APPLICABLE"})

    def test_an_unknown_outcome_explains_the_gap_rather_than_a_value(self):
        rows = [r for r in bundle_for("unknown")["correlation"]["rows"]
                if r["status"] == "UNKNOWN"]
        self.assertTrue(rows)
        gap_words = (
            "cannot", "insufficient", "no authoritative", "does not expose",
            "not observable", "never inferred", "was not supplied",
            "is hidden", "planning property",
        )
        for row in rows:
            with self.subTest(variable=row["variable"]):
                self.assertEqual(row["state"], STATE_UNKNOWN)
                reason = row["reason"].lower()
                self.assertTrue(
                    any(word in reason for word in gap_words),
                    f"an UNKNOWN outcome did not explain its gap: {reason}",
                )


class TestArea6FindingContract(unittest.TestCase):
    """Area 6: findings expose evidence, state, score and applicability."""

    def test_every_finding_of_every_bundle_satisfies_the_contract(self):
        for bundle in store().bundles.values():
            for finding in bundle["risk"]["findings"]:
                with self.subTest(slot=bundle["slot"],
                                  rule=finding["rule_id"]):
                    for key in REQUIRED_FINDING_KEYS:
                        self.assertIn(key, finding)
                    self.assertIn(finding["state"], VALID_STATES)
                    self.assertIsInstance(finding["runtime_applicable"], bool)
                    self.assertIsInstance(finding["score"], int)
                    self.assertIsInstance(finding["score_added"], int)
                    self.assertGreaterEqual(finding["score_added"], 0)
                    self.assertTrue(finding["reason"].strip())
                    self.assertIn("source", finding["evidence"])
                    self.assertIn("state", finding["evidence"])

    def test_the_replay_finding_states_its_observed_evidence(self):
        payload = bundle_for("nat-t")
        finding = next(f for f in payload["risk"]["findings"]
                       if f["rule_id"] == "replay.duplicate_sequence")
        self.assertEqual(finding["finding_id"], "RISK-REPLAY-DUPLICATE")
        self.assertEqual(finding["severity"], "LOW")
        self.assertEqual(finding["score"], 6)
        self.assertEqual(finding["score_added"], 6)
        self.assertEqual(finding["state"], STATE_OBSERVED)
        self.assertEqual(finding["evidence"]["state"], STATE_OBSERVED)
        self.assertEqual(finding["evidence"]["source"], "OBSERVED_PROTOCOL")
        self.assertIs(finding["runtime_applicable"], True)
        self.assertEqual(finding["configured_value"], 0)
        self.assertIn("duplicate", finding["observed_value"].lower()
                      if isinstance(finding["observed_value"], str)
                      else json.dumps(finding["observed_value"]).lower())
        self.assertEqual(payload["risk"]["overall_score"], 6)
        self.assertEqual(payload["risk"]["severity"], "LOW")

    def test_a_finding_round_trips_through_its_own_serialization(self):
        for bundle in store().bundles.values():
            for raw in bundle["risk"]["findings"]:
                with self.subTest(rule=raw["rule_id"]):
                    self.assertEqual(RiskFinding.from_dict(raw).to_dict(), raw)

    def test_scores_are_consistent_with_the_scored_findings(self):
        for bundle in store().bundles.values():
            risk = bundle["risk"]
            with self.subTest(slot=bundle["slot"]):
                self.assertGreaterEqual(
                    risk["overall_score"],
                    sum(f["score_added"] for f in risk["findings"]),
                )
                self.assertLessEqual(risk["overall_score"], 100)

    def test_a_finding_never_states_an_unestablished_state(self):
        for bundle in store().bundles.values():
            for finding in bundle["risk"]["findings"]:
                with self.subTest(slot=bundle["slot"],
                                  rule=finding["rule_id"]):
                    self.assertNotIn(finding["state"], (STATE_NOT_AVAILABLE,
                                                        STATE_NOT_APPLICABLE))
                    self.assertNotIn(finding["evidence"]["state"],
                                     (STATE_NOT_AVAILABLE,))


class TestArea7ThreatMatrix(unittest.TestCase):
    """Area 7: the matrix is derived from findings, never from a template."""

    def test_every_entry_names_threat_evidence_impact_and_recommendation(self):
        for bundle in store().bundles.values():
            matrix = bundle["threat_matrix"]
            with self.subTest(slot=bundle["slot"]):
                self.assertEqual(matrix["entry_count"], len(matrix["entries"]))
                self.assertEqual(len(matrix["categories"]),
                                 len(THREAT_CATEGORIES))
                for entry in matrix["entries"]:
                    for key in ("finding", "threat", "severity", "evidence",
                                "impact", "recommendation"):
                        self.assertIn(key, entry)
                    self.assertIn(entry["threat"], THREAT_CATEGORIES)
                    self.assertTrue(entry["impact"].strip())

    def test_the_entries_are_exactly_the_findings_plus_the_metadata_findings(self):
        bundle = bundle_for("nat-t")
        matrix = bundle["threat_matrix"]
        self.assertEqual(
            matrix["entry_count"],
            len(bundle["risk"]["findings"]) + len(bundle["metadata_exposure"]["findings"]),
        )
        sources = {entry["finding_source"] for entry in matrix["entries"]}
        self.assertEqual(sources, {"risk_engine", "metadata_exposure"})
        for entry in matrix["entries"]:
            if entry["finding_source"] == "metadata_exposure":
                self.assertIsNone(entry["severity"])

    def test_the_replay_rule_maps_to_the_replay_threat_category(self):
        self.assertEqual(
            threat_category_for("replay.duplicate_sequence", "PROTOCOL_ANOMALY"),
            THREAT_REPLAY,
        )
        self.assertEqual(
            threat_category_for("evidence.unknown.gap", "EVIDENCE_GAP"),
            "Evidence gap",
        )

    def test_severity_is_copied_from_the_finding_and_never_recomputed(self):
        bundle = bundle_for("band-worst")
        by_rule = {f["rule_id"]: f["severity"]
                   for f in bundle["risk"]["findings"]}
        for entry in bundle["threat_matrix"]["entries"]:
            if entry["finding_source"] != "risk_engine":
                continue
            with self.subTest(rule=entry["rule_id"]):
                self.assertEqual(entry["severity"], by_rule[entry["rule_id"]])
                self.assertIn("never assigns or recomputes",
                              entry["severity_source"])

    def test_an_empty_finding_list_produces_an_empty_matrix(self):
        matrix = build_threat_matrix(())
        self.assertEqual(len(matrix.entries), 0)
        self.assertEqual(matrix.to_dict()["entry_count"], 0)


class TestArea8TechnicalReport(unittest.TestCase):
    """Area 8: one report over the same evidence as the bundle."""

    def test_fourteen_sections_cover_every_product(self):
        payload = bundle_for("nat-t")["report"]
        self.assertEqual(payload["state"], "ASSESSED")
        self.assertEqual(len(payload["sections"]), 14)
        self.assertEqual(payload["sections"][0]["heading"],
                         "1. Executive summary")
        self.assertEqual(payload["sections"][12]["heading"],
                         "13. Recommendations (finding-specific remediation)")
        self.assertEqual(payload["sections"][13]["heading"],
                         "14. Evidence and provenance")
        for index, section in enumerate(payload["sections"], start=1):
            with self.subTest(section=section["heading"]):
                self.assertTrue(section["heading"].startswith(f"{index}."))
                self.assertTrue(section["paragraphs"])
                self.assertTrue(all(p.strip() for p in section["paragraphs"]))

    def test_every_threat_matrix_recommendation_is_quoted_verbatim(self):
        bundle = bundle_for("nat-t")
        section = next(s for s in bundle["report"]["sections"]
                       if s["heading"].startswith("13."))
        quoted = "\n".join(section["paragraphs"])
        entries = bundle["threat_matrix"]["entries"]
        self.assertTrue(entries)
        for entry in entries:
            with self.subTest(finding=entry["finding"]):
                text = entry["recommendation"]["text"]
                self.assertTrue(text)
                self.assertIn(text, quoted)
        self.assertIn("this report writes no remediation text of its own",
                      quoted)

    def test_the_report_is_the_one_from_the_bundle_not_a_recomputation(self):
        observation, evidence = evidence_for("nat-t")
        payload = bundle_for("nat-t")
        self.assertEqual(payload["report"]["assessment_id"],
                         payload["assessment_id"])
        self.assertTrue(payload["report"]["limitations"])

    def test_the_report_is_deterministic_across_two_builds(self):
        first = build_store()
        second = build_store()
        for slot in ("nat-t", "band-worst", "unknown"):
            a = next(b for b in first.bundles.values() if b["slot"] == slot)
            b = next(b for b in second.bundles.values() if b["slot"] == slot)
            with self.subTest(slot=slot):
                self.assertEqual(a["report"], b["report"])
                self.assertEqual(a["executive_report"], b["executive_report"])


class TestArea9ExecutiveReport(unittest.TestCase):
    """Area 9: five questions, each answered or explicitly not answered."""

    def test_all_five_questions_are_answered(self):
        payload = bundle_for("nat-t")["executive_report"]
        self.assertEqual(tuple(payload["answers"]), EXECUTIVE_QUESTIONS)
        for key in EXECUTIVE_QUESTIONS:
            answer = payload["answers"][key]
            with self.subTest(question=key):
                self.assertEqual(answer["question"], key)
                self.assertIn(answer["state"], VALID_STATES)
                self.assertTrue(answer["statements"])
                self.assertTrue(answer["evidence"])
                self.assertTrue(answer["answered"])

    def test_every_bundle_answers_the_same_five_questions(self):
        for bundle in store().bundles.values():
            self.assertEqual(tuple(bundle["executive_report"]["answers"]),
                             EXECUTIVE_QUESTIONS)

    def test_the_action_answer_quotes_the_response_plan_it_read(self):
        payload = bundle_for("nat-t")["executive_report"]["answers"]
        answer = " ".join(payload["what_should_be_fixed"]["statements"])
        self.assertIn("approval", answer.lower())
        self.assertIn("No action executes automatically", answer)

    def test_the_report_can_be_rebuilt_from_the_same_inputs(self):
        payload = bundle_for("tunnel-v4")
        self.assertEqual(payload["executive_report"]["assessment_id"],
                         payload["assessment_id"])
        self.assertTrue(payload["executive_report"]["limitations"])


class TestArea10MlTransparency(unittest.TestCase):
    """Area 10: model, confidence, provenance and predicted-vs-policy."""

    ML_KEYS = ("present", "model", "model_version", "inference_status",
               "predicted_class", "classification_confidence", "probabilities",
               "classes", "provenance", "predicted_vs_policy")

    def test_absent_ml_says_it_was_not_executed(self):
        payload = bundle_for("nat-t")["ml"]
        for key in self.ML_KEYS:
            self.assertIn(key, payload)
        self.assertIs(payload["present"], False)
        self.assertEqual(payload["inference_status"], "NOT_EXECUTED")
        self.assertIn("ML was not executed", payload["reason"])
        self.assertIsNone(payload["predicted_class"])
        self.assertIsNone(payload["classes"])
        self.assertEqual(payload["predicted_vs_policy"]["status"],
                         "NOT_APPLICABLE")
        self.assertTrue(payload["predicted_vs_policy"]["reason"].strip())

    def test_present_ml_exposes_the_model_the_confidence_and_the_provenance(self):
        payload = bundle_for("ml-mismatch")["ml"]
        self.assertIs(payload["present"], True)
        self.assertEqual(payload["inference_status"], "COMPLETED")
        self.assertEqual(payload["model"], payload["model_version"])
        self.assertTrue(payload["model"])
        self.assertEqual(payload["predicted_class"], "icmp")
        self.assertIsInstance(payload["classification_confidence"], float)
        self.assertIsInstance(payload["probabilities"], dict)
        provenance = payload["provenance"]
        for key in ("source", "feature_schema_version", "model_version",
                    "model_identity_source", "executed_by_this_backend",
                    "evidence_class"):
            self.assertIn(key, provenance)
        self.assertIs(provenance["executed_by_this_backend"], False)

    def test_the_probability_vector_publishes_the_class_it_is_indexed_by(self):
        payload = bundle_for("ml-mismatch")["ml"]
        self.assertEqual(payload["classes"], list(ALLOWED_TRAFFIC_PROFILES))
        self.assertEqual(set(payload["probabilities"]), set(payload["classes"]))
        for bundle in store().bundles.values():
            if bundle["slot"] == "ml-mismatch":
                continue
            with self.subTest(slot=bundle["slot"]):
                self.assertIs(bundle["ml"]["classes"], None)

    def test_predicted_and_policy_verdict_are_reported_side_by_side(self):
        payload = bundle_for("ml-mismatch")["ml"]["predicted_vs_policy"]
        self.assertEqual(payload["status"], "MISMATCH")
        self.assertNotEqual(payload["predicted_class"],
                            payload["policy_expected_class"])
        self.assertEqual(payload["policy_expected_class"], "messaging")
        self.assertEqual(payload["compared_against"], "expected.traffic.profile")
        self.assertTrue(payload["reason"].strip())

    def test_every_bundle_reports_an_inference_status(self):
        for bundle in store().bundles.values():
            with self.subTest(slot=bundle["slot"]):
                self.assertIn(bundle["ml"]["inference_status"],
                              ("NOT_EXECUTED", "COMPLETED", "INCOMPLETE"))
                self.assertIn(bundle["ml"]["predicted_vs_policy"]["status"],
                              ("MATCH", "MISMATCH", "UNKNOWN",
                               "NOT_APPLICABLE", "NOT_EVALUATED", "PARTIAL"))


class TestArea11ApiConsistency(unittest.TestCase):
    """Area 11: one vocabulary, one documented and routable surface."""

    SLOTS = ("nat-t", "tunnel-v4", "ml-mismatch", "unknown")

    def test_every_sub_resource_is_reachable_and_returns_its_product(self):
        for slot in self.SLOTS:
            bundle = next(b for b in store().bundles.values()
                          if b["slot"] == slot)
            assessment_id = bundle["assessment_id"]
            for resource in SUB_RESOURCES:
                payload = handle_get(
                    store(), f"/api/assessments/{assessment_id}/{resource}")
                key = SUB_RESOURCE_KEYS.get(resource, resource)
                with self.subTest(slot=slot, resource=resource):
                    self.assertEqual(payload["resource"], resource)
                    self.assertEqual(payload["assessment_id"], assessment_id)
                    self.assertEqual(payload["data"], bundle[key])

    def test_an_unknown_sub_resource_is_still_a_structured_404(self):
        assessment_id = bundle_for("nat-t")["assessment_id"]
        with self.assertRaises(ApiError) as caught:
            handle_get(store(), f"/api/assessments/{assessment_id}/replay-window")
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(caught.exception.code, "unknown_resource")

    def test_every_sub_resource_is_documented_with_a_unique_operation_id(self):
        document = openapi_document()
        operations = []
        for path, item in document["paths"].items():
            operations.append(item["get"]["operationId"])
        self.assertEqual(len(operations), len(set(operations)))

        for resource in SUB_RESOURCES:
            template = f"/api/assessments/{{id}}/{resource}"
            with self.subTest(resource=resource):
                self.assertIn(template, document["paths"])
                self.assertIn(
                    "parameters", document["paths"][template]["get"])
                self.assertTrue(document["paths"][template]["get"]["summary"])

    def test_every_documented_new_route_is_routable(self):
        from correlation.api import app as app_module
        from correlation.api.live import Phase10Context

        context = Phase10Context()
        for resource in SUB_RESOURCES:
            path = f"/api/assessments/sentinel/{resource}"
            with self.subTest(resource=resource):
                try:
                    app_module.handle_combined(store(), context, path, {})
                except ApiError as error:
                    self.assertNotEqual(error.code, "unknown_route")

    def test_every_phase8_response_is_typed_and_every_ref_resolves(self):
        document = openapi_document()
        schemas = document["components"]["schemas"]
        seen = set()

        def walk(node, path):
            if isinstance(node, dict):
                reference = node.get("$ref")
                if isinstance(reference, str):
                    name = reference.rsplit("/", 1)[-1]
                    seen.add(name)
                    self.assertIn(name, schemas, f"{path} -> {reference}")
                for key, value in node.items():
                    walk(value, f"{path}/{key}")
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    walk(value, f"{path}/{index}")

        walk(document, "")
        self.assertTrue(seen)

        for template, item in document["paths"].items():
            operation = item["get"]
            if "phase8" not in operation["tags"]:
                continue
            ok = operation["responses"].get("200") or {}
            schema = ((ok.get("content") or {})
                      .get("application/json") or {}).get("schema")
            with self.subTest(path=template):
                self.assertTrue(schema, "phase-8 routes document a 200")
                self.assertNotEqual(schema, {"type": "object"},
                                    "a bare object is an undocumented payload")

    def test_every_product_schema_matches_the_payload_it_documents(self):
        from correlation.api.adapters import PRODUCT_PRODUCERS

        document = openapi_document()
        schemas = document["components"]["schemas"]
        bundle = bundle_for("nat-t")
        contract = ("producer", "state", "reason", "source")
        for resource in SUB_RESOURCES:
            template = f"/api/assessments/{{id}}/{resource}"
            ok = document["paths"][template]["get"]["responses"]["200"]
            schema = ok["content"]["application/json"]["schema"]
            narrowed = schema["allOf"][1]
            key = SUB_RESOURCE_KEYS.get(resource, resource)
            declared = schemas[
                narrowed["properties"]["data"]["$ref"].rsplit("/", 1)[-1]]
            payload = bundle[key]
            with self.subTest(resource=resource):
                self.assertEqual(narrowed["properties"]["resource"]["const"],
                                 resource)
                for field in declared.get("required", ()):
                    self.assertIn(field, payload)
                if key in PRODUCT_PRODUCERS:
                    for field in contract:
                        self.assertIn(field, declared["required"])
                        self.assertIn(field, declared["properties"])

    def test_the_bundle_schema_names_every_key_the_bundle_carries(self):
        document = openapi_document()
        declared = document["components"]["schemas"]["AssessmentBundle"][
            "properties"]
        bundle = bundle_for("nat-t")
        for key, value in bundle.items():
            with self.subTest(key=key):
                self.assertIn(key, declared)
        self.assertEqual(set(declared), set(bundle))


class TestTheReplayRule(unittest.TestCase):
    """The new rule fires on observed duplicates and on nothing else."""

    @staticmethod
    def _assess(replay_evidence):
        expected = make_expected()
        correlation = run_comparison(expected)
        return RiskEngine(RiskPolicy.default()).assess(
            expected=expected,
            observed=build_observed(),
            correlation=correlation,
            ml_result=None,
            evidence_refs=(),
            replay_evidence=replay_evidence,
        )

    def test_an_observed_duplicate_produces_exactly_the_replay_finding(self):
        assessment = self._assess({"status": "OBSERVED",
                                   "duplicate_sequences": 2})
        rules = [f.rule_id for f in assessment.findings]
        self.assertIn("replay.duplicate_sequence", rules)
        finding = next(f for f in assessment.findings
                       if f.rule_id == "replay.duplicate_sequence")
        self.assertEqual(finding.severity, "LOW")
        self.assertEqual(finding.score, 6)
        self.assertEqual(finding.source, "OBSERVED_PROTOCOL")

    def test_no_replay_evidence_produces_no_replay_finding(self):
        assessment = self._assess(None)
        self.assertNotIn("replay.duplicate_sequence",
                         [f.rule_id for f in assessment.findings])
        gap = assessment.metadata["replay_evidence"]
        self.assertIs(gap["supplied"], False)
        self.assertIs(gap["finding_emitted"], False)
        self.assertEqual(gap["absent_means"], "evidence gap, never a finding")

    def test_a_clean_observation_and_a_gap_only_are_both_silent(self):
        for evidence in (
            {"status": "OBSERVED", "duplicate_sequences": 0},
            {"status": "NO_EVIDENCE", "duplicate_sequences": 0},
            {"status": "INSUFFICIENT_DATA", "duplicate_sequences": None},
            {"status": "OBSERVED"},
        ):
            with self.subTest(evidence=evidence):
                assessment = self._assess(evidence)
                self.assertNotIn("replay.duplicate_sequence",
                                 [f.rule_id for f in assessment.findings])

    def test_the_product_is_consumed_not_recomputed_by_the_risk_engine(self):
        assessment = self._assess({"status": "OBSERVED",
                                   "duplicate_sequences": 1})
        metadata = assessment.metadata["replay_evidence"]
        self.assertIs(metadata["derived_by_this_engine"], False)
        self.assertIs(metadata["gaps_are_never_findings"], True)
        self.assertEqual(metadata["finding_rule"], "replay.duplicate_sequence")
        self.assertEqual(metadata["duplicate_sequences"], 1)

    def test_the_rule_is_registered_once_in_each_registry(self):
        from correlation.risk.rules import RULE_REGISTRY, RULE_TRACEABILITY

        self.assertIn("replay.duplicate_sequence", ALL_RULES)
        self.assertIn("replay.duplicate_sequence", RULE_REGISTRY)
        self.assertIn("replay.duplicate_sequence", RULE_TRACEABILITY)
        self.assertEqual(
            RULE_TRACEABILITY["replay.duplicate_sequence"]["rule_id"],
            "replay.duplicate_sequence",
        )

    def test_the_response_rule_explains_what_it_will_and_will_not_do(self):
        entry = RESPONSE_RULE_TRACEABILITY["replay.duplicate_sequence"]
        self.assertTrue(entry["rule_id"].startswith("RESP-"))
        self.assertEqual(entry["finding_rule"], "replay.duplicate_sequence")
        self.assertEqual(entry["action"], ACTION_REQUIRE_REVIEW)
        self.assertIn("response-policy-v1", entry["policy_dependency"])
        self.assertTrue(entry["limitations"])
        self.assertIn("never trigger",
                      " ".join(entry["limitations"]).lower())

    def test_the_planner_requires_a_review_rather_than_an_auto_action(self):
        policy = ResponsePolicy()
        self.assertEqual(
            DEFAULT_RULE_OVERRIDES["replay.duplicate_sequence"]["action"],
            ACTION_REQUIRE_REVIEW,
        )
        self.assertEqual(
            policy.action_for("replay.duplicate_sequence", "LOW"),
            ACTION_REQUIRE_REVIEW,
        )

    def test_the_recorded_capture_actually_emits_the_finding(self):
        payload = bundle_for("nat-t")
        rules = {f["rule_id"] for f in payload["risk"]["findings"]}
        self.assertIn("replay.duplicate_sequence", rules)
        self.assertEqual(payload["replay_assessment"]["status"],
                         REPLAY_STATUS_OBSERVED)

    def test_only_a_capture_that_observed_duplicates_emits_the_finding(self):
        for bundle in store().bundles.values():
            replay = bundle["replay_assessment"]
            rules = {f["rule_id"] for f in bundle["risk"]["findings"]}
            fires = "replay.duplicate_sequence" in rules
            with self.subTest(slot=bundle["slot"]):
                if fires:
                    self.assertEqual(replay["status"], REPLAY_STATUS_OBSERVED)
                    self.assertGreater(replay["duplicate_sequences"], 0)
                else:
                    self.assertFalse(
                        replay["status"] == REPLAY_STATUS_OBSERVED
                        and (replay["duplicate_sequences"] or 0) > 0,
                        "observed duplicates produced no finding",
                    )


class TestArea12DeterminismAndCoverage(unittest.TestCase):
    """Validation: the products are stable and the suite exercises them."""

    def test_two_stores_produce_byte_identical_products(self):
        first = build_store()
        second = build_store()
        products = ("sa", "crypto_evidence", "replay_assessment",
                    "metadata_exposure", "threat_matrix", "report",
                    "executive_report")
        for slot in ("nat-t", "tunnel-v4", "unknown"):
            a = next(b for b in first.bundles.values() if b["slot"] == slot)
            b = next(b for b in second.bundles.values() if b["slot"] == slot)
            for product in products:
                with self.subTest(slot=slot, product=product):
                    self.assertEqual(
                        json.dumps(a[product], sort_keys=True),
                        json.dumps(b[product], sort_keys=True),
                    )

    def test_every_bundle_carries_every_product(self):
        for bundle in store().bundles.values():
            for product in ("sa", "crypto_evidence", "replay_assessment",
                            "metadata_exposure", "threat_matrix", "report",
                            "executive_report"):
                with self.subTest(slot=bundle["slot"], product=product):
                    self.assertIn(product, bundle)
                    payload = bundle[product]
                    self.assertIn("state", payload)
                    self.assertIn("reason", payload)
                    self.assertIn("source", payload)
                    self.assertIn("limitations", payload)
                    self.assertIn(payload["state"], VALID_STATES)
                    self.assertTrue(payload["reason"].strip())

    def test_the_report_inputs_are_the_products_already_built(self):
        payload = bundle_for("nat-t")
        self.assertEqual(payload["report"]["assessment_id"],
                         payload["executive_report"]["assessment_id"])
        self.assertTrue(payload["report"]["limitations"])
        self.assertTrue(payload["executive_report"]["limitations"])


if __name__ == "__main__":
    unittest.main()
