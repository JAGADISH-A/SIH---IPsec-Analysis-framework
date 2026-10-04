"""Root-cause classification tests for Sentinel's IPsec verification pipeline.

Every test here drives the *real* classifier with the *real* strongSwan log
lines captured from the lab (see ``controller/test_diagnose_real_logs.py`` for
the provenance of these fixtures), and asserts on the parsed evidence, not on
a hardcoded expectation of the final string. If the classifier stopped reading
the exchange a notification occurred in, these fail.

No Gemini/LLM, no similarity scoring, no probabilistic branch.
"""

import unittest

from controller import diagnose
from controller.diagnose import (
    AUTHENTICATION_FAILURE,
    DETERMINISTIC,
    ESP_PROPOSAL_MISMATCH,
    IKE_PROPOSAL_MISMATCH,
    INSUFFICIENT_EVIDENCE,
    NAT_T_FAILURE,
    TRAFFIC_SELECTOR_MISMATCH,
    UNKNOWN_IPSEC_FAILURE,
    UNSUPPORTED_CONFIGURATION,
)


# --------------------------------------------------------------------------
# Real charon lines (strongSwan 5.9.x) from the lab's fault-injection runs.
# --------------------------------------------------------------------------

PSK_LOG = """
03[CFG] vici initiate CHILD_SA 'gw-a-to-gw-b'
05[IKE] initiating IKE_SA gw-a-to-gw-b[1] to 192.168.100.2
05[ENC] generating IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) N(FRAG_SUP) N(HASH_ALG) N(REDIR_SUP) ]
05[NET] sending packet: from 192.168.100.1[500] to 192.168.100.2[500] (464 bytes)
14[ENC] parsed IKE_SA_INIT response 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) N(FRAG_SUP) N(HASH_ALG) N(CHDLESS_SUP) N(MULT_AUTH) ]
14[IKE] establishing CHILD_SA gw-a-to-gw-b{3}
14[ENC] generating IKE_AUTH request 1 [ IDi N(INIT_CONTACT) IDr AUTH SA TSi TSr N(MOBIKE_SUP) ]
14[NET] sending packet: from 192.168.100.1[4500] to 192.168.100.2[4500] (384 bytes)
13[ENC] parsed IKE_AUTH response 1 [ N(AUTH_FAILED) ]
13[IKE] received AUTHENTICATION_FAILED notify error
"""

IKE_PROPOSAL_LOG = """
15[CFG] vici initiate CHILD_SA 'gw-a-to-gw-b'
05[IKE] initiating IKE_SA gw-a-to-gw-b[1] to 192.168.100.2
05[ENC] generating IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) N(FRAG_SUP) N(HASH_ALG) N(REDIR_SUP) ]
05[NET] sending packet: from 192.168.100.1[500] to 192.168.100.2[500] (592 bytes)
14[ENC] parsed IKE_SA_INIT response 0 [ N(NO_PROP) ]
14[IKE] received NO_PROPOSAL_CHOSEN notify error
"""

ESP_PROPOSAL_LOG = """
15[CFG] vici initiate CHILD_SA 'gw-a-to-gw-b'
15[IKE] initiating IKE_SA gw-a-to-gw-b[1] to 192.168.100.2
05[ENC] generating IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) N(FRAG_SUP) N(HASH_ALG) N(REDIR_SUP) ]
14[ENC] parsed IKE_SA_INIT response 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) N(FRAG_SUP) N(HASH_ALG) N(CHDLESS_SUP) N(MULT_AUTH) ]
11[IKE] establishing CHILD_SA gw-a-to-gw-b{3}
11[ENC] generating IKE_AUTH request 1 [ IDi N(INIT_CONTACT) IDr AUTH SA TSi TSr N(MOBIKE_SUP) ]
11[NET] sending packet: from 192.168.100.1[4500] to 192.168.100.2[4500] (384 bytes)
15[ENC] parsed IKE_AUTH response 1 [ IDr AUTH N(MOBIKE_SUP) N(ADD_4_ADDR) N(NO_PROP) ]
15[IKE] received NO_PROPOSAL_CHOSEN notify, no CHILD_SA built
15[IKE] failed to establish CHILD_SA, keeping IKE_SA
"""

TS_LOG = """
15[IKE] initiating IKE_SA gw-a-to-gw-b[1] to 192.168.100.2
14[ENC] parsed IKE_SA_INIT response 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) N(FRAG_SUP) N(HASH_ALG) ]
16[ENC] parsed IKE_AUTH response 1 [ IDr AUTH SA TSi TSr N(MOBIKE_SUP) ]
12[IKE] CHILD_SA gw-a-to-gw-b{3} established with SPIs ca27a6e1_i cd72f586_o and TS 2001:db8:99::/64 === 2001:db8:99::/64
"""

NAT_T_SUCCESS_SAS = """
host-c-to-host-d: #1, ESTABLISHED, IKEv2, 06d6fdfe_i* 9b434e2d1d7bac9f_r
  local  'host-c' @ 10.20.1.10[4500]
  remote 'host-d' @ 10.30.1.20[4500]
  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
  host-c-to-host-d: #2, reqid 1, INSTALLED, TRANSPORT-in-UDP, ESP:AES_GCM_16-128
    in  c4b31102,    192 bytes,     3 packets,    62s ago
    out c0c5a603,    192 bytes,     3 packets,    63s ago
    local  10.20.1.10/32
    remote 10.30.1.20/32
"""

NAT_T_FAILURE_LOG = """
05[IKE] initiating IKE_SA host-c-to-host-d[1] to 10.30.1.20
04[ENC] parsed IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) N(FRAG_SUP) ]
04[IKE] NAT detection failed for the responder payload, cannot use NAT-T
"""


def _classify(log, sa_output="", **kwargs):
    return diagnose.classify_failure(
        stage=kwargs.pop("stage", "IPSEC"),
        sa_state=diagnose.parse_sa_state(sa_output),
        ike_evidence=diagnose.parse_ike_evidence(log),
        **kwargs,
    )


class TestEvidenceParsing(unittest.TestCase):
    """The parser must recover the exchange each notification occurred in."""

    def test_auth_failed_attributed_to_ike_auth(self):
        parsed = diagnose.parse_ike_evidence(PSK_LOG)
        self.assertIn("AUTH_FAILED", parsed["notifications"])
        auth_events = [
            e for e in parsed["events"] if e["notification"] == "AUTH_FAILED"
        ]
        self.assertTrue(auth_events)
        for event in auth_events:
            self.assertEqual(event["exchange"], "IKE_AUTH")

    def test_no_proposal_in_ike_sa_init(self):
        parsed = diagnose.parse_ike_evidence(IKE_PROPOSAL_LOG)
        events = [
            e for e in parsed["events"]
            if e["notification"] == "NO_PROPOSAL_CHOSEN"
        ]
        self.assertTrue(events)
        for event in events:
            self.assertEqual(event["exchange"], "IKE_SA_INIT")

    def test_no_proposal_in_ike_auth_is_distinguished(self):
        parsed = diagnose.parse_ike_evidence(ESP_PROPOSAL_LOG)
        events = [
            e for e in parsed["events"]
            if e["notification"] == "NO_PROPOSAL_CHOSEN"
        ]
        self.assertTrue(events)
        for event in events:
            self.assertEqual(event["exchange"], "IKE_AUTH")

    def test_notification_without_exchange_context_is_marked(self):
        parsed = diagnose.parse_ike_evidence(
            "13[IKE] received NO_PROPOSAL_CHOSEN notify error"
        )
        self.assertIn("NO_PROPOSAL_CHOSEN", parsed["notifications"])
        self.assertTrue(parsed["has_unattributed_notification"])

    def test_sa_state_parsing(self):
        state = diagnose.parse_sa_state(NAT_T_SUCCESS_SAS)
        self.assertEqual(state["ike_state"], "ESTABLISHED")
        self.assertEqual(state["child_state"], "INSTALLED")
        self.assertEqual(state["mode"], "TRANSPORT")
        self.assertTrue(state["nat_t"])
        self.assertEqual(state["encapsulation"], "UDP_4500")

    def test_empty_sa_state_is_no_sa_not_established(self):
        state = diagnose.parse_sa_state("")
        self.assertEqual(state["ike_state"], "NO-SA")
        self.assertEqual(state["child_state"], "NOT-INSTALLED")


class TestRequiredClassifications(unittest.TestCase):
    """Each required classification, driven by its real evidence."""

    def test_psk_mismatch_is_authentication_failure(self):
        result = _classify(PSK_LOG)
        self.assertEqual(result["root_cause"], AUTHENTICATION_FAILURE)
        self.assertEqual(result["stage"], "IPSEC")
        self.assertEqual(result["confidence"], DETERMINISTIC)
        self.assertIn("authentication failed", result["reason"].lower())
        self.assertEqual(result["evidence"]["notifications"], ["AUTH_FAILED"])
        self.assertEqual(result["evidence"]["ike_state"], "NO-SA")

    def test_ike_proposal_mismatch(self):
        result = _classify(IKE_PROPOSAL_LOG)
        self.assertEqual(result["root_cause"], IKE_PROPOSAL_MISMATCH)
        self.assertEqual(result["stage"], "IPSEC")
        self.assertEqual(result["confidence"], DETERMINISTIC)
        self.assertIn("IKE_SA_INIT", result["reason"])
        self.assertIn("NO_PROPOSAL_CHOSEN", result["evidence"]["notifications"])

    def test_esp_proposal_mismatch(self):
        # IKE established + CHILD not installed is the state that distinguishes
        # this from an IKE proposal mismatch.
        result = _classify(
            ESP_PROPOSAL_LOG,
            sa_output="host-c: #1, ESTABLISHED, IKEv2",
        )
        self.assertEqual(result["root_cause"], ESP_PROPOSAL_MISMATCH)
        self.assertEqual(result["stage"], "IPSEC")
        self.assertEqual(result["confidence"], DETERMINISTIC)
        self.assertIn("IKE_AUTH", result["reason"])
        self.assertEqual(result["evidence"]["ike_state"], "ESTABLISHED")
        self.assertEqual(result["evidence"]["child_state"], "NOT-INSTALLED")

    def test_ts_mismatch_is_data_plane_traffic_selector(self):
        result = _classify(
            TS_LOG,
            sa_output="ESTABLISHED INSTALLED",
            stage="CONNECTIVITY",
            connectivity={"status": "FAIL", "packet_loss": 100.0},
            probe_target="2001:db8:2::10",
        )
        self.assertEqual(result["root_cause"], TRAFFIC_SELECTOR_MISMATCH)
        self.assertEqual(result["stage"], "CONNECTIVITY")
        self.assertEqual(result["confidence"], DETERMINISTIC)
        # The installed selector provably excludes the probed destination.
        self.assertEqual(
            result["evidence"]["child_selectors"],
            ["2001:db8:99::/64 === 2001:db8:99::/64"],
        )
        self.assertEqual(result["evidence"]["probe_target"], "2001:db8:2::10")

    def test_data_plane_failure_without_ts_evidence_is_unknown(self):
        # SAs up, traffic lost, but the selectors DO cover the probe: packet
        # loss alone must never be reported as a TS mismatch.
        result = _classify(
            TS_LOG,
            sa_output="ESTABLISHED INSTALLED",
            stage="CONNECTIVITY",
            connectivity={"status": "FAIL", "packet_loss": 100.0},
            probe_target="2001:db8:99::10",
        )
        self.assertEqual(result["root_cause"], UNKNOWN_IPSEC_FAILURE)
        self.assertEqual(result["confidence"], INSUFFICIENT_EVIDENCE)

    def test_nat_t_failure_is_classified_separately(self):
        result = _classify(
            NAT_T_FAILURE_LOG, nat=True, stage="IPSEC",
        )
        self.assertEqual(result["root_cause"], NAT_T_FAILURE)
        self.assertIn("nat_failure_markers", result["evidence"])

    def test_successful_nat_t_is_never_a_nat_failure(self):
        # Ordinary, healthy UDP/4500 NAT-T operation.
        result = _classify(
            "12[IKE] CHILD_SA host-c-to-host-d{1} established with SPIs a_i b_o "
            "and TS 10.30.1.10/32 === 10.30.1.20/32",
            sa_output=NAT_T_SUCCESS_SAS,
            nat=True,
        )
        self.assertNotEqual(result["root_cause"], NAT_T_FAILURE)
        self.assertTrue(result["evidence"]["nat_t_negotiated"])

    def test_healthy_non_nat_sa_state_is_not_classified_as_a_failure(self):
        """A healthy tunnel must never produce a failure root cause.

        The classifier is only invoked on a failure path, so the invariant that
        matters is: no failure verdict may be derived from a healthy SA state
        with no notification evidence.
        """
        failure_root_causes = {
            AUTHENTICATION_FAILURE, IKE_PROPOSAL_MISMATCH,
            ESP_PROPOSAL_MISMATCH, TRAFFIC_SELECTOR_MISMATCH, NAT_T_FAILURE,
        }
        for sas in (
            "host-a: #1, ESTABLISHED, IKEv2\n  host-a-to-gw-b: #2, INSTALLED, TUNNEL",
            NAT_T_SUCCESS_SAS,
        ):
            result = _classify("", sa_output=sas, nat=("4500" in sas))
            self.assertNotIn(result["root_cause"], failure_root_causes)


class TestUnknownAndInsufficientEvidence(unittest.TestCase):
    """The classifier must refuse to guess."""

    def test_generic_ike_sa_message_alone_yields_unknown(self):
        # This is the exact symptom string Sentinel used to report for every
        # IKE-level fault. On its own it must NOT produce a root cause.
        result = _classify("", sa_output="")
        self.assertEqual(result["root_cause"], UNKNOWN_IPSEC_FAILURE)
        self.assertEqual(result["confidence"], INSUFFICIENT_EVIDENCE)
        self.assertIn("IKE_SA state: NO-SA", result["reason"])

    def test_unknown_result_states_available_evidence(self):
        result = _classify("", sa_output="")
        self.assertIn("ike_state", result["evidence"])
        self.assertIn("child_state", result["evidence"])
        self.assertEqual(result["evidence"]["notifications"], [])

    def test_no_proposal_without_exchange_is_unknown(self):
        result = _classify(
            "13[IKE] received NO_PROPOSAL_CHOSEN notify error",
            sa_output="",
        )
        self.assertEqual(result["root_cause"], UNKNOWN_IPSEC_FAILURE)
        self.assertEqual(result["confidence"], INSUFFICIENT_EVIDENCE)
        self.assertIn("NO_PROPOSAL_CHOSEN", result["evidence"]["notifications"])

    def test_no_proposal_in_ike_auth_without_established_ike_is_unknown(self):
        # The exchange says IKE_AUTH but no IKE_SA is established, so the
        # evidence cannot prove the failure was at the CHILD_SA layer.
        result = _classify(ESP_PROPOSAL_LOG, sa_output="")
        self.assertEqual(result["root_cause"], UNKNOWN_IPSEC_FAILURE)
        self.assertEqual(result["confidence"], INSUFFICIENT_EVIDENCE)

    def test_ike_up_child_down_without_notification_is_unknown(self):
        result = _classify("", sa_output="ESTABLISHED")
        self.assertEqual(result["root_cause"], UNKNOWN_IPSEC_FAILURE)
        self.assertIn("no CHILD_SA", result["reason"])


class TestExchangeDisambiguation(unittest.TestCase):
    """NO_PROPOSAL_CHOSEN must NOT collapse into one verdict."""

    def test_same_notification_different_exchange_different_classification(self):
        in_init = _classify(
            IKE_PROPOSAL_LOG, sa_output="",
        )
        in_auth_ike_up = _classify(
            ESP_PROPOSAL_LOG, sa_output="ESTABLISHED",
        )
        self.assertEqual(in_init["root_cause"], IKE_PROPOSAL_MISMATCH)
        self.assertEqual(in_auth_ike_up["root_cause"], ESP_PROPOSAL_MISMATCH)
        self.assertNotEqual(in_init["root_cause"], in_auth_ike_up["root_cause"])

    def test_moving_the_notification_to_the_other_exchange_flips_the_verdict(self):
        """Mutation guard: the verdict tracks the exchange, not the string."""
        moved = ESP_PROPOSAL_LOG.replace(
            "parsed IKE_AUTH response 1 [ IDr AUTH N(MOBIKE_SUP) N(ADD_4_ADDR) N(NO_PROP) ]",
            "parsed IKE_SA_INIT response 0 [ N(NO_PROP) ]",
        ).replace(
            "failed to establish CHILD_SA, keeping IKE_SA",
            "received NO_PROPOSAL_CHOSEN notify error",
        )
        parsed = diagnose.parse_ike_evidence(moved)
        moved_events = [
            e for e in parsed["events"]
            if e["notification"] == "NO_PROPOSAL_CHOSEN"
        ]
        self.assertTrue(moved_events)
        self.assertEqual(
            {e["exchange"] for e in moved_events}, {"IKE_SA_INIT"}
        )
        # Nothing may still be attributed to IKE_AUTH after the move.
        self.assertNotIn(
            "IKE_AUTH", [e["exchange"] for e in moved_events]
        )
        result = diagnose.classify_failure(
            stage="IPSEC",
            sa_state=diagnose.parse_sa_state("ESTABLISHED"),
            ike_evidence=parsed,
        )
        self.assertEqual(result["root_cause"], IKE_PROPOSAL_MISMATCH)


class TestNoModelDependency(unittest.TestCase):
    """The classifier is deterministic and has no AI dependency."""

    def test_module_does_not_import_any_model_or_http_client(self):
        """Static dependency check: no AI/network imports anywhere.

        Inspected over the *code* (docstrings and comments excluded) so the
        module's own "Gemini never participates" documentation does not trip
        its own guard.
        """
        import ast
        import inspect
        from pathlib import Path

        source = inspect.getsource(diagnose)
        tree = ast.parse(source)

        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
            # Any attribute access that looks like a client call.
            elif isinstance(node, ast.Attribute) and node.attr in {
                "get", "post", "post_for_json", "generate_content", "embed",
            }:
                base = getattr(node.value, "id", None)
                if base:
                    imported.add(f"{base}.{node.attr}")

        forbidden = {
            "gemini", "google", "openai", "anthropic", "cohere", "ollama",
            "requests", "httpx", "urllib", "urllib3", "http", "socket",
            "transformers", "torch", "tensorflow", "sklearn", "numpy",
            "pandas", "sentence_transformers", "litellm", "langchain",
        }
        overlap = imported & forbidden
        self.assertEqual(
            overlap, set(),
            f"diagnose must have no AI/network dependency, found: {overlap}",
        )

    def test_classifier_is_a_pure_function_of_its_inputs(self):
        """Two different evidence sets must be able to produce two different
        verdicts, and the same evidence must always produce the same one."""
        ike_init = diagnose.classify_failure(
            stage="IPSEC",
            sa_state=diagnose.parse_sa_state(""),
            ike_evidence=diagnose.parse_ike_evidence(IKE_PROPOSAL_LOG),
        )
        ike_auth = diagnose.classify_failure(
            stage="IPSEC",
            sa_state=diagnose.parse_sa_state("ESTABLISHED"),
            ike_evidence=diagnose.parse_ike_evidence(ESP_PROPOSAL_LOG),
        )
        self.assertNotEqual(ike_init["root_cause"], ike_auth["root_cause"])
        self.assertEqual(
            diagnose.classify_failure(
                stage="IPSEC",
                sa_state=diagnose.parse_sa_state(""),
                ike_evidence=diagnose.parse_ike_evidence(IKE_PROPOSAL_LOG),
            ),
            ike_init,
        )

    def test_classification_is_repeatable(self):
        first = _classify(PSK_LOG)
        second = _classify(PSK_LOG)
        self.assertEqual(first, second)

    def test_confidence_values_are_non_numeric_categories(self):
        result = _classify(PSK_LOG)
        self.assertIn(result["confidence"], {DETERMINISTIC, INSUFFICIENT_EVIDENCE})
        self.assertNotIsInstance(result["confidence"], float)


class TestUnsupportedConfiguration(unittest.TestCase):
    def test_constant_is_exposed(self):
        self.assertEqual(UNSUPPORTED_CONFIGURATION, "UNSUPPORTED_CONFIGURATION")


if __name__ == "__main__":
    unittest.main()