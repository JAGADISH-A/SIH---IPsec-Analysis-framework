"""Pipeline-level root-cause classification tests.

``controller/test_diagnose.py`` covers the classifier as a pure function. This
module covers the wiring: that a real ``verify_ipsec`` failure raises an error
carrying the classification, that the classification is derived from the
evidence actually collected, and that a successful run stays successful.

No lab, no network, no model.
"""

import unittest
from unittest.mock import patch

from controller import diagnose, executor
from controller.executor import (
    ConnectivityVerificationError,
    IpsecVerificationError,
)


ESTABLISHED_INSTALLED = (
    "host-a-to-gw-b: #1, ESTABLISHED, IKEv2, a_i* b_r\n"
    "  host-a-to-gw-b: #2, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-128"
)

AUTH_FAILED_LOG = (
    "14[ENC] parsed IKE_SA_INIT response 0 [ SA KE No N(NATD_S_IP) ]\n"
    "14[ENC] generating IKE_AUTH request 1 [ IDi IDr AUTH SA TSi TSr ]\n"
    "13[ENC] parsed IKE_AUTH response 1 [ N(AUTH_FAILED) ]\n"
    "13[IKE] received AUTHENTICATION_FAILED notify error\n"
)

IKE_INIT_NOPROPOSAL_LOG = (
    "05[ENC] generating IKE_SA_INIT request 0 [ SA KE No ]\n"
    "14[ENC] parsed IKE_SA_INIT response 0 [ N(NO_PROP) ]\n"
    "14[IKE] received NO_PROPOSAL_CHOSEN notify error\n"
)

ESP_NOPROPOSAL_LOG = (
    "11[ENC] parsed IKE_SA_INIT response 0 [ SA KE No ]\n"
    "11[ENC] generating IKE_AUTH request 1 [ IDi IDr AUTH SA TSi TSr ]\n"
    "15[ENC] parsed IKE_AUTH response 1 [ IDr AUTH SA N(NO_PROP) ]\n"
    "15[IKE] received NO_PROPOSAL_CHOSEN notify, no CHILD_SA built\n"
    "15[IKE] failed to establish CHILD_SA, keeping IKE_SA\n"
)


def _run_verify_ipsec(sas_output, charon_log):
    """Drive the real verify_ipsec with mocked subprocess output.

    ``_privileged`` is patched because it shells out to privilege detection; the
    command construction itself is not what these tests are about.
    """
    sas_calls = []

    def fake_run(command, timeout=None, cwd=None):
        sas_calls.append(command)
        return sas_output

    with patch.object(executor, "run", side_effect=fake_run), \
            patch.object(executor, "_privileged", side_effect=lambda *a: list(a)), \
            patch.object(executor.subprocess, "run") as mock_srun:
        mock_srun.return_value = type(
            "R", (), {"stdout": charon_log, "stderr": ""}
        )()
        return executor.verify_ipsec("tunnel", "ipv6"), sas_calls


class TestVerifyIpsecCarriesClassification(unittest.TestCase):
    def test_ike_sa_failure_classifies_from_real_log(self):
        with self.assertRaises(IpsecVerificationError) as ctx:
            _run_verify_ipsec("", AUTH_FAILED_LOG)
        classification = ctx.exception.classification
        self.assertEqual(
            classification["root_cause"], diagnose.AUTHENTICATION_FAILURE
        )
        self.assertEqual(classification["stage"], "IPSEC")
        self.assertEqual(classification["confidence"], diagnose.DETERMINISTIC)
        self.assertIn("AUTH_FAILED", classification["evidence"]["notifications"])

    def test_ike_proposal_failure_classifies_as_ike_mismatch(self):
        with self.assertRaises(IpsecVerificationError) as ctx:
            _run_verify_ipsec("", IKE_INIT_NOPROPOSAL_LOG)
        self.assertEqual(
            ctx.exception.classification["root_cause"],
            diagnose.IKE_PROPOSAL_MISMATCH,
        )

    def test_child_sa_failure_classifies_as_esp_mismatch(self):
        # IKE_SA is ESTABLISHED (so verify passes the first check) but the
        # CHILD_SA never installed, and the log attributes NO_PROPOSAL_CHOSEN
        # to IKE_AUTH.
        with self.assertRaises(IpsecVerificationError) as ctx:
            _run_verify_ipsec(
                "host-a-to-gw-b: #1, ESTABLISHED, IKEv2, a_i* b_r", ESP_NOPROPOSAL_LOG
            )
        classification = ctx.exception.classification
        self.assertEqual(
            classification["root_cause"], diagnose.ESP_PROPOSAL_MISMATCH
        )
        self.assertEqual(classification["evidence"]["ike_state"], "ESTABLISHED")
        self.assertEqual(
            classification["evidence"]["child_state"], "NOT-INSTALLED"
        )

    def test_generic_failure_without_evidence_is_unknown(self):
        with self.assertRaises(IpsecVerificationError) as ctx:
            _run_verify_ipsec("", "")
        classification = ctx.exception.classification
        self.assertEqual(
            classification["root_cause"], diagnose.UNKNOWN_IPSEC_FAILURE
        )
        self.assertEqual(
            classification["confidence"], diagnose.INSUFFICIENT_EVIDENCE
        )

    def test_original_exception_contract_is_preserved(self):
        """The generic message and RuntimeError type must not change."""
        with self.assertRaises(RuntimeError) as ctx:
            _run_verify_ipsec("", "")
        self.assertEqual(str(ctx.exception), "IKE SA is not established")
        self.assertIsInstance(ctx.exception, IpsecVerificationError)

    def test_child_sa_message_is_preserved(self):
        with self.assertRaises(RuntimeError) as ctx:
            _run_verify_ipsec(
                "host-a-to-gw-b: #1, ESTABLISHED, IKEv2, a_i* b_r", ""
            )
        self.assertEqual(str(ctx.exception), "CHILD SA is not installed")

    def test_successful_run_is_untouched_and_has_no_classification(self):
        result, _ = _run_verify_ipsec(ESTABLISHED_INSTALLED, "")
        self.assertEqual(result["ike_sa"], "ESTABLISHED")
        self.assertEqual(result["child_sa"], "INSTALLED")
        self.assertEqual(result["mode"], "TUNNEL")
        self.assertNotIn("classification", result)


class TestClassificationDependsOnCollectedEvidence(unittest.TestCase):
    """Removing the evidence must remove the specific verdict."""

    def test_without_charon_log_the_verdict_degrades_to_unknown(self):
        with self.assertRaises(IpsecVerificationError) as ctx:
            _run_verify_ipsec("", "")
        self.assertEqual(
            ctx.exception.classification["root_cause"],
            diagnose.UNKNOWN_IPSEC_FAILURE,
        )

    def test_charon_log_must_be_collected_from_both_peers(self):
        with patch.object(executor, "run", return_value=""), \
                patch.object(
                    executor, "_privileged", side_effect=lambda *a: list(a)
                ), \
                patch.object(executor.subprocess, "run") as mock_srun:
            mock_srun.return_value = type(
                "R", (), {"stdout": AUTH_FAILED_LOG, "stderr": ""}
            )()
            with self.assertRaises(IpsecVerificationError):
                executor.verify_ipsec("tunnel", "ipv6")
        logged = [
            c.args[0] for c in mock_srun.call_args_list
            if "logs" in c.args[0]
        ]
        self.assertEqual(len(logged), 2, logged)
        # Evidence must come from BOTH peers: the initiator and the responder
        # report the same negotiation from opposite sides, and the useful line
        # can be on either one.
        self.assertIn("clab-ipsec-gw-a", logged[0])
        self.assertIn("clab-ipsec-gw-b", logged[1])


class TestConnectivityClassification(unittest.TestCase):
    def test_connectivity_error_carries_classification(self):
        err = ConnectivityVerificationError("ping failed")
        self.assertEqual(
            err.classification["root_cause"], diagnose.UNKNOWN_IPSEC_FAILURE
        )
        self.assertIsInstance(err, RuntimeError)

    def test_data_plane_ts_mismatch_uses_installed_selectors(self):
        log = (
            "12[IKE] CHILD_SA gw-a-to-gw-b{3} established with SPIs a_i b_o "
            "and TS 2001:db8:99::/64 === 2001:db8:99::/64"
        )
        result = diagnose.classify_failure(
            stage="CONNECTIVITY",
            sa_state=diagnose.parse_sa_state(ESTABLISHED_INSTALLED),
            ike_evidence=diagnose.parse_ike_evidence(log),
            connectivity={"status": "FAIL", "packet_loss": 100.0},
            probe_target="2001:db8:2::10",
        )
        self.assertEqual(
            result["root_cause"], diagnose.TRAFFIC_SELECTOR_MISMATCH
        )
        self.assertEqual(result["stage"], "CONNECTIVITY")

    def test_connectivity_failure_without_selectors_is_unknown(self):
        result = diagnose.classify_failure(
            stage="CONNECTIVITY",
            sa_state=diagnose.parse_sa_state(ESTABLISHED_INSTALLED),
            ike_evidence=diagnose.parse_ike_evidence(""),
            connectivity={"status": "FAIL", "packet_loss": 100.0},
            probe_target="2001:db8:2::10",
        )
        self.assertEqual(
            result["root_cause"], diagnose.UNKNOWN_IPSEC_FAILURE
        )
        self.assertEqual(
            result["confidence"], diagnose.INSUFFICIENT_EVIDENCE
        )

    def test_probe_target_reaches_the_classifier(self):
        """Regression: the probe destination must be plumbed through.

        The classifier can only prove a selector excludes the destination if it
        knows what the destination was. When the target was dropped, a real TS
        mismatch silently degraded to UNKNOWN_IPSEC_FAILURE.
        """
        captured = {}

        def _fake_classify(*args, **kwargs):
            captured.update(kwargs)
            return {"stage": "CONNECTIVITY",
                    "root_cause": diagnose.UNKNOWN_IPSEC_FAILURE,
                    "confidence": diagnose.INSUFFICIENT_EVIDENCE,
                    "reason": "captured", "evidence": {}}

        with patch.object(executor, "run") as mock_run, \
                patch.object(executor, "_privileged",
                             side_effect=lambda *a: list(a)), \
                patch.object(executor, "_classify_connectivity",
                             side_effect=_fake_classify):
            mock_run.return_value = (
                "3 packets transmitted, 0 received, 100% packet loss, time 4ms"
            )
            connectivity = executor.test_connectivity("tunnel", "ipv6", nat=False)
        self.assertEqual(connectivity["status"], "FAIL")
        self.assertIn("classification", connectivity)
        self.assertIn("probe_target", captured)
        self.assertEqual(captured["probe_target"], "2001:db8:2::10")


if __name__ == "__main__":
    unittest.main()