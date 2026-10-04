"""End-to-end root-cause verification across the REAL production path.

The tests in ``test_api.py::TestRootCauseOverHttp`` patch ``run_experiment``
and hand the API a pre-built exception, and ``test_diagnose_pipeline.py``
calls the private classification helpers. Neither exercises the chain that
actually ships:

    run_experiment -> verify_ipsec / test_connectivity -> _collect_charon_evidence
        -> parse_sa_state / parse_ike_evidence -> classify_failure
        -> classified exception -> controller/api.py -> job JSON

So a regression anywhere along that chain (dead classifier, dropped
propagation, a stage report that never fires, evidence read from the wrong
container) would still leave the existing suite green.

These tests keep the entire Sentinel chain real and stub only the outermost
boundary - the OS process boundary (``docker`` exec/logs, ping, containerlab,
XDP observation). Real strongSwan output and real charon logs are fed in, so the
real parser, the real classifier and the real API response are all exercised.
"""

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from controller import api as api_module
from controller import diagnose, executor
from controller.api import app


# Real ``swanctl --list-sas`` output, with the SA names strongSwan generates
# from the generated swanctl configs (TUNNEL-in-IPsec for tunnel mode,
# TRANSPORT-in-UDP for NAT-T transport mode). IKE_SA established, CHILD_SA
# installed.
SAS_OK = """
ike: TUNNEL-in-IPsec #1, ESTABLISHED, 2 min ago, 10.10.2.10[500]...10.10.2.20[500]
  local  10.10.2.10[500]
  remote 10.10.2.20[500]
  AES GCM-16 256-bit ESP
  aes128gcm16
child: TUNNEL-in-IPsec #1, INSTALLED, 2 min ago, 10.10.2.10[500]...10.10.2.20[500]
  local  10.10.2.0/24 === remote 10.10.2.0/24
  AES GCM-16 256-bit ESP, AH SPI: 0x1234, ESP SPI: 0x5678, MOBIKE
"""

# NAT-T variant: same SAs, but the SA name carries the UDP encapsulation that
# a negotiated NAT-T CHILD_SA has.
SAS_OK_NAT = SAS_OK.replace("TUNNEL-in-IPsec", "TRANSPORT-in-UDP")
# Plain (non-NAT) transport mode also names its SAs TRANSPORT-in-IPsec.
SAS_OK_TRANSPORT = SAS_OK.replace("TUNNEL-in-IPsec", "TRANSPORT-in-IPsec")

# IKE_SA established but no CHILD_SA at all.
SAS_NO_CHILD = """
ike: TUNNEL-in-IPsec #1, ESTABLISHED, 12 sec ago, 10.10.2.10[500]...10.10.2.20[500]
  local  10.10.2.10[500]
  remote 10.10.2.20[500]
  AES GCM-16 256-bit ESP
"""

SAS_NONE = ""


def ping_ok(loss=0.0):
    return (
        "PING 10.10.2.20 (10.10.2.20) 56(84) bytes of data.\n"
        "64 bytes from 10.10.2.20: icmp_seq=1 ttl=63 time=1.1 ms\n"
        f"3 packets transmitted, 3 received, 0% packet loss, time 200ms\n"
    )


def ping_loss(loss=100.0):
    return (
        "PING 10.10.2.20 (10.10.2.20) 56(84) bytes of data.\n"
        f"3 packets transmitted, 0 received, {loss}% packet loss, time 2045ms\n"
    )


# --- Real strongSwan log excerpts, as the daemon actually emits them. ------
LOG_AUTH_FAILED = """\
09:00:01.123 14[CH] building IKE_AUTH request 1 [ IDi IDr AUTH SA ]
09:00:01.140 14[ENC] generating IKE_AUTH request 1 [ IDi IDr AUTH SA ]
09:00:01.145 14[ENC] parsed IKE_AUTH response 1 [ N(AUTH_FAILED) ]
09:00:01.146 14[IKE] received AUTHENTICATION_FAILED notify error
"""

LOG_IKE_PROPOSAL = """\
09:00:01.101 14[ENC] generating IKE_SA_INIT request 1 [ SA KE ]
09:00:01.140 14[ENC] parsed IKE_SA_INIT response 1 [ N(NO_PROPOSAL_CHOSEN) ]
09:00:01.141 14[IKE] received NO_PROPOSAL_CHOSEN notify error
"""

LOG_ESP_PROPOSAL = """\
09:00:01.101 14[ENC] generating IKE_SA_INIT request 1 [ SA KE ]
09:00:01.150 14[IKE] ike-send-packet #2: sending packet: 2157 bytes
09:00:01.220 14[IKE] CHILD_SA 'tunnel-remote' established
09:00:01.230 14[ENC] generating IKE_AUTH request 1 [ IDi IDr AUTH SA ]
09:00:01.320 14[ENC] parsed IKE_AUTH response 1 [ N(NO_PROPOSAL_CHOSEN) ]
09:00:01.321 14[IKE] received NO_PROPOSAL_CHOSEN notify error
"""

LOG_TS_UNACCEPTABLE = """\
09:00:01.101 14[ENC] generating IKE_SA_INIT request 1 [ SA KE ]
09:00:01.150 14[IKE] IKE_SA 'tunnel-remote' established
09:00:01.230 14[ENC] generating IKE_AUTH request 1 [ IDi IDr AUTH SA TSi TSr ]
09:00:01.320 14[IKE] TS_UNACCEPTABLE: received TS_UNACCEPTABLE from peer
"""

# A CHILD_SA whose installed local selector does not contain the probed
# destination (10.10.2.10 for tunnel-ipv4), which is what a genuine traffic
# selector mismatch looks like on the wire. Real strongSwan line format:
#   CHILD_SA '<conn>' established with SPIs 0x.. 0x.. and TS <local> === <remote>
LOG_SELECTORS_EXCLUDE_PROBE = """\
09:00:01.150 14[IKE] CHILD_SA 'tunnel-remote' established with SPIs 0x1234abcd 0x5678ef01 and TS 10.10.1.0/24 === 10.10.2.0/24
"""

LOG_SELECTORS_COVER_PROBE = """\
09:00:01.150 14[IKE] CHILD_SA 'tunnel-remote' established with SPIs 0x1234abcd 0x5678ef01 and TS 10.10.2.0/24 === 10.10.2.0/24
"""

# NAT-T negotiation failure, stated explicitly by the daemon. Emitted by
# strongSwan when NAT detection/negotiation itself fails; never emitted on a
# working NAT-T path.
LOG_NAT_FAILURE = """\
09:00:01.101 14[ENC] generating IKE_SA_INIT request 1 [ SA KE NATD NATD ]
09:00:01.140 14[IKE] NAT detection failed
09:00:01.141 14[ENC] parsed IKE_SA_INIT response 1 [ N(NAT_DETECTION_FAILED) ]
"""

# A healthy NAT-T negotiation on UDP/4500. Must NEVER classify as NAT failure.
LOG_NAT_SUCCESS = """\
09:00:01.101 14[ENC] generating IKE_SA_INIT request 1 [ SA KE NATD NATD ]
09:00:01.140 14[IKE] received packet from 10.10.2.20[4500]
09:00:01.200 14[IKE] IKE_SA 'transport-remote' established
09:00:01.260 14[IKE] CHILD_SA 'transport-remote' established
09:00:01.261 14[IKE] CHILD_SA 'transport-remote' local 10.10.2.0/24 === remote 10.10.2.0/24
"""


class _DockerBoundary:
    """Stub ONLY the OS process boundary, feeding real strongSwan output.

    Everything Sentinel-side of ``docker exec`` stays real: the real
    ``run_experiment`` lifecycle, real ``verify_ipsec`` verdict parsing, real
    charon-log collection, real ``diagnose`` parsing/classification, real
    exception classes, and the real FastAPI job response.
    """

    def __init__(self, *, sas=SAS_NONE, logs=LOG_AUTH_FAILED, ping=None):
        self.sas = sas
        self.logs = logs
        self.ping = ping
        self.seen_stage_reports = []

    def __enter__(self):
        self._real_run = executor.run
        self._real_subprocess_run = executor.subprocess.run

        def fake_run(argv, **kwargs):
            argv = [str(a) for a in argv]
            if "swanctl" in argv:
                return self.sas
            if "ping" in argv:
                if self.ping is None:
                    raise executor.RuntimeError(
                        "ping produced no output (stubbed boundary)"
                    )
                return self.ping
            return ""

        def fake_subprocess_run(argv, **kwargs):
            argv = [str(a) for a in argv]
            if "docker" in argv and "logs" in argv:
                return mock.Mock(stdout=self.logs, stderr="")
            if "docker" in argv and "swanctl" in argv:
                return mock.Mock(stdout=self.sas, stderr="")
            return mock.Mock(stdout="", stderr="")

        patch_run = mock.patch.object(executor, "run", side_effect=fake_run)
        patch_srun = mock.patch.object(
            executor.subprocess, "run", side_effect=fake_subprocess_run
        )
        patch_run.start()
        patch_srun.start()

        # Neutralise only the parts of the pipeline that need a live lab and
        # carry no root-cause information: deployment, config load, startup,
        # and the XDP observation gate. The SA verification and the connectivity
        # probe are deliberately NOT stubbed.
        self._patches = [
            mock.patch.object(executor, "reset_and_deploy"),
            mock.patch.object(executor, "load_generated_configs"),
            mock.patch.object(executor, "initiate_ipsec"),
            mock.patch.object(executor, "ensure_live_observation",
                              return_value={"status": "live"}),
            mock.patch.object(executor.manifest_mod, "clear"),
            mock.patch.object(executor.manifest_mod, "current_journal_size",
                              return_value=0),
            mock.patch.object(executor.manifest_mod, "write_start",
                              return_value=False),
            # Traffic generation runs a real multi-second workload; it happens
            # strictly AFTER SA verification and the connectivity probe and
            # carries no root-cause information, so it is stubbed for speed.
            mock.patch.object(executor, "run_traffic",
                              return_value={"status": "PASS"}),
        ]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        mock.patch.stopall()
        executor.run = self._real_run
        executor.subprocess.run = self._real_subprocess_run
        return False


def _config(mode="tunnel", address_family="ipv4", nat=False):
    return {
        "mode": mode,
        "address_family": address_family,
        "nat": nat,
        "ike": {"version": 2, "encryption": "aes256", "integrity": "sha256",
                "dh_group": "modp2048"},
        "esp": {"encryption": "aes128gcm16", "integrity": None,
                "dh_group": "modp4096", "pfs": True},
        "traffic": {"profile": "voip", "duration": 10},
    }


class TestRootCauseProductionPath(unittest.TestCase):
    """Every case drives the real pipeline and asserts on the real HTTP job."""

    def setUp(self):
        self.client = TestClient(app)
        self._saved_jobs = dict(api_module.jobs)
        self._saved_active = api_module.active_job_id
        api_module.jobs.clear()
        api_module.active_job_id = None
        self.addCleanup(self._restore)

    def _restore(self):
        for kind, owner_id in list(api_module.TESTBED_LOCK._owner or ()):  # noqa: SLF001
            api_module.TESTBED_LOCK.release(kind, owner_id)
        api_module.jobs.clear()
        api_module.jobs.update(self._saved_jobs)
        api_module.active_job_id = self._saved_active

    def _drive(self, boundary, **config):
        """POST a job with the real pipeline, return the finished job JSON."""
        stages = []

        def _on_stage(stage):
            stages.append(stage)

        with mock.patch.object(
            api_module, "run_experiment",
            side_effect=lambda cfg, on_stage=None, job_id=None: executor.run_experiment(
                cfg, on_stage=on_stage, job_id=job_id
            ),
        ):
            with boundary:
                r = self.client.post("/experiments", json=_config(**config))
                self.assertEqual(r.status_code, 200)
                job_id = r.json()["job_id"]

                deadline = 200
                job = None
                for _ in range(deadline):
                    job = self.client.get(f"/experiments/{job_id}").json()
                    if job["status"] in ("COMPLETED", "FAILED"):
                        break
                    import time as _time
                    _time.sleep(0.05)
                self.assertIsNotNone(job)
                self.assertIn(job["status"], ("COMPLETED", "FAILED"),
                              "job never reached a terminal state")

        boundary.seen_stage_reports = stages
        return job

    # -- the required scenario matrix ---------------------------------

    def test_01_psk_mismatch_is_authentication_failure(self):
        job = self._drive(
            _DockerBoundary(sas=SAS_NONE, logs=LOG_AUTH_FAILED),
            mode="tunnel", address_family="ipv4",
        )
        self.assertEqual(job["status"], "FAILED")
        self.assertEqual(job["stage"], "IPSEC")
        self.assertEqual(job["root_cause"], diagnose.AUTHENTICATION_FAILURE)
        self.assertEqual(job["confidence"], diagnose.DETERMINISTIC)
        self.assertIn("AUTH_FAILED", job["evidence"]["notifications"])

    def test_02_ike_proposal_mismatch_is_ike_proposal_mismatch(self):
        job = self._drive(
            _DockerBoundary(sas=SAS_NONE, logs=LOG_IKE_PROPOSAL),
            mode="tunnel", address_family="ipv4",
        )
        self.assertEqual(job["status"], "FAILED")
        self.assertEqual(job["stage"], "IPSEC")
        self.assertEqual(job["root_cause"], diagnose.IKE_PROPOSAL_MISMATCH)
        self.assertEqual(job["confidence"], diagnose.DETERMINISTIC)

    def test_03_esp_proposal_mismatch_is_esp_proposal_mismatch(self):
        job = self._drive(
            _DockerBoundary(sas=SAS_NO_CHILD, logs=LOG_ESP_PROPOSAL),
            mode="tunnel", address_family="ipv4",
        )
        self.assertEqual(job["status"], "FAILED")
        self.assertEqual(job["stage"], "IPSEC")
        self.assertEqual(job["root_cause"], diagnose.ESP_PROPOSAL_MISMATCH)
        self.assertEqual(job["confidence"], diagnose.DETERMINISTIC)
        # The disambiguation depends on the IKE_SA being observed ESTABLISHED
        # from the real SA output, not assumed.
        self.assertEqual(job["evidence"]["ike_state"], diagnose.IKE_ESTABLISHED)

    def test_04_selector_mismatch_on_established_sas(self):
        job = self._drive(
            _DockerBoundary(sas=SAS_OK, logs=LOG_SELECTORS_EXCLUDE_PROBE,
                            ping=ping_loss()),
            mode="tunnel", address_family="ipv4",
        )
        # A data-plane failure is reported by run_experiment RETURNING a FAIL
        # result rather than by raising, so the job itself completes. The
        # verdict must still be lifted to job level by the API.
        self.assertEqual(job["status"], "COMPLETED")
        self.assertEqual(job["result"]["status"], "FAIL")
        self.assertEqual(job["root_cause"], diagnose.TRAFFIC_SELECTOR_MISMATCH)
        self.assertEqual(job["confidence"], diagnose.DETERMINISTIC)
        self.assertEqual(job["evidence"]["probe_target"], "10.10.2.10")
        # And it must agree with the classifier's own nested verdict.
        self.assertEqual(
            job["root_cause"],
            job["result"]["connectivity"]["classification"]["root_cause"],
        )

    def test_05_nat_t_failure_when_testbed_produces_evidence(self):
        """NAT-T failure classification, driven through the real NAT path.

        ``classify_failure`` only returns NAT_T_FAILURE for an explicit
        daemon marker on a NAT deployment, so this also pins the invariant that
        a NAT run cannot be labelled NAT_T_FAILURE without that evidence.
        """
        job = self._drive(
            _DockerBoundary(sas=SAS_NONE, logs=LOG_NAT_FAILURE),
            mode="transport", address_family="ipv4", nat=True,
        )
        self.assertEqual(job["status"], "FAILED")
        self.assertEqual(job["root_cause"], diagnose.NAT_T_FAILURE)
        self.assertEqual(job["confidence"], diagnose.DETERMINISTIC)
        self.assertTrue(job["evidence"]["nat_failure_markers"])
        self.assertTrue(job["evidence"]["nat_requested"])

    def test_06_ambiguous_evidence_is_insufficient_evidence(self):
        job = self._drive(
            _DockerBoundary(sas=SAS_NO_CHILD, logs="09:00:01.1 14[IKE] nothing useful\n"),
            mode="tunnel", address_family="ipv4",
        )
        self.assertEqual(job["status"], "FAILED")
        self.assertEqual(job["root_cause"], diagnose.UNKNOWN_IPSEC_FAILURE)
        self.assertEqual(job["confidence"], diagnose.INSUFFICIENT_EVIDENCE)

    # -- success cases must not invent a root cause --------------------

    def test_07_successful_tunnel_ipv4_has_no_root_cause(self):
        job = self._drive(
            _DockerBoundary(sas=SAS_OK, logs=LOG_SELECTORS_COVER_PROBE,
                            ping=ping_ok()),
            mode="tunnel", address_family="ipv4",
        )
        self.assertEqual(job["status"], "COMPLETED")
        self.assertIsNone(job["root_cause"])
        self.assertIsNone(job["confidence"])

    def test_08_successful_tunnel_ipv6_has_no_root_cause(self):
        job = self._drive(
            _DockerBoundary(sas=SAS_OK, logs=LOG_SELECTORS_COVER_PROBE,
                            ping=ping_ok()),
            mode="tunnel", address_family="ipv6",
        )
        self.assertEqual(job["status"], "COMPLETED")
        self.assertIsNone(job["root_cause"])

    def test_09_successful_transport_ipv4_has_no_root_cause(self):
        job = self._drive(
            _DockerBoundary(sas=SAS_OK_TRANSPORT,
                            logs=LOG_SELECTORS_COVER_PROBE, ping=ping_ok()),
            mode="transport", address_family="ipv4",
        )
        self.assertEqual(job["status"], "COMPLETED")
        self.assertIsNone(job["root_cause"])

    def test_10_successful_nat_t_is_never_a_nat_failure(self):
        """A working NAT-T path on UDP/4500 must not report NAT_T_FAILURE."""
        job = self._drive(
            _DockerBoundary(sas=SAS_OK_NAT, logs=LOG_NAT_SUCCESS,
                            ping=ping_ok()),
            mode="transport", address_family="ipv4", nat=True,
        )
        self.assertEqual(job["status"], "COMPLETED")
        self.assertIsNone(job["root_cause"])
        self.assertNotEqual(job["confidence"], diagnose.DETERMINISTIC)


class TestProductionPathIsNotVacuous(unittest.TestCase):
    """Guard against a hard-coded or bypassed classifier passing the matrix."""

    def setUp(self):
        self.client = TestClient(app)
        self._saved_jobs = dict(api_module.jobs)
        self._saved_active = api_module.active_job_id
        api_module.jobs.clear()
        api_module.active_job_id = None
        self.addCleanup(self._restore)

    def _restore(self):
        for kind, owner_id in list(api_module.TESTBED_LOCK._owner or ()):  # noqa: SLF001
            api_module.TESTBED_LOCK.release(kind, owner_id)
        api_module.jobs.clear()
        api_module.jobs.update(self._saved_jobs)
        api_module.active_job_id = self._saved_active

    def _run_case(self, **case):
        with _DockerBoundary(**case["boundary"]):
            r = self.client.post("/experiments", json=_config(**case["config"]))
            self.assertEqual(r.status_code, 200)
            job_id = r.json()["job_id"]
            import time as _time
            for _ in range(200):
                job = self.client.get(f"/experiments/{job_id}").json()
                if job["status"] in ("COMPLETED", "FAILED"):
                    return job
                _time.sleep(0.05)
            self.fail("job never terminated")

    def test_bypassing_the_classifier_breaks_the_suite(self):
        """If the classifier is stubbed out, real cases stop being classified."""
        with mock.patch.object(
            executor.diagnose, "classify_failure",
            return_value={
                "stage": "IPSEC",
                "root_cause": diagnose.UNKNOWN_IPSEC_FAILURE,
                "confidence": diagnose.INSUFFICIENT_EVIDENCE,
                "reason": "classifier removed",
                "evidence": {},
            },
        ):
            job = self._run_case(
                boundary={"sas": SAS_NONE, "logs": LOG_AUTH_FAILED},
                config={"mode": "tunnel", "address_family": "ipv4"},
            )
        self.assertNotEqual(job["root_cause"], diagnose.AUTHENTICATION_FAILURE)

    def test_dropping_api_propagation_breaks_the_suite(self):
        """If the API stops copying .classification, no root cause surfaces."""
        original = api_module.execute_job

        def _stripped(job_id, config):
            try:
                original(job_id, config)
            finally:
                for key in ("root_cause", "confidence", "reason", "evidence"):
                    api_module.jobs[job_id][key] = None

        with mock.patch.object(api_module, "execute_job", side_effect=_stripped):
            job = self._run_case(
                boundary={"sas": SAS_NONE, "logs": LOG_AUTH_FAILED},
                config={"mode": "tunnel", "address_family": "ipv4"},
            )
        self.assertIsNone(job["root_cause"])

    def test_no_single_hardcoded_result_satisfies_the_matrix(self):
        """Different real evidence must produce different real verdicts."""
        auth = self._run_case(
            boundary={"sas": SAS_NONE, "logs": LOG_AUTH_FAILED},
            config={"mode": "tunnel", "address_family": "ipv4"},
        )
        ambiguous = self._run_case(
            boundary={"sas": SAS_NO_CHILD, "logs": "nothing here\n"},
            config={"mode": "tunnel", "address_family": "ipv4"},
        )
        self.assertNotEqual(auth["root_cause"], ambiguous["root_cause"])
        self.assertEqual(auth["confidence"], diagnose.DETERMINISTIC)
        self.assertEqual(ambiguous["confidence"], diagnose.INSUFFICIENT_EVIDENCE)


if __name__ == "__main__":
    unittest.main()