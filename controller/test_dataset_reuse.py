"""Module-10 tests for the additive topology-reuse seam.

Covers MODULE9_DESIGN.md §14 cases A–M with a fake clock + a scripted
executor-runtime stub.  No containerlab, no strongSwan, no wall-clock: every
assertion is on the *decision* table and the *sequence of operations* the
manager requests, which is exactly what the dataset pipeline will consume.

Authoritative contract under test (controller/reuse.py):

    TopologyReuseManager(can_reuse, reset_and_deploy, reuse_and_reinitiate)

plus the campaign seam ``reset_and_deploy_or_reuse`` that chooses between
them.  Reuse is ALWAYS config-only (StrongSwan reload + re-initiation in
place); it never happens across a different ``mode`` because that is a
different containerlab topology file.

Lifecycle under test (target=2, mirroring a real dataset run):

  sample 1: manager._prev_identity=None  -> can_reuse=False -> fresh deploy
            -> _prev_identity="tunnel"
  sample 2: can_reuse("tunnel")=True     -> terminate->load->initiate->verify
            -> verify result returned, _reused_count=1
  reuse failure: any callback raises    -> fallback fresh deploy once
"""

import unittest

from . import reuse as reuse_mod


class RecallRunner:
    """Deterministic fake for the executor-side operation seams.

    Records the ordered list of operations it was asked to run and lets the
    test assert exact op sequences per transition, without any testbed.  Each
    method is failure-injectable so the fallback rules can be pinned down.
    """

    def __init__(self):
        self.seen = []
        self.verified = {
            "ike_sa": "ESTABLISHED", "child_sa": "INSTALLED", "mode": "TUNNEL",
        }
        self.fail_terminate = False
        self.fail_load = False
        self.fail_initiate = False
        self.fail_verify = False
        self.fail_fresh = False

    # -- the strongSwan/topology seams the reuse path delegates to -------------
    def terminate(self):
        self.seen.append("terminate")
        if self.fail_terminate:
            raise RuntimeError("terminate failed")

    def load(self):
        self.seen.append("load")
        if self.fail_load:
            raise RuntimeError("load failed")

    def initiate(self):
        self.seen.append("initiate")
        if self.fail_initiate:
            raise RuntimeError("initiate failed")

    def verify(self):
        self.seen.append("verify")
        if self.fail_verify:
            raise RuntimeError("verify failed")
        return dict(self.verified)

    def fresh(self, mode):
        self.seen.append(f"fresh:{mode}")
        if self.fail_fresh:
            raise RuntimeError("fresh deploy failed")


def seam(manager, runner, mode, family, log, recorder=None):
    """One full seam call through the campaign-shaped signature."""
    return reuse_mod.reset_and_deploy_or_reuse(
        mode, family, reuse_manager=manager, fresh_fn=runner.fresh,
        terminate_fn=runner.terminate, load_fn=runner.load,
        initiate_fn=runner.initiate, verify_fn=runner.verify,
        recorder=recorder, log=log,
    )


def manager_with(log):
    return reuse_mod.TopologyReuseManager(log=log)


class TestManagerDecision(unittest.TestCase):
    def setUp(self):
        self.log = []
        self.runner = RecallRunner()
        self.manager = manager_with(self.log.append)

    def test_can_reuse_false_when_no_prior_sample(self):
        self.assertFalse(self.manager.can_reuse("tunnel"))
        self.assertFalse(self.manager.can_reuse("transport"))

    def test_can_reuse_true_only_after_successful_fresh_deploy(self):
        self.manager.reset_and_deploy(
            "tunnel", "ipv4", mode_func=lambda: self.runner.fresh("tunnel"))
        self.assertTrue(self.manager.can_reuse("tunnel"))
        self.assertFalse(self.manager.can_reuse("transport"))
        self.assertEqual(self.runner.seen, ["fresh:tunnel"])

    def test_failed_fresh_deploy_does_not_record_identity(self):
        self.runner.fail_fresh = True
        with self.assertRaises(RuntimeError):
            self.manager.reset_and_deploy(
                "tunnel", "ipv4", mode_func=lambda: self.runner.fresh("tunnel"))
        self.assertIsNone(self.manager.stats()["last_topology_identity"])
        self.assertFalse(self.manager.can_reuse("tunnel"))


class TestManagerReuseAndReinitiate(unittest.TestCase):
    def setUp(self):
        self.log = []
        self.runner = RecallRunner()
        self.manager = manager_with(self.log.append)

    def test_reuse_calls_callbacks_in_exact_order(self):
        outcome = self.manager.reuse_and_reinitiate(
            "tunnel", "ipv4",
            terminate_fn=self.runner.terminate,
            load_fn=self.runner.load,
            initiate_fn=self.runner.initiate,
            verify_fn=self.runner.verify,
        )
        self.assertEqual(
            self.runner.seen, ["terminate", "load", "initiate", "verify"],
        )
        self.assertIsNotNone(outcome)

    def test_verify_result_is_returned(self):
        outcome = self.manager.reuse_and_reinitiate(
            "tunnel", "ipv4",
            terminate_fn=self.runner.terminate,
            load_fn=self.runner.load,
            initiate_fn=self.runner.initiate,
            verify_fn=self.runner.verify,
        )
        self.assertEqual(outcome, self.runner.verified)

    def test_verify_success_updates_identity_and_reuse_count(self):
        self.manager.reset_and_deploy(
            "tunnel", "ipv4", mode_func=lambda: self.runner.fresh("tunnel"))
        self.manager.reuse_and_reinitiate(
            "tunnel", "ipv6",
            terminate_fn=self.runner.terminate,
            load_fn=self.runner.load,
            initiate_fn=self.runner.initiate,
            verify_fn=self.runner.verify,
        )
        self.assertEqual(self.manager.stats()["reused"], 1)
        self.assertEqual(self.manager.stats()["fresh_deploy"], 1)
        self.assertEqual(
            self.manager.stats()["last_topology_identity"], "tunnel")

    def test_falsy_verify_raises_reuse_verification_error(self):
        self.manager.reset_and_deploy(
            "tunnel", "ipv4", mode_func=lambda: self.runner.fresh("tunnel"))
        with self.assertRaises(reuse_mod.ReuseVerificationError):
            self.manager.reuse_and_reinitiate(
                "tunnel", "ipv6",
                terminate_fn=self.runner.terminate,
                load_fn=self.runner.load,
                initiate_fn=self.runner.initiate,
                verify_fn=lambda: {},
            )
        self.assertEqual(self.manager.stats()["reused"], 0)


class TestSeamLifecycle(unittest.TestCase):
    """Two-consecutive-sample lifecycle, exactly as the dataset executor feeds
    the campaign pipeline."""

    def setUp(self):
        self.log = []
        self.runner = RecallRunner()

    def test_target2_fresh_then_reuse(self):
        manager = manager_with(self.log.append)
        first = seam(manager, self.runner, "tunnel", "ipv4", self.log.append)
        self.assertEqual(first, {"reused": False,
                                 "identity": "tunnel"})
        self.assertEqual(self.runner.seen, ["fresh:tunnel"])

        second = seam(manager, self.runner, "tunnel", "ipv6", self.log.append)
        self.assertEqual(second["reused"], True)
        self.assertEqual(second["identity"], "tunnel")
        self.assertEqual(second["ipsec"], self.runner.verified)
        self.assertEqual(
            self.runner.seen,
            ["fresh:tunnel", "terminate", "load", "initiate", "verify"],
        )
        self.assertEqual(manager.stats()["reused"], 1)
        self.assertEqual(manager.stats()["fresh_deploy"], 1)
        self.assertEqual(manager.stats()["fallback_after_reuse_failure"], 0)

    def test_manager_persists_across_samples(self):
        manager = manager_with(self.log.append)
        for family in ("ipv4", "ipv6", "ipv4"):
            seam(manager, self.runner, "tunnel", family, self.log.append)
        self.assertEqual(manager.stats()["fresh_deploy"], 1)
        self.assertEqual(manager.stats()["reused"], 2)
        self.assertEqual(
            self.runner.seen,
            ["fresh:tunnel", "terminate", "load", "initiate", "verify",
             "terminate", "load", "initiate", "verify"],
        )

    def test_mode_change_forces_new_fresh_deploy(self):
        manager = manager_with(self.log.append)
        seam(manager, self.runner, "tunnel", "ipv4", self.log.append)
        out = seam(manager, self.runner, "transport", "ipv4", self.log.append)
        self.assertEqual(out["reused"], False)
        self.assertEqual(
            self.runner.seen, ["fresh:tunnel", "fresh:transport"],
        )

    def test_ipv4_to_ipv6_same_mode_reuses(self):
        manager = manager_with(self.log.append)
        seam(manager, self.runner, "tunnel", "ipv4", self.log.append)
        out = seam(manager, self.runner, "tunnel", "ipv6", self.log.append)
        self.assertEqual(out["reused"], True)
        self.assertEqual(
            self.runner.seen,
            ["fresh:tunnel", "terminate", "load", "initiate", "verify"],
        )

    def test_verify_failure_falls_back_to_fresh_deploy(self):
        manager = manager_with(self.log.append)
        seam(manager, self.runner, "tunnel", "ipv4", self.log.append)
        self.runner.fail_verify = True
        out = seam(manager, self.runner, "tunnel", "ipv6", self.log.append)
        self.assertEqual(out["reused"], False)
        self.assertEqual(
            self.runner.seen,
            ["fresh:tunnel", "terminate", "load", "initiate", "verify",
             "fresh:tunnel"],
        )
        self.assertEqual(manager.stats()["fallback_after_reuse_failure"], 1)
        self.assertEqual(manager.stats()["reused"], 0)
        self.assertEqual(manager.stats()["fresh_deploy"], 2)

    def test_terminate_failure_falls_back_to_fresh_deploy(self):
        manager = manager_with(self.log.append)
        seam(manager, self.runner, "tunnel", "ipv4", self.log.append)
        self.runner.fail_terminate = True
        out = seam(manager, self.runner, "tunnel", "ipv6", self.log.append)
        self.assertEqual(out["reused"], False)
        self.assertEqual(manager.stats()["fallback_after_reuse_failure"], 1)
        self.assertEqual(
            self.runner.seen,
            ["fresh:tunnel", "terminate", "fresh:tunnel"],
        )

    def test_a_failed_reuse_never_counts_as_success(self):
        manager = manager_with(self.log.append)
        seam(manager, self.runner, "tunnel", "ipv4", self.log.append)
        self.runner.fail_verify = True
        failed = seam(manager, self.runner, "tunnel", "ipv6", self.log.append)
        self.assertEqual(failed["reused"], False)
        # only the fallback fresh deployment may produce a sample; the reuse
        # attempt itself is never credited as success.
        self.assertEqual(manager.stats()["reused"], 0)

    def test_new_manager_after_resume_starts_fresh(self):
        first = manager_with(self.log.append)
        seam(first, self.runner, "tunnel", "ipv4", self.log.append)
        # A resumed run creates a NEW manager (_prev_identity=None): the first
        # sample after resume MUST perform a full fresh deployment.
        resumed = manager_with(self.log.append)
        self.assertIsNone(resumed.stats()["last_topology_identity"])
        self.assertFalse(resumed.can_reuse("tunnel"))
        out = seam(resumed, self.runner, "tunnel", "ipv4", self.log.append)
        self.assertEqual(out["reused"], False)
        self.assertEqual(
            self.runner.seen, ["fresh:tunnel", "fresh:tunnel"],
        )

    def test_reuse_none_remains_historical(self):
        out = reuse_mod.reset_and_deploy_or_reuse(
            "tunnel", "ipv4", fresh_fn=self.runner.fresh,
            log=self.log.append,
        )
        self.assertEqual(out, {"reused": False, "identity": "tunnel"})
        self.assertEqual(self.runner.seen, ["fresh:tunnel"])

    def test_stats_are_observable_for_reporting(self):
        manager = manager_with(self.log.append)
        seam(manager, self.runner, "tunnel", "ipv4", self.log.append)
        seam(manager, self.runner, "tunnel", "ipv6", self.log.append)
        self.assertEqual(
            manager.stats(),
            {
                "reused": 1,
                "fresh_deploy": 1,
                "fallback_after_reuse_failure": 0,
                "last_topology_identity": "tunnel",
            },
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)