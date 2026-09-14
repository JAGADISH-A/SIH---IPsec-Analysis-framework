"""Additive Module-10 tests for the StrongSwan reuse DECISION seam.

Scope: the ``TopologyReuseManager`` decision table from MODULE9_DESIGN.md
(§4 reuse conditions, §13 fallback) plus the campaign seam
``reset_and_deploy_or_reuse``.  Uses a fake clock + fake recorder only;
NO testbed, NO containerlab, NO wall clock.  Asserts exactly that:

  * topology identity is ``mode``-only (tunnel|transport) — family is config,
  * same-mode consecutive samples → ``can_reuse`` True,
  * mode change (tunnel→transport) → ``can_reuse`` False → fresh deploy,
  * IPv4→IPv6 within the same mode follows the config-only identity contract,
  * ``reset_and_deploy_or_reuse`` delegates to a supplied fresh resolver when
    reuse is ruled out, and to the terminate→load→initiate→verify lifecycle
    when reuse is possible,
  * the manager is NEVER created by the seam (a new manager means a resume →
    first sample fresh deploy),
  * reuse failure falls back to a full fresh deployment and only fresh
    deployments update the recorded topology identity.
"""

import unittest

from . import reuse as reuse_mod


class _FakeClock:
    def __init__(self, start=100.0):
        self.t = start

    def __call__(self):
        return self.t

    def step(self, d):
        self.t += d


class _Ops:
    """Records the ordered pipeline operations a test manager requests."""

    def __init__(self):
        self.seen = []

    def reset_and_deploy(self, mode):
        self.seen.append(f"fresh.deploy:{mode}")

    def reuse_and_reinitiate(self, mode, address_family):
        self.seen.append(f"reuse.reinit:{mode}:{address_family}")


class _SeamOps:
    """Deterministic fakes for the four reuse callbacks + the fresh deploy.

    Records the ordered operation sequence exactly as the seam requests it,
    mirroring what ``campaign`` passes (real closures around the executor
    functions) without a testbed.
    """

    def __init__(self):
        self.seen = []
        self.verify_result = {
            "ike_sa": "ESTABLISHED", "child_sa": "INSTALLED", "mode": "TUNNEL",
        }
        self.verify_fail = False
        self.terminate_fail = False

    def fresh(self, mode):
        self.seen.append(f"fresh.deploy:{mode}")

    def terminate(self):
        self.seen.append("terminate")
        if self.terminate_fail:
            raise RuntimeError("terminate failed")

    def load(self):
        self.seen.append("load")

    def initiate(self):
        self.seen.append("initiate")

    def verify(self):
        self.seen.append("verify")
        if self.verify_fail:
            raise RuntimeError("verify failed")
        return dict(self.verify_result)


class TestTopologyIdentity(unittest.TestCase):
    def test_identity_is_mode_sensitive(self):
        self.assertNotEqual(
            reuse_mod.topology_identity("tunnel", "ipv4"),
            reuse_mod.topology_identity("transport", "ipv4"),
        )

    def test_identity_family_insensitive_within_mode(self):
        self.assertEqual(
            reuse_mod.topology_identity("tunnel", "ipv4"),
            reuse_mod.topology_identity("tunnel", "ipv6"),
        )


class TestReuseDecisionTable(unittest.TestCase):
    def setUp(self):
        self.clock = _FakeClock()
        self.ops = _Ops()
        self.log = []

    def test_same_mode_consecutive_can_reuse(self):
        manager = reuse_mod.TopologyReuseManager(log=self.log.append,
                                                 clock=self.clock)
        self.assertFalse(manager.can_reuse(None))
        manager.reset_and_deploy(
            "tunnel", "ipv4",
            mode_func=lambda: self.ops.reset_and_deploy("tunnel"))
        self.assertTrue(
            manager.can_reuse(reuse_mod.topology_identity(
                "tunnel", "ipv4")))

    def test_mode_change_forces_fresh_deploy(self):
        manager = reuse_mod.TopologyReuseManager(log=self.log.append,
                                                 clock=self.clock)
        self.assertFalse(
            manager.can_reuse(reuse_mod.topology_identity(
                "transport", "ipv4")))

    def test_reset_and_deploy_or_reuse_delegates_to_fresh_when_reuse_no(self):
        def fresh(mode):
            self.ops.reset_and_deploy(mode)
            return {"reused": False}

        outcome = reuse_mod.reset_and_deploy_or_reuse(
            "tunnel", "ipv4", fresh_fn=fresh, log=self.log.append,
        )
        self.assertEqual(outcome["reused"], False)
        self.assertEqual(self.ops.seen, ["fresh.deploy:tunnel"])

    def test_failed_fresh_deploy_does_not_update_prev_identity(self):
        manager = reuse_mod.TopologyReuseManager(log=self.log.append,
                                                 clock=self.clock)
        seam_ops = _SeamOps()

        def failing_fresh(mode):
            raise RuntimeError("deploy failed")

        with self.assertRaises(RuntimeError):
            reuse_mod.reset_and_deploy_or_reuse(
                "tunnel", "ipv4", reuse_manager=manager,
                fresh_fn=failing_fresh, terminate_fn=seam_ops.terminate,
                load_fn=seam_ops.load, initiate_fn=seam_ops.initiate,
                verify_fn=seam_ops.verify, log=self.log.append,
            )
        self.assertIsNone(manager.stats()["last_topology_identity"])
        self.assertFalse(manager.can_reuse("tunnel"))

    def test_successful_fresh_deploy_updates_prev_identity(self):
        manager = reuse_mod.TopologyReuseManager(log=self.log.append,
                                                 clock=self.clock)
        seam_ops = _SeamOps()
        outcome = reuse_mod.reset_and_deploy_or_reuse(
            "tunnel", "ipv4", reuse_manager=manager, fresh_fn=seam_ops.fresh,
            terminate_fn=seam_ops.terminate, load_fn=seam_ops.load,
            initiate_fn=seam_ops.initiate, verify_fn=seam_ops.verify,
            log=self.log.append,
        )
        self.assertEqual(outcome["reused"], False)
        self.assertEqual(manager.stats()["last_topology_identity"], "tunnel")


class TestSeamLifecycle(unittest.TestCase):
    def setUp(self):
        self.log = []

    def test_first_sample_with_manager_is_fresh(self):
        manager = reuse_mod.TopologyReuseManager(log=self.log.append)
        ops = _SeamOps()
        outcome = reuse_mod.reset_and_deploy_or_reuse(
            "tunnel", "ipv4", reuse_manager=manager, fresh_fn=ops.fresh,
            terminate_fn=ops.terminate, load_fn=ops.load,
            initiate_fn=ops.initiate, verify_fn=ops.verify,
            log=self.log.append,
        )
        self.assertEqual(outcome["reused"], False)
        self.assertEqual(ops.seen, ["fresh.deploy:tunnel"])

    def test_same_manager_same_mode_reuses(self):
        manager = reuse_mod.TopologyReuseManager(log=self.log.append)
        ops = _SeamOps()
        reuse_mod.reset_and_deploy_or_reuse(
            "tunnel", "ipv4", reuse_manager=manager, fresh_fn=ops.fresh,
            terminate_fn=ops.terminate, load_fn=ops.load,
            initiate_fn=ops.initiate, verify_fn=ops.verify,
            log=self.log.append,
        )
        outcome = reuse_mod.reset_and_deploy_or_reuse(
            "tunnel", "ipv6", reuse_manager=manager, fresh_fn=ops.fresh,
            terminate_fn=ops.terminate, load_fn=ops.load,
            initiate_fn=ops.initiate, verify_fn=ops.verify,
            log=self.log.append,
        )
        self.assertEqual(outcome["reused"], True)
        self.assertEqual(outcome["ipsec"], ops.verify_result)
        self.assertEqual(
            ops.seen,
            ["fresh.deploy:tunnel", "terminate", "load", "initiate", "verify"],
        )
        self.assertEqual(manager.stats()["last_topology_identity"], "tunnel")
        self.assertEqual(manager.stats()["reused"], 1)
        self.assertEqual(manager.stats()["fresh_deploy"], 1)

    def test_manager_persists_between_consecutive_samples(self):
        manager = reuse_mod.TopologyReuseManager(log=self.log.append)
        ops = _SeamOps()
        for _family in ("ipv4", "ipv6", "ipv4"):
            reuse_mod.reset_and_deploy_or_reuse(
                "tunnel", _family, reuse_manager=manager,
                fresh_fn=ops.fresh, terminate_fn=ops.terminate,
                load_fn=ops.load, initiate_fn=ops.initiate,
                verify_fn=ops.verify, log=self.log.append,
            )
        self.assertEqual(manager.stats()["reused"], 2)
        self.assertEqual(manager.stats()["fresh_deploy"], 1)
        self.assertEqual(manager.stats()["last_topology_identity"], "tunnel")

    def test_mode_change_forces_fresh_deploy_via_seam(self):
        manager = reuse_mod.TopologyReuseManager(log=self.log.append)
        ops = _SeamOps()
        reuse_mod.reset_and_deploy_or_reuse(
            "tunnel", "ipv4", reuse_manager=manager, fresh_fn=ops.fresh,
            terminate_fn=ops.terminate, load_fn=ops.load,
            initiate_fn=ops.initiate, verify_fn=ops.verify,
            log=self.log.append,
        )
        outcome = reuse_mod.reset_and_deploy_or_reuse(
            "transport", "ipv4", reuse_manager=manager, fresh_fn=ops.fresh,
            terminate_fn=ops.terminate, load_fn=ops.load,
            initiate_fn=ops.initiate, verify_fn=ops.verify,
            log=self.log.append,
        )
        self.assertEqual(outcome["reused"], False)
        self.assertEqual(
            ops.seen, ["fresh.deploy:tunnel", "fresh.deploy:transport"],
        )

    def test_ipv4_to_ipv6_same_mode_reuses(self):
        manager = reuse_mod.TopologyReuseManager(log=self.log.append)
        ops = _SeamOps()
        reuse_mod.reset_and_deploy_or_reuse(
            "tunnel", "ipv4", reuse_manager=manager, fresh_fn=ops.fresh,
            terminate_fn=ops.terminate, load_fn=ops.load,
            initiate_fn=ops.initiate, verify_fn=ops.verify,
            log=self.log.append,
        )
        outcome = reuse_mod.reset_and_deploy_or_reuse(
            "tunnel", "ipv6", reuse_manager=manager, fresh_fn=ops.fresh,
            terminate_fn=ops.terminate, load_fn=ops.load,
            initiate_fn=ops.initiate, verify_fn=ops.verify,
            log=self.log.append,
        )
        self.assertEqual(outcome["reused"], True)

    def test_reuse_verification_failure_falls_back_to_fresh(self):
        manager = reuse_mod.TopologyReuseManager(log=self.log.append)
        ops = _SeamOps()
        reuse_mod.reset_and_deploy_or_reuse(
            "tunnel", "ipv4", reuse_manager=manager, fresh_fn=ops.fresh,
            terminate_fn=ops.terminate, load_fn=ops.load,
            initiate_fn=ops.initiate, verify_fn=ops.verify,
            log=self.log.append,
        )
        ops.verify_fail = True
        outcome = reuse_mod.reset_and_deploy_or_reuse(
            "tunnel", "ipv6", reuse_manager=manager, fresh_fn=ops.fresh,
            terminate_fn=ops.terminate, load_fn=ops.load,
            initiate_fn=ops.initiate, verify_fn=ops.verify,
            log=self.log.append,
        )
        self.assertEqual(outcome["reused"], False)
        self.assertEqual(
            ops.seen,
            ["fresh.deploy:tunnel", "terminate", "load", "initiate",
             "verify", "fresh.deploy:tunnel"],
        )
        self.assertEqual(manager.stats()["fallback_after_reuse_failure"], 1)
        self.assertEqual(manager.stats()["last_topology_identity"], "tunnel")

    def test_termination_failure_falls_back_to_fresh(self):
        manager = reuse_mod.TopologyReuseManager(log=self.log.append)
        ops = _SeamOps()
        reuse_mod.reset_and_deploy_or_reuse(
            "tunnel", "ipv4", reuse_manager=manager, fresh_fn=ops.fresh,
            terminate_fn=ops.terminate, load_fn=ops.load,
            initiate_fn=ops.initiate, verify_fn=ops.verify,
            log=self.log.append,
        )
        ops.terminate_fail = True
        outcome = reuse_mod.reset_and_deploy_or_reuse(
            "tunnel", "ipv6", reuse_manager=manager, fresh_fn=ops.fresh,
            terminate_fn=ops.terminate, load_fn=ops.load,
            initiate_fn=ops.initiate, verify_fn=ops.verify,
            log=self.log.append,
        )
        self.assertEqual(outcome["reused"], False)
        self.assertEqual(manager.stats()["fallback_after_reuse_failure"], 1)

    def test_new_manager_after_resume_first_sample_fresh(self):
        first = reuse_mod.TopologyReuseManager(log=self.log.append)
        resumed = reuse_mod.TopologyReuseManager(log=self.log.append)
        ops = _SeamOps()
        reuse_mod.reset_and_deploy_or_reuse(
            "tunnel", "ipv4", reuse_manager=first, fresh_fn=ops.fresh,
            terminate_fn=ops.terminate, load_fn=ops.load,
            initiate_fn=ops.initiate, verify_fn=ops.verify,
            log=self.log.append,
        )
        # A fresh execute_dataset_run() invocation creates a NEW manager with
        # _prev_identity=None -> the first sample after resume is fresh.
        outcome = reuse_mod.reset_and_deploy_or_reuse(
            "tunnel", "ipv4", reuse_manager=resumed, fresh_fn=ops.fresh,
            terminate_fn=ops.terminate, load_fn=ops.load,
            initiate_fn=ops.initiate, verify_fn=ops.verify,
            log=self.log.append,
        )
        self.assertEqual(outcome["reused"], False)
        self.assertEqual(ops.seen, ["fresh.deploy:tunnel", "fresh.deploy:tunnel"])

    def test_reuse_none_remains_backward_compatible(self):
        ops = _SeamOps()
        outcome = reuse_mod.reset_and_deploy_or_reuse(
            "tunnel", "ipv4", fresh_fn=ops.fresh, log=self.log.append,
        )
        self.assertEqual(outcome["reused"], False)
        self.assertEqual(ops.seen, ["fresh.deploy:tunnel"])

    def test_missing_callbacks_with_manager_does_not_reuse(self):
        manager = reuse_mod.TopologyReuseManager(log=self.log.append)
        ops = _SeamOps()
        reuse_mod.reset_and_deploy_or_reuse(
            "tunnel", "ipv4", reuse_manager=manager, fresh_fn=ops.fresh,
            terminate_fn=ops.terminate, load_fn=ops.load,
            initiate_fn=ops.initiate, verify_fn=ops.verify,
            log=self.log.append,
        )
        outcome = reuse_mod.reset_and_deploy_or_reuse(
            "tunnel", "ipv6", reuse_manager=manager, fresh_fn=ops.fresh,
            terminate_fn=ops.terminate, load_fn=ops.load,
            initiate_fn=ops.initiate, verify_fn=None,
            log=self.log.append,
        )
        self.assertEqual(outcome["reused"], False)
        self.assertEqual(
            ops.seen, ["fresh.deploy:tunnel", "fresh.deploy:tunnel"],
        )


if __name__ == "__main__":
    unittest.main()