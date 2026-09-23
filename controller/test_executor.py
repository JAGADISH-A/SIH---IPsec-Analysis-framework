"""Unit tests for the executor testbed-lifecycle layer (non-lab).

Covers the host-bridge lifecycle routing (tunnel deploy/destroy go through the
authoritative ``scripts/deploy-ipsec.sh`` wrapper, transport keeps the raw
containerlab calls), the surfacing of real stderr in command errors, the
stage-appropriate bounded subprocess timeout (with full process-group cleanup)
and the fatal-topology error mapping.  Everything is mocked; nothing touches
the lab.

A regression test asserts the non-interactive guarantee: every privileged
testbed subprocess must run under ``sudo -n`` so a background/web worker can
never block on an interactive sudo prompt (the root cause of a dataset run
stuck in RUNNING when non-interactive privilege is unavailable).
"""

import signal
import subprocess
import unittest
from unittest import mock
from unittest.mock import patch

from controller import executor as executor_mod
from controller.executor import (
    FatalTopologyError,
    LIFECYCLE_SCRIPT,
    SUDO,
    deploy,
    destroy,
    reset_and_deploy,
    run,
)


class _FakePopen:
    def __init__(self, command, **kwargs):
        self.command = command
        self.pid = 4242
        self.returncode = 0
        self._out = ""
        self._err = ""
        self._timed_out = None

    def communicate(self, timeout=None):
        if self._timed_out:
            raise subprocess.TimeoutExpired(
                " ".join(self.command), timeout,
                output=self._out, stderr=self._err,
            )
        return self._out, self._err

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass


def _popen_side_effect(returncode=0, stdout="", stderr="", timed_out=False):
    # The ``stdout``/``stderr`` kwargs here are the *captured output* the fake
    # should return, NOT the Popen kwargs (which are PIPE == -1).
    def _make(command, **kwargs):
        fake = _FakePopen(command)
        fake.returncode = returncode
        fake._out = stdout
        fake._err = stderr
        fake._timed_out = timed_out
        return fake
    return _make


class TestRunNonInteractiveSudo(unittest.TestCase):
    def test_run_injects_noninteractive_sudo(self):
        """A worker's privileged command must never prompt for a password."""
        with patch.object(executor_mod.subprocess, "Popen",
                          side_effect=_popen_side_effect(stdout="ok\n")) as popen:
            output = run(["sudo", "containerlab", "version"])
        self.assertEqual(output, "ok\n")
        self.assertEqual(popen.call_args[0][0][:2], list(SUDO))

    def test_run_does_not_double_inject_noninteractive_sudo(self):
        with patch.object(executor_mod.subprocess, "Popen",
                          side_effect=_popen_side_effect(stdout="ok\n")) as popen:
            output = run(["sudo", "-n", "containerlab", "version"])
        self.assertEqual(output, "ok\n")
        self.assertEqual(popen.call_args[0][0], ["sudo", "-n", "containerlab", "version"])

    def test_run_timeout_kills_process_group_and_raises(self):
        with patch.object(executor_mod.subprocess, "Popen",
                          side_effect=_popen_side_effect(
                              stderr="containerlab deploy hung", timed_out=True
                          )) as popen, \
                patch.object(executor_mod.os, "killpg") as killpg, \
                patch.object(executor_mod.os, "getpgid", return_value=4242):
            with self.assertRaises(RuntimeError) as ctx:
                run(["sudo", "bash", "deploy-ipsec.sh", "deploy"],
                    timeout=5.0)
        self.assertIn("timed out after 5s", str(ctx.exception))
        self.assertIn("process group killed", str(ctx.exception))
        self.assertIn("containerlab deploy hung", str(ctx.exception))
        killpg.assert_called_once()
        args, kwargs = killpg.call_args
        self.assertEqual(args[0], 4242)
        self.assertEqual(args[1], signal.SIGKILL)


class TestRunErrorDetail(unittest.TestCase):
    def test_nonzero_exit_includes_stderr(self):
        with patch.object(
            executor_mod.subprocess, "Popen",
            side_effect=_popen_side_effect(
                returncode=1,
                stderr="Bridge \"br-wan\" referenced in topology "
                       "but does not exist\n"),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                run(["sudo", "containerlab", "deploy", "-t", "x.yml"])
        self.assertIn("Bridge \"br-wan\" referenced", str(ctx.exception))

    def test_nonzero_exit_falls_back_to_stdout(self):
        with patch.object(
            executor_mod.subprocess, "Popen",
            side_effect=_popen_side_effect(
                returncode=1, stdout="some diagnostic"),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                run(["sudo", "nope"])
        self.assertIn("some diagnostic", str(ctx.exception))

    def test_zero_exit_returns_stdout(self):
        with patch.object(
            executor_mod.subprocess, "Popen",
            side_effect=_popen_side_effect(stdout="done\n"),
        ):
            self.assertEqual(run(["sudo", "echo", "done"]), "done\n")


class TestSudoAuthFailureIsFatal(unittest.TestCase):
    def test_sudo_auth_failure_maps_to_fatal_topology_error(self):
        """Missing non-interactive privilege must fail the deploy fast and
        surface real sudo stderr, never hang the run in RUNNING."""
        with patch.object(executor_mod, "run", side_effect=RuntimeError(
            "Command failed with exit code 1: sudo: a password is required"
        )):
            with self.assertRaises(FatalTopologyError) as ctx:
                deploy("tunnel")
        self.assertIn("sudo: a password is required", str(ctx.exception))
        self.assertIn("FatalTopologyError", type(ctx.exception).__name__)


class TestDeployLifecycle(unittest.TestCase):
    def test_tunnel_deploy_routes_through_lifecycle_script(self):
        with patch.object(executor_mod, "run") as mock_run:
            mock_run.return_value = "ok"
            deploy("tunnel")
        args, kwargs = mock_run.call_args
        self.assertEqual(args[0], ["sudo", "-n", "bash",
                                   str(LIFECYCLE_SCRIPT), "deploy"])
        self.assertEqual(kwargs["timeout"], executor_mod.LIFECYCLE_TIMEOUT)

    def test_tunnel_destroy_routes_through_lifecycle_script(self):
        with patch.object(executor_mod, "run") as mock_run:
            mock_run.return_value = "ok"
            destroy("tunnel")
        args, kwargs = mock_run.call_args
        self.assertEqual(args[0], ["sudo", "-n", "bash",
                                   str(LIFECYCLE_SCRIPT), "destroy"])
        self.assertEqual(kwargs["timeout"], executor_mod.DESTROY_TIMEOUT)

    def test_transport_deploy_stays_on_containerlab(self):
        with patch.object(executor_mod, "run") as mock_run:
            mock_run.return_value = "ok"
            deploy("transport")
        args, kwargs = mock_run.call_args
        self.assertEqual(args[0][0:3], ["sudo", "-n", "containerlab"])
        self.assertEqual(args[0][3], "deploy")
        self.assertTrue(str(args[0][5]).endswith("transport/ipsec.clab.yml"))
        self.assertEqual(kwargs["timeout"], executor_mod.LIFECYCLE_TIMEOUT)

    def test_transport_destroy_stays_on_containerlab(self):
        with patch.object(executor_mod, "run") as mock_run:
            mock_run.return_value = "ok"
            destroy("transport")
        args, kwargs = mock_run.call_args
        self.assertEqual(args[0][0:3], ["sudo", "-n", "containerlab"])
        self.assertEqual(args[0][3], "destroy")
        self.assertIn("--cleanup", args[0])
        self.assertEqual(kwargs["timeout"], executor_mod.DESTROY_TIMEOUT)

    def test_deploy_failure_raises_fatal_topology_error(self):
        with patch.object(executor_mod, "run", side_effect=RuntimeError(
            "Command failed with exit code 1: Bridge br-wan missing"
        )):
            with self.assertRaises(FatalTopologyError) as ctx:
                deploy("tunnel")
        self.assertIn("Bridge br-wan missing", str(ctx.exception))

    def test_fatal_topology_error_is_runtime_error(self):
        self.assertTrue(issubclass(FatalTopologyError, RuntimeError))

    def test_reset_and_deploy_destroys_both_then_deploys(self):
        with patch.object(executor_mod, "destroy") as mock_destroy, \
                patch.object(executor_mod, "deploy") as mock_deploy:
            reset_and_deploy("tunnel")
        mock_destroy.assert_any_call("tunnel")
        mock_destroy.assert_any_call("transport")
        mock_deploy.assert_called_once_with("tunnel")


if __name__ == "__main__":
    unittest.main()