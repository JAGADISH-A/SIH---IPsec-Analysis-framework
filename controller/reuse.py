"""Additive StrongSwan/topology reuse manager for the dataset pipeline.

Module-10 implementation of the Module-9 design.  Additive and opt-in:

  * ``campaign.execute_trial_pipeline(..., reuse=None)`` — when ``reuse`` is
    ``None`` the pipeline is byte-for-byte the pre-module path (every sample
    runs a full ``reset_and_deploy(mode)`` === destroy + fresh containerlab
    deploy), exactly as before.  Reuse NEVER changes control flow for a path
    that does not ask for it.
  * When a ``TopologyReuseManager`` is provided, consecutive dataset samples
    that share the *containerlab identity* (``mode``) skip the containerlab
    destroy+deploy and instead perform a safe StrongSwan reset in place:

        swanctl --terminate --child <name>   kill CHILD SA
        swanctl --terminate --ike  <name>    kill IKE SA  (guarantees the old
                                             proposal/SA cannot persist)
        swanctl --load-conns --file <cfg>    load new generated conns
        swanctl --initiate --child  <name>   establish the new SA
        verify_ipsec(mode, address_family)   verify new selectors/family/proposal

    ``address_family`` is config-only in this codebase (the containerlab
    topology file depends ONLY on ``mode``; both address families live in the
    same containers and both selector families are pinned at deploy time), so
    family transitions are reusable in place.  Any StrongSwan/verify failure
    during reuse falls back to a full fresh ``reset_and_deploy`` for THAT
    sample (never a silent stale reuse, never a wrong proposal labeled PASS).

Nothing in this module writes to the dataset, the executor's planner, capture
isolation, features, the frontend, or the API.
"""

from __future__ import annotations

import time
from pathlib import Path

from . import executor as executor_mod
from . import topology as topology_mod
from . import timing as timing_mod


def topology_identity(mode, address_family):
    """The containerlab identity.

    Authoritative (verified against ``controller/topology.py`` and the two
    ``.clab.yml`` files): the containerlab deployment differs ONLY by ``mode``
    (``tunnel`` | ``transport``).  ``address_family`` selects config-only
    (generated strongSwan selectors/capture facing/labels) that both families
    already coexist in the same deployed containers.

    We therefore key reuse on ``mode`` and treat family as a config reload.
    """
    return mode


class TopologyReuseManager:
    """Stateful, deterministic reuse decision for a dataset run.

    Owns the previous sample's topology identity plus per-sample timings (an
    injectable ``timing.TimingRecorder`` for the reset path, default None =
    no timing side effects).  The manager NEVER influences which samples are
    planned or their ordering; it only decides, at execute time,
    deploy-fresh vs reuse-in-place for the CURRENT sample.
    """

    def __init__(self, log=None, clock=None):
        self.log = log or (lambda msg: None)
        self.clock = clock or time.monotonic
        self._prev_identity = None
        self._reused_count = 0
        self._deploy_count = 0
        self._fallbacks = 0

    # -- additive reporting (never affects control flow) -------------------
    def stats(self):
        return {
            "reused": self._reused_count,
            "fresh_deploy": self._deploy_count,
            "fallback_after_reuse_failure": self._fallbacks,
            "last_topology_identity": self._prev_identity,
        }

    # -- decision -----------------------------------------------------------
    def can_reuse(self, mode):
        """True iff the previous sample's containerlab identity survives.

        Only ``mode`` is structural here.  Family/ESP/DH/PFS changes are all
        config-only reloads (see design) and are handled by the reset-and-
        reinitiate path, not by a fresh deploy.
        """
        if self._prev_identity is None:
            return False
        return self._prev_identity == mode

    # -- execution stages (delegated; each delegates to campaign/executor) ---
    def reset_and_deploy(self, mode, address_family, mode_func):
        """Full fresh path — the original pipeline, unchanged.

        The topology identity is recorded ONLY AFTER the fresh deployment
        succeeds: a failed ``mode_func`` propagates and must not mark the
        containers as reusable.
        """
        result = mode_func()
        self._deploy_count += 1
        self._prev_identity = topology_identity(mode, address_family)
        return result

    def reuse_and_reinitiate(self, mode, address_family, *, terminate_fn,
                             load_fn, initiate_fn, verify_fn, recorder=None,
                             before_initiate_fn=None):
        """In-place StrongSwan reset+rereinitiate with strong fallback.

        Safe order (see docs/architecture/MODULE9_DESIGN.md §4):

          1. terminate every active CHILD SA
          2. terminate the IKE SA (so no old proposal can survive)
          3. load the new generated configs
          4. start the IKE+ESP capture (``before_initiate_fn``), so the fresh
             negotiation below is observed
          5. initiate the new CHILD SA
          6. re-verify IPsec against the new selectors/family/proposal

        Any failure at ANY stage → the caller (campaign) falls back to a
        full fresh ``reset_and_deploy`` for this sample; never a stale SA
        silently marked PASS.  The real ``verify_fn()`` result is returned
        (not collapsed into a boolean); if ``verify_fn`` raises, the
        exception propagates to the caller's fallback handling.
        """
        with timing_mod.stage(recorder, "sa_reset"):
            terminate_fn()
        with timing_mod.stage(recorder, "sa_reload"):
            load_fn()
        if before_initiate_fn is not None:
            before_initiate_fn()
        with timing_mod.stage(recorder, "sa_initiate"):
            initiate_fn()
        verify_result = verify_fn()
        if not verify_result:
            raise ReuseVerificationError(
                "reused SA failed verification; will fall back to fresh deploy"
            )
        self._reused_count += 1
        self._prev_identity = topology_identity(mode, address_family)
        self.log(
            f"REUSE mode={mode} family={address_family} "
            f"in-place SA reset+reinitiate verified"
        )
        return verify_result


class ReuseVerificationError(RuntimeError):
    """Raised when a reused (in-place) SA fails the same verification that a
    fresh deploy must pass.  The trial is retried via fresh deploy — reuse
    is never allowed to weaken a sample's success criteria."""


def reset_and_deploy_or_reuse(mode, address_family, *, reuse_manager=None,
                              fresh_fn=None, recorder=None, log=None,
                              terminate_fn=None, load_fn=None,
                              initiate_fn=None, verify_fn=None,
                              before_initiate_fn=None):
    """Module-10 seam: deploy-fresh OR reuse-in-place, decided by the manager.

    Additive dispatch used by the (reuse-aware) dataset execution path.  It
    delegates to ``executor.reset_and_deploy(mode)`` whenever a reuse manager
    is not supplied (or reuse is ruled out), i.e. the default remains
    byte-for-byte the historical fresh destroy+deploy behaviour (identical to
    calling ``campaign.reset_and_deploy(mode)`` directly).

    ``reuse_manager`` is the persistent, per-dataset-run
    ``TopologyReuseManager``.  This function NEVER creates the manager; its
    lifetime is owned by ``dataset_executor.execute_dataset_run`` so that
    ``_prev_identity`` survives across consecutive samples of the SAME run.

    When reuse is attempted, the full lifecycle runs in order:
    ``terminate_fn`` -> ``load_fn`` -> ``before_initiate_fn`` (capture start
    for IKE+ESP, optional) -> ``initiate_fn`` -> ``verify_fn`` and any failure
    falls back to a full fresh deployment through ``fresh_fn``.  A failed
    reuse is never counted as a successful sample by itself.
    """
    log = log or (lambda msg: None)

    if reuse_manager is None:
        if fresh_fn is None:
            raise ValueError(
                "reset_and_deploy_or_reuse requires fresh_fn when reuse is disabled"
            )
        fresh_fn(mode)
        return {"reused": False, "identity": topology_identity(mode, address_family)}

    if fresh_fn is None:
        raise ValueError("reset_and_deploy_or_reuse requires fresh_fn")

    if reuse_manager.can_reuse(mode) and all(
        fn is not None
        for fn in (terminate_fn, load_fn, initiate_fn, verify_fn)
    ):
        try:
            verify_result = reuse_manager.reuse_and_reinitiate(
                mode, address_family,
                terminate_fn=terminate_fn,
                load_fn=load_fn,
                initiate_fn=initiate_fn,
                verify_fn=verify_fn,
                recorder=recorder,
                before_initiate_fn=before_initiate_fn,
            )
        except Exception as exc:
            reuse_manager._fallbacks += 1
            log(
                f"reuse failed ({type(exc).__name__}: {exc}) -> "
                f"fresh reset_and_deploy({mode})"
            )
            reuse_manager.reset_and_deploy(
                mode, address_family, mode_func=lambda: fresh_fn(mode),
            )
            return {"reused": False, "identity": topology_identity(mode, address_family)}
        log(f"reused containers (mode={mode}) -> in-place StrongSwan reinit OK")
        return {
            "reused": True,
            "identity": topology_identity(mode, address_family),
            "ipsec": verify_result,
        }

    log(f"reuse not possible -> fresh reset_and_deploy({mode})")
    reuse_manager.reset_and_deploy(
        mode, address_family, mode_func=lambda: fresh_fn(mode),
    )
    return {"reused": False, "identity": topology_identity(mode, address_family)}
