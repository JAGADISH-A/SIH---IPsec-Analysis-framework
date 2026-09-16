"""Campaign runner for IPsec testbed experiments.

Driven by a campaign.json that explicitly lists the configurations and
traffic profiles to run (no implicit Cartesian product).

Pipeline per experiment:

  DEPLOY/RESET TOPOLOGY -> GENERATE CONFIG -> START CAPTURE (IKE+ESP)
  -> LOAD CONFIG -> INITIATE IPsec -> VERIFY IPsec -> VERIFY CONNECTIVITY
  -> START LISTENER -> START TRAFFIC -> RUN DURATION -> STOP TRAFFIC
  -> STOP CAPTURE -> COPY PCAP -> EXTRACT FEATURES -> SAVE METADATA+LABEL

A failure in any step marks the experiment as failed, saves failure
metadata, cleans up and moves on to the next trial.

``execute_trial_pipeline`` exposes the exact same pipeline as a reusable
operation for the dataset executor (Module 3): it returns the artifacts
without saving them so the caller decides where they belong, and it raises on
any failure so the caller controls retry/commit.  ``cleanup_experiment`` is
the single shared best-effort teardown used by both runners.
"""

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

from .executor import (
    reset_and_deploy,
    load_generated_configs,
    initiate_ipsec,
    terminate_sas,
    verify_ipsec,
    test_connectivity,
    validate_config,
    destroy,
)
from . import traffic as traffic_mod
from . import capture as capture_mod
from . import features as features_mod
from . import dataset as dataset_mod
from . import timing as timing_mod
from . import reuse as reuse_mod

DEFAULT_CAMPAIGN = "campaign.json"

# Canonical capture default (IKE + ESP [+ AH]) lives in the capture layer;
# re-exported here so ``campaign.DEFAULT_CAPTURE_FILTER`` keeps working.
DEFAULT_CAPTURE_FILTER = capture_mod.DEFAULT_CAPTURE_FILTER

DEFAULT_PORT = 20000

# The capture now starts BEFORE the IKE initiation, so the tcpdump session
# must stay alive across the whole pre-initiate/verify/connectivity/setup
# window as well as the traffic duration.  This lead time is a safety margin
# on top of the traffic duration; stop_capture() terminates tcpdump early
# right after traffic ends so the pcap is flushed on schedule.
CAPTURE_LEAD_TIME = 60


def load_campaign(path):
    campaign = json.loads(Path(path).read_text())
    experiments = campaign.get("experiments")
    if not isinstance(experiments, list) or not experiments:
        raise ValueError("campaign.json must contain a non-empty 'experiments' list")
    for cfg in experiments:
        for key in ("mode", "address_family", "ike", "esp", "traffic"):
            if key not in cfg:
                raise ValueError(f"experiment missing '{key}': {cfg}")
        validate_config(cfg)
    return campaign


def cleanup_experiment(runtime_ctx, mode, tmp_dir=None, skip_destroy=False):
    """Best-effort, idempotent teardown of one attempt's testbed resources.

    Shared by the campaign runner and the dataset executor so that no second,
    independent cleanup implementation exists.  Never raises.

    ``skip_destroy=True`` keeps the containerlab topology alive (used by the
    dataset executor when the next sample can reuse it); the temp dir and
    traffic receivers are still cleaned up.
    """
    containers = (
        (runtime_ctx.get("source_container"), runtime_ctx.get("destination_container"))
        if isinstance(runtime_ctx, dict)
        else (None, None)
    )
    for container in containers:
        if container:
            try:
                traffic_mod.stop_receiver(container)
            except Exception:
                pass
    if not skip_destroy:
        try:
            destroy(mode)
        except Exception:
            pass
    if tmp_dir is not None:
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass


def execute_trial_pipeline(experiment_id, config, traffic_cfg, tmp_dir,
                           run_id=None, log=None, recorder=None, reuse=None):
    """Run one complete sample pipeline and return its artifacts.

    Additive Module-10 seam: ``reuse`` is an optional
    ``reuse_mod.TopologyReuseManager``.  When ``None`` (the default) this
    function is byte-for-byte behaviourally identical to an uninstrumented
    run: every sample performs a full ``reset_and_deploy(mode)``.  When
    provided, consecutive dataset samples sharing the SAME containerlab
    topology identity (``mode``) are served by an in-place StrongSwan
    reset+reinitiate instead of a fresh destroy+deploy.  The reuse manager
    never widens PASS criteria and falls back to a full fresh deployment on
    any verification failure (see controller/reuse.py).

    ``recorder`` is an optional, purely additive ``timing_mod.TimingRecorder``
    (default ``None``).  When ``None`` every ``timing_mod.stage`` block below
    is a ``nullcontext`` and this function is byte-for-byte behaviourally
    identical to an uninstrumented run.  When provided it only *records*
    monotonic per-stage durations; nothing downstream reads them and the
    recorder never influences the pipeline's control flow or a failure path.

    Exact success criteria (all must hold):

      * topology is deployed and the generated configs are loaded,
      * IPsec verification passes (IKE ESTABLISHED, CHILD INSTALLED, right
        mode), ``verify_ipsec`` raises otherwise,
      * connectivity probe is PASS,
      * the traffic sender returns PASS,
      * the capture contains at least one ESP packet.

    Returns a dict with ``status == "PASS"`` plus the experiment metadata,
    extracted features, traffic log, local pcap path and the IPsec /
    connectivity verification results.  Raises on any failure; the caller
    (``run_trial`` or the dataset executor) is responsible for cleanup.
    Nothing is written to the global dataset or any persistent store here.
    """
    log = log or (lambda msg: None)
    profile = traffic_cfg["profile"]
    duration = float(traffic_cfg.get("duration", 30.0))
    port = int(traffic_cfg.get("port", DEFAULT_PORT))
    capture_filter = traffic_cfg.get("capture_filter", DEFAULT_CAPTURE_FILTER)
    mode = config["mode"]
    address_family = config["address_family"]

    tmp_dir = Path(tmp_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    remote_pcap = f"/tmp/{experiment_id}.pcap"

    runtime_ctx = traffic_mod.runtime(mode, address_family)
    cap_container, cap_wan_ip = capture_mod.capture_facing(mode, address_family)
    runtime_ctx["capture_container"] = cap_container
    runtime_ctx["capture_interface"] = None

    capture_seconds = int(duration) + CAPTURE_LEAD_TIME

    def start_ipsec_capture():
        """Resolve the live WAN interface and start the IKE+ESP capture.

        Started immediately after deploy (fresh) or after the config reload
        (reuse), i.e. BEFORE the swanctl initiate, so the negotiation itself
        (IKE_SA_INIT/IKE_AUTH) lands in the pcap ahead of the ESP data.
        """
        cap_iface = capture_mod.detect_capture_interface(cap_container, cap_wan_ip)
        runtime_ctx["capture_interface"] = cap_iface
        log(f"capture interface {cap_container}:{cap_iface} verified (WAN {cap_wan_ip})")
        capture_mod.start_capture(
            cap_container, cap_iface, remote_pcap,
            seconds=capture_seconds, filter_expr=capture_filter,
        )
        log(f"capture started on {cap_container}:{cap_iface} ({capture_filter})")

    result = reuse_mod.reset_and_deploy_or_reuse(
        mode,
        address_family,
        reuse_manager=reuse,
        fresh_fn=reset_and_deploy,
        terminate_fn=lambda: terminate_sas(mode, address_family),
        load_fn=lambda: load_generated_configs(config),
        initiate_fn=lambda: initiate_ipsec(mode, address_family),
        verify_fn=lambda: verify_ipsec(mode, address_family),
        before_initiate_fn=start_ipsec_capture,
        recorder=recorder,
        log=log,
    )
    if result.get("reused"):
        ipsec = result["ipsec"]
    else:
        start_ipsec_capture()
        load_generated_configs(config)
        initiate_ipsec(mode, address_family)
        ipsec = verify_ipsec(mode, address_family)
    log("IPsec status IKE=ESTABLISHED CHILD=INSTALLED")

    connectivity = test_connectivity(mode, address_family)
    if connectivity["status"] != "PASS":
        raise RuntimeError(f"connectivity verification failed: {connectivity}")
    log("connectivity verified PASS")

    traffic_mod.copy_trafficgen(runtime_ctx["source_container"])
    traffic_mod.copy_trafficgen(runtime_ctx["destination_container"])

    traffic_mod.start_receiver(
        runtime_ctx["destination_container"],
        runtime_ctx["destination_ip"],
        port=port,
        duration=duration + 10,
    )
    log("traffic listener started")
    traffic_mod.wait_receiver(
        runtime_ctx["source_container"],
        runtime_ctx["destination_ip"],
        port=port,
    )
    log("traffic listener ready")

    log(f"traffic started ({profile}: {duration:.0f}s)")
    traffic_log, sender_status = traffic_mod.run_sender(
        runtime_ctx["source_container"], profile,
        runtime_ctx["destination_ip"], port=port, duration=duration,
    )
    log("traffic stopped")
    if sender_status != "PASS":
        raise RuntimeError("traffic generation failed")

    traffic_mod.stop_receiver(runtime_ctx["destination_container"])
    capture_mod.stop_capture(cap_container, remote_pcap)
    pcap_path = tmp_dir / "capture.pcap"
    capture_mod.copy_capture(cap_container, remote_pcap, pcap_path)
    log("capture stopped")

    fs_extract = features_mod.extract_features(
        pcap_path, capture_ip=cap_wan_ip, nominal_duration=duration,
    )
    log(f"features extracted packet_count={fs_extract['packet_count']}")

    if fs_extract["packet_count"] == 0:
        raise RuntimeError("capture contains no ESP packets")

    traffic = {
        "profile": profile,
        "duration": duration,
        "port": port,
        "capture_filter": capture_filter,
        "traffic_model": traffic_mod.resolve_traffic_model(profile, duration, port),
    }
    metadata = dataset_mod.build_metadata(
        experiment_id, config, traffic, runtime_ctx,
        run_id=run_id, ipsec=ipsec, connectivity=connectivity,
        status="PASS",
    )

    return {
        "status": "PASS",
        "experiment_id": experiment_id,
        "metadata": metadata,
        "features": fs_extract,
        "traffic_log": traffic_log,
        "pcap_path": pcap_path,
        "ipsec": ipsec,
        "connectivity": connectivity,
        "runtime_ctx": runtime_ctx,
        "capture_wan_ip": cap_wan_ip,
    }


def run_trial(seq, campaign_cfg, results_root):
    cfg = campaign_cfg["experiments"][seq - 1]
    run_id = campaign_cfg.get("run_id") or time.strftime("%Y%m%d-%H%M%S")
    tag = f"EXP-{seq:04d}"
    experiment_id = f"{run_id}-exp-{seq:04d}"

    traffic_cfg = cfg["traffic"]
    mode = cfg["mode"]
    address_family = cfg["address_family"]

    results_root = Path(results_root)
    tmp_dir = results_root / ".tmp" / experiment_id
    runtime_ctx = {"source_container": None, "destination_container": None}

    def log(msg):
        print(f"[{tag}] {msg}", flush=True)

    log(f"configuration mode={mode} family={address_family} "
        f"ike={cfg['ike']['encryption']}-{cfg['ike']['integrity']}-{cfg['ike']['dh_group']} "
        f"esp={cfg['esp']['encryption']}-{cfg['esp']['integrity']}-{cfg['esp']['dh_group']} "
        f"pfs={cfg['esp']['pfs']}")
    log(f"traffic profile {traffic_cfg['profile']} duration={traffic_cfg.get('duration', 30.0)}s "
        f"port={traffic_cfg.get('port', DEFAULT_PORT)}")

    try:
        outcome = execute_trial_pipeline(
            experiment_id, cfg, traffic_cfg, tmp_dir,
            run_id=run_id, log=log,
        )
        dataset_mod.save_experiment(
            results_root, experiment_id, outcome["metadata"],
            outcome["features"], outcome["traffic_log"],
            pcap_source=outcome["pcap_path"],
        )
        log("dataset saved")
        return {"experiment_id": experiment_id, "status": "PASS"}

    except Exception as exc:
        log(f"FAILED: {exc}")
        metadata = dataset_mod.build_metadata(
            experiment_id, cfg, traffic_cfg, runtime_ctx,
            run_id=run_id, status="FAILED", error=str(exc),
        )
        dataset_mod.save_failure(results_root, experiment_id, metadata, repr(exc))
        log("failure metadata saved")
        return {"experiment_id": experiment_id, "status": "FAILED", "error": str(exc)}

    finally:
        cleanup_experiment(runtime_ctx, mode, tmp_dir)
        log("cleanup complete")


def main(argv=None):
    parser = argparse.ArgumentParser(description="IPsec testbed campaign runner")
    parser.add_argument("--campaign", default=DEFAULT_CAMPAIGN, help="campaign.json path")
    parser.add_argument("--results-root", default=dataset_mod.DEFAULT_RESULTS_ROOT,
                        help="directory under which experiments are written")
    parser.add_argument("--max-experiments", type=int, default=None,
                        help="run at most this many experiments from the campaign")
    args = parser.parse_args(argv)

    campaign = load_campaign(args.campaign)
    run_id = campaign.get("run_id") or time.strftime("%Y%m%d-%H%M%S")
    total = len(campaign["experiments"])
    if args.max_experiments is not None:
        total = min(total, args.max_experiments)
    print(f"\n=== Campaign run {run_id}: {total} experiment(s) ===")
    print(f"Campaign file: {args.campaign}")
    print(f"Results root:  {args.results_root}\n")

    outcomes = []
    for seq in range(1, total + 1):
        outcome = run_trial(seq, campaign, args.results_root)
        outcomes.append(outcome)

    passed = sum(1 for o in outcomes if o["status"] == "PASS")
    print("\n=== Campaign summary ===")
    for o in outcomes:
        print(f"  {o['experiment_id']}: {o['status']}"
              + (f" ({o['error']})" if o.get("error") else ""))
    print(f"  passed {passed}/{total}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())