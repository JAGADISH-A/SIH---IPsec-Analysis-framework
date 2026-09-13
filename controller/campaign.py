"""Campaign runner for IPsec testbed experiments.

Driven by a campaign.json that explicitly lists the configurations and
traffic profiles to run (no implicit Cartesian product).

Pipeline per experiment:

  DEPLOY/RESET TOPOLOGY -> GENERATE CONFIG -> LOAD CONFIG -> INITIATE IPsec
  -> VERIFY IPsec -> VERIFY CONNECTIVITY -> START CAPTURE -> START LISTENER
  -> START TRAFFIC -> RUN DURATION -> STOP TRAFFIC -> STOP CAPTURE
  -> COPY PCAP -> EXTRACT FEATURES -> SAVE METADATA+LABEL -> CLEAN UP

A failure in any step marks the experiment as failed, saves failure
metadata, cleans up and moves on to the next trial.
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
    verify_ipsec,
    test_connectivity,
    validate_config,
)
from . import traffic as traffic_mod
from . import capture as capture_mod
from . import features as features_mod
from . import dataset as dataset_mod

DEFAULT_CAMPAIGN = "campaign.json"
DEFAULT_CAPTURE_FILTER = "esp"
DEFAULT_PORT = 20000


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


def run_trial(seq, campaign_cfg, results_root):
    cfg = campaign_cfg["experiments"][seq - 1]
    run_id = campaign_cfg.get("run_id") or time.strftime("%Y%m%d-%H%M%S")
    tag = f"EXP-{seq:04d}"
    experiment_id = f"{run_id}-exp-{seq:04d}"

    traffic_cfg = cfg["traffic"]
    profile = traffic_cfg["profile"]
    duration = float(traffic_cfg.get("duration", 30.0))
    port = int(traffic_cfg.get("port", DEFAULT_PORT))
    capture_filter = traffic_cfg.get("capture_filter", DEFAULT_CAPTURE_FILTER)
    mode = cfg["mode"]
    address_family = cfg["address_family"]

    def log(msg):
        print(f"[{tag}] {msg}", flush=True)

    log(f"configuration mode={mode} family={address_family} "
        f"ike={cfg['ike']['encryption']}-{cfg['ike']['integrity']}-{cfg['ike']['dh_group']} "
        f"esp={cfg['esp']['encryption']}-{cfg['esp']['integrity']}-{cfg['esp']['dh_group']} "
        f"pfs={cfg['esp']['pfs']}")
    log(f"traffic profile {profile} duration={duration:.0f}s port={port}")

    results_root = Path(results_root)
    tmp_dir = results_root / ".tmp" / experiment_id
    tmp_dir.mkdir(parents=True, exist_ok=True)
    remote_pcap = f"/tmp/{experiment_id}.pcap"

    runtime_ctx = traffic_mod.runtime(mode, address_family)
    cap_container, cap_wan_ip = capture_mod.capture_facing(mode, address_family)
    runtime_ctx["capture_container"] = cap_container
    runtime_ctx["capture_interface"] = None
    metadata = None
    try:
        reset_and_deploy(mode)
        load_generated_configs(cfg)
        initiate_ipsec(mode, address_family)
        ipsec = verify_ipsec(mode, address_family)
        log("IPsec status IKE=ESTABLISHED CHILD=INSTALLED")

        connectivity = test_connectivity(mode, address_family)
        if connectivity["status"] != "PASS":
            raise RuntimeError(f"connectivity verification failed: {connectivity}")
        log("connectivity verified PASS")

        traffic_mod.copy_trafficgen(runtime_ctx["source_container"])
        traffic_mod.copy_trafficgen(runtime_ctx["destination_container"])

        cap_iface = capture_mod.detect_capture_interface(cap_container, cap_wan_ip)
        runtime_ctx["capture_interface"] = cap_iface
        log(f"capture interface {cap_container}:{cap_iface} verified (WAN {cap_wan_ip})")

        capture_mod.start_capture(
            cap_container, cap_iface, remote_pcap,
            seconds=duration + 5, filter_expr=capture_filter,
        )
        log(f"capture started on {cap_container}:{cap_iface} ({capture_filter})")

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
        capture_mod.copy_capture(cap_container, remote_pcap, tmp_dir / "capture.pcap")
        log("capture stopped")

        fs_extract = features_mod.extract_features(
            tmp_dir / "capture.pcap",
            capture_ip=cap_wan_ip,
            nominal_duration=duration,
        )
        log(f"features extracted packet_count={fs_extract['packet_count']}")

        if fs_extract["packet_count"] == 0:
            raise RuntimeError("capture contains no ESP packets")

        metadata = dataset_mod.build_metadata(
            experiment_id, cfg, traffic_cfg, runtime_ctx,
            run_id=run_id, ipsec=ipsec, connectivity=connectivity,
            status="PASS",
        )
        dataset_mod.save_experiment(
            results_root, experiment_id, metadata, fs_extract,
            traffic_log, pcap_source=tmp_dir / "capture.pcap",
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
        for container in (
            runtime_ctx.get("source_container"),
            runtime_ctx.get("destination_container"),
        ):
            if container:
                try:
                    traffic_mod.stop_receiver(container)
                except Exception:
                    pass
        try:
            reset_and_deploy_destroy(mode)
        except Exception:
            pass
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass
        log("cleanup complete")


def reset_and_deploy_destroy(mode):
    """Best-effort topology teardown used during cleanup."""
    from .executor import destroy
    try:
        destroy(mode)
    except RuntimeError:
        pass


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