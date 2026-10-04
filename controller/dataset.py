"""Dataset persistence for IPsec testbed experiments.

Layout (per campaign run):

  results/<experiment_id>/metadata.json
  results/<experiment_id>/features.json
  results/<experiment_id>/traffic.log
  results/<experiment_id>/capture.pcap

Aggregate:

  results/dataset/features.csv
  results/dataset/metadata.jsonl
"""

import csv
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from . import capture as capture_mod

DEFAULT_RESULTS_ROOT = "results"

FEATURE_COLUMNS = [
    "packet_count", "total_bytes", "mean_packet_size", "packet_size_std",
    "min_packet_size", "max_packet_size",
    "packet_size_p10", "packet_size_p50", "packet_size_p90",
    "packet_size_p95", "packet_size_p99",
    "unique_packet_size_count", "packet_size_entropy",
    "small_packet_ratio", "large_packet_ratio",
    "outbound_packet_count", "inbound_packet_count",
    "outbound_bytes", "inbound_bytes",
    "outbound_packet_ratio", "inbound_packet_ratio",
    "outbound_byte_ratio", "inbound_byte_ratio",
    "outbound_mean_packet_size", "inbound_mean_packet_size",
    "outbound_packets_per_second", "inbound_packets_per_second",
    "outbound_packet_size_p10", "outbound_packet_size_p50",
    "outbound_packet_size_p90", "outbound_packet_size_p95",
    "outbound_packet_size_p99",
    "inbound_packet_size_p10", "inbound_packet_size_p50",
    "inbound_packet_size_p90", "inbound_packet_size_p95",
    "inbound_packet_size_p99",
    "mean_inter_arrival_time", "inter_arrival_time_std",
    "min_inter_arrival_time", "max_inter_arrival_time",
    "packets_per_second", "bytes_per_second", "flow_duration",
    "burst_count", "mean_burst_packets", "mean_burst_duration",
    "burst_packet_ratio",
    "burst_count_10ms", "burst_count_50ms", "burst_count_200ms",
    "mean_burst_packets_10ms", "mean_burst_packets_50ms",
    "mean_burst_packets_200ms",
]

META_COLUMNS = [
    "run_id", "experiment_id", "timestamp", "status", "mode", "address_family",
    "ike_version", "ike_encryption", "ike_integrity", "ike_dh",
    "esp_encryption", "esp_integrity", "esp_dh", "pfs",
    "traffic_type", "traffic_duration",
]

DATASET_PATH = "dataset"


def utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


def build_metadata(experiment_id, config, traffic, runtime_ctx, run_id=None,
                   ipsec=None, connectivity=None, status="PASS", error=None,
                   timestamp=None):
    metadata = {
        "run_id": run_id,
        "experiment_id": experiment_id,
        "timestamp": timestamp or utcnow_iso(),
        "status": status,
        "mode": config["mode"],
        "address_family": config["address_family"],
        # NAT-T is a property of the PATH, not of the IPsec mode, so it is
        # recorded as its own axis.  Without it a NAT-T sample is
        # indistinguishable from the direct transport sample in the dataset,
        # and its ESP length distribution would be silently attributed to the
        # direct deployment.
        "nat": bool(config.get("nat", False)),
        "ike_version": config["ike"]["version"],
        "ike_encryption": config["ike"]["encryption"],
        "ike_integrity": config["ike"]["integrity"],
        "ike_dh": config["ike"]["dh_group"],
        "esp_encryption": config["esp"]["encryption"],
        "esp_integrity": config["esp"]["integrity"],
        "esp_dh": config["esp"]["dh_group"],
        "pfs": config["esp"]["pfs"],
        "traffic_type": traffic["profile"],
        "traffic_duration": traffic["duration"],
        "traffic_port": traffic.get("port", 20000),
        "capture_filter": traffic.get("capture_filter", capture_mod.DEFAULT_CAPTURE_FILTER),
        "traffic_model": traffic.get("traffic_model"),
        "source_container": runtime_ctx.get("source_container"),
        "source_ip": runtime_ctx.get("source_ip"),
        "destination_container": runtime_ctx.get("destination_container"),
        "destination_ip": runtime_ctx.get("destination_ip"),
        "capture_container": runtime_ctx.get("capture_container"),
        "capture_interface": runtime_ctx.get("capture_interface"),
    }
    if ipsec:
        metadata["ipsec"] = ipsec
    if connectivity:
        metadata["connectivity"] = connectivity
    if error:
        metadata["error"] = error
    return metadata


def save_experiment(results_root, experiment_id, metadata, features,
                    traffic_log, pcap_source=None):
    """Persist one experiment under results_root/<experiment_id>/."""
    results_root = Path(results_root)
    exp_dir = results_root / experiment_id
    exp_dir.mkdir(parents=True, exist_ok=True)

    (exp_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
    if traffic_log:
        (exp_dir / "traffic.log").write_text(traffic_log)
    if features:
        (exp_dir / "features.json").write_text(json.dumps(features, indent=2))
    if pcap_source:
        shutil.copy2(pcap_source, exp_dir / "capture.pcap")

    if features:
        append_aggregate(results_root, metadata, features)
    return exp_dir


def append_aggregate(results_root, metadata, features):
    """Append a row to the global dataset files."""
    results_root = Path(results_root)
    dataset_dir = results_root / DATASET_PATH
    dataset_dir.mkdir(parents=True, exist_ok=True)

    meta_path = dataset_dir / "metadata.jsonl"
    with open(meta_path, "a") as fh:
        fh.write(json.dumps(metadata) + "\n")

    csv_path = dataset_dir / "features.csv"
    row = {col: metadata.get(col) for col in META_COLUMNS}
    row.update({col: features.get(col) for col in FEATURE_COLUMNS})
    headers = META_COLUMNS + FEATURE_COLUMNS
    new_file = not csv_path.exists()
    with open(csv_path, "a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=headers)
        if new_file:
            writer.writeheader()
        writer.writerow(row)


def save_failure(results_root, experiment_id, metadata, error_trace):
    """Persist a failed experiment without polluting the labeled dataset."""
    results_root = Path(results_root)
    exp_dir = results_root / experiment_id
    exp_dir.mkdir(parents=True, exist_ok=True)
    (exp_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
    (exp_dir / "error.log").write_text(error_trace)
    return exp_dir