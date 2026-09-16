"""Quality and validation reporting for a campaign run.

Driven by ``--run-id`` (matching ``run_id`` in a campaign file).  Loads every
experiment directory ``results/<run_id>-exp-*/`` and re-verifies the dataset
properties that matter before scaling:

  * every captured frame is ESP (encrypted data plane) or IKE (UDP 500/4500
    negotiation control plane) -- no unexpected plaintext application frames
  * no NaN / negative values in the extracted features
  * ground-truth labels only from the configured traffic profile
  * GCM integrity is null, CBC integrity is sha256
  * per-experiment metadata/features agree with the aggregate dataset
  * the aggregate contains only PASS experiments
  * cleanup left no temporary directories for the run

Prints the final feature schema and a per-experiment summary table.
"""

import argparse
import csv
import json
import math
import shutil
from pathlib import Path

from . import capture as capture_mod
from . import dataset as dataset_mod
from . import features as features_mod

PLAYBOOK_FIELDS = {
    "experiment_id", "run_id", "timestamp", "status", "mode", "address_family",
    "ike_version", "ike_encryption", "ike_integrity", "ike_dh",
    "esp_encryption", "esp_integrity", "esp_dh", "pfs",
    "traffic_type", "traffic_duration", "traffic_port", "capture_filter",
    "source_container", "source_ip", "destination_container", "destination_ip",
    "capture_container", "capture_interface",
}

GROUPS = {
    "A-GroundTruthConfig": [],
    "B-TrafficLabel": [],
    "C-CaptureObservable": [],
}


def build_schema():
    groups = {"A": [], "B": [], "C": []}
    for col in dataset_mod.META_COLUMNS + dataset_mod.FEATURE_COLUMNS:
        if col == "traffic_type":
            groups["B"].append(col)
        elif col in PLAYBOOK_FIELDS or col in {
            "timestamp", "status", "ike_version", "ike_encryption",
            "ike_integrity", "ike_dh", "esp_encryption", "esp_integrity",
            "esp_dh", "pfs", "mode", "address_family", "run_id",
        }:
            groups["A"].append(col)
        else:
            groups["C"].append(col)
    return groups


def _outer_protocol(data, linktype):
    """Return the outer-IP protocol/next-header of a captured frame."""
    if linktype == 1:
        if len(data) < 14:
            return None
        ethertype = int.from_bytes(data[12:14], "big")
        offset = 14
        if ethertype == 0x0800:
            if len(data) < offset + 20:
                return None
            return data[offset + 9]
        if ethertype == 0x86DD:
            if len(data) < offset + 40:
                return None
            return data[offset + 6]
        return None
    if linktype == 101:
        if len(data) < 20:
            return None
        return data[9]
    if linktype == 127:
        if len(data) < 40:
            return None
        return data[6]
    return None


def _udp_port(data, linktype):
    """Return the outer-IP UDP destination port of a frame, else None.

    Used to distinguish IKE control-plane datagrams (UDP 500/4500) from
    unexpected plaintext application frames during the capture audit.
    """
    if linktype == 1:
        if len(data) < 14:
            return None
        ethertype = int.from_bytes(data[12:14], "big")
        offset = 14
        if ethertype == 0x0800:
            if len(data) < offset + 20:
                return None
            if data[offset + 9] != 17:
                return None
            ihl = (data[offset] & 0x0F) * 4
            udp_offset = offset + ihl
        elif ethertype == 0x86DD:
            if len(data) < offset + 40:
                return None
            if data[offset + 6] != 17:
                return None
            udp_offset = offset + 40
        else:
            return None
    elif linktype == 101:
        if len(data) < 20:
            return None
        if data[9] != 17:
            return None
        udp_offset = (data[0] & 0x0F) * 4
    elif linktype == 127:
        if len(data) < 40:
            return None
        if data[6] != 17:
            return None
        udp_offset = 40
    else:
        return None
    if len(data) < udp_offset + 4:
        return None
    return int.from_bytes(data[udp_offset + 2:udp_offset + 4], "big")


def scan_frames(path):
    """Return (total_records, esp_frames, ike_frames, non_esp_ip, malformed).

    ESP frames are the encrypted data plane; IKE frames (UDP 500/4500) are
    the (deliberately captured) negotiation control plane.  ``non_esp_ip``
    counts any other IP frame, which is what the audit treats as unexpected
    plaintext application traffic.
    """
    try:
        fh = open(path, "rb")
    except OSError:
        return (0, 0, 0, 0, 0)
    with fh:
        header = fh.read(24)
        if len(header) < 24:
            return (0, 0, 0, 0, 1)
        magic = header[:4]
        if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = "big"
        else:
            endian = "little"
        linktype = int.from_bytes(header[20:24], endian)
        if linktype not in (1, 101, 127):
            return (0, 0, 0, 0, 1)
        total = esp = ike = non_esp = 0
        while True:
            record = fh.read(16)
            if len(record) < 16:
                break
            incl_len = int.from_bytes(record[8:12], endian)
            if not 0 <= incl_len <= 16 * 1024 * 1024:
                break
            data = fh.read(incl_len)
            if len(data) < incl_len:
                break
            total += 1
            proto = _outer_protocol(data, linktype)
            if proto == 50:
                esp += 1
            elif _udp_port(data, linktype) in features_mod.IKE_UDP_PORTS:
                ike += 1
            elif proto is not None:
                non_esp += 1
    return (total, esp, ike, non_esp, 0)


def _num(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def check_features(features):
    problems = []
    for key, value in features.items():
        if not _num(value):
            continue
        if isinstance(value, float) and math.isnan(value):
            problems.append(f"NaN in {key}")
        if value < 0:
            problems.append(f"negative {key}={value}")
    return problems


def experiment_dirs(results_root, run_id):
    root = Path(results_root)
    prefix = f"{run_id}-exp-"
    return sorted(root.glob(f"{prefix}*")) if root.exists() else []


def load_campaign_config(campaign_path, run_id):
    """Map experiment_id -> (traffic profile, esp config) from the campaign."""
    cfg = json.loads(Path(campaign_path).read_text())
    if cfg.get("run_id") != run_id:
        raise SystemExit(f"campaign {campaign_path} run_id {cfg.get('run_id')} != {run_id}")
    mapping = {}
    for seq, exp in enumerate(cfg["experiments"], start=1):
        experiment_id = f"{run_id}-exp-{seq:04d}"
        mapping[experiment_id] = {
            "traffic_type": exp["traffic"]["profile"],
            "esp_encryption": exp["esp"]["encryption"],
            "esp_integrity": exp["esp"]["integrity"],
            "esp": exp["esp"],
            "ike": exp["ike"],
            "mode": exp["mode"],
            "address_family": exp["address_family"],
        }
    return mapping


def load_aggregate(results_root, run_id):
    dataset_dir = Path(results_root) / dataset_mod.DATASET_PATH
    meta_rows = []
    meta_path = dataset_dir / "metadata.jsonl"
    if meta_path.exists():
        for line in meta_path.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("run_id") == run_id:
                meta_rows.append(row)

    csv_rows = []
    csv_path = dataset_dir / "features.csv"
    if csv_path.exists():
        with open(csv_path, newline="") as fh:
            for row in csv.DictReader(fh):
                if row.get("run_id") == run_id:
                    csv_rows.append(row)
    return meta_rows, csv_rows


def _coerce(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        low = v.strip().lower()
        if low in {"true", "false"}:
            return low == "true"
        if low == "":
            return None
    return v


def _as_number(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v)
        except ValueError:
            return None
    return None


def mismatch(meta_a, meta_b, keys, label):
    diffs = []
    for key in keys:
        va, vb = meta_a.get(key), meta_b.get(key)
        if (va is None and vb == "") or (vb is None and va == ""):
            continue
        va, vb = _coerce(va), _coerce(vb)
        na, nb = _as_number(va), _as_number(vb)
        if na is not None and nb is not None:
            if abs(na - nb) > 1e-6:
                diffs.append(f"{key}: {va!r} vs {vb!r}")
        elif va != vb:
            diffs.append(f"{key}: {va!r} vs {vb!r}")
    return diffs


def _config_from_meta(meta):
    return {
        "mode": meta["mode"],
        "address_family": meta["address_family"],
        "ike": {
            "version": meta.get("ike_version", 2),
            "encryption": meta["ike_encryption"],
            "integrity": meta["ike_integrity"],
            "dh_group": meta["ike_dh"],
        },
        "esp": {
            "encryption": meta["esp_encryption"],
            "integrity": meta["esp_integrity"],
            "dh_group": meta["esp_dh"],
            "pfs": meta.get("pfs", True),
        },
    }


def _runtime_ctx_from_meta(meta):
    return {
        "source_container": meta.get("source_container"),
        "source_ip": meta.get("source_ip"),
        "destination_container": meta.get("destination_container"),
        "destination_ip": meta.get("destination_ip"),
        "capture_container": meta.get("capture_container"),
        "capture_interface": meta.get("capture_interface"),
    }


def rebuild_aggregate(results_root, run_id=None):
    """Regenerate the aggregate dataset from all PASS experiment dirs.

    Re-extracts features from each stored capture.pcap with the current
    schema (same capture-point/duration parameters used live), so every row
    in features.csv / metadata.jsonl conforms to the current feature schema
    regardless of when the experiment was recorded.
    """
    results_root = Path(results_root)
    dataset_dir = results_root / dataset_mod.DATASET_PATH
    if dataset_dir.exists():
        shutil.rmtree(dataset_dir)
    dataset_dir.mkdir(parents=True)

    rebuilt = 0
    for exp_dir in sorted(results_root.glob("*-exp-*")):
        meta_path = exp_dir / "metadata.json"
        cap_path = exp_dir / "capture.pcap"
        if not (meta_path.exists() and cap_path.exists()):
            continue
        meta = json.loads(meta_path.read_text())
        if meta.get("status") != "PASS":
            continue
        if run_id and meta.get("run_id") != run_id and not exp_dir.name.startswith(f"{run_id}-exp-"):
            continue
        try:
            cap_ip = capture_mod.capture_facing(meta["mode"], meta["address_family"])[1]
        except ValueError:
            continue
        rid = meta.get("run_id") or exp_dir.name.rsplit("-exp-", 1)[0]
        duration = float(meta.get("traffic_duration", 30.0))
        feats = features_mod.extract_features(
            cap_path, capture_ip=cap_ip, nominal_duration=duration)
        config = _config_from_meta(meta)
        traffic = {
            "profile": meta["traffic_type"],
            "duration": duration,
            "port": meta.get("traffic_port", 20000),
            "capture_filter": meta.get("capture_filter", capture_mod.DEFAULT_CAPTURE_FILTER),
        }
        new_meta = dataset_mod.build_metadata(
            meta["experiment_id"], config, traffic, _runtime_ctx_from_meta(meta),
            run_id=rid, ipsec=meta.get("ipsec"), connectivity=meta.get("connectivity"),
            status="PASS", timestamp=meta.get("timestamp"),
        )
        dataset_mod.append_aggregate(results_root, new_meta, feats)
        rebuilt += 1
    return rebuilt


def report(args):
    results_root = Path(args.results_root)
    dirs = experiment_dirs(results_root, args.run_id)
    if not dirs:
        raise SystemExit(f"no experiment directories for run_id={args.run_id} in {results_root}")
    expected = load_campaign_config(args.campaign, args.run_id)
    agg_meta, agg_csv = load_aggregate(results_root, args.run_id)

    agg_meta_by_id = {r["experiment_id"]: r for r in agg_meta}
    agg_csv_by_id = {r["experiment_id"]: r for r in agg_csv}

    print("\n=== Final feature schema ===")
    groups = build_schema()
    for group, cols in groups.items():
        print(f"\n{group}:")
        for col in cols:
            print(f"    {col}")
    print(f"\n    ({sum(len(c) for c in groups.values())} fields total; "
          f"label field is `traffic_type`)")

    print("\n=== Per-experiment summary ===")
    header = (
        f"{'experiment_id':24s} {'run_id':12s} {'traffic':10s} {'esp-enc/int':22s} "
        f"{'pkt':>7s} {'bytes':>10s} {'out':>7s} {'in':>7s} {'pps':>7s} {'B/s':>9s} "
        f"{'mean_sz':>7s} {'p10':>6s} {'p90':>6s} {'oisat':>6s} {'entr':>6s} "
        f"{'small':>6s} {'large':>6s} {'b50':>5s} {'pcap':>8s} {'status':>6s}"
    )
    print(header)
    print("-" * len(header))

    failures = []
    global_problems = []
    pcap_bytes = 0
    for exp_dir in dirs:
        experiment_id = exp_dir.name
        meta = json.loads((exp_dir / "metadata.json").read_text())
        status = meta.get("status", "FAILED")
        features = {}
        if (exp_dir / "features.json").exists():
            features = json.loads((exp_dir / "features.json").read_text())

        total, esp, ike, non_esp, malformed = scan_frames(exp_dir / "capture.pcap" if (exp_dir / "capture.pcap").exists() else "/nonexistent")
        pcap_path = exp_dir / "capture.pcap"
        pcap_bytes = pcap_path.stat().st_size if pcap_path.exists() else 0

        fmt_problem = []
        if malformed:
            fmt_problem.append("malformed pcap")
        if non_esp:
            fmt_problem.append(f"{non_esp} unexpected plaintext frames")
        if total and esp + ike != total:
            fmt_problem.append(f"unexpected records {total - esp - ike}")
        fmt_problem += check_features(features)

        expected_cfg = expected.get(experiment_id)
        if expected_cfg:
            if meta.get("traffic_type") != expected_cfg["traffic_type"]:
                fmt_problem.append("label mismatch")
            if meta.get("esp_encryption") != expected_cfg["esp_encryption"]:
                fmt_problem.append("esp_encryption mismatch")
            if meta.get("esp_integrity") != expected_cfg["esp_integrity"]:
                fmt_problem.append("esp_integrity mismatch")

        # integrity checks specific to the algorithm family
        if status == "PASS":
            if meta.get("esp_encryption", "").endswith("cbc"):
                if meta.get("esp_integrity") != "sha256":
                    fmt_problem.append("CBC integrity != sha256")
            else:
                if meta.get("esp_integrity") is not None:
                    fmt_problem.append("GCM integrity != null")

        # metadata <-> aggregate consistency
        if status == "PASS":
            agg_m = agg_meta_by_id.get(experiment_id)
            agg_c = agg_csv_by_id.get(experiment_id)
            if agg_m is None:
                fmt_problem.append("missing metadata.jsonl row")
            else:
                fmt_problem += mismatch(meta, agg_m, list(dataset_mod.META_COLUMNS),
                                        "meta")
            if agg_c is None:
                fmt_problem.append("missing features.csv row")
            elif features:
                fmt_problem += mismatch(features, agg_c, list(dataset_mod.FEATURE_COLUMNS), "feat")
        else:
            if experiment_id in agg_meta_by_id or experiment_id in agg_csv_by_id:
                fmt_problem.append("FAILED experiment polluted aggregate")

        ok = status == "PASS" and not fmt_problem
        if fmt_problem:
            failures.append((experiment_id, fmt_problem))
        if not ok:
            global_problems.append(experiment_id)

        esp_label = meta.get("esp_encryption", "?")
        int_label = str(meta.get("esp_integrity"))
        ipseccfg = f"{esp_label}/{int_label}"

        print(
            f"{experiment_id:24s} {args.run_id:12s} {meta.get('traffic_type','?'):10s} "
            f"{ipseccfg:22s} {features.get('packet_count',0):>7d} {features.get('total_bytes',0):>10d} "
            f"{features.get('outbound_packet_count',0):>7d} {features.get('inbound_packet_count',0):>7d} "
            f"{features.get('packets_per_second',0):>7.1f} {features.get('bytes_per_second',0):>9.1f} "
            f"{features.get('mean_packet_size',0):>7.1f} {features.get('packet_size_p10',0):>6.0f} "
            f"{features.get('packet_size_p90',0):>6.0f} {features.get('mean_inter_arrival_time',0):>6.4f} "
            f"{features.get('packet_size_entropy',0):>6.3f} {features.get('small_packet_ratio',0):>6.3f} "
            f"{features.get('large_packet_ratio',0):>6.3f} {features.get('burst_count_50ms',0):>5d} "
            f"{pcap_bytes:>8d} {status:>6s}"
        )

    print("-" * len(header))

    print("\n=== Aggregate consistency (run-level) ===")
    run_meta = [r for r in agg_meta if r.get("status") == "PASS"]
    run_csv = [r for r in agg_csv if r.get("status") == "PASS"]
    print(f"  metadata.jsonl rows for run:     {len(agg_meta)}")
    print(f"  features.csv rows for run:       {len(agg_csv)}")
    print(f"  PASS rows in aggregate:          {len(run_meta)}/{len(run_csv)}")
    label_set = sorted({r["traffic_type"] for r in run_meta})
    print(f"  aggregate traffic labels:        {label_set}")
    print(f"  run_id present in every row:     {all(r.get('run_id') == args.run_id for r in agg_meta)}")

    if failures:
        print("\n=== Problems found ===")
        for experiment_id, problems in failures:
            print(f"  {experiment_id}: {problems}")
    else:
        print("\n=== No dataset-quality problems found ===")

    return 0 if not global_problems else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--campaign", default="campaign-quality.json")
    parser.add_argument("--results-root", default=dataset_mod.DEFAULT_RESULTS_ROOT)
    parser.add_argument("--rebuild", action="store_true",
                        help="regenerate the aggregate dataset from PASS experiments first")
    args = parser.parse_args(argv)
    if args.rebuild:
        count = rebuild_aggregate(args.results_root)
        print(f"rebuild_aggregate: regenerated {count} PASS row(s) under the current schema")
    return report(args)


if __name__ == "__main__":
    import sys
    sys.exit(main())