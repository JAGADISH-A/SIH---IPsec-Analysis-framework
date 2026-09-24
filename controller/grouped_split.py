"""Deterministic grouped, stratified train/validation/test split for the ML layer.

Samples are grouped by ``configuration_id``; a configuration group is never
split across train/validation/test. Assignment is a greedy, fully deterministic
group-placement algorithm (no random shuffling), stratified best-effort on
``traffic_profile`` at group granularity, and persisted to
``results/ml/split_v1.json`` for reproducibility.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path

SPLIT_SEED = 7
SPLIT_ORDER = ("train", "validation", "test")
SPLIT_RATIOS = {"train": 0.70, "validation": 0.15, "test": 0.15}
SPLIT_STRATEGY = "grouped_stratified_greedy_by_configuration_id"
DEFAULT_SPLIT_PATH = Path("results") / "ml" / "split_v1.json"

from controller.dataset_loader import TARGET_CLASSES


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _content_hash(samples: list[dict]) -> str:
    canonical = json.dumps(
        sorted(samples, key=lambda s: (s["sequence"], s["experiment_id"])),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_sample_records(
    y, groups, dataset_run_id, experiment_id, sequence
) -> list[dict]:
    records = []
    for i in range(len(y)):
        records.append(
            {
                "experiment_id": str(experiment_id[i]),
                "dataset_run_id": str(dataset_run_id[i]),
                "sequence": int(sequence[i]),
                "configuration_id": str(groups[i]),
                "target": str(y[i]),
            }
        )
    return records


def assign_groups(records: list[dict], seed: int = SPLIT_SEED) -> dict[str, str]:
    """Return ``{experiment_id: split}`` placing whole configuration groups."""
    classes = list(TARGET_CLASSES)
    ratios = [SPLIT_RATIOS[s] for s in SPLIT_ORDER]
    total = len(records)

    groups: dict[str, list[dict]] = {}
    for rec in records:
        groups.setdefault(rec["configuration_id"], []).append(rec)
    group_ids = sorted(groups)
    for gid in group_ids:
        groups[gid].sort(key=lambda r: (r["sequence"], r["experiment_id"]))

    per_class_total = {c: 0 for c in classes}
    for rec in records:
        per_class_total[rec["target"]] += 1

    target = {s: {c: round(per_class_total[c] * r) for c in classes}
              for s, r in zip(SPLIT_ORDER, ratios)}
    target_total = {s: sum(target[s].values()) for s in SPLIT_ORDER}

    counts = {s: {c: 0 for c in classes} for s in SPLIT_ORDER}
    deficit = {s: {c: target[s][c] - counts[s][c] for c in classes}
               for s in SPLIT_ORDER}
    assignment: dict[str, str] = {}
    seed_used = seed

    for gid in group_ids:
        group = groups[gid]
        group_class = {c: 0 for c in classes}
        for rec in group:
            group_class[rec["target"]] += 1
        group_size = len(group)

        scored = []
        for order_index, s in enumerate(SPLIT_ORDER):
            benefit = sum(
                group_class[c] * max(deficit[s][c], 0) for c in classes
            )
            fill = (
                sum(counts[s].values()) + group_size
            ) / (target_total[s] + 1e-9)
            scored.append((benefit, -fill, -order_index, s))
        scored.sort(reverse=True)
        best_split = scored[0][3]

        for rec in group:
            counts[best_split][rec["target"]] += 1
            deficit[best_split][rec["target"]] = (
                target[best_split][rec["target"]] - counts[best_split][rec["target"]]
            )
            assignment[rec["experiment_id"]] = best_split

    return assignment, seed_used, counts, target, per_class_total


def verify_split(
    assignment: dict[str, str], records: list[dict]
) -> dict:
    """Check group isolation and one-and-only-one membership per sample."""
    by_exp = {rec["experiment_id"]: rec for rec in records}
    if set(assignment) != set(by_exp):
        raise ValueError("assignment keys do not match record experiment ids")
    split_of = {}
    split_groups = {s: set() for s in SPLIT_ORDER}
    duplicates = []
    for rec in records:
        exp = rec["experiment_id"]
        split = assignment[exp]
        if exp in split_of:
            duplicates.append(exp)
        split_of[exp] = split
        split_groups[split].add(rec["configuration_id"])

    pair_overlap = {}
    for a, b in (("train", "validation"), ("train", "test"), ("validation", "test")):
        pair_overlap[f"{a}_x_{b}"] = len(split_groups[a] & split_groups[b])

    group_to_splits: dict[str, set] = {}
    for rec in records:
        group_to_splits.setdefault(rec["configuration_id"], set()).add(
            assignment[rec["experiment_id"]]
        )
    spanning = sorted(
        gid for gid, splits in group_to_splits.items() if len(splits) > 1
    )

    report = {
        "group_isolation_ok": all(v == 0 for v in pair_overlap.values())
        and not spanning,
        "pair_overlap": pair_overlap,
        "groups_spanning_splits": spanning,
        "duplicate_experiment_ids": duplicates,
        "every_sample_once": len(split_of) == len(records) and not duplicates,
    }
    return report


def assemble_split(
    x, y, groups, metadata, seed: int = SPLIT_SEED
) -> tuple[dict, dict]:
    """Compute assignment + verification given loader output."""
    records = build_sample_records(
        y,
        groups,
        metadata["dataset_run_id"],
        metadata["experiment_id"],
        metadata["sequence"],
    )
    assignment, seed_used, counts, target_quotas, per_class_total = assign_groups(
        records, seed=seed
    )
    report = verify_split(assignment, records)
    return {"assignment": assignment, "records": records,
            "counts": counts, "target_quotas": target_quotas,
            "per_class_total": per_class_total, "seed": seed_used}, report


def build_split_json(
    x, y, groups, metadata, seed: int = SPLIT_SEED,
    split_path: Path = DEFAULT_SPLIT_PATH,
) -> Path:
    """Compute, verify and persist ``results/ml/split_v1.json``."""
    result, report = assemble_split(x, y, groups, metadata, seed=seed)
    assignment, records = result["assignment"], result["records"]

    samples = []
    for rec in records:
        samples.append(
            {
                "experiment_id": rec["experiment_id"],
                "dataset_run_id": rec["dataset_run_id"],
                "sequence": rec["sequence"],
                "split": assignment[rec["experiment_id"]],
                "configuration_id": rec["configuration_id"],
                "target": rec["target"],
            }
        )

    split_counts = {s: 0 for s in SPLIT_ORDER}
    for rec in samples:
        split_counts[rec["split"]] += 1

    split_hash = _content_hash(samples)
    document = {
        "strategy": SPLIT_STRATEGY,
        "ratios": SPLIT_RATIOS,
        "seed": result["seed"],
        "created_at": _utcnow(),
        "input_fingerprints": metadata["input_fingerprints"],
        "samples": samples,
        "split_counts": split_counts,
        "verification": report,
        "split_hash": split_hash,
    }
    if not report["group_isolation_ok"] or not report["every_sample_once"]:
        raise ValueError(f"split verification failed: {report}")

    split_path = Path(split_path)
    split_path.parent.mkdir(parents=True, exist_ok=True)
    split_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return split_path


def load_split(split_path: Path = DEFAULT_SPLIT_PATH) -> dict:
    """Load a persisted split document."""
    return json.loads(Path(split_path).read_text(encoding="utf-8"))


def assignment_lookup(document: dict) -> dict[str, str]:
    return {s["experiment_id"]: s["split"] for s in document["samples"]}


def main() -> None:
    from controller.dataset_loader import load_dataset

    x, y, features, groups, metadata = load_dataset()
    path = build_split_json(x, y, groups, metadata)
    document = load_split(path)
    print("split written:", path)
    print("split_counts:", document["split_counts"])
    print("verification:", document["verification"])
    print("split_hash:", document["split_hash"])


if __name__ == "__main__":
    main()