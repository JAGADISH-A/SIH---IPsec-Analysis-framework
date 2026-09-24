"""Deterministic, security-posture-aware dataset sample planner (Module 2).

This module is the second component of incremental Dataset Generation.  Given
an existing Dataset Run (Module 1, ``dataset_run.py``), it produces a
reproducible *plan* for ``target_samples`` samples that independently varies
two axes:

* the IPsec security configuration (mode, address family, ESP cipher suite,
  ESP integrity, ESP DH group, PFS), and
* the traffic profile.

Design invariants:

* deterministic: no randomness anywhere; the same arguments always produce the
  same plan (no seed required);
* posture-aware: every candidate configuration is classified into one of five
  posture bands by an explicit deterministic rule (``posture_of_config``);
* validated: every configuration in the plan has already passed
  ``validate_config``;
* balanced: traffic profile quotas differ by at most one sample.

A candidate is enumerated when it is *shape-compatible* with the schema (all
mode/family/cipher/integrity/DH/PFS combinations).  A candidate is *accepted*
into the catalogue if and only if ``validate_config`` accepts it; shape
violations (e.g. GCM + separate HMAC, CBC without an integrity algorithm) land
in the rejected list with the validator's reason.

Retry semantics belong to the execution layer (future module): one logical
``sequence`` slot must yield exactly one successful sample before the slot is
considered done, so a failed or interrupted attempt never advances the
traffic-profile or posture quotas reflected in the plan.

No experiment is executed by anything in this module.
"""

from . import dataset_run as dataset_run_mod
from .traffic import PROFILES
from .validate import validate_config

PLANNER_VERSION = "v1"

# Posture round-robin order.  Bands are derived from posture_of_config scores:
#   STRONG  >= 11
#   GOOD      9-10
#   MEDIUM    6-8
#   WEAK      4-5
#   WORST    == 3
POSTURE_ORDER = ("STRONG", "GOOD", "MEDIUM", "WEAK", "WORST")

MODES = ("tunnel", "transport")
ADDRESS_FAMILIES = ("ipv4", "ipv6")

ESP_CIPHERS = ("aes128gcm16", "aes256gcm16", "aes128cbc", "aes256cbc")
ESP_INTEGRITY_CANDIDATES = (None, "sha256", "sha384", "sha512")
DH_GROUPS = ("modp2048", "modp3072", "modp4096")

DH_SCORES = {"modp2048": 1, "modp3072": 3, "modp4096": 4}

# The IKE phase is a fixed baseline, not a posture variable.
IKE_BASELINE = {
    "version": 2,
    "encryption": "aes256",
    "integrity": "sha256",
    "dh_group": "modp2048",
}

PLAN_FILENAME = "plan.json"


def validate_target_samples(target_samples):
    if isinstance(target_samples, bool) or not isinstance(target_samples, int):
        raise ValueError("target_samples must be an integer")
    if target_samples <= 0:
        raise ValueError(f"target_samples must be > 0, got {target_samples}")


def validate_traffic_profile(profile):
    if profile not in PROFILES:
        raise ValueError(
            f"unsupported traffic profile '{profile}', "
            f"expected one of {list(PROFILES)}"
        )


def posture_of_config(config):
    """Return (posture_band, score) for an (already valid) configuration."""
    esp = config["esp"]

    family = 4 if esp["encryption"].endswith("gcm16") else 2
    key = 2 if esp["encryption"].startswith("aes256") else 1
    pfs_score = 2 if esp["pfs"] else 0
    dh_score = DH_SCORES[esp["dh_group"]] if esp["pfs"] else 0

    score = family + key + pfs_score + dh_score
    if score >= 11:
        posture = "STRONG"
    elif score >= 9:
        posture = "GOOD"
    elif score >= 6:
        posture = "MEDIUM"
    elif score >= 4:
        posture = "WEAK"
    else:
        posture = "WORST"
    return posture, score


def configuration_id(config):
    """Stable human-readable id from the discriminating configuration fields."""
    esp = config["esp"]
    esp_integrity = esp["integrity"] if esp["integrity"] is not None else "none"
    pfs = "true" if esp["pfs"] else "false"
    return (
        f"{config['mode']}-{config['address_family']}-"
        f"{esp['encryption']}-{esp_integrity}-{esp['dh_group']}-{pfs}"
    )


def enumerate_candidates():
    """Yield every shape-compatible candidate configuration in fixed order."""
    for mode in MODES:
        for address_family in ADDRESS_FAMILIES:
            for encryption in ESP_CIPHERS:
                for integrity in ESP_INTEGRITY_CANDIDATES:
                    for dh_group in DH_GROUPS:
                        for pfs in (True, False):
                            yield {
                                "mode": mode,
                                "address_family": address_family,
                                "ike": dict(IKE_BASELINE),
                                "esp": {
                                    "encryption": encryption,
                                    "integrity": integrity,
                                    "dh_group": dh_group,
                                    "pfs": pfs,
                                },
                            }


def build_catalogue():
    """Classify every candidate by validity and, when valid, by posture.

    Returns {"accepted": [...], "rejected": [...]}.  Accepted entries carry
    configuration_id, config, security_posture and score.  Rejected entries
    carry configuration_id, config and reason (from the validator).
    """
    accepted = []
    rejected = []
    for config in enumerate_candidates():
        try:
            validate_config(config)
        except ValueError as exc:
            rejected.append(
                {
                    "configuration_id": configuration_id(config),
                    "config": config,
                    "reason": str(exc),
                }
            )
            continue
        posture, score = posture_of_config(config)
        accepted.append(
            {
                "configuration_id": configuration_id(config),
                "config": config,
                "security_posture": posture,
                "score": score,
            }
        )
    return {"accepted": accepted, "rejected": rejected}


def traffic_quota(target_samples):
    """Per-profile sample quotas that differ by at most one."""
    validate_target_samples(target_samples)
    base, remainder = divmod(target_samples, len(PROFILES))
    return {
        profile: base + (1 if index < remainder else 0)
        for index, profile in enumerate(PROFILES)
    }


def profile_sequence(target_samples):
    """Round-robin traffic profile sequence honouring the balanced quotas."""
    remaining = dict(traffic_quota(target_samples))
    sequence = []
    while True:
        advanced = False
        for profile in PROFILES:
            if remaining[profile] > 0:
                sequence.append(profile)
                remaining[profile] -= 1
                advanced = True
        if not advanced:
            break
    return sequence


def build_sample_plan(target_samples):
    """Build a deterministic sample plan for ``target_samples`` samples.

    The posture is chosen round-robin over the non-empty posture bands;
    within a band the configuration cycles deterministically over that band's
    accepted catalogue.  Traffic profiles are assigned round-robin from the
    balanced per-profile quotas.
    """
    validate_target_samples(target_samples)
    catalogue = build_catalogue()

    by_posture = {}
    for entry in catalogue["accepted"]:
        by_posture.setdefault(entry["security_posture"], []).append(entry)
    available_postures = [p for p in POSTURE_ORDER if by_posture.get(p)]
    if not available_postures:
        raise RuntimeError("catalogue contains no accepted configurations")

    sequences = profile_sequence(target_samples)
    posture_counters = {p: 0 for p in POSTURE_ORDER}
    used_ids = {p: [] for p in POSTURE_ORDER}
    samples = []

    posture_index = 0
    for sequence_number, profile in enumerate(sequences, start=1):
        posture = available_postures[posture_index % len(available_postures)]
        posture_index += 1

        entries = by_posture[posture]
        entry = entries[posture_counters[posture] % len(entries)]
        posture_counters[posture] += 1
        used_ids[posture].append(entry["configuration_id"])

        samples.append(
            {
                "sequence": sequence_number,
                "traffic_profile": profile,
                "security_posture": posture,
                "configuration_id": entry["configuration_id"],
                "ipsec_configuration": entry["config"],
            }
        )

    posture_planned = {
        p: sum(1 for s in samples if s["security_posture"] == p)
        for p in POSTURE_ORDER
    }
    posture_unique = {p: len(set(used_ids[p])) for p in POSTURE_ORDER}
    posture_reuses = {
        p: posture_planned[p] - posture_unique[p] for p in POSTURE_ORDER
    }
    per_posture_catalogue = {
        p: sum(1 for e in catalogue["accepted"] if e["security_posture"] == p)
        for p in POSTURE_ORDER
    }

    return {
        "planner_version": PLANNER_VERSION,
        "dataset_schema_version": dataset_run_mod.SCHEMA_VERSION,
        "target_samples": target_samples,
        "traffic_quota": traffic_quota(target_samples),
        "posture_planned": posture_planned,
        "posture_unique_configuration_count": posture_unique,
        "posture_configuration_reuses": posture_reuses,
        "catalogue": {
            "total_candidates": (
                len(catalogue["accepted"]) + len(catalogue["rejected"])
            ),
            "accepted": len(catalogue["accepted"]),
            "rejected": len(catalogue["rejected"]),
            "per_posture": per_posture_catalogue,
        },
        "samples": samples,
    }


def write_sample_plan(results_root, dataset_run_id, plan):
    """Write ``plan`` to the run's staging/plan.json atomically."""
    run_dir = dataset_run_mod.run_directory(results_root, dataset_run_id)
    if not run_dir.exists():
        raise FileNotFoundError(f"dataset run not found: {dataset_run_id}")
    path = run_dir / "staging" / PLAN_FILENAME
    dataset_run_mod._atomic_write_json(path, plan)
    return path


def main():
    catalogue = build_catalogue()
    per_posture = {
        p: sum(1 for e in catalogue["accepted"] if e["security_posture"] == p)
        for p in POSTURE_ORDER
    }

    print("IPsec configuration catalogue")
    print("=============================")
    total_candidates = len(catalogue["accepted"]) + len(catalogue["rejected"])
    print(f"candidates enumerated : {total_candidates}")
    print(f"accepted (valid)      : {catalogue['accepted']}")
    print(f"rejected (invalid)    : {catalogue['rejected']}")
    print("posture bands:")
    print(f"  STRONG  >= 11 : {per_posture['STRONG']}")
    print(f"  GOOD    9-10  : {per_posture['GOOD']}")
    print(f"  MEDIUM  6-8   : {per_posture['MEDIUM']}")
    print(f"  WEAK    4-5   : {per_posture['WEAK']}")
    print(f"  WORST   == 3  : {per_posture['WORST']}")

    print()
    print("Traffic balance examples")
    print("========================")
    for n in (6, 10, 50, 100):
        quota = traffic_quota(n)
        counts = list(quota.values())
        print(f"  target={n:>3}  quota={counts}  max-min={max(counts) - min(counts)}")

    for n in (6, 50):
        plan = build_sample_plan(n)
        print()
        print(f"Sample plan for target={n}")
        print(f"  posture_planned={plan['posture_planned']}")
        sample_id = plan["samples"][0]
        print(
            f"  first sample: seq={sample_id['sequence']} "
            f"profile={sample_id['traffic_profile']} "
            f"posture={sample_id['security_posture']} "
            f"config={sample_id['configuration_id']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())