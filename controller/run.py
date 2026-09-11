import argparse
import json

from .config import CONFIG
from .validate import validate_config
from .executor import run_experiment


def parse_bool(value):
    value = value.lower()

    if value in {"true", "yes", "1"}:
        return True

    if value in {"false", "no", "0"}:
        return False

    raise argparse.ArgumentTypeError("PFS must be true or false")


def main():
    parser = argparse.ArgumentParser(
        description="IPsec Testbed Experiment Runner"
    )

    parser.add_argument(
        "--mode",
        choices=["tunnel", "transport"],
        default=CONFIG["mode"],
    )

    parser.add_argument(
        "--address-family",
        choices=["ipv4", "ipv6"],
        default=CONFIG["address_family"],
    )

    parser.add_argument(
        "--ike-version",
        type=int,
        choices=[1, 2],
        default=CONFIG["ike"]["version"],
    )

    parser.add_argument(
        "--ike-encryption",
        choices=["aes128", "aes256"],
        default=CONFIG["ike"]["encryption"],
    )

    parser.add_argument(
        "--ike-integrity",
        choices=["sha256", "sha384", "sha512"],
        default=CONFIG["ike"]["integrity"],
    )

    parser.add_argument(
        "--dh-group",
        choices=["modp2048", "modp3072", "modp4096"],
        default=CONFIG["ike"]["dh_group"],
    )

    parser.add_argument(
        "--esp-encryption",
        choices=[
            "aes128gcm16",
            "aes256gcm16",
            "aes128cbc",
            "aes256cbc",
        ],
        default=CONFIG["esp"]["encryption"],
    )

    parser.add_argument(
        "--esp-integrity",
        choices=["sha256", "sha384", "sha512"],
        default=CONFIG["esp"].get("integrity"),
    )

    parser.add_argument(
        "--pfs",
        type=parse_bool,
        default=CONFIG["esp"]["pfs"],
    )

    args = parser.parse_args()

    config = {
        "mode": args.mode,
        "address_family": args.address_family,
        "ike": {
            "version": args.ike_version,
            "encryption": args.ike_encryption,
            "integrity": args.ike_integrity,
            "dh_group": args.dh_group,
        },
        "esp": {
            "encryption": args.esp_encryption,
            "integrity": args.esp_integrity,
            "dh_group": args.dh_group,
            "pfs": args.pfs,
        },
    }

    validate_config(config)

    CONFIG.clear()
    CONFIG.update(config)

    print("\n=== Selected Configuration ===")
    print(f"Mode:           {config['mode']}")
    print(f"Address family: {config['address_family']}")
    print(f"IKE version:    {config['ike']['version']}")
    print(f"IKE encryption: {config['ike']['encryption']}")
    print(f"IKE integrity:  {config['ike']['integrity']}")
    print(f"DH group:       {config['ike']['dh_group']}")
    print(f"ESP encryption: {config['esp']['encryption']}")
    print(f"ESP integrity:  {config['esp']['integrity']}")
    print(f"PFS:            {config['esp']['pfs']}")

    result = run_experiment(config)

    print("\n=== Experiment Result ===\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
