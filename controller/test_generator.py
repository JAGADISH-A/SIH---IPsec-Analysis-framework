from controller.config import CONFIG
from controller.topology import TOPOLOGIES
from controller.generator import generate_swanctl_config


if __name__ == "__main__":
    topology = TOPOLOGIES[CONFIG["mode"]][CONFIG["address_family"]]

    local = topology["local"]
    remote = topology["remote"]

    output = generate_swanctl_config(
        CONFIG,
        local,
        remote,
    )

    print(output)

    print("\n--- Reverse configuration ---\n")

    output = generate_swanctl_config(
        CONFIG,
        remote,
        local,
    )

    print(output)
