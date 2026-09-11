from config import CONFIG
from validate import validate_config


if __name__ == "__main__":
    validate_config(CONFIG)

    print("Configuration is valid")
    print()
    print(f"Mode:       {CONFIG['mode']}")
    print(f"IKE:        {CONFIG['ike']}")
    print(f"ESP:        {CONFIG['esp']}")
