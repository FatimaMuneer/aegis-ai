import os
from pathlib import Path
import yaml


def policy_dir() -> Path:
    return Path(os.environ.get("AEGIS_POLICY_DIR", Path(__file__).parent / "policies"))


def load(name: str) -> dict:
    """Load policies/<name>.yaml. A missing file means an empty policy."""
    path = policy_dir() / f"{name}.yaml"
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}
