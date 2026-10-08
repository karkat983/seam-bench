"""Load config.yaml and resolve paths relative to the repo root."""
import pathlib
from typing import Any

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = ROOT / "config.yaml"


def load_config(path: pathlib.Path | str = DEFAULT_CONFIG) -> dict[str, Any]:
    with open(path) as f:
        return yaml.safe_load(f)


def resolve(cfg: dict[str, Any], key: str) -> pathlib.Path:
    """Return paths.<key> from the config as an absolute path."""
    return ROOT / cfg["paths"][key]
