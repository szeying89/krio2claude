import json
from pathlib import Path

import yaml

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "kb"


def load_json(name: str):
    return json.loads((FIXTURES_DIR / name).read_text())


def load_yaml(name: str):
    return yaml.safe_load((FIXTURES_DIR / name).read_text())
