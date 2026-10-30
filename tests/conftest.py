import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest


@pytest.fixture
def config():
    with open(ROOT / "config.json", encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["cve_matcher"]["db_path"] = str(ROOT / "data" / "cve_db.json")
    return cfg
