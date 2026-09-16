from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Some developer environments preload another project named ``app``. Put this
# repository first so the tests always exercise the checked-out package.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
for module_name in list(sys.modules):
    if module_name == "app" or module_name.startswith("app."):
        del sys.modules[module_name]

@pytest.fixture
def suspicious_alert() -> dict:
    return {
        "alert_id": "test-alert",
        "alert_type": "suspicious_login",
        "timestamp": "2026-09-15T21:00:00+00:00",
        "username": "jsmith",
        "source_ip": "185.22.14.8",
        "hostname": "jsmith-laptop",
        "description": "Suspicious login with repeated failed attempts",
        "failed_attempts": 7,
    }


@pytest.fixture
def alert_file(tmp_path, suspicious_alert):
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(suspicious_alert), encoding="utf-8")
    return path
