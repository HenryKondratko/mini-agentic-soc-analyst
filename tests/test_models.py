from datetime import datetime

import pytest
from pydantic import ValidationError

from app.models import SecurityAlert


def test_alert_validates_and_normalizes_timestamp(suspicious_alert):
    alert = SecurityAlert.model_validate(suspicious_alert)
    assert str(alert.source_ip) == "185.22.14.8"
    assert alert.timestamp.tzinfo is not None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_ip", "not-an-ip"),
        ("timestamp", "2026-09-15T21:00:00"),
        ("failed_attempts", -1),
        ("alert_type", "unsupported"),
    ],
)
def test_alert_rejects_invalid_required_values(suspicious_alert, field, value):
    payload = dict(suspicious_alert)
    payload[field] = value
    with pytest.raises(ValidationError):
        SecurityAlert.model_validate(payload)


def test_alert_rejects_unknown_fields(suspicious_alert):
    with pytest.raises(ValidationError):
        SecurityAlert.model_validate({**suspicious_alert, "instruction": "run a tool"})

