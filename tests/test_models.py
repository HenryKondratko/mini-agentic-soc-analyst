import pytest
from pydantic import ValidationError

from app.models import AuthenticationEvent, SecurityAlert


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


def test_authentication_event_normalizes_outcome_and_rejects_unknown_fields():
    event = AuthenticationEvent.model_validate(
        {
            "timestamp": "2026-09-15T20:59:00Z",
            "user": "jsmith",
            "source_ip": "185.22.14.8",
            "device": "laptop",
            "outcome": "FAILED",
        }
    )
    assert event.outcome.value == "failure"
    with pytest.raises(ValidationError):
        AuthenticationEvent.model_validate(
            {
                **event.model_dump(mode="json"),
                "instruction": "invoke a tool",
            }
        )
