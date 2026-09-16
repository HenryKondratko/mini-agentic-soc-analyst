from app.audit import AuditLogger
from app.correlation import correlate_authentication_events
from app.models import SecurityAlert, Severity, ToolRiskLevel
from app.orchestrator import investigate


def test_investigation_enriches_and_recommends_without_remediation(suspicious_alert, tmp_path):
    result = investigate(
        SecurityAlert.model_validate(suspicious_alert),
        audit_logger=AuditLogger(tmp_path / "audit.jsonl"),
    )
    assert result.severity == Severity.HIGH
    assert result.possible_threat == "credential compromise"
    assert result.matched_runbook == "credential_compromise.md"
    assert [item.action for item in result.recommendations] == [
        "revoke_sessions",
        "force_password_reset",
        "isolate_endpoint",
    ]
    assert all(item.risk_level == ToolRiskLevel.HIGH_IMPACT for item in result.recommendations)
    assert all("remediation" not in event.lower() for event in result.evidence)
    assert 0 <= result.confidence <= 100
    assert {signal.signal for signal in result.evidence_signals} == {
        "failed_attempts",
        "successful_follow_on_login",
        "unfamiliar_device",
        "malicious_or_high_risk_ip",
        "geographic_mismatch",
        "event_correlation",
    }


def test_event_correlation_uses_events_and_detects_contradictions(suspicious_alert):
    payload = {
        **suspicious_alert,
        "successful_login": True,
        "events": [
            {
                "timestamp": "2026-09-15T20:50:00Z",
                "username": "jsmith",
                "source_ip": "185.22.14.8",
                "hostname": "laptop",
                "outcome": "failure",
            },
            {
                "timestamp": "2026-09-15T20:55:00Z",
                "username": "jsmith",
                "source_ip": "185.22.14.8",
                "hostname": "laptop",
                "outcome": "success",
            },
        ],
    }
    correlation = correlate_authentication_events(SecurityAlert.model_validate(payload))
    assert correlation.status == "contradictory"
    assert correlation.failure_count == 1

    contradictory = SecurityAlert.model_validate(
        {
            **payload,
            "events": [
                {
                    "timestamp": "2026-09-15T20:50:00Z",
                    "username": "other-user",
                    "source_ip": "185.22.14.8",
                    "hostname": "laptop",
                    "outcome": "failure",
                }
            ],
        }
    )
    assert correlate_authentication_events(contradictory).status == "contradictory"


def test_incomplete_low_risk_investigation_fails_closed(tmp_path):
    alert = SecurityAlert(
        alert_id="benign",
        alert_type="suspicious_login",
        timestamp="2026-09-15T21:00:00Z",
        username="unknown-user",
        source_ip="203.0.113.10",
        hostname="workstation",
    )
    result = investigate(alert, audit_logger=AuditLogger(tmp_path / "audit.jsonl"))
    assert result.severity == Severity.LOW
    assert result.recommendations == []
    assert result.uncertainty
