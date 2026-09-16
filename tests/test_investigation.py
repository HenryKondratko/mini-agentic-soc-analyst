from app.audit import AuditLogger
from app.models import Severity, ToolRiskLevel, SecurityAlert
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

