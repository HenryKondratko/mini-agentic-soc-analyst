import json

from app.audit import AuditLogger
from app.models import Severity, ToolRiskLevel
from tools.guardrails import dispatch_tool


def test_deterministic_threat_intel_and_identity(tmp_path):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    intel = dispatch_tool("check_ip_reputation", {"ip": "185.22.14.8"}, alert_id="a", audit_logger=logger)
    identity = dispatch_tool("lookup_identity_history", {"username": "jsmith"}, alert_id="a", audit_logger=logger)
    assert intel.ok and intel.result.score == 92
    assert intel.result.risk_level == Severity.HIGH
    assert intel.result.country == "Netherlands"
    assert intel.result.malicious is True
    assert identity.result.typical_region == "Michigan, US"
    assert "jsmith-laptop" in identity.result.known_devices


def test_unknown_ip_is_low_risk(tmp_path):
    result = dispatch_tool(
        "check_ip_reputation",
        {"ip": "203.0.113.10"},
        audit_logger=AuditLogger(tmp_path / "audit.jsonl"),
    )
    assert result.ok and result.result.risk_level == Severity.LOW
    assert result.result.malicious is False


def test_read_only_allowed_high_impact_requires_approval(tmp_path):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    rejected = dispatch_tool("revoke_sessions", {"username": "jsmith"}, alert_id="a", audit_logger=logger)
    approved = dispatch_tool(
        "revoke_sessions",
        {"username": "jsmith"},
        approval=True,
        alert_id="a",
        audit_logger=logger,
    )
    assert rejected.ok is False and rejected.decision == "REJECTED"
    assert approved.ok is True and approved.risk_level == ToolRiskLevel.HIGH_IMPACT.value


def test_unknown_tool_and_bad_args_fail_closed(tmp_path):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    unknown = dispatch_tool("execute_arbitrary_text", {}, audit_logger=logger)
    bad = dispatch_tool("check_ip_reputation", {"ip": "bad"}, audit_logger=logger)
    assert not unknown.ok and not bad.ok
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert all(event["decision"] == "REJECTED" for event in events)
