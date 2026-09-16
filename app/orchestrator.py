"""Deterministic enrichment and evidence-first investigation orchestration."""

from __future__ import annotations

from app.audit import AuditLogger
from app.models import (
    InvestigationResult,
    RecommendedAction,
    SecurityAlert,
    Severity,
    ToolRiskLevel,
)
from tools.guardrails import dispatch_tool


def investigate(alert: SecurityAlert, audit_logger: AuditLogger | None = None) -> InvestigationResult:
    """Enrich and recommend; deliberately never executes remediation."""
    logger = audit_logger or AuditLogger()
    intel_call = dispatch_tool(
        "check_ip_reputation",
        {"ip": str(alert.source_ip)},
        alert_id=alert.alert_id,
        audit_logger=logger,
    )
    identity_call = dispatch_tool(
        "lookup_identity_history",
        {"username": alert.username},
        alert_id=alert.alert_id,
        audit_logger=logger,
    )
    runbook_query = (
        "credential compromise authentication failed successful login "
        "unfamiliar device geographic anomaly"
        if alert.alert_type.value == "suspicious_login"
        else f"{alert.alert_type.value} {alert.description}"
    )
    runbook_call = dispatch_tool(
        "retrieve_runbook",
        {"query": runbook_query},
        alert_id=alert.alert_id,
        audit_logger=logger,
    )
    if not (intel_call.ok and identity_call.ok and runbook_call.ok):
        raise RuntimeError("read-only enrichment failed closed")

    intel = intel_call.result
    identity = identity_call.result
    runbook = runbook_call.result
    high_confidence = (
        alert.alert_type.value == "suspicious_login"
        and intel.risk_level == Severity.HIGH
        and intel.malicious
    )
    severity = Severity.HIGH if high_confidence else intel.risk_level
    possible_threat = "credential compromise" if high_confidence else "suspicious activity"
    evidence = [
        f"{alert.failed_attempts} failed authentication attempts followed by "
        f"{'a successful' if alert.successful_login else 'no successful'} login.",
        f"Device is {'known' if alert.device_known else 'unfamiliar'} for {alert.username}.",
        f"Threat intelligence scored {intel.score}/100 ({intel.risk_level.value}) for {intel.ip}.",
        f"Source is classified as {'malicious' if intel.malicious else 'not malicious'}; country={intel.country or 'unknown'}.",
        f"Identity history lists typical region {identity.typical_region or 'unknown'}; "
        f"current source country is {intel.country or 'unknown'}.",
        f"Runbook {runbook.matched_runbook} selected with token-overlap score {runbook.score}.",
    ]
    recommendations: list[RecommendedAction] = []
    if high_confidence:
        recommendations = [
            RecommendedAction(
                action="revoke_sessions",
                risk_level=ToolRiskLevel.HIGH_IMPACT,
                target=alert.username,
                rationale="Invalidate active sessions after a high-confidence credential compromise.",
            ),
            RecommendedAction(
                action="force_password_reset",
                risk_level=ToolRiskLevel.HIGH_IMPACT,
                target=alert.username,
                rationale="Require new credentials after suspicious authentication.",
            ),
            RecommendedAction(
                action="isolate_endpoint",
                risk_level=ToolRiskLevel.HIGH_IMPACT,
                target=alert.hostname,
                rationale="Investigate the associated endpoint while limiting potential spread.",
            ),
        ]
    return InvestigationResult(
        alert=alert,
        threat_intel=intel,
        identity_history=identity,
        matched_runbook=runbook.matched_runbook,
        retrieval_score=runbook.score,
        evidence=evidence,
        severity=severity,
        possible_threat=possible_threat,
        recommendations=recommendations,
    )
