"""Deterministic enrichment and evidence-first investigation orchestration."""

from __future__ import annotations

from typing import cast

from app.audit import AuditLogger
from app.correlation import correlate_authentication_events
from app.models import (
    EvidenceSignal,
    IdentityHistoryResult,
    InvestigationResult,
    RecommendedAction,
    SecurityAlert,
    Severity,
    ThreatIntelResult,
    ToolRiskLevel,
)
from tools.guardrails import dispatch_tool
from tools.results import RunbookRetrievalResponse


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
        "credential compromise authentication failed successful login unfamiliar device geographic anomaly"
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

    intel = cast(ThreatIntelResult, intel_call.result)
    identity = cast(IdentityHistoryResult, identity_call.result)
    runbook = cast(RunbookRetrievalResponse, runbook_call.result)
    correlation = correlate_authentication_events(alert)
    signals: list[EvidenceSignal] = []
    uncertainty: list[str] = []
    confidence = 0

    failure_score = 30 if correlation.failure_count >= 5 else 20 if correlation.failure_count >= 2 else 0
    signals.append(
        EvidenceSignal(
            signal="failed_attempts",
            classification="positive" if failure_score else "neutral",
            detail=f"{correlation.failure_count} failed authentication attempts observed",
            score=failure_score,
        )
    )
    confidence += failure_score

    successful_follow_on = correlation.success_after_failure or (
        alert.successful_login and correlation.source == "aggregate"
    )
    success_score = 20 if successful_follow_on else 0
    signals.append(
        EvidenceSignal(
            signal="successful_follow_on_login",
            classification="positive" if successful_follow_on else "neutral",
            detail="A successful login followed authentication failures"
            if successful_follow_on
            else "No successful follow-on login was established",
            score=success_score,
        )
    )
    confidence += success_score

    device_reported = "device_known" in alert.model_fields_set
    device_unfamiliar = device_reported and not alert.device_known
    device_score = 15 if device_unfamiliar else 0
    if not device_reported:
        uncertainty.append("device familiarity was not supplied")
    signals.append(
        EvidenceSignal(
            signal="unfamiliar_device",
            classification="positive" if device_unfamiliar else "unknown" if not device_reported else "neutral",
            detail="The device is unfamiliar"
            if device_unfamiliar
            else "Device familiarity is unavailable"
            if not device_reported
            else "The device is known",
            score=device_score,
        )
    )
    confidence += device_score

    ip_score = 35 if intel.malicious else 25 if intel.risk_level == Severity.HIGH else 0
    signals.append(
        EvidenceSignal(
            signal="malicious_or_high_risk_ip",
            classification="positive" if ip_score else "neutral",
            detail=f"Threat intelligence scored {intel.score}/100 ({intel.risk_level.value})",
            score=ip_score,
        )
    )
    confidence += ip_score

    typical_region = identity.typical_region
    country = intel.country
    geo_known = bool(typical_region and country)
    geographic_mismatch = (
        country.casefold() not in typical_region.casefold()
        if typical_region is not None and country is not None
        else False
    )
    if not geo_known:
        uncertainty.append("geographic comparison was unavailable")
    geo_score = 10 if geographic_mismatch else 0
    signals.append(
        EvidenceSignal(
            signal="geographic_mismatch",
            classification="positive" if geographic_mismatch else "unknown" if not geo_known else "neutral",
            detail="Current source country differs from the typical identity region"
            if geographic_mismatch
            else "Geographic comparison is unavailable"
            if not geo_known
            else "Current source is consistent with the typical identity region",
            score=geo_score,
        )
    )
    confidence += geo_score

    correlation_score = 25 if correlation.correlated else 0
    if correlation.status in {"unavailable", "contradictory"}:
        uncertainty.append(correlation.reason)
    signals.append(
        EvidenceSignal(
            signal="event_correlation",
            classification="positive"
            if correlation.correlated
            else "contradictory"
            if correlation.status == "contradictory"
            else "unknown"
            if correlation.status == "unavailable"
            else "neutral",
            detail=correlation.reason,
            score=correlation_score,
        )
    )
    confidence += correlation_score
    confidence = min(confidence, 100)

    essential_evidence = (
        alert.alert_type.value == "suspicious_login"
        and correlation.failure_count >= 2
        and ip_score > 0
        and correlation.status != "contradictory"
    )
    high_confidence = essential_evidence and confidence >= 70
    severity = Severity.HIGH if high_confidence else Severity.MEDIUM if confidence >= 40 else Severity.LOW
    possible_threat = "credential compromise" if high_confidence else "suspicious activity"
    evidence = [
        f"{correlation.failure_count} failed authentication attempts followed by "
        f"{'a successful' if successful_follow_on else 'no established successful'} login.",
        f"Device is {'known' if alert.device_known else 'unfamiliar'} for {alert.username}.",
        f"Threat intelligence scored {intel.score}/100 ({intel.risk_level.value}) for {intel.ip}.",
        "Source is classified as "
        f"{'malicious' if intel.malicious else 'not malicious'}; "
        f"country={intel.country or 'unknown'}.",
        f"Identity history lists typical region {identity.typical_region or 'unknown'}; "
        f"current source country is {intel.country or 'unknown'}.",
        f"Runbook {runbook.matched_runbook} selected with token-overlap score {runbook.score}.",
    ]
    if uncertainty:
        evidence.append("Uncertainty: " + "; ".join(uncertainty))
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
        evidence_signals=signals,
        confidence=confidence,
        uncertainty=uncertainty,
        severity=severity,
        possible_threat=possible_threat,
        recommendations=recommendations,
    )
