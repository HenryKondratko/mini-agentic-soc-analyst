"""Validated domain models used by the investigation workflow."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator


class AlertType(str, Enum):
    SUSPICIOUS_LOGIN = "suspicious_login"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    MALWARE = "malware"
    DATA_EXFILTRATION = "data_exfiltration"
    PHISHING = "phishing"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ToolRiskLevel(str, Enum):
    READ_ONLY = "READ_ONLY"
    HIGH_IMPACT = "HIGH_IMPACT"


class SecurityAlert(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    alert_id: str = Field(min_length=1)
    alert_type: AlertType = Field(validation_alias=AliasChoices("alert_type", "type"))
    timestamp: datetime
    username: str = Field(
        min_length=1,
        validation_alias=AliasChoices("username", "user"),
    )
    source_ip: IPvAnyAddress
    hostname: str = Field(min_length=1)
    description: str = ""
    failed_attempts: int = Field(default=0, ge=0)
    successful_login: bool = False
    device_known: bool = False

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value.astimezone(timezone.utc)


class ThreatIntelResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: IPvAnyAddress
    score: int = Field(ge=0, le=100)
    risk_level: Severity
    country: str | None = None
    malicious: bool
    source: str = Field(min_length=1)


class IdentityHistoryResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1)
    typical_region: str | None = None
    known_devices: list[str] = Field(default_factory=list)
    auth_locations: list[str] = Field(default_factory=list)
    recent_events: list[str] = Field(default_factory=list)


class RecommendedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=1)
    risk_level: ToolRiskLevel
    target: str = Field(min_length=1)
    rationale: str = Field(min_length=1)


class InvestigationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert: SecurityAlert
    threat_intel: ThreatIntelResult
    identity_history: IdentityHistoryResult
    matched_runbook: str
    retrieval_score: int = Field(ge=0)
    evidence: list[str] = Field(min_length=1)
    severity: Severity
    possible_threat: str = Field(min_length=1)
    recommendations: list[RecommendedAction] = Field(default_factory=list)


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    alert_id: str = Field(min_length=1)
    action: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    risk_level: ToolRiskLevel
    decision: str = Field(min_length=1)
    result: Any

    @field_validator("timestamp")
    @classmethod
    def audit_timestamp_is_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value.astimezone(timezone.utc)
