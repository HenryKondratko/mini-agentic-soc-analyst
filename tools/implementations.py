"""Deterministic simulated integrations. They do not change external state."""

from __future__ import annotations

from app.models import IdentityHistoryResult, Severity, ThreatIntelResult
from app.retrieval import retrieve_runbook
from tools.requests import (
    CheckIPReputationRequest,
    ForcePasswordResetRequest,
    IsolateEndpointRequest,
    LookupIdentityHistoryRequest,
    RetrieveRunbookRequest,
    RevokeSessionsRequest,
)
from tools.results import RunbookRetrievalResponse, ToolResponse


def check_ip_reputation(request: CheckIPReputationRequest) -> ThreatIntelResult:
    if str(request.ip) == "185.22.14.8":
        return ThreatIntelResult(
            ip=request.ip,
            score=92,
            risk_level=Severity.HIGH,
            country="Netherlands",
            malicious=True,
            source="deterministic-fixture",
        )
    return ThreatIntelResult(
        ip=request.ip,
        score=5,
        risk_level=Severity.LOW,
        country=None,
        malicious=False,
        source="deterministic-fixture",
    )


def lookup_identity_history(request: LookupIdentityHistoryRequest) -> IdentityHistoryResult:
    if request.username.lower() == "jsmith":
        return IdentityHistoryResult(
            username=request.username,
            typical_region="Michigan, US",
            known_devices=["jsmith-laptop", "jsmith-mobile"],
            auth_locations=["Detroit, US", "Ann Arbor, US"],
            recent_events=[
                "Successful login from jsmith-laptop in Michigan",
                "Failed login burst from an unfamiliar location",
            ],
        )
    return IdentityHistoryResult(
        username=request.username,
        typical_region=None,
        known_devices=[],
        auth_locations=[],
        recent_events=[],
    )


def retrieve_runbook_tool(request: RetrieveRunbookRequest) -> RunbookRetrievalResponse:
    name, content, score = retrieve_runbook(request.query)
    return RunbookRetrievalResponse(matched_runbook=name, content=content, score=score)


def revoke_sessions(request: RevokeSessionsRequest) -> ToolResponse:
    return ToolResponse(message=f"Simulated session revocation for {request.username}; no external change made.")


def force_password_reset(request: ForcePasswordResetRequest) -> ToolResponse:
    return ToolResponse(message=f"Simulated password reset for {request.username}; no external change made.")


def isolate_endpoint(request: IsolateEndpointRequest) -> ToolResponse:
    return ToolResponse(message=f"Simulated endpoint isolation for {request.hostname}; no external change made.")
