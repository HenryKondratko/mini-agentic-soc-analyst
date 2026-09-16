"""Explicit allowlist: names, risk, request model, and implementation are fixed in code."""

from dataclasses import dataclass
from typing import Any, Callable, Type

from pydantic import BaseModel

from app.models import ToolRiskLevel
from tools import implementations
from tools.requests import (
    CheckIPReputationRequest,
    ForcePasswordResetRequest,
    IsolateEndpointRequest,
    LookupIdentityHistoryRequest,
    RetrieveRunbookRequest,
    RevokeSessionsRequest,
)


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    risk_level: ToolRiskLevel
    request_model: Type[BaseModel]
    handler: Callable[[Any], BaseModel]


TOOL_REGISTRY: dict[str, ToolDefinition] = {
    "check_ip_reputation": ToolDefinition(
        "check_ip_reputation", ToolRiskLevel.READ_ONLY, CheckIPReputationRequest, implementations.check_ip_reputation
    ),
    "lookup_identity_history": ToolDefinition(
        "lookup_identity_history",
        ToolRiskLevel.READ_ONLY,
        LookupIdentityHistoryRequest,
        implementations.lookup_identity_history,
    ),
    "retrieve_runbook": ToolDefinition(
        "retrieve_runbook", ToolRiskLevel.READ_ONLY, RetrieveRunbookRequest, implementations.retrieve_runbook_tool
    ),
    "revoke_sessions": ToolDefinition(
        "revoke_sessions", ToolRiskLevel.HIGH_IMPACT, RevokeSessionsRequest, implementations.revoke_sessions
    ),
    "force_password_reset": ToolDefinition(
        "force_password_reset",
        ToolRiskLevel.HIGH_IMPACT,
        ForcePasswordResetRequest,
        implementations.force_password_reset,
    ),
    "isolate_endpoint": ToolDefinition(
        "isolate_endpoint",
        ToolRiskLevel.HIGH_IMPACT,
        IsolateEndpointRequest,
        implementations.isolate_endpoint,
    ),
}
