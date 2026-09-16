"""Fail-closed dispatcher enforcing the explicit registry and approval boundary."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from app.audit import AuditLogger
from app.models import ToolRiskLevel
from tools.registry import TOOL_REGISTRY
from tools.results import ToolDispatchResult


def dispatch_tool(
    tool_name: str,
    args: Mapping[str, Any],
    *,
    approval: bool = False,
    alert_id: str = "unattributed",
    audit_logger: AuditLogger | None = None,
) -> ToolDispatchResult:
    """Validate and dispatch one allowlisted tool; unknown or unsafe calls fail closed."""
    logger = audit_logger or AuditLogger()
    definition = TOOL_REGISTRY.get(tool_name)
    if definition is None:
        risk = ToolRiskLevel.HIGH_IMPACT
        error = f"tool is not allowlisted: {tool_name}"
        logger.record(
            alert_id=alert_id, action="dispatch", tool=tool_name, risk_level=risk, decision="REJECTED", result=error
        )
        return ToolDispatchResult(tool=tool_name, risk_level=risk.value, decision="REJECTED", ok=False, error=error)
    try:
        request = definition.request_model.model_validate(dict(args))
    except (ValidationError, TypeError, ValueError) as exc:
        error = f"invalid tool request: {exc}"
        logger.record(
            alert_id=alert_id,
            action="dispatch",
            tool=tool_name,
            risk_level=definition.risk_level,
            decision="REJECTED",
            result=error,
        )
        return ToolDispatchResult(
            tool=tool_name,
            risk_level=definition.risk_level.value,
            decision="REJECTED",
            ok=False,
            error=error,
        )
    if definition.risk_level == ToolRiskLevel.HIGH_IMPACT and not approval:
        error = "explicit approval is required for high-impact tools"
        logger.record(
            alert_id=alert_id,
            action="dispatch",
            tool=tool_name,
            risk_level=definition.risk_level,
            decision="REJECTED",
            result=error,
        )
        return ToolDispatchResult(
            tool=tool_name,
            risk_level=definition.risk_level.value,
            decision="REJECTED",
            ok=False,
            error=error,
        )
    try:
        result = definition.handler(request)
    except (TypeError, ValueError) as exc:
        error = f"tool execution failed closed: {exc}"
        logger.record(
            alert_id=alert_id,
            action="dispatch",
            tool=tool_name,
            risk_level=definition.risk_level,
            decision="REJECTED",
            result=error,
        )
        return ToolDispatchResult(
            tool=tool_name,
            risk_level=definition.risk_level.value,
            decision="REJECTED",
            ok=False,
            error=error,
        )
    logger.record(
        alert_id=alert_id,
        action="dispatch",
        tool=tool_name,
        risk_level=definition.risk_level,
        decision="ALLOWED",
        result=result.model_dump(mode="json"),
    )
    return ToolDispatchResult(
        tool=tool_name,
        risk_level=definition.risk_level.value,
        decision="ALLOWED",
        ok=True,
        result=result,
    )
