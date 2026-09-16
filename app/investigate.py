"""Command line entry point: python -m app.investigate alert.json."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import cast

from pydantic import ValidationError

from app.audit import AuditLogger
from app.models import InvestigationResult, RecommendedAction, SecurityAlert, ToolRiskLevel
from app.orchestrator import investigate
from tools.guardrails import dispatch_tool
from tools.results import ToolResponse


def _load_alert(path: Path) -> SecurityAlert:
    try:
        with path.open(encoding="utf-8") as stream:
            payload = json.load(stream)
        return SecurityAlert.model_validate(payload)
    except FileNotFoundError as exc:
        raise ValueError(f"alert file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"alert file is not valid JSON: {exc.msg}") from exc
    except ValidationError as exc:
        details = "; ".join(f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}" for error in exc.errors())
        raise ValueError(f"alert validation failed: {details}") from exc


def _recommendation_args(action: str, target: str) -> dict[str, str] | None:
    if action in {"revoke_sessions", "force_password_reset"}:
        return {"username": target}
    if action == "isolate_endpoint":
        return {"hostname": target}
    return None


def _dispatch_recommendation(
    result: InvestigationResult,
    logger: AuditLogger,
    action: str,
    *,
    approved: bool,
) -> None:
    recommendation = next(
        (item for item in result.recommendations if item.action == action),
        None,
    )
    if recommendation is None:
        error = f"action is not an exact recommendation for this investigation: {action}"
        logger.record(
            alert_id=result.alert.alert_id,
            action="approve-action",
            tool=action or "empty-action",
            risk_level=ToolRiskLevel.HIGH_IMPACT,
            decision="REJECTED",
            result=error,
        )
        print(f"Action rejected safely: {error}")
        return
    args = _recommendation_args(recommendation.action, recommendation.target)
    if args is None:
        error = f"recommendation has no safe argument mapping: {recommendation.action}"
        logger.record(
            alert_id=result.alert.alert_id,
            action="approve-action",
            tool=recommendation.action,
            risk_level=ToolRiskLevel.HIGH_IMPACT,
            decision="REJECTED",
            result=error,
        )
        print(f"Action rejected safely: {error}")
        return
    call = dispatch_tool(
        recommendation.action,
        args,
        approval=approved,
        alert_id=result.alert.alert_id,
        audit_logger=logger,
    )
    if call.ok and isinstance(call.result, ToolResponse):
        print(f"Action result: {call.result.message}")
    else:
        print(f"Action rejected safely: {call.error}")


def _execute_one_recommendation(result: InvestigationResult, logger: AuditLogger) -> None:
    if not result.recommendations:
        return
    recommendation = result.recommendations[0]
    try:
        answer = (
            input(f"Approve one high-impact action, {recommendation.action} on {recommendation.target}? [y/N] ")
            .strip()
            .lower()
        )
    except EOFError:
        answer = ""
    if answer in {"y", "yes"}:
        _dispatch_recommendation(result, logger, recommendation.action, approved=True)
    else:
        _dispatch_recommendation(result, logger, recommendation.action, approved=False)


def _print_result(result: InvestigationResult) -> None:
    print(f"Investigation {result.alert.alert_id}: {result.severity.value}")
    print(f"Confidence: {result.confidence}/100")
    print(f"Possible threat: {result.possible_threat}")
    print(f"Runbook: {result.matched_runbook} (score {result.retrieval_score})")
    print("Evidence:")
    for item in result.evidence:
        print(f"  - {item}")
    if result.recommendations:
        print("Recommendations:")
        for raw_item in result.recommendations:
            recommendation_item = cast(RecommendedAction, raw_item)
            print(f"  - {recommendation_item.action} ({recommendation_item.target})")
    else:
        print("No high-impact action recommended.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("alert_file")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--approve-action")
    try:
        parsed = parser.parse_args(argv if argv is not None else sys.argv[1:])
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        alert = _load_alert(Path(parsed.alert_file))
        logger = AuditLogger()
        result = investigate(alert, audit_logger=logger)
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    _print_result(result)
    if parsed.dry_run:
        return 0
    if parsed.approve_action is not None:
        _dispatch_recommendation(result, logger, parsed.approve_action, approved=True)
    elif result.recommendations:
        _execute_one_recommendation(result, logger)
    else:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
