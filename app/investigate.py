"""Command line entry point: python -m app.investigate alert.json."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pydantic import ValidationError

from app.audit import AuditLogger
from app.models import SecurityAlert
from app.orchestrator import investigate
from tools.guardrails import dispatch_tool


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
        details = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors()
        )
        raise ValueError(f"alert validation failed: {details}") from exc


def _execute_one_recommendation(result, logger: AuditLogger) -> None:
    if not result.recommendations:
        return
    recommendation = result.recommendations[0]
    try:
        answer = input(
            f"Approve one high-impact action, {recommendation.action} on "
            f"{recommendation.target}? [y/N] "
        ).strip().lower()
    except EOFError:
        answer = ""
    approved = answer in {"y", "yes"}
    args = (
        {"hostname": recommendation.target}
        if recommendation.action == "isolate_endpoint"
        else {"username": recommendation.target}
    )
    call = dispatch_tool(
        recommendation.action,
        args,
        approval=approved,
        alert_id=result.alert.alert_id,
        audit_logger=logger,
    )
    if call.ok:
        print(f"Action result: {call.result.message}")
    else:
        print(f"Action rejected safely: {call.error}")


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1:
        print("Usage: python -m app.investigate <alert.json>", file=sys.stderr)
        return 2
    try:
        alert = _load_alert(Path(args[0]))
        logger = AuditLogger()
        result = investigate(alert, audit_logger=logger)
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print(f"Investigation {result.alert.alert_id}: {result.severity.value}")
    print(f"Possible threat: {result.possible_threat}")
    print(f"Runbook: {result.matched_runbook} (score {result.retrieval_score})")
    print("Evidence:")
    for item in result.evidence:
        print(f"  - {item}")
    if result.recommendations:
        print("Recommendations:")
        for item in result.recommendations:
            print(f"  - {item.action} ({item.target})")
        _execute_one_recommendation(result, logger)
    else:
        print("No high-impact action recommended.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
