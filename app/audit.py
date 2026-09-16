"""Append-only JSONL audit logging."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from app.models import AuditEvent, ToolRiskLevel


class AuditLogger:
    """Writes one validated event per line and creates its parent directory."""

    def __init__(self, path: str | Path = "logs/audit.jsonl") -> None:
        self.path = Path(path)
        self._lock = Lock()

    def record(
        self,
        *,
        alert_id: str,
        action: str,
        tool: str,
        risk_level: ToolRiskLevel,
        decision: str,
        result: Any,
    ) -> AuditEvent:
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc),
            alert_id=alert_id,
            action=action,
            tool=tool,
            risk_level=risk_level,
            decision=decision,
            result=result,
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event.model_dump(mode="json"), sort_keys=True)
        with self._lock, self.path.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
        return event
