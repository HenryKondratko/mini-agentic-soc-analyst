"""Deterministic keyword/token-overlap retrieval for local runbooks."""

from __future__ import annotations

import re
from pathlib import Path

TOKEN_RE = re.compile(r"[a-z0-9_]+")
RUNBOOK_DIR = Path(__file__).resolve().parent.parent / "knowledge"


def _tokens(text: str) -> set[str]:
    return set(TOKEN_RE.findall(text.lower()))


def retrieve_runbook(query: str, directory: Path = RUNBOOK_DIR) -> tuple[str, str, int]:
    """Return (runbook name, markdown content, overlap score) deterministically."""
    candidates: list[tuple[int, str, Path]] = []
    for path in sorted(directory.glob("*.md")):
        content = path.read_text(encoding="utf-8")
        score = len(_tokens(query) & _tokens(content))
        candidates.append((score, path.name, path))
    if not candidates:
        raise FileNotFoundError(f"no runbooks found in {directory}")
    score, name, path = max(candidates, key=lambda item: (item[0], item[1]))
    return name, path.read_text(encoding="utf-8"), score
