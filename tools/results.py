"""Typed result objects returned by simulated tools."""

from pydantic import BaseModel, ConfigDict, Field


class ToolResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1)


class RunbookRetrievalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    matched_runbook: str = Field(min_length=1)
    content: str = Field(min_length=1)
    score: int


class ToolDispatchResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    tool: str
    risk_level: str
    decision: str
    ok: bool
    result: object | None = None
    error: str | None = None
