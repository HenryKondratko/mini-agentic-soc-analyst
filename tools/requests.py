"""Strict request schemas for every registered tool."""

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CheckIPReputationRequest(_Request):
    ip: IPvAnyAddress


class LookupIdentityHistoryRequest(_Request):
    username: str = Field(min_length=1)


class RetrieveRunbookRequest(_Request):
    query: str = Field(min_length=1)


class RevokeSessionsRequest(_Request):
    username: str = Field(min_length=1)


class ForcePasswordResetRequest(_Request):
    username: str = Field(min_length=1)


class IsolateEndpointRequest(_Request):
    hostname: str = Field(min_length=1)
