from __future__ import annotations

import datetime as dt
from typing import Any, Dict, List, Optional

from sqlalchemy import Column, JSON
from sqlmodel import Field

from acp_backend.models.base import SQLModelBase


class Role(SQLModelBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    permissions: List[str] = Field(default_factory=list, sa_column=Column(JSON))


class Agent(SQLModelBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    hashed_api_key: str = Field(index=True)
    role_id: Optional[int] = Field(default=None, foreign_key="role.id")


class User(SQLModelBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    hashed_token: str
    role_id: Optional[int] = Field(default=None, foreign_key="role.id")


class Tool(SQLModelBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    type: str  # http or internal
    endpoint: Optional[str] = None
    requires_approval: bool = Field(default=False)
    allowed_domains: List[str] = Field(default_factory=list, sa_column=Column(JSON))


class ApprovalRequest(SQLModelBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    approval_id: str = Field(index=True)
    agent_id: Optional[int] = Field(default=None, foreign_key="agent.id")
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    tool_name: str
    status: str = Field(default="PENDING")
    created_at: dt.datetime = Field(default_factory=dt.datetime.utcnow)
    token: str
    approved_by: Optional[str] = None


class AuditLogEntry(SQLModelBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: dt.datetime = Field(default_factory=dt.datetime.utcnow, index=True)
    action: str
    agent_id: Optional[int] = None
    user_id: Optional[int] = None
    tool_name: Optional[str] = None
    decision: str
    details: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    prev_hash: str = Field(default="0" * 64)
    current_hash: str = Field(default="")
    trace_id: Optional[str] = None


class Trace(SQLModelBase, table=True):
    trace_id: str = Field(primary_key=True)
    created_at: dt.datetime = Field(default_factory=dt.datetime.utcnow, index=True)
    agent_id: Optional[int] = None
    user_id: Optional[int] = None
    tool_name: str
    request_payload: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    redacted_request: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    response_payload: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    redacted_response: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    policy_decision: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    execution_details: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
