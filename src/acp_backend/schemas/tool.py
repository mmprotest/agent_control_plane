from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class ToolExecutionRequest(BaseModel):
    tool_name: str
    args: Dict[str, Any]
    agent_id: Optional[int] = None
    user_id: Optional[int] = None
    trace_id: Optional[str] = None
    purpose: Optional[str] = None
    reasoning: Optional[str] = None
    approval_token: Optional[str] = None


class ToolExecutionResponse(BaseModel):
    status: str
    output: Optional[Dict[str, Any]] = None
    approval_id: Optional[str] = None
    approval_token: Optional[str] = None
    redactions: Optional[Dict[str, Any]] = None
    trace_id: Optional[str] = None
    message: Optional[str] = None
