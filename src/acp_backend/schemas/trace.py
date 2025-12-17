from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel


class TraceReplayResponse(BaseModel):
    trace_id: str
    request_payload: Dict[str, Any]
    redacted_request: Dict[str, Any]
    response_payload: Dict[str, Any]
    redacted_response: Dict[str, Any]
    policy_decision: Dict[str, Any]
    execution_details: Dict[str, Any]
    dry_run_result: Optional[Dict[str, Any]] = None
