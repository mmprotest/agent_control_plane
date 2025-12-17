from __future__ import annotations

import json
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Header, HTTPException
from sqlmodel import Session, select

from acp_backend.core.auth import AuthContext, require_auth
from acp_backend.core.config import get_settings
from acp_backend.core.logging import setup_logging
from acp_backend.core.security import verify_secret
from acp_backend.core.utils import canonical_json, generate_trace_id
from acp_backend.database import get_session, init_db
from acp_backend.models.entities import Agent, ApprovalRequest, Role, Tool, Trace, User
from acp_backend.schemas.tool import ToolExecutionRequest, ToolExecutionResponse
from acp_backend.schemas.trace import TraceReplayResponse
from acp_backend.services import audit
from acp_backend.services.dlp import scan_and_redact
from acp_backend.services.policy import PolicyEngine
from acp_backend.services.rate_limit import RateLimiter
from acp_backend.tooling.http_connector import HttpToolConnector
from acp_backend.tooling.internal_tools import InternalToolRegistry


settings = get_settings()
setup_logging()
app = FastAPI(title="MCP Firewall", version="0.2.0")
policy_engine = PolicyEngine()
rate_limiter = RateLimiter()
internal_tools = InternalToolRegistry()
http_connector = HttpToolConnector()


@app.on_event("startup")
def on_startup() -> None:
    init_db()


async def get_db_session() -> Session:
    with get_session() as session:
        yield session


def authenticate_agent(session: Session, api_key: str) -> Agent:
    agents = session.exec(select(Agent)).all()
    for agent in agents:
        if verify_secret(api_key, agent.hashed_api_key):
            return agent
    raise HTTPException(status_code=401, detail="invalid_api_key")


def authenticate_user(session: Session, token: Optional[str]) -> Optional[User]:
    if token is None:
        return None
    users = session.exec(select(User)).all()
    for user in users:
        if verify_secret(token, user.hashed_token):
            return user
    return None


@app.post(f"{settings.api_prefix}/tool/execute", response_model=ToolExecutionResponse)
async def execute_tool(
    request: ToolExecutionRequest,
    auth_context: AuthContext = Depends(require_auth),
    api_key: str = Header(..., alias="X-API-Key"),
    user_token: Optional[str] = Header(default=None, alias="X-User-Token"),
    session: Session = Depends(get_db_session),
) -> ToolExecutionResponse:
    if not rate_limiter.allow(api_key, settings.rate_limit_per_minute):
        raise HTTPException(status_code=429, detail="rate_limited")
    trace_id = request.trace_id or generate_trace_id()
    agent = authenticate_agent(session, api_key)
    user = authenticate_user(session, user_token)
    user_id: Optional[int] = user.id if user else None

    tool = session.exec(select(Tool).where(Tool.name == request.tool_name)).first()
    if not tool:
        raise HTTPException(status_code=404, detail="unknown_tool")

    agent_role = session.get(Role, agent.role_id) if agent.role_id else None
    user_role = session.get(Role, user.role_id) if user and user.role_id else None

    redacted_args, redactions = scan_and_redact(
        {"args": request.args, "reasoning": request.reasoning}
    )

    def _deny(reason: str, *, violation: Optional[Dict[str, Any]] = None) -> ToolExecutionResponse:
        trace = Trace(
            trace_id=trace_id,
            agent_id=agent.id,
            tenant_id=auth_context.tenant_id,
            user_id=user_id,
            tool_name=request.tool_name,
            request_payload=request.model_dump(),
            redacted_request=redacted_args,
            policy_decision={
                "decision": "deny",
                "rule": None,
                "constraints": {},
                "violation": violation or {"reason": reason},
            },
            response_payload={"status": "denied", "reason": reason},
            redacted_response={"status": "denied"},
            execution_details={"reason": reason},
        )
        session.add(trace)
        session.commit()
        audit.append_audit_log(
            session,
            {
                "action": "tool_denied",
                "tenant_id": auth_context.tenant_id,
                "principal_id": auth_context.principal_id,
                "agent_id": agent.id,
                "user_id": user_id,
                "tool_name": request.tool_name,
                "decision": "deny",
                "details": {"reason": reason, "violation": violation},
                "trace_id": trace_id,
            },
        )
        return ToolExecutionResponse(
            status="DENIED", message=reason, redactions=redactions, trace_id=trace_id
        )

    if not agent_role:
        return _deny("agent_role_missing")
    if request.tool_name not in agent_role.permissions and "*" not in agent_role.permissions:
        return _deny("agent_role_denied")
    if user:
        if not user_role:
            return _deny("user_role_missing")
        if request.tool_name not in user_role.permissions and "*" not in user_role.permissions:
            return _deny("user_role_denied")

    decision = policy_engine.evaluate(
        tool_name=request.tool_name,
        agent_id=agent.id,
        role=agent_role.name if agent_role else None,
        purpose=request.purpose,
    )

    def _violation(reason: str, meta: Dict[str, Any]) -> ToolExecutionResponse:
        violation = {"reason": reason, **meta}
        trace = Trace(
            trace_id=trace_id,
            agent_id=agent.id,
            tenant_id=auth_context.tenant_id,
            user_id=user_id,
            tool_name=request.tool_name,
            request_payload=request.model_dump(),
            redacted_request=redacted_args,
            policy_decision={
                "decision": decision.decision,
                "rule": decision.matched_rule,
                "constraints": decision.constraints,
                "violation": violation,
            },
            response_payload={"status": "denied", "reason": reason},
            redacted_response={"status": "denied"},
            execution_details={"reason": reason},
        )
        session.add(trace)
        session.commit()
        audit.append_audit_log(
            session,
            {
                "action": "tool_denied",
                "tenant_id": auth_context.tenant_id,
                "principal_id": auth_context.principal_id,
                "agent_id": agent.id,
                "user_id": user_id,
                "tool_name": request.tool_name,
                "decision": "deny",
                "details": {"policy_rule": decision.matched_rule, "violation": violation},
                "trace_id": trace_id,
            },
        )
        return ToolExecutionResponse(
            status="DENIED", message=reason, redactions=redactions, trace_id=trace_id
        )

    def _size_bytes(payload: Any) -> int:
        try:
            serialized = canonical_json(
                payload if isinstance(payload, dict) else {"value": payload}
            )
        except TypeError:
            serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return len(serialized.encode("utf-8"))

    max_bytes = decision.constraints.get("max_bytes") if decision.constraints else None
    if max_bytes is not None:
        if _size_bytes(request.args) > int(max_bytes):
            return _violation("max_bytes_exceeded", {"subject": "args", "limit": max_bytes})

    if decision.constraints.get("max_calls_per_minute"):
        limit = int(decision.constraints["max_calls_per_minute"])
        rate_key = f"{auth_context.tenant_id}:{request.tool_name}"
        if not rate_limiter.allow(rate_key, limit):
            return _violation("rate_limited", {"limit": limit, "window_seconds": 60})

    if tool.type == "http":
        host = urlparse(tool.endpoint or "").hostname
        allowed_domains = decision.constraints.get("allow_domains") or tool.allowed_domains
        denied_domains = decision.constraints.get("deny_domains") or tool.denied_domains
        if allowed_domains and host not in allowed_domains:
            return _violation("domain_not_allowed", {"host": host, "allow": allowed_domains})
        if denied_domains and host in denied_domains:
            return _violation("domain_denied", {"host": host, "deny": denied_domains})

    if decision.decision == "deny":
        return _violation("policy_denied", {"policy_rule": decision.matched_rule or "default"})

    approved_token: Optional[str] = None
    if request.approval_token:
        approval = session.exec(
            select(ApprovalRequest).where(ApprovalRequest.token == request.approval_token)
        ).first()
        if approval and approval.status == "APPROVED":
            approved_token = approval.token

    if decision.decision == "approval_required" or tool.requires_approval:
        if not approved_token:
            approval = ApprovalRequest(
                approval_id=generate_trace_id(),
                agent_id=agent.id,
                tenant_id=auth_context.tenant_id,
                user_id=user_id,
                tool_name=request.tool_name,
                status="PENDING",
                token=generate_trace_id(),
            )
            session.add(approval)
            session.commit()
            session.refresh(approval)
            audit.append_audit_log(
                session,
                {
                    "action": "approval_created",
                    "tenant_id": auth_context.tenant_id,
                    "principal_id": auth_context.principal_id,
                    "agent_id": agent.id,
                    "user_id": user_id,
                    "tool_name": request.tool_name,
                    "decision": "pending",
                    "details": {"approval_id": approval.approval_id},
                    "trace_id": trace_id,
                },
            )
            return ToolExecutionResponse(
                status="PENDING",
                approval_id=approval.approval_id,
                approval_token=approval.token,
                redactions=redactions,
                trace_id=trace_id,
                message="approval_required",
            )

    output: Dict[str, Any] = {}
    execution_details: Dict[str, Any] = {}
    try:
        if tool.type == "http":
            output = await http_connector.execute(
                tool.endpoint or "", request.args, tool.allowed_domains, tool.denied_domains
            )
        else:
            output = internal_tools.execute(request.tool_name, request.args)
        execution_details = {"status": "success"}
    except Exception as exc:  # noqa: BLE001
        execution_details = {"status": "error", "message": str(exc)}
        output = {"error": str(exc)}

    redacted_output, output_redactions = scan_and_redact(output)
    combined_redactions = {**redactions, **output_redactions}

    if max_bytes is not None and _size_bytes(output) > int(max_bytes):
        return _violation("max_bytes_exceeded", {"subject": "output", "limit": max_bytes})

    trace = Trace(
        trace_id=trace_id,
        agent_id=agent.id,
        tenant_id=auth_context.tenant_id,
        user_id=user_id,
        tool_name=request.tool_name,
        request_payload=request.model_dump(),
        redacted_request=redacted_args,
        response_payload=output,
        redacted_response=redacted_output,
        policy_decision={
            "decision": decision.decision,
            "rule": decision.matched_rule,
            "constraints": decision.constraints,
        },
        execution_details=execution_details,
    )
    session.add(trace)
    session.commit()

    audit.append_audit_log(
        session,
        {
            "action": "tool_executed",
            "tenant_id": auth_context.tenant_id,
            "principal_id": auth_context.principal_id,
            "agent_id": agent.id,
            "user_id": user_id,
            "tool_name": request.tool_name,
            "decision": decision.decision,
            "details": execution_details,
            "trace_id": trace_id,
        },
    )
    return ToolExecutionResponse(
        status="SUCCESS", output=output, redactions=combined_redactions, trace_id=trace_id
    )


@app.post(f"{settings.api_prefix}/approvals/{{approval_id}}/approve")
async def approve_request(
    approval_id: str,
    token: str,
    approver: str,
    session: Session = Depends(get_db_session),
    auth_context: AuthContext = Depends(require_auth),
) -> Dict[str, str]:
    approval = session.exec(
        select(ApprovalRequest).where(ApprovalRequest.approval_id == approval_id)
    ).first()
    if not approval:
        raise HTTPException(status_code=404, detail="approval_not_found")
    if approval.token != token:
        raise HTTPException(status_code=403, detail="invalid_token")
    approval.status = "APPROVED"
    approval.approved_by = approver
    session.add(approval)
    session.commit()
    audit.append_audit_log(
        session,
        {
            "action": "approval_completed",
            "tenant_id": auth_context.tenant_id,
            "principal_id": auth_context.principal_id,
            "agent_id": approval.agent_id,
            "user_id": approval.user_id,
            "tool_name": approval.tool_name,
            "decision": "approved",
            "details": {"approval_id": approval_id, "approved_by": approver},
            "trace_id": None,
        },
    )
    return {"status": "approved", "execution_token": approval.token}


@app.get(f"{settings.api_prefix}/traces/{{trace_id}}/replay", response_model=TraceReplayResponse)
async def replay_trace(
    trace_id: str,
    dry_run: bool = False,
    session: Session = Depends(get_db_session),
    auth_context: AuthContext = Depends(require_auth),
) -> TraceReplayResponse:
    trace = session.get(Trace, trace_id)
    if not trace:
        raise HTTPException(status_code=404, detail="trace_not_found")
    dry_run_result: Optional[Dict[str, Any]] = None
    if dry_run:
        decision = policy_engine.evaluate(
            tool_name=trace.tool_name,
            agent_id=trace.agent_id,
            role=None,
            purpose=trace.request_payload.get("purpose"),
        )
        dry_run_result = {
            "decision": decision.decision,
            "rule": decision.matched_rule,
            "constraints": decision.constraints,
        }
    return TraceReplayResponse(
        trace_id=trace.trace_id,
        request_payload=trace.request_payload,
        redacted_request=trace.redacted_request,
        response_payload=trace.response_payload,
        redacted_response=trace.redacted_response,
        policy_decision=trace.policy_decision,
        execution_details=trace.execution_details,
        dry_run_result=dry_run_result,
    )


@app.get("/")
async def root() -> Dict[str, str]:
    return {"status": "ok"}
