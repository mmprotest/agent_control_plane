from __future__ import annotations

from sqlmodel import Session, create_engine

from acp_backend.models.entities import AuditLogEntry
from acp_backend.services.audit import append_audit_log


def test_hash_chain_integrity():
    engine = create_engine("sqlite:///:memory:")
    AuditLogEntry.metadata.create_all(engine)
    with Session(engine) as session:
        first = append_audit_log(
            session,
            {
                "action": "a",
                "decision": "x",
                "details": {},
                "agent_id": 1,
                "user_id": None,
                "tool_name": "echo",
                "trace_id": "t1",
            },
        )
        second = append_audit_log(
            session,
            {
                "action": "b",
                "decision": "y",
                "details": {},
                "agent_id": 1,
                "user_id": None,
                "tool_name": "echo",
                "trace_id": "t2",
            },
        )
        assert first.current_hash != second.current_hash
        assert second.prev_hash == first.current_hash
