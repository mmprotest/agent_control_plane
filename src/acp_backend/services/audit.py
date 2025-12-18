from __future__ import annotations

from typing import Any, Dict

from sqlmodel import Session, select

from acp_backend.core.utils import hash_chain
from acp_backend.models.entities import AuditLogEntry


def append_audit_log(session: Session, entry_data: Dict[str, Any]) -> AuditLogEntry:
    normalized = _normalize_entry(entry_data)
    last_hash = "0" * 64
    last_entry = session.exec(select(AuditLogEntry).order_by(AuditLogEntry.id.desc())).first()
    if last_entry:
        last_hash = last_entry.current_hash
    current_hash = hash_chain(last_hash, normalized)
    entry = AuditLogEntry(**normalized, prev_hash=last_hash, current_hash=current_hash)
    session.add(entry)
    session.commit()
    session.refresh(entry)
    return entry


def reconstruct_entry_payload(entry: AuditLogEntry) -> Dict[str, Any]:
    return _normalize_entry(entry.__dict__)


def verify_audit_log(session: Session) -> bool:
    entries = session.exec(select(AuditLogEntry).order_by(AuditLogEntry.id)).all()
    last_hash = "0" * 64
    for entry in entries:
        payload = reconstruct_entry_payload(entry)
        expected_current = hash_chain(last_hash, payload)
        if entry.prev_hash != last_hash or entry.current_hash != expected_current:
            return False
        last_hash = entry.current_hash
    return True


def _normalize_entry(entry_data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "action": entry_data.get("action"),
        "tenant_id": entry_data.get("tenant_id"),
        "principal_id": entry_data.get("principal_id"),
        "agent_id": entry_data.get("agent_id"),
        "user_id": entry_data.get("user_id"),
        "tool_name": entry_data.get("tool_name"),
        "decision": entry_data.get("decision"),
        "details": entry_data.get("details") or {},
        "trace_id": entry_data.get("trace_id"),
    }
