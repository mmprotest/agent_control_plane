from __future__ import annotations

from typing import Any, Dict

from sqlmodel import Session, select

from acp_backend.core.utils import canonical_json, hash_chain
from acp_backend.models.entities import AuditLogEntry


def append_audit_log(session: Session, entry_data: Dict[str, Any]) -> AuditLogEntry:
    last_hash = "0" * 64
    last_entry = session.exec(select(AuditLogEntry).order_by(AuditLogEntry.id.desc())).first()
    if last_entry:
        last_hash = last_entry.current_hash
    current_hash = hash_chain(last_hash, entry_data)
    entry = AuditLogEntry(**entry_data, prev_hash=last_hash, current_hash=current_hash)
    session.add(entry)
    session.commit()
    session.refresh(entry)
    return entry
