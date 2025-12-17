from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Dict


def canonical_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_chain(prev_hash: str, entry: Dict[str, Any]) -> str:
    canonical = canonical_json(entry)
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def generate_trace_id() -> str:
    return uuid.uuid4().hex
