from __future__ import annotations

import re
from typing import Any, Dict, Iterable, Tuple

from acp_backend.core.config import get_settings

SECRET_REGEX = re.compile(r"(sk-[A-Za-z0-9]{16,})")
EMAIL_REGEX = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_REGEX = re.compile(r"\+?\d{1,2}?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")


def _iter_strings(data: Any, path: str = "") -> Iterable[Tuple[str, str]]:
    if isinstance(data, dict):
        for key, value in data.items():
            new_path = f"{path}.{key}" if path else key
            yield from _iter_strings(value, new_path)
    elif isinstance(data, list):
        for idx, value in enumerate(data):
            new_path = f"{path}[{idx}]"
            yield from _iter_strings(value, new_path)
    elif isinstance(data, str):
        yield path, data


def _apply_redaction(value: str) -> str:
    return "***REDACTED***"


def scan_and_redact(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    settings = get_settings()
    redactions: Dict[str, str] = {}
    custom_patterns = [re.compile(p) for p in settings.dlp_custom_patterns]

    def sanitize(obj: Any, path: str = "") -> Any:
        if isinstance(obj, dict):
            return {k: sanitize(v, f"{path}.{k}" if path else k) for k, v in obj.items()}
        if isinstance(obj, list):
            return [sanitize(v, f"{path}[{i}]") for i, v in enumerate(obj)]
        if isinstance(obj, str):
            for label, regex in (
                ("secret", SECRET_REGEX),
                ("email", EMAIL_REGEX),
                ("phone", PHONE_REGEX),
            ):
                if regex.search(obj):
                    redactions[path] = label
                    return _apply_redaction(obj)
            for regex in custom_patterns:
                if regex.search(obj):
                    redactions[path] = "custom"
                    return _apply_redaction(obj)
            return obj
        return obj

    sanitized = sanitize(payload)
    return sanitized, redactions
