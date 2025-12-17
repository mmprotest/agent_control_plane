from __future__ import annotations

from acp_backend.services.dlp import scan_and_redact


def test_dlp_redacts_secrets():
    payload = {"key": "sk-1234567890123456", "email": "test@example.com"}
    redacted, redactions = scan_and_redact(payload)
    assert redacted["key"] == "***REDACTED***"
    assert "key" in redactions
    assert redacted["email"] == "***REDACTED***"
