from __future__ import annotations

import tempfile
import yaml

from acp_backend.services.policy import PolicyEngine


def test_policy_allows_match():
    data = {"rules": [{"tool": "echo", "role": "operator", "decision": "allow"}]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.safe_dump(data, f)
        path = f.name
    engine = PolicyEngine(policy_path=path)
    decision = engine.evaluate(tool_name="echo", agent_id=1, role="operator", purpose=None)
    assert decision.decision == "allow"
    assert decision.matched_rule == data["rules"][0]


def test_policy_denies_default():
    data = {"rules": []}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.safe_dump(data, f)
        path = f.name
    engine = PolicyEngine(policy_path=path)
    decision = engine.evaluate(tool_name="unknown", agent_id=None, role=None, purpose=None)
    assert decision.decision == "deny"
