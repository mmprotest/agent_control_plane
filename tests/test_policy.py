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
    assert decision.matched_rule and decision.matched_rule["tool"] == "echo"


def test_policy_denies_default():
    data = {"rules": []}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.safe_dump(data, f)
        path = f.name
    engine = PolicyEngine(policy_path=path)
    decision = engine.evaluate(tool_name="unknown", agent_id=None, role=None, purpose=None)
    assert decision.decision == "deny"


def test_policy_deny_overrides_allow_even_when_specific():
    data = {
        "rules": [
            {"tool": "*", "decision": "deny"},
            {"tool": "echo", "role": "operator", "decision": "allow"},
        ]
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.safe_dump(data, f)
        path = f.name
    engine = PolicyEngine(policy_path=path)
    decision = engine.evaluate(tool_name="echo", agent_id=1, role="operator", purpose=None)
    assert decision.decision == "deny"
    assert decision.matched_rule_index == 0


def test_policy_most_specific_allow_wins():
    data = {
        "rules": [
            {"tool": "*", "decision": "allow"},
            {"tool": "echo", "role": "operator", "decision": "allow", "id": "specific"},
        ]
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.safe_dump(data, f)
        path = f.name
    engine = PolicyEngine(policy_path=path)
    decision = engine.evaluate(tool_name="echo", agent_id=1, role="operator", purpose=None)
    assert decision.decision == "allow"
    assert decision.matched_rule_id == "specific"
    assert decision.specificity_score and decision.specificity_score[0] == 2


def test_policy_tie_breaks_with_rule_order():
    data = {
        "rules": [
            {"tool": "echo", "decision": "allow", "id": "first"},
            {"tool": "echo", "decision": "allow", "id": "second"},
        ]
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.safe_dump(data, f)
        path = f.name
    engine = PolicyEngine(policy_path=path)
    decision = engine.evaluate(tool_name="echo", agent_id=None, role=None, purpose=None)
    assert decision.decision == "allow"
    assert decision.matched_rule_id == "second"
    assert decision.matched_rule_index == 1


def test_policy_explanation_includes_selectors():
    data = {
        "rules": [
            {
                "tool": "echo",
                "role": ["operator", "observer"],
                "purpose": "greeting",
                "decision": "allow",
                "id": "explain",
            }
        ]
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.safe_dump(data, f)
        path = f.name
    engine = PolicyEngine(policy_path=path)
    decision = engine.evaluate(
        tool_name="echo", agent_id=None, role="operator", purpose="greeting", user_attributes={}
    )
    assert decision.decision == "allow"
    assert decision.matched_rule_id == "explain"
    assert decision.matched_selectors == {
        "tool": "echo",
        "role": "operator",
        "purpose": "greeting",
    }
