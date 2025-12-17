from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import yaml

from acp_backend.core.config import get_settings


@dataclass
class PolicyDecision:
    decision: str
    constraints: Dict[str, Any]
    matched_rule: Optional[Dict[str, Any]]


class PolicyEngine:
    def __init__(self, policy_path: Optional[str] = None):
        self.policy_path = policy_path or get_settings().policy_path
        self.rules: List[Dict[str, Any]] = []
        self.load()

    def load(self) -> None:
        with open(self.policy_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        self.rules = data.get("rules", [])

    def evaluate(
        self,
        *,
        tool_name: str,
        agent_id: Optional[int],
        role: Optional[str],
        purpose: Optional[str],
        user_attributes: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        for rule in self.rules:
            if not self._matches(rule, tool_name, agent_id, role, purpose, user_attributes):
                continue
            decision = rule.get("decision", "deny")
            constraints = rule.get("constraints", {})
            return PolicyDecision(decision=decision, constraints=constraints, matched_rule=rule)
        return PolicyDecision(decision="deny", constraints={}, matched_rule=None)

    def _matches(
        self,
        rule: Dict[str, Any],
        tool_name: str,
        agent_id: Optional[int],
        role: Optional[str],
        purpose: Optional[str],
        user_attributes: Optional[Dict[str, Any]],
    ) -> bool:
        def match_value(rule_value: Any, candidate: Any) -> bool:
            if rule_value is None:
                return True
            if isinstance(rule_value, list):
                return candidate in rule_value
            return rule_value == candidate

        if not match_value(rule.get("tool"), tool_name):
            return False
        if not match_value(rule.get("agent_id"), agent_id):
            return False
        if not match_value(rule.get("role"), role):
            return False
        if not match_value(rule.get("purpose"), purpose):
            return False
        attributes = rule.get("user_attributes") or {}
        if attributes and user_attributes:
            for key, value in attributes.items():
                if user_attributes.get(key) != value:
                    return False
        elif attributes and not user_attributes:
            return False
        return True
