from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import yaml

from acp_backend.core.config import get_settings


_logger = logging.getLogger(__name__)
_WARNED_ALIASES: set[str] = set()


@dataclass
class PolicyDecision:
    decision: str
    constraints: Dict[str, Any]
    matched_rule: Optional[Dict[str, Any]]
    matched_rule_id: Optional[str] | None = None
    matched_rule_index: Optional[int] = None
    specificity_score: Tuple[int, ...] | None = None
    matched_selectors: Dict[str, Any] | None = None


class PolicyEngine:
    def __init__(self, policy_path: Optional[str] = None):
        self.policy_path = policy_path or get_settings().policy_path
        self.rules: List[Dict[str, Any]] = []
        self.load()

    def load(self) -> None:
        with open(self.policy_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        raw_rules = data.get("rules", [])
        self.rules = [self._normalize_rule(rule) for rule in raw_rules]

    def evaluate(
        self,
        *,
        tool_name: str,
        agent_id: Optional[int],
        role: Optional[str],
        purpose: Optional[str],
        user_attributes: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        best_rule: Optional[Dict[str, Any]] = None
        best_match_meta: Optional[Dict[str, Any]] = None
        best_score: Tuple[int, ...] | None = None
        best_index: Optional[int] = None

        for idx, rule in enumerate(self.rules):
            match = self._match(rule, tool_name, agent_id, role, purpose, user_attributes)
            if not match:
                continue
            specificity = match["specificity"]
            decision = rule.get("decision", "deny")

            if best_rule is None:
                best_rule = rule
                best_match_meta = match
                best_score = specificity
                best_index = idx
                continue

            if best_rule.get("decision") == "deny" and decision != "deny":
                continue
            if decision == "deny" and best_rule.get("decision") != "deny":
                best_rule = rule
                best_match_meta = match
                best_score = specificity
                best_index = idx
                continue

            if specificity > (best_score or (0,)):
                best_rule = rule
                best_match_meta = match
                best_score = specificity
                best_index = idx
                continue
            if specificity == best_score and idx > (best_index or -1):
                best_rule = rule
                best_match_meta = match
                best_score = specificity
                best_index = idx

        if best_rule and best_match_meta:
            constraints = self._canonicalize_constraints(best_rule.get("constraints") or {})
            return PolicyDecision(
                decision=str(best_rule.get("decision", "deny")),
                constraints=constraints,
                matched_rule=best_rule,
                matched_rule_id=str(best_rule.get("id")) if best_rule.get("id") else None,
                matched_rule_index=best_index,
                specificity_score=best_score,
                matched_selectors=best_match_meta.get("matched_selectors"),
            )
        return PolicyDecision(
            decision="deny",
            constraints={},
            matched_rule=None,
            matched_rule_id=None,
            matched_rule_index=None,
            specificity_score=None,
            matched_selectors=None,
        )

    def _normalize_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        normalized = dict(rule)
        if "tool_name" in normalized and "tool" not in normalized:
            normalized["tool"] = normalized["tool_name"]
            self._warn_once("tool_name", "tool")
        if "roles" in normalized and "role" not in normalized:
            normalized["role"] = normalized["roles"]
            self._warn_once("roles", "role")
        if "user_attrs" in normalized and "user_attributes" not in normalized:
            normalized["user_attributes"] = normalized["user_attrs"]
            self._warn_once("user_attrs", "user_attributes")
        normalized["constraints"] = self._canonicalize_constraints(
            normalized.get("constraints") or {}
        )
        return normalized

    def _canonicalize_constraints(self, constraints: Dict[str, Any]) -> Dict[str, Any]:
        canonical = dict(constraints)
        if "allowed_domains" in canonical and "allow_domains" not in canonical:
            canonical["allow_domains"] = canonical.pop("allowed_domains")
            self._warn_once("allowed_domains", "allow_domains")
        if "rate_limit_per_minute" in canonical and "max_calls_per_minute" not in canonical:
            canonical["max_calls_per_minute"] = canonical.pop("rate_limit_per_minute")
            self._warn_once("rate_limit_per_minute", "max_calls_per_minute")
        return canonical

    def _warn_once(self, legacy: str, new: str) -> None:
        key = f"{legacy}->{new}"
        if key in _WARNED_ALIASES:
            return
        _WARNED_ALIASES.add(key)
        _logger.warning("legacy_policy_key: %s -> %s", legacy, new)

    def _match(
        self,
        rule: Dict[str, Any],
        tool_name: str,
        agent_id: Optional[int],
        role: Optional[str],
        purpose: Optional[str],
        user_attributes: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        selectors: Dict[str, Any] = {}

        def _match_tool(rule_value: Any) -> Tuple[bool, int]:
            if rule_value is None:
                return True, 0
            values = rule_value if isinstance(rule_value, list) else [rule_value]
            best_specificity = -1
            matched = False
            for value in values:
                if value is None:
                    matched = True
                    best_specificity = max(best_specificity, 0)
                    continue
                pattern = str(value)
                if pattern == tool_name:
                    matched = True
                    best_specificity = max(best_specificity, 2)
                elif fnmatch.fnmatch(tool_name, pattern):
                    matched = True
                    best_specificity = max(best_specificity, 1)
            return matched, max(best_specificity, 0)

        def _match_value(rule_value: Any, candidate: Any) -> Tuple[bool, int]:
            if rule_value is None:
                return True, 0
            if isinstance(rule_value, list):
                return (candidate in rule_value, 1 if candidate in rule_value else 0)
            return (rule_value == candidate, 1 if rule_value == candidate else 0)

        tool_matched, tool_specificity = _match_tool(rule.get("tool"))
        if not tool_matched:
            return None
        selectors["tool"] = tool_name

        agent_matched, agent_specificity = _match_value(rule.get("agent_id"), agent_id)
        if not agent_matched:
            return None
        if agent_specificity:
            selectors["agent_id"] = agent_id

        role_matched, role_specificity = _match_value(rule.get("role"), role)
        if not role_matched:
            return None
        if role_specificity:
            selectors["role"] = role

        purpose_matched, purpose_specificity = _match_value(rule.get("purpose"), purpose)
        if not purpose_matched:
            return None
        if purpose_specificity:
            selectors["purpose"] = purpose

        attributes = rule.get("user_attributes") or {}
        attr_specificity = 0
        if attributes:
            if not user_attributes:
                return None
            for key, value in attributes.items():
                if user_attributes.get(key) != value:
                    return None
            attr_specificity = len(attributes)
            selectors["user_attributes"] = attributes

        selector_count = sum(
            1
            for part in [
                rule.get("tool"),
                rule.get("agent_id"),
                rule.get("role"),
                rule.get("purpose"),
                attributes,
            ]
            if part is not None
        )

        specificity = (
            tool_specificity,
            role_specificity,
            purpose_specificity,
            1 if agent_specificity else 0,
            attr_specificity,
            selector_count,
        )

        return {
            "matched_selectors": selectors,
            "specificity": specificity,
        }
