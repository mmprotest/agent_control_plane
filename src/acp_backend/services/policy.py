from __future__ import annotations

import fnmatch

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import yaml

from acp_backend.core.config import get_settings
from acp_backend.schemas.policy import PolicyExplanation


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
    policy_sha: Optional[str] = None
    evaluation_timestamp: datetime | None = None
    triggered_constraints: Dict[str, Any] | None = None

    def to_explanation(
        self, triggered_constraints: Optional[Dict[str, Any]] | None = None
    ) -> PolicyExplanation:
        return PolicyExplanation(
            decision=self.decision,
            matched_rule_id=self.matched_rule_id,
            matched_rule_index=self.matched_rule_index,
            specificity_score=self.specificity_score[0]
            if self.specificity_score
            else 0,
            matched_selectors=self.matched_selectors or {},
            triggered_constraints=triggered_constraints
            if triggered_constraints is not None
            else self.triggered_constraints
            or {},
            evaluation_timestamp=self.evaluation_timestamp or datetime.utcnow(),
            policy_sha=self.policy_sha,
        )

    def to_explanation_dict(
        self, triggered_constraints: Optional[Dict[str, Any]] | None = None
    ) -> Dict[str, Any]:
        return self.to_explanation(triggered_constraints).model_dump(mode="json")


class PolicyEngine:
    def __init__(self, policy_path: Optional[str] = None):
        self.policy_path = policy_path or get_settings().policy_path
        self.rules: List[Dict[str, Any]] = []
        self.policy_sha: Optional[str] = None
        self.load()

    def load(self) -> None:
        with open(self.policy_path, "r", encoding="utf-8") as f:
            raw_content = f.read()
            self.policy_sha = self._compute_sha(raw_content)
            data = yaml.safe_load(raw_content) or {}
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
        matches: List[Tuple[Dict[str, Any], Dict[str, Any], Tuple[int, ...], int]] = []

        for idx, rule in enumerate(self.rules):
            match = self._match(rule, tool_name, agent_id, role, purpose, user_attributes)
            if not match:
                continue
            specificity = match["specificity"]
            matches.append((rule, match, specificity, idx))

        def _sort_key(item: Tuple[Dict[str, Any], Dict[str, Any], Tuple[int, ...], int]):
            _, _, spec, idx = item
            return spec, idx

        timestamp = datetime.utcnow()

        def _build_decision(item: Tuple[Dict[str, Any], Dict[str, Any], Tuple[int, ...], int]):
            rule, match_meta, specificity, idx = item
            constraints = self._canonicalize_constraints(rule.get("constraints") or {})
            return PolicyDecision(
                decision=str(rule.get("decision", "deny")),
                constraints=constraints,
                matched_rule=rule,
                matched_rule_id=str(rule.get("id")) if rule.get("id") else None,
                matched_rule_index=idx,
                specificity_score=specificity,
                matched_selectors=match_meta.get("matched_selectors"),
                policy_sha=self.policy_sha,
                evaluation_timestamp=timestamp,
            )

        if matches:
            denies = [m for m in matches if str(m[0].get("decision", "deny")) == "deny"]
            approvals = [
                m
                for m in matches
                if str(m[0].get("decision", "deny")) == "approval_required"
            ]
            allows = [m for m in matches if str(m[0].get("decision", "deny")) == "allow"]

            for bucket in (denies, approvals, allows):
                if bucket:
                    chosen = sorted(bucket, key=_sort_key, reverse=True)[0]
                    return _build_decision(chosen)

        return PolicyDecision(
            decision="deny",
            constraints={},
            matched_rule=None,
            matched_rule_id=None,
            matched_rule_index=None,
            specificity_score=None,
            matched_selectors=None,
            policy_sha=self.policy_sha,
            evaluation_timestamp=timestamp,
            triggered_constraints={"reason": "no matching rules"},
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

    def _compute_sha(self, content: str) -> str:
        import hashlib

        return hashlib.sha256(content.encode("utf-8")).hexdigest()

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
