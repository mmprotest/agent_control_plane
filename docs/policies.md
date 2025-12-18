# Policies

Policies live in YAML files. Each rule can match on tool name (supports exact or shell-style patterns), agent id, role, purpose, or user attributes.

```yaml
rules:
  - tool: echo
    agent_id: [1]
    role: operator
    purpose: greeting
    decision: allow
    constraints:
      max_cost: 10
  - tool: sum_numbers
    decision: approval_required
    role: operator
  - tool: secret_fetch
    decision: deny
```

Decisions:
- `allow`: execute immediately
- `deny`: block and log (DENY always overrides conflicting ALLOW rules)
- `approval_required`: create `ApprovalRequest` and return `PENDING`

Rule precedence is deterministic: more-specific matches (exact tool > pattern > wildcard; explicit role/purpose/agent/user_attributes) win, and ties resolve to the later rule in the file.

Decision resolution evaluates **all matching rules** and orders them by specificity (descending) and rule index (descending). The engine picks:
1. Any matching `deny` rule (top-ranked deny wins)
2. Otherwise any matching `approval_required`
3. Otherwise any matching `allow`
4. Otherwise default deny with reason `"no matching rules"`

Constraints can specify limits such as `max_cost`, `max_rows`, `allow_domains`, `deny_domains`, or `max_calls_per_minute`. Legacy aliases are accepted with warnings: `allowed_domains` -> `allow_domains`, `rate_limit_per_minute` -> `max_calls_per_minute`.
MCP Firewall enforces constraints in this order after RBAC and policy matching:
- `deny_domains` then `allow_domains` for HTTP tools (host must be allowed and not denied, with robust URL parsing)
- `max_bytes` across canonicalized args and redacted outputs
- `max_calls_per_minute` per tenant + principal/agent + tool (in-memory rate limit)
- `approval_required` (if set)

## Decision explanation
Every policy evaluation emits a structured `PolicyExplanation` that is returned to callers, persisted in traces, and hash-chained into audit logs:

```json
{
  "decision": "allow",
  "matched_rule_id": "rule-123",
  "matched_rule_index": 2,
  "specificity_score": 6,
  "matched_selectors": {"tool": "echo", "role": "operator"},
  "triggered_constraints": {},
  "evaluation_timestamp": "2024-01-01T00:00:00Z",
  "policy_sha": "..."
}
```

When denials come from RBAC or constraints (domains, byte limits, rate limits), the explanation captures the triggered constraint and any policy metadata when available.
