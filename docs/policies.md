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

Constraints can specify limits such as `max_cost`, `max_rows`, `allow_domains`, `deny_domains`, or `max_calls_per_minute`. Legacy aliases are accepted with warnings: `allowed_domains` -> `allow_domains`, `rate_limit_per_minute` -> `max_calls_per_minute`.
MCP Firewall enforces constraints in this order after RBAC and policy matching:
- `deny_domains` then `allow_domains` for HTTP tools (host must be allowed and not denied, with robust URL parsing)
- `max_bytes` across canonicalized args and redacted outputs
- `max_calls_per_minute` per tenant + principal/agent + tool (in-memory rate limit)
- `approval_required` (if set)
