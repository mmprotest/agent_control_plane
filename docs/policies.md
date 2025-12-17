# Policies

Policies live in YAML files. Each rule can match on tool name, agent id, role, purpose, or user attributes.

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
- `deny`: block and log
- `approval_required`: create `ApprovalRequest` and return `PENDING`

Constraints can specify limits such as `max_cost`, `max_rows`, `allowed_domains`, or `rate_limit_per_minute`.
MCP Firewall enforces constraints in this order after RBAC and policy matching:
- `allow_domains`/`deny_domains` for HTTP tools (host must be allowed and not denied)
- `max_bytes` across args and outputs (canonical JSON byte length)
- `max_calls_per_minute` per tenant + tool (in-memory rate limit)
- `approval_required` (if set)
