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
