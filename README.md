# MCP Firewall

Security and governance firewall for Model Context Protocol (MCP) tool ecosystems. MCP Firewall enforces RBAC, per-tool policy constraints, approvals, and auditability for any tool connector.

## What is MCP Firewall?
- **Identity-bound policy decisions**: every request carries principal, tenant, and roles from JWT/OIDC and is evaluated with explicit context.
- **Tamper-evident audit chain + verification CLI**: audit entries are hash-chained for forensics-ready evidence.
- **Adversarial harness with artifacts (proof-driven)**: tests assert denials/redactions and produce artifacts for validation.

## Repository structure
- `src/acp_backend`: FastAPI service, policy engine, DLP, audit hashing
- `src/acp_sdk`: Python SDK for agents
- `src/acp_cli`: Typer-based CLI
- `policies/`: YAML policy bundles
- `scripts/`: helpers for seeding and setup
- `examples/`: toy agent walkthrough
- `docs/`: architecture, security, replay, and policy references
- `tests/`: unit + adversarial harness

## Architecture overview
```
Agent SDK -> /v1/tool/execute -> Policy + RBAC + DLP -> (approval?) -> Tool connector -> Trace store -> Audit log (hash chain)
                                               \-> Replay API
```
- **RBAC** via roles and tool permissions.
- **Policy-as-code** via YAML rules (allow/deny/approval_required + constraints).
- **DLP** redacts secrets/PII/custom regex before persistence and before returning.
- **Audit** append-only, hash-chained entries.
- **Replay** exposes deterministic trace retrieval + dry-run policy evaluation.
- **Tools**: HTTP connector + internal tool registry behind a uniform executor.

## Quickstart
1. Install deps: `make install`
2. Seed demo data: `python scripts/seed_data.py`
3. Run API locally: `make run`
4. Exercise toy agent (handles allowed, denied, approval, replay): `python examples/toy_agent.py`
5. Lint/tests: `make lint` and `make test`

### 30-second demo
```bash
# terminal 1
make run

# terminal 2 (uses CLI with either MCP_FIREWALL_TOKEN or --dev-token)
python -m acp_cli.main execute --api-key demo-key --tool echo --args '{"message": "hi"}' --dev-token
```

### Example policy snippet
```yaml
- tool: echo
  role: operator
  decision: allow
- tool: secret_fetch
  purpose: exfiltration
  decision: deny
- tool: sum_numbers
  role: operator
  decision: approval_required
```

## Docker Compose
```
docker compose up --build
```
Brings up Postgres, API (`localhost:8000`), and Adminer (`localhost:8080`).

## Policy examples
See `policies/default.yaml`:
```yaml
- tool: echo
  decision: allow
  role: operator
- tool: sum_numbers
  decision: approval_required
  role: operator
  constraints:
    max_cost: 100
- tool: secret_fetch
  decision: deny
  purpose: exfiltration
```

## Threat model
- **Untrusted LLM output**: all inputs treated as adversarial; DLP scans args/reasoning and responses.
- **Prompt injection / excessive agency**: adversarial tests assert denials/redactions.
- **Data exfiltration**: allowlist domains + deny rules; approvals gate sensitive tools.
- **Tampering**: audit log hash chain detects removal/modification.
- **Replay**: traces contain canonicalized request/response/policy for deterministic inspection.

## Security Claims
- JWT/OIDC authentication enforced on every `/v1/*` endpoint with explicit principal/tenant binding.
- Audit entries and traces carry tenant + principal context and are hash chained for tamper evidence.
- DLP redacts secrets by default before persistence, validated via adversarial tests.

## How replay works
- Every tool request persists raw + redacted payloads and policy decision.
- `/v1/traces/{trace_id}/replay?dry_run=true` re-evaluates policy without executing the tool.
- Stored trace payloads enable deterministic reproduction.

## Hash chain
- Each `AuditLogEntry` stores `prev_hash` + `current_hash = sha256(prev_hash + canonical_json(entry))`.
- Any mutation breaks the chain, providing tamper evidence.

## OpenTelemetry compatibility
Trace IDs are propagated from SDK to backend; include them in logs and traces for correlation.

## Approvals and enforcement order
- Evaluation order: **RBAC -> policy rules -> constraints (domains/max_bytes/rate limits) -> approvals -> execution**. Denials at any stage are logged and audited.
- Policies (or tool config) can require `approval_required`.
- Backend returns `status=PENDING` + `approval_id` + `approval_token`; approver calls `/v1/approvals/{id}/approve` with bearer auth to receive execution token.
- Agent retries `execute` with `approval_token` to proceed.

## Adversarial harness
- `tests/adversarial` simulates prompt injection, parameter smuggling, and excessive agency against local API.

