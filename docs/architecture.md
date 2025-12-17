# Architecture

## Components
- FastAPI backend with SQLModel + Postgres
- Policy engine loading YAML rules
- DLP pipeline redacting secrets/PII/custom regex
- Tool connectors: HTTP + internal registry
- Tamper-evident audit log (hash chain)
- Trace store for replay (raw + redacted)
- Python SDK + CLI for agents

## Request flow
1. SDK calls `/v1/tool/execute` with tool, args, metadata.
2. Backend authenticates agent (API key) and optional user token.
3. Rate limiter enforces per-agent budget.
4. Policy + RBAC evaluated against tool, role, purpose.
5. DLP scans input/"reasoning"; redactions captured.
6. If approval required, approval request recorded; otherwise tool executes.
7. Output DLP scan runs; trace persisted.
8. Audit log entry appended with hash-chained integrity.

## Replay
Stored trace records enable deterministic reconstruction and dry-run policy evaluation.
