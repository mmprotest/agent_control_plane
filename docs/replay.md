# Replay

- Each trace stores request, response, redactions, policy decision, and execution metadata.
- Canonical JSON serialization ensures deterministic hashes and stable replay.
- `GET /v1/traces/{trace_id}/replay` returns the stored trace; `?dry_run=true` re-evaluates policy without executing the tool.
- Audit log hash chain links entries for tamper evidence when inspecting replays.
