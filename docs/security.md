# Security posture (mapped to OWASP LLM Top 10)

1. **Prompt injection**: treat reasoning + args as untrusted, DLP scanning, deny policies, adversarial tests.
2. **Insecure output handling**: redactions applied before storage/response; audit hashes tamper-evident.
3. **Training data poisoning**: not applicable; policy enforcement prevents unsafe tool calls.
4. **Model theft**: tools gated by RBAC and approvals; traces limited to minimum details.
5. **Privacy leaks**: DLP detects emails/phones/secrets/custom regex.
6. **Excessive agency**: rate limits + deny rules for chaining behavior.
7. **Insecure plugins/tools**: allowed domains and type-specific connectors.
8. **Unauthorized access**: API keys hashed with bcrypt, optional user tokens + roles.
9. **Supply chain**: dependencies pinned to permissive licenses.
10. **Logging/monitoring gaps**: structured JSON logs, hash-chained audit, replay endpoints.
