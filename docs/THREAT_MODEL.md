# Threat model and data classification

BNK-002 defines the security boundary for the bank-neutral engine foundation. It is a design and enforcement baseline, not a production-readiness claim. The repository still contains only synthetic, non-production banking behavior.

## Assets and trust boundaries

Protected assets include customer identity and financial data, documents, credentials and authentication factors, consent and audit evidence, institution configuration, model prompts and outputs, embeddings and derived profiles. The principal boundaries are the public client to authenticated tenant context, tenant services to deterministic policy checks, policy checks to provider adapters, and tenant storage to logs, model contexts, support access and public output.

Tenant identity must come from authenticated server context. Caller-supplied tenant fields, model output, and provider callbacks are untrusted until independently verified. AI suggestions are untrusted content and never authorize a transfer, ledger mutation, credit decision, fee, investment, or disclosure.

## Threats and required controls

| Threat | Security consequence | Required control |
| --- | --- | --- |
| Spoofed tenant or actor | Cross-tenant disclosure or action | Authenticated context, tenant-bound queries, deny on mismatch |
| Tampered payment or consent terms | Unauthorized financial action | Exact-version records, deterministic policy checks, step-up approval, idempotency |
| Replayed provider command | Duplicate financial effect | Tenant-scoped idempotency keys and exact-term replay checks |
| Sensitive data in logs or public output | Privacy breach | Explicit classification and fail-closed handling decisions |
| Prompt injection or unsafe model output | Policy bypass or data exposure | Minimized approved context, output validation, deterministic authorization after inference |
| Credential or document disclosure to a model | Secret or regulated-data exposure | Restricted classification; model context denied by default |
| Malicious or mistaken support access | Excessive internal disclosure | Least privilege, tenant scope, audited time-bounded access |
| Forged callback or stale state | False settlement or balance state | Signature verification, freshness checks, reconciliation to bank-of-record |
| Dependency or build compromise | Code execution or secret theft | Pinned dependencies, isolated CI, scanning and provenance in later roadmap units |
| Data remanence or over-retention | Unnecessary exposure | Category-specific retention, deletion evidence and immutable required audit records |

## Classification contract

- `PUBLIC`: specifically approved public content. It may be published and logged.
- `INTERNAL`: synthetic test data and operational metadata. Tenant-scoped metadata still requires a validated tenant.
- `CONFIDENTIAL`: tenant configuration, staff notes, and approved model prompts or outputs. It is not application-log or public-output material.
- `RESTRICTED`: customer identity, financial data, documents, credentials, consent/audit evidence, embeddings, and derived profiles. It is denied from application logs, public output, and model context by default.

Every use names a known category and operation. Unknown categories or operations fail closed. Non-public tenant data requires a validated `tenant_*` boundary, and cross-tenant movement is always denied. A successful data-use decision does not grant any banking permission.

## Scope and follow-up

This unit supplies a machine-checkable classification baseline and negative tests. Later roadmap units must add authenticated identity, consent storage, policy enforcement, durable audit events, secrets scanning, retention automation, adapter verification, incident response, disaster recovery, and independent production acceptance. No live accounts, customer data, provider credentials, or fund movement are permitted by this change.
