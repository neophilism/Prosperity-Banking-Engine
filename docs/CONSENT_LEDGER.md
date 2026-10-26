# Consent and revocation ledger

BNK-005 adds an append-only, tenant-bound consent record for the verified identity introduced by BNK-004.

- A grant names the consent subject through verified issuer and subject claims, a bounded purpose, explicit scopes, a policy version and an expiry.
- Request IDs are tenant-scoped and idempotent. Reuse with different terms fails closed.
- Revocation requires the same verified subject and the exact current version. It appends a new event and immediately disables every scope without deleting the grant evidence.
- Authorization checks the current event, verified tenant and subject, expiry and exact scope. Unknown, expired, cross-tenant, cross-subject and revoked consent returns no permission.
- History is an immutable subject-visible event sequence. A consent decision does not authorize a payment, ledger mutation, disclosure, model call or provider action by itself.

This zero-dependency ledger is a deterministic engine control and test fixture. Production persistence, audit export, retention policy, key management and regulatory acceptance remain later work units.
