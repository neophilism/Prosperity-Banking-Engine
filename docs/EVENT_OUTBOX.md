# Event schemas and transactional outbox

BNK-007 defines a deterministic synthetic event envelope and tenant-scoped outbox control.

- Event schemas have an exact type, version and bounded required payload fields. Only schemas compiled by the module are accepted.
- Payloads are canonicalized with sorted object keys, restricted to bounded JSON values and deeply frozen before enqueue.
- Tenant-scoped idempotency keys replay only exact requests. Reuse with different terms fails closed, and event IDs are unique per tenant.
- Verified active identities enqueue, view, claim and complete only their tenant's events.
- Claims use bounded leases and monotonically increasing delivery versions. Only the exact unexpired worker lease can publish; expired leases may be reclaimed.
- Published events remain immutable and cannot be claimed again.

The outbox does not contact a broker or bank adapter. Persistence, database transactions, delivery integrations, retention, audit export and production acceptance remain later work units.
