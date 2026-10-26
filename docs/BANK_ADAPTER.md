# Bank adapter contract and fake ledger

BNK-008 defines a bank-neutral contract for later institution adapters and a deterministic fake ledger for tests and development.

- Contracts declare a bounded version and an explicit subset of account reads, transaction reads and payment simulation.
- Every contract and response is marked `SYNTHETIC_ONLY`; the contract cannot settle funds.
- The fake ledger accepts synthetic fixtures, requires active verified identities and filters all reads by the verified tenant claim.
- Payment simulation requires tenant-bound synthetic authorization, positive integer minor units, matching currency and sufficient synthetic funds.
- Tenant-scoped request IDs replay only exact requests. A replay with different terms fails closed and never applies a second debit.
- Simulated receipts and transactions state that they are not settled. Returned records are immutable copies.

This module has no network integration, persistence, credentials, real customer data or live payment rail. Production adapters, secrets, reconciliation, authorization provenance and independent acceptance remain later roadmap work.
