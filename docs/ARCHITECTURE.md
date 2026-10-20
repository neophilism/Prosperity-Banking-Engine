# Bank-neutral architecture

The engine is a separately deployable white-label, multi-tenant operating platform. Each institution has isolated financial data, documents, policies, agents, logs, secrets, branding, and banking-provider adapters. A bank-specific application is **not** part of this repository.

Customer API → Authenticated tenant identity → Scoped consent → AI personal banker / entrepreneur studio → deterministic policy gateway → human/step-up approval → audited provider adapter → bank-of-record.

## Mandatory invariants

- Never derive tenant identity from a caller's untrusted field. The current synthetic context is **not** an authentication implementation.
- AI output is never permission to make a payment, change a balance, grant credit, accept an investment, or assess a fee.
- Fee-bearing overdraft coverage OFF by default. Only explicit, granular, revocable coverage can ever incur an overdraft fee. Force-post must not create an unauthorized bank fee.
- Separate insured banking activities from legally appropriate, independently authorized equity-investment services.
- Use integer minor units for currency amounts; bank core authoritative for balance and posting; reconcile pending, returned and disputed transactions.
- Company IP, customer documents, embeddings, and agent workspaces must be tenant/project separated.
- No live financial data, real accounts, or fund transfers until relevant regulatory/partner approvals, audits, disaster recovery and production-readiness reviews.

## Bounded contexts

Foundation & identity; tenant and branding management; consent/policy gateway; event/outbox and reconciliation; bank adapters; personal banker and financial forecasting; entrepreneur studio and evidence ledger; funding matching; observability/compliance; regulated launch controls.

The foundation PR contains only a zero-dependency in-memory simulation to establish boundaries. Durable enforcement, security, real integrations and operational readiness are subsequent independently accepted units.
