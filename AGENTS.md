# Engine-first directive

This repository develops the **Prosperity Banking Engine** only.

MANDATORY: **No downstream bank-specific application may be started until every engine work unit (BNK-001 through BNK-047) is implemented, tested, merged, independently accepted, and production-readiness gates satisfied.** All developer agents must continue working on available engine tasks. If blocked, switch to the next unblocked engine task, not a client application.

No client-bank names, institution-specific colors, marketing text, logos, or customer-specific code belong in this repository. It must support unrelated financial institutions as independent tenants, with configurable branding, policies and adapters.

Use the single canonical plan in registry/prs.json. Planned does not mean partially implemented. Do not fabricate PR numbers, passing tests, deployment approvals, or acceptance. Pull requests must use stable BNK-XXX identifiers. GitHub is authoritative for actual PR status. No AI may directly transfer real money, mutate a bank ledger, or approve its own financial actions.

Run npm run check. Foundation examples are synthetic-only, never production banking.