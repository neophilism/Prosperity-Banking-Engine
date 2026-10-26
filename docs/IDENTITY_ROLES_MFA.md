# Identity, roles and MFA boundary

BNK-004 adds a bank-neutral authorization control for verified identity claims, tenant-bound roles and fresh multi-factor evidence. It does not select or provision an identity provider.

## Trust contract

- A deployment supplies a credential verifier. The engine accepts only claims returned with explicit successful verification; tenant, issuer, subject, authentication time, expiry and authentication methods are all required.
- Role names and permissions are deployment-configured and bounded. Assignments match the verified tenant, issuer and subject exactly, must reference a known role, and must be active and unrevoked.
- Authorization denies unknown permissions, missing roles, cross-tenant assignments, expired identities and stale or single-method step-up evidence.
- MFA evidence comes from the verified identity adapter. The engine does not receive, persist or compare passwords, security keys, biometrics, recovery codes or other factor secrets.

The result is an authorization decision only. It cannot transfer funds, mutate a ledger, approve credit, assess a fee, activate a provider or make model output authoritative. All current examples and tests remain synthetic-only. Production use still requires provider configuration, durable assignment storage, key management, audit evidence, recovery controls and independent security acceptance in later roadmap units.
