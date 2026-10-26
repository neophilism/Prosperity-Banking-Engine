# Deny-by-default policy gateway

BNK-006 adds a deterministic authorization boundary in front of later banking engine capabilities.

- Only explicitly compiled action rules can allow a request. Unknown actions have no wildcard or implicit fallback.
- A decision requires a verifier-produced identity, exact tenant match and an active role assignment granting the rule's exact permission.
- Rules may also require fresh multi-method authentication and an active exact-scope consent from the BNK-005 ledger.
- Missing, expired, revoked, malformed or cross-tenant evidence produces an immutable denial decision with a bounded reason code.
- Allowed decisions record the policy version, action, subject, permission, roles and consent scope used for the decision.

The gateway performs no banking action. It is an in-memory synthetic engine control; production policy distribution, persistence, audit export, legal approval and independent acceptance remain later work units.