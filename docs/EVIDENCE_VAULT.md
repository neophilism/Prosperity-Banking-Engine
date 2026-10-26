# Tenant-isolated evidence vault

BNK-009 adds an in-memory, bank-neutral metadata vault for evidence commitments. It stores no document bytes, plaintext, ciphertext, credentials or encryption keys.

Every operation requires a live verifier-produced tenant identity and an exact allow decision from the canonical deny-by-default policy gateway. Evidence IDs and idempotency keys are tenant-scoped. Reads and lists only resolve records inside the authenticated tenant, so a caller cannot use another tenant's identifier to discover whether evidence exists.

A record contains a lowercase SHA-256 content commitment, bounded external key reference, explicit data category and classification, media type, byte length, capture time, source code and immutable producer provenance. Exact retries return the original record; changed terms and duplicate evidence IDs fail closed. Raw-content fields are rejected to keep protected material out of this process and its logs.

This unit is synthetic and memory-only. It does not provide durable object storage, encryption or key custody, upload transport, malware/content-disarm scanning, legal retention, deletion, backup, recovery, provider signatures or production deployment. Those controls require later independently accepted units and authorized infrastructure.
