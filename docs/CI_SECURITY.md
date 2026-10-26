# CI security and ephemeral environments

BNK-003 keeps validation dependency-free and synthetic-only.

- Every pull request and `main` push runs the complete test, registry, and repository secret checks.
- Checkout does not persist GitHub credentials. Workflow permissions remain read-only.
- Each run receives a unique `ci-<run>-<attempt>` identity and a workspace beneath `RUNNER_TEMP`.
- The ephemeral check refuses a reused nonempty directory, writes only a synthetic marker, and removes the directory before success.
- Live database URLs, bank credentials, client secrets, and production tenant identifiers are forbidden in this CI contract.
- Secret scanning covers text source and configuration files for private keys, provider tokens, access keys, and credential assignments. It reports file paths but never prints matched values.

This is a baseline, not production acceptance. Later units still own dependency pinning, artifact provenance, deployment isolation, durable integration environments, credential rotation, and independent security review.
