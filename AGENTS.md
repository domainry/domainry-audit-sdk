# Development rules

- Answer architecture and implementation questions from the current repository code and tests, not from memory.
- Every database has exactly one host-owned migration ledger named `_schema_migrations`. Module host contracts must require host-coordinated migrations and must not enable module-private migration ledgers.
- Persistence contracts must use `github.com/domainry/domainry-orm` abstractions. Raw SQL escape hatches require an explicit unsupported-ORM case and dialect-focused tests in the implementation repository.
- SDK contracts expose host infrastructure capabilities only; business implementation remains outside the SDK.
