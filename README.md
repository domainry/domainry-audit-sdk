# Domainry Audit SDK

Deployment-neutral contracts for the Domainry Audit module. Hosts provide the
database pool and transaction lifecycle; the Audit module owns event semantics,
schema, persistence, querying, export and lifecycle behavior.

## Package layout

- The root package is the stable `Factory` and `Binding` entrypoint.
- `contract` contains deployment-neutral Audit values and business capabilities.
- `application` contains reusable Audit application ports and orchestration helpers.
- `modulehost` describes the database, transaction, dialect, and host-coordinated migration capabilities borrowed by an embedded module.

The SDK does not expose a `repository` package. Audit persistence remains implementation-owned; host-facing infrastructure belongs to `modulehost` and business-facing capabilities belong to `contract` or `application`.

Run `go test ./...` before publishing an immutable SDK version.
