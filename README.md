# Feather Authority

Feather Authority owns durable capability definitions, roles, grants,
assignments, scopes, expiry, suspension, revocation, and explainable decisions.
Core remains the authenticated policy-evaluation boundary, while every domain
continues to authorize its own protected mutations.

The current development foundation provides Contract 1 lifecycle/readiness,
checksum-protected migrations, and a bounded capability registry. It does not
yet issue roles or assignments and therefore grants no permissions.

## Startup order

Start Authority after Core and Organizations, and before Admin and protected
gameplay consumers:

```text
ensure feather-core
ensure feather-organizations
ensure feather-authority
ensure feather-admin
```

When `Config.DevMode` is enabled, the server console exposes the read-only
`AuthorityFoundationSmokeTest` command.
