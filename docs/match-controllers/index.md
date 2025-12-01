# Match Controllers

Match controllers run during the **match phase**, after analysis completes. They evaluate requests in parallel, emit a `MatchVerdict`, and the configured authorization policy combines those verdicts to allow or deny the request.

## Available Controllers
- [IP Match](/match-controllers/ip-match)
- [IP Match Database](/match-controllers/ip-match-database)
- [ASN Match](/match-controllers/asn-match)
- [ASN Match Database](/match-controllers/asn-match-database)
- [Geofence Match](/match-controllers/geofence-match)

## Combining Controllers

Use the Policy DSL to express allow/deny logic:

```yaml
authorizationPolicy: "allowlist && !blocklist && !blocked_asn"
```

`allowlist`, `blocklist`, and `blocked_asn` correspond to `name` fields of the match controllers configured in `matchControllers`.
