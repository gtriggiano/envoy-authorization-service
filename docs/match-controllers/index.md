# Match Controllers

Match controllers run during the **match phase**, after analysis completes. They evaluate requests in parallel, emit a `MatchVerdict`, and the configured authorization policy combines those verdicts to allow or deny the request.

## Available Controllers

### [ASN Match](/match-controllers/asn-match)
Matches client Autonomous System Numbers (ASN) against static lists. Useful for allowing trusted cloud providers, CDNs, or blocking networks known for malicious activity. Requires the `maxmind-asn` analysis controller.

### [ASN Match Database](/match-controllers/asn-match-database)
Matches client ASNs against dynamic lists stored in Redis or PostgreSQL. Enables real-time ASN reputation management based on threat intelligence or business relationships. Requires the `maxmind-asn` analysis controller.

### [Geofence Match](/match-controllers/geofence-match)
Matches client geographic location against GeoJSON polygon definitions. Use for compliance with data residency requirements, regional access restrictions, or fraud prevention. Requires the `maxmind-geoip` analysis controller.

### [IP Match](/match-controllers/ip-match)
Matches client IP addresses against static CIDR lists loaded from files. Ideal for corporate network ranges, known malicious IPs, or any scenario where your allow/deny lists are managed as text files.

### [IP Match Database](/match-controllers/ip-match-database)
Matches client IP addresses against dynamic lists stored in Redis or PostgreSQL. Perfect for behavioral analysis systems, threat intelligence feeds, or partner management platforms that maintain real-time IP reputation data.

## Combining Controllers

Use the Policy DSL to express allow/deny logic:

```yaml
authorizationPolicy: "allowlist && !blocklist && !blocked_asn"
```

`allowlist`, `blocklist`, and `blocked_asn` correspond to `name` fields of the match controllers configured in `matchControllers`.
