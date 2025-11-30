# Match Controllers

Match controllers run during the **match phase**, after analysis.

They run in parallel, each evaluating the request against its configured logic.

Each controller emits a `MatchVerdict`.

The **authorization policy** will be evaluated against these verdicts to decide whether the request is allowed.

## IP Match

The `ip-match` controller sets `IsMatch=true` when the client IP is contained in a CIDR
list.

```yaml
matchControllers:
  - name: corporate-network
    type: ip-match
    settings:
      cidrList: config/corporate-network-cidrs.txt
```

**Setting**
- `cidrList` (required): Path to a text file with CIDR entries (one per line; `#` for comments).

## IP Match Database

The `ip-match-database` controller sets `IsMatch=true` when the client IP exists in an
external data source (Redis or PostgreSQL). Use policy to decide whether a match allows
or denies (e.g., `authorizationPolicy: "!scraper-blocker"` for a deny list).

### Redis Example
```yaml
matchControllers:
  - name: suspect-scraper
    type: ip-match-database
    settings:
      matchesOnFailure: false
      cache:
        ttl: 10m
      database:
        type: redis
        redis:
          keyPrefix: "suspect-scraper:"
          host: redis.example.com
          port: 6379
```

### PostgreSQL Example
```yaml
matchControllers:
  - name: customer-whitelisted-ip
    type: ip-match-database
    settings:
      matchesOnFailure: false
      database:
        type: postgres
        connectionTimeout: 500ms
        postgres:
          query: "SELECT 1 FROM customer_whitelisted_ips WHERE ip = $1 LIMIT 1"
          host: postgres.example.com
          port: 5432
          databaseName: security
          usernameEnv: POSTGRES_USER
          passwordEnv: POSTGRES_PASSWORD
```

**Key settings**

- **`matchesOnFailure`** (bool, default: `false`): Controls the `IsMatch` value when database queries fail.
  - `false` (default): Database errors result in `IsMatch=false`
  - `true`: Database errors result in `IsMatch=true`
  
  The fail-open vs fail-closed behavior depends on your authorization policy:
  - **Deny list** (e.g., `!scraper`): Use `matchesOnFailure: false` to fail-open (allow traffic on DB failure)
  - **Allow list** (e.g., `trusted-partner`): Use `matchesOnFailure: true` to fail-open (allow traffic on DB failure)

- **`cache.ttl`** (duration): Enable in-memory caching of match results to reduce database load and improve performance. Both positive (found) and negative (not found) results are cached.

- **`database.type`**: Either `redis` or `postgres`, each with backend-specific configuration fields.

## ASN Match

The `asn-match` controller sets `IsMatch=true` when the client ASN appears in a configured
list. It requires the `maxmind-asn` analysis controller to supply ASN data.

```yaml
analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: GeoLite2-ASN.mmdb

matchControllers:
  - name: cloud-providers
    type: asn-match
    settings:
      asnList: config/cloud-providers-asns.txt
```

**Setting**
- `asnList` (required): Path to a text file with ASN numbers (one per line; `AS` prefix optional).

## Combining Controllers

Use the Policy DSL to combine matches:

```yaml
authorizationPolicy: "allowlist && !blocklist && !blocked_asn"
```

## Next Steps

- [Configure Analysis Controllers](/configuration/analysis-controllers)
- [Write Policy Expressions](/configuration/policy-dsl)
- [Configure Server & Metrics](/configuration/server-metrics)
- [View Configuration Examples](/examples/)
