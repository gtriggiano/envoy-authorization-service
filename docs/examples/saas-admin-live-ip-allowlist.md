# SaaS Admin Console with Live IP Allowlists

Multi-tenant B2B admin portals often need fast-moving IP allowlists that customer success teams manage directly. This pattern keeps security strict while avoiding config redeploys.

## Scenario
- Enterprise customers expect console access only from their corporate networks.
- Support can add/remove IPs in a shared security database without restarting Envoy.
- SREs keep a break-glass allowlist for incidents, while a threat feed blocks bad actors.
- Analytics teams still want network/UA context for audits.

## Controllers Used
- `maxmind-asn` — enrich requests with ASN for network telemetry.
- `ua-detect` — capture device/UA signals for audit trails.
- `ip-match-database` (`customer-allowlist`) — Postgres-backed allowlist managed by CSM/Support.
- `ip-match` (`sre-breakglass`) — short static list for emergency access.
- `ip-match` (`threat-blocklist`) — rolling denylist fed by SOC.

## Policy
Allow if the IP is in the live customer allowlist **or** SRE break-glass list, and not in the threat blocklist:

```yaml
authorizationPolicy: "(customer-allowlist || sre-breakglass) && !threat-blocklist"
```

## Example Configuration
```yaml
analysisControllers:
  - name: asn
    type: maxmind-asn
    settings:
      databasePath: config/GeoLite2-ASN.mmdb

  - name: user-agent
    type: ua-detect

matchControllers:
  - name: customer-allowlist
    type: ip-match-database
    settings:
      matchesOnFailure: false        # Fail closed if DB unavailable
      cache:
        ttl: 5m                    # Smooth churn when teams edit IPs
      database:
        type: postgres
        connectionTimeout: 500ms
        postgres:
          query: |
            SELECT 1
            FROM customer_admin_ips ai
            JOIN customers c ON ai.customer_id = c.id
            WHERE ai.ip = $1
              AND c.active = true
              AND ai.enabled = true
              AND (ai.expires_at IS NULL OR ai.expires_at > NOW())
            LIMIT 1
          host: postgres.security.svc.cluster.local
          port: 5432
          databaseName: security
          usernameEnv: DB_USER
          passwordEnv: DB_PASSWORD

  - name: sre-breakglass
    type: ip-match
    settings:
      cidrList: config/sre-breakglass-ips.txt

  - name: threat-blocklist
    type: ip-match
    settings:
      cidrList: config/soc-threat-blocklist.txt
```

## Request Flow
1. `maxmind-asn` and `ua-detect` enrich every request with headers like `X-ASN-Number` and `X-UA-Device-Type` for downstream audit logs.
2. `customer-allowlist` checks Postgres; results are cached to avoid hot queries during login peaks.
3. `sre-breakglass` provides controlled emergency access if the DB is down or misconfigured.
4. `threat-blocklist` provides an immediate kill switch for malicious ranges supplied by SOC.

## Value Delivered
- Customers self-serve IP changes without waiting for deploys.
- Security teams retain central oversight and instant block capability.
- Audit/analytics get rich network + device context from analysis controllers.

## Observability
- Database controller exposes `envoy_authz_match_database_*` metrics
- Include `X-ASN-Organization` and `X-UA-Device-Type` in request logs to trace unusual access patterns.
