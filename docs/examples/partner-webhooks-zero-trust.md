# Zero-Trust Partner Webhooks

Secure inbound webhooks from external SaaS partners (billing, messaging, observability) using layered network checks and dynamic blocks while preserving telemetry for debugging.

## Scenario
- Only specific partner networks should reach internal webhook receivers.
- Partners occasionally rotate IPs; your team maintains both static CIDRs and dynamic DB lists.
- During incidents you need a fast kill-switch for malicious sources without editing Envoy config.
- Observability teams want ASN/Geo/UA context to trace delivery issues with partners.

## Controllers Used
- `maxmind-asn` — tag requests with partner ASNs for dashboards.
- `maxmind-geoip` — capture country/region to detect unexpected egress locations.
- `ip-match` (`partner-cidrs`) — primary allowlist supplied by partners (text files).
- `ip-match-database` (`partner-live`) — Postgres table for temporary IPs partners add via ticket.
- `asn-match` (`partner-asns`) — allowlist of expected ASNs per provider.
- `ip-match-database` (`incident-block`) — Redis kill-switch populated by SOC during an incident.

## Policy
Allow only when source matches partner CIDRs **or** live DB allowlist, belongs to approved ASNs, and is not in the incident blocklist:

```yaml
authorizationPolicy: "(partner-cidrs || partner-live) && partner-asns && !incident-block"
```

## Example Configuration
```yaml
analysisControllers:
  - name: asn
    type: maxmind-asn
    settings:
      databasePath: config/GeoLite2-ASN.mmdb

  - name: geoip
    type: maxmind-geoip
    settings:
      databasePath: config/GeoLite2-City.mmdb

matchControllers:
  - name: partner-cidrs
    type: ip-match
    settings:
      cidrList: config/partners/webhook-cidrs.txt

  - name: partner-live
    type: ip-match-database
    settings:
      matchesOnFailure: true          # Fail-open to avoid partner outages
      cache:
        ttl: 30m
      database:
        type: postgres
        postgres:
          query: "SELECT 1 FROM partner_webhook_ips WHERE ip = $1 AND active = true"
          host: postgres.partners.svc.cluster.local
          port: 5432
          databaseName: partners
          usernameEnv: DB_USER
          passwordEnv: DB_PASSWORD

  - name: partner-asns
    type: asn-match
    settings:
      asnList: config/partners/partner-asns.txt

  - name: incident-block
    type: ip-match-database
    settings:
      cache:
        ttl: 5m
      database:
        type: redis
        redis:
          keyPrefix: "block:webhook:"
          host: redis.soc.svc.cluster.local
          port: 6379
```

## Request Flow
1. Analysis controllers emit headers so upstream webhook handlers can log ASN + location for each delivery.
2. Static partner CIDRs cover official ranges; `partner-live` catches ad-hoc ranges partners add temporarily.
3. `partner-asns` ensures traffic originates from the partner’s network, defending against spoofed IP headers.
4. `incident-block` gives SOC instant deny capability via Redis without reloading Envoy.

## Value Delivered
- Reduces partner outage risk with fail-open DB allowlist while keeping a hard deny switch.
- Telemetry-rich headers accelerate debugging when partners claim delivery success.
- Works across multiple partners by simply adding more CIDR/ASN files per provider.

## Reliability Tips
- Keep `partner-live` TTL shorter than partner change windows; revalidate entries automatically.
- Alert on `incident-block` hits to ensure SOC playbooks close the loop.
