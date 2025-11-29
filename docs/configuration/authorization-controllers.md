# Authorization Controllers

Authorization controllers run during the **second phase** of request processing to make allow/deny decisions. They execute concurrently and can access analysis reports from the first phase.

## IP Match

The `ip-match` controller matches the request IP address in relation to a CIDR list.

**Configuration**:
```yaml
authorizationControllers:
  - name: corporate-network
    type: ip-match
    settings:
      action: allow  # or deny
      cidrList: config/corporate-ips.txt
```

**Settings**:
- `action` (required): `allow` (allowlist mode) or `deny` (denylist mode)
- `cidrList` (required): Path to text file with CIDR ranges (one per line)

**Authorization Logic**:

| Action | IP Matches | Result |
|--------|-----------|---------|
| `allow` | Yes | ALLOW (OK) |
| `allow` | No | DENY (403) |
| `deny` | Yes | DENY (403) |
| `deny` | No | ALLOW (OK) |

**CIDR List Format**:
```txt
# Corporate office networks
192.0.2.0/24
198.51.100.0/24

# VPN range
10.0.0.0/8
```

**Use Cases**:
- Restrict access to corporate networks
- Whitelist partner IP ranges
- Block known threat actors
- Bot/scraper protection

---

## ASN Match

The `asn-match` controller matches request IP Autonomous System Number in relation to a list of AS numbers.

**Requirements**: Requires `maxmind-asn` analysis controller

**Configuration**:
```yaml
analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: GeoLite2-ASN.mmdb

authorizationControllers:
  - name: cloud-providers
    type: asn-match
    settings:
      action: allow  # or deny
      asList: config/allowed-asns.txt
```

**Settings**:
- `action` (required): `allow` (allowlist mode) or `deny` (denylist mode)
- `asList` (required): Path to text file with ASN numbers (one per line)

**Authorization Logic**:

| Action | ASN Matches | Result |
|--------|------------|---------|
| `allow` | Yes | ALLOW (OK) |
| `allow` | No | DENY (403) |
| `deny` | Yes | DENY (403) |
| `deny` | No | ALLOW (OK) |

**ASN List Format**:
```txt
# AWS
16509
14618

# Google Cloud
15169
396982

# Azure
8075
```

**Use Cases**:
- Allow only major cloud providers
- Block hosting providers known for abuse
- Restrict access by network ownership
- Geographic network filtering

---

## IP Match Database

The `ip-match-database` controller matches the request IP in relation to a lookup to an external database (Redis or PostgreSQL).

**Configuration (Redis)**:
```yaml
authorizationControllers:
  - name: scraper-block
    type: ip-match-database
    settings:
      action: deny
      cache:
        ttl: 10m
      database:
        type: redis
        redis:
          keyPrefix: "scraper:"
          host: redis.example.com
          port: 6379
          passwordEnv: REDIS_PASSWORD
```

**Configuration (PostgreSQL)**:
```yaml
authorizationControllers:
  - name: partner-allow
    type: ip-match-database
    settings:
      action: allow
      cache:
        ttl: 15m
      database:
        type: postgres
        postgres:
          query: "SELECT 1 FROM partners WHERE ip = $1 LIMIT 1"
          host: postgres.example.com
          port: 5432
          databaseName: security
          usernameEnv: DB_USER
          passwordEnv: DB_PASSWORD
```

**Key Settings**:
- `action`: `allow` or `deny`
- `cache.ttl`: Cache duration (e.g., `10m`, `1h`)
- `database.type`: `redis` or `postgres`
- `alwaysDenyOnDbUnavailable`: Fail-closed when DB is down

**Features**:
- Dynamic IP control
- TTL-based caching
- TLS/SSL support
- Connection pooling (PostgreSQL)
- Comprehensive metrics

**Use Cases**:
- Dynamic scraper blocking
- Partner IP management
- Threat intelligence integration
- Behavioral analysis integration

## Combining Controllers

Use the Policy DSL to combine multiple authorization controllers:

```yaml
authorizationControllers:
  - name: corporate-net
    type: ip-match
    settings:
      action: allow
      cidrList: corporate-ips.txt
  
  - name: partners
    type: ip-match-database
    settings:
      action: allow
      database:
        type: postgres
        postgres:
          query: "SELECT 1 FROM partners WHERE ip = $1"
  
  - name: blocked-ips
    type: ip-match
    settings:
      action: deny
      cidrList: blocked-ips.txt
  
  - name: blocked-asns
    type: asn-match
    settings:
      action: deny
      asList: blocked-asns.txt

# Allow corporate OR partners, but block explicit denylists
authorizationPolicy: "(corporate-net || partners) && !blocked-ips && !blocked-asns"
```

## Best Practices

### 1. Use Descriptive Names for Controllers

```yaml
# Good
- name: corporate-office-network
- name: aws-cloudfront-asns
- name: known-scrapers

# Avoid
- name: controller1
- name: ip-check
```
### 2. Use Caching for Database Controllers

Always enable caching for `ip-match-database`:
```yaml
cache:
  ttl: 10m  # Balance freshness vs performance
```

## Managing IP and ASN Lists

### Optimize CIDR Lists

```bash
envoy-authorization-service synthesize-cidr-list \
  --file blocked-ips.txt \
  --overwrite
```

### Deduplicate ASN Lists

```bash
envoy-authorization-service synthesize-asn-list \
  --file allowed-asns.txt \
  --overwrite
```

## Next Steps

- [Configure Analysis Controllers](/configuration/analysis-controllers)
- [Write Policy Expressions](/configuration/policy-dsl)
- [Configure Server & Metrics](/configuration/server-metrics)
- [View Configuration Examples](/examples/)
