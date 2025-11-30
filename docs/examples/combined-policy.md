# Combined Policies

Examples of complex authorization policies combining multiple controllers and strategies.

## Use Cases

Implement defense-in-depth with multiple authorization layers:
- Allow trusted sources (corporate + partners + cloud)
- Block known threats (malicious IPs + abusive ASNs)

## Use Bypass Mode For Testing Complex Policies

Test controller behavior without enforcing policy:

```yaml
authorizationPolicy: "(corporate || partners) && !threats"
authorizationPolicyBypass: true
```

## Examples

### Multi-Source Allowlist with Denylists

**Scenario**: Allow corporate network, partners, or cloud providers, but always block known threats.

**config.yaml**:
```yaml
authorizationPolicy: "(corporate-network || partner-networks || cloud-providers) && !blocked-ips && !malicious-asns"

analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: GeoLite2-ASN.mmdb

matchControllers:
  # Allowlist sources
  - name: corporate-network
    type: ip-match
    settings:
      cidrList: corporate-ips.txt
  
  - name: partner-networks
    type: ip-match
    settings:
      cidrList: partner-ips.txt
  
  - name: cloud-providers
    type: asn-match
    settings:
      asList: cloud-asns.txt
  
  # Denylist sources
  - name: blocked-ips
    type: ip-match
    settings:
      cidrList: blocked-ips.txt
  
  - name: malicious-asns
    type: asn-match
    settings:
      asList: malicious-asns.txt
```

**Policy Breakdown**:
```
(corporate-network || partner-networks || cloud-providers)  # Allow from any trusted source
&&                                                           # AND
!blocked-ips                                                # NOT in IP blocklist
&&                                                           # AND
!malicious-asns                                            # NOT from malicious ASN
```

**Behavior**:

| Source | In Corporate? | In Partners? | Cloud ASN? | In Blocklist? | Malicious ASN? | Result |
|--------|--------------|-------------|------------|--------------|---------------|---------|
| Office IP | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ ALLOW |
| Partner IP | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ ALLOW |
| AWS IP | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ ALLOW |
| Blocked IP | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ DENY |
| Malicious | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ DENY |
| Unknown | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ DENY |

### Database-Backed Partners

**Scenario**: Allow corporate or dynamic partner list from database.

**config.yaml**:
```yaml
authorizationPolicy: "((corporate-network || partner-database) || trusted-cloud-asns) && !blocked-threats"

analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: GeoLite2-ASN.mmdb

matchControllers:
  - name: corporate-network
    type: ip-match
    settings:
      cidrList: corporate-ips.txt
  
  - name: partner-database
    type: ip-match-database
    settings:
      matchesOnFailure: true  # Fail-open: allow traffic if DB is down (IsMatch=true)
      cache:
        ttl: 15m
      database:
        type: postgres
        postgres:
          query: "SELECT 1 FROM partners WHERE ip = $1 AND active = true LIMIT 1"
          host: postgres.default.svc.cluster.local
          port: 5432
          databaseName: security
          usernameEnv: DB_USER
          passwordEnv: DB_PASSWORD
  
  - name: blocked-threats
    type: ip-match
    settings:
      cidrList: threats.txt
  
  - name: trusted-cloud-asns
    type: asn-match
    settings:
      asList: trusted-asns.txt
```

**Benefits**:
- Dynamic partner management (no config reload)
- Cached database lookups (15m TTL)
- Multiple trusted sources
- Override with threat blocklist

### Geographic + Network Control

**Scenario**: Allow only from specific countries AND trusted networks.

**config.yaml**:
```yaml
authorizationPolicy: "(corporate-ips || trusted-asns) && !blocked-countries"

analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: GeoLite2-ASN.mmdb
  
  - name: geoip-detect
    type: maxmind-geoip
    settings:
      databasePath: GeoLite2-City.mmdb

matchControllers:
  - name: corporate-ips
    type: ip-match
    settings:
      cidrList: corporate-ips.txt
  
  - name: trusted-asns
    type: asn-match
    settings:
      asList: trusted-asns.txt
  
  - name: blocked-countries
    type: ip-match
    settings:
      cidrList: blocked-country-ranges.txt
```

**Use Case**: 
- Comply with data residency requirements
- Block traffic from sanctioned countries
- Allow corporate + cloud providers only

### Bot Detection + Allowlisting

**Scenario**: Block bots except from allowlisted IPs.

**config.yaml**:
```yaml
authorizationPolicy: "allowlisted-ips || !known-bot-ips"

analysisControllers:
  - name: user-agent
    type: ua-detect

matchControllers:
  - name: allowlisted-ips
    type: ip-match
    settings:
      cidrList: allowed-ips.txt
  
  - name: known-bot-ips
    type: ip-match-database
    settings:
      matchesOnFailure: false  # Fail-open: don't treat as bot if Redis is down
      cache:
        ttl: 10m
      database:
        type: redis
        redis:
          keyPrefix: "bot:"
          host: redis.default.svc.cluster.local
          port: 6379
```

**Behavior**:
- Allowlisted IPs always pass
- Other IPs blocked if flagged as bots in Redis
- User agent data available to upstream (headers)

### Time-Based with Dynamic Blocking

**Scenario**: Scraper detection system adds IPs to Redis, blocked for 1 hour.

**config.yaml**:
```yaml
authorizationPolicy: "corporate-network || !scraper-blocker"

matchControllers:
  - name: corporate-network
    type: ip-match
    settings:
      cidrList: corporate-ips.txt
  
  - name: scraper-blocker
    type: ip-match-database
    settings:
      matchesOnFailure: false  # Fail-open: allow traffic if Redis is down
      cache:
        ttl: 5m  # Cache block status
      database:
        type: redis
        connectionTimeout: 100ms
        redis:
          keyPrefix: "scraper:"
          host: redis.default.svc.cluster.local
          port: 6379
```

**Redis Management**:
```bash
# Add IP to blocklist (expires in 1 hour)
SET scraper:1.2.3.4 1 EX 3600

# Remove IP from blocklist
DEL scraper:1.2.3.4

# Check if IP is blocked
EXISTS scraper:1.2.3.4
```

**Benefits**:
- Automatic expiry (no cleanup needed)
- Fast lookups (Redis + cache)
- Dynamic blocking (no config reload)

## Next Steps

- [IP Match](/examples/ip-match)
- [ASN Match](/examples/asn-match)
- [IP Match - Redis](/examples/ip-match-redis)
- [Policy DSL Reference](/policy-dsl)