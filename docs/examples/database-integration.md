# IP Allow/Deny Redis Lookup

Use Redis for dynamic IP control based on behavioral analysis, threat intelligence, or partner management.

## Overview

The `ip-match-database` controller enables:
- **Dynamic checks**: Add/remove IPs without config changes
- **Time-based control**: Auto-expire blocks using TTL
- **External integration**: Connect to threat feeds or behavioral systems
- **Performance**: Built-in caching for fast lookups

## Use Cases

### 1. Scraper Detection
Block IPs identified as scrapers by behavioral analysis.

### 2. Partner Management
Dynamically manage partner IP allowlists.

### 3. Threat Intelligence
Integrate external threat feeds (e.g., abuse.ch, AbuseIPDB).

### 4. Rate Limiting Integration
Block IPs that exceeded rate limits.

## Example

**Scenario**: Block scrapers detected by your application.

**config.yaml**:
```yaml
authorizationPolicy: "!scraper-blocker"

authorizationControllers:
  - name: scraper-blocker
    type: ip-match-database
    settings:
      action: deny
      cache:
        ttl: 10m
      database:
        type: redis
        redis:
          keyPrefix: "scraper:"
          host: redis.default.svc.cluster.local
```

**Managing IPs in Redis**:
```bash
# Block an IP (expires in 1 hour)
SET scraper:1.2.3.4 1 EX 3600

# Block permanently
SET scraper:1.2.3.5 1

# Remove block
DEL scraper:1.2.3.4

# Check if IP is blocked
EXISTS scraper:1.2.3.4

# List all blocked IPs
KEYS scraper:*
```

## Error Handling

### Default Behavior

**For `action: deny` (blocklist)**:
- Database available, IP found → DENY
- Database available, IP not found → ALLOW
- Database unavailable → ALLOW (fail-open)

**For `action: allow` (allowlist)**:
- Database available, IP found → ALLOW
- Database available, IP not found → DENY
- Database unavailable → DENY (fail-closed)

### Override: Always Deny on DB Failure

```yaml
settings:
  action: allow
  alwaysDenyOnDbUnavailable: true  # Fail-closed regardless of action
```

## Caching Strategy

### Why Cache?

- Reduce database load
- Improve latency (0.1ms vs 1-10ms)
- Handle database outages gracefully

### Cache Behavior

```yaml
cache:
  ttl: 10m  # Cache both "found" and "not found" for 10 minutes
```

- Both positive and negative results are cached
- TTL provides natural memory bounds
- No cache size limit

## Next Steps

- [Combined Policies](/examples/combined-policy)
- [Production Deployment](/guides/production)
- [Observability Guide](/guides/observability)
- [IP Match Database Reference](https://github.com/gtriggiano/envoy-authorization-service/blob/main/pkg/authorization/ip_match_database/Readme.md)
