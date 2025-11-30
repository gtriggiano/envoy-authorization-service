# IP Match - Redis

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
authorizationPolicy: "!scraper"

matchControllers:
  - name: scraper
    type: ip-match-database
    settings:
      matchesOnFailure: false
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

## Configuration Options

### matchesOnFailure

Controls the `IsMatch` value when database queries fail (connection timeout, network error, etc.):

```yaml
matchesOnFailure: false  # Default: IsMatch=false on DB failure
matchesOnFailure: true   # IsMatch=true on DB failure
```

The resulting behavior (allow vs deny) depends on your authorization policy:

**Example 1 - Deny List (Scraper Blocking)**

```yaml
authorizationPolicy: "!scraper"  # Allow if NOT a scraper

matchControllers:
  - name: scraper
    type: ip-match-database
    settings:
      matchesOnFailure: false  # Fail-open: allow traffic if Redis is down
      database:
        type: redis
        redis:
          keyPrefix: "scraper:"
```

When Redis is unavailable:
- `matchesOnFailure: false` → IsMatch=false → `!scraper` = `!false` = `true` → **ALLOW** (fail-open)
- `matchesOnFailure: true` → IsMatch=true → `!scraper` = `!true` = `false` → **DENY** (fail-closed)

**Example 2 - Allow List (Trusted Partners)**

```yaml
authorizationPolicy: "trusted-partner"  # Allow if IS a trusted partner

matchControllers:
  - name: trusted-partner
    type: ip-match-database
    settings:
      matchesOnFailure: true  # Fail-open: allow traffic if DB is down
      database:
        type: postgres
```

When PostgreSQL is unavailable:
- `matchesOnFailure: false` → IsMatch=false → `trusted-partner` = `false` → **DENY** (fail-closed)
- `matchesOnFailure: true` → IsMatch=true → `trusted-partner` = `true` → **ALLOW** (fail-open)

**Guidelines**:
- **Deny lists**: Use `matchesOnFailure: false` for fail-open (prefer availability)
- **Allow lists**: Use `matchesOnFailure: true` for fail-open (prefer availability)
- Adjust based on whether you prioritize availability or security during outages

### Caching Strategy

**Why Cache?**

- Reduce database load
- Improve latency (0.1ms vs 1-10ms)
- Handle database outages gracefully

**Cache Behavior**:

```yaml
cache:
  ttl: 10m  # Cache both "found" and "not found" for 10 minutes
```

- Both positive and negative results are cached
- TTL provides natural memory bounds
- No cache size limit

## Next Steps

- [Combined Policies](/examples/combined-policy)
- [Observability Guide](/guides/observability)