# IP Match

Configure IP-based access control using allowlists (whitelists) and denylists (blacklists).

## Use Cases

- **Corporate Network Access**: Restrict access to office IP ranges
- **Partner Integration**: Whitelist specific partner networks
- **Threat Mitigation**: Block known malicious IPs
- **Bot Protection**: Deny known scraper IP ranges


## Managing CIDR Lists

### Optimize Lists

Remove redundant CIDR entries:

```bash
envoy-authorization-service synthesize-cidr-list \
  --file allowed-ips.txt \
  --overwrite
```

**Before**:
```txt
10.0.0.0/24
10.0.0.0/25  # Redundant - contained by /24
10.0.0.50/32 # Redundant - contained by /24
```

**After**:
```txt
10.0.0.0/24
```
## Examples

### Simple Allowlist

Allow only specific IP ranges:

**config.yaml**:
```yaml
server:
  address: ":9001"

metrics:
  address: ":9090"

matchControllers:
  - name: corporate-network
    type: ip-match
    settings:
      cidrList: allowed-ips.txt

authorizationPolicy: "corporate-network"
```

**allowed-ips.txt**:
```txt
# Corporate office
192.0.2.0/24

# VPN range
10.0.0.0/16

# Remote office
198.51.100.0/24
```

**Behavior**:
- IPs in the list: ✅ ALLOW
- IPs not in the list: ❌ DENY (403 Forbidden)

### Simple Denylist

Block specific IP ranges, allow everything else:

**config.yaml**:
```yaml
server:
  address: ":9001"

metrics:
  address: ":9090"

matchControllers:
  - name: blocked-ips
    type: ip-match
    settings:
      cidrList: blocked-ips.txt

authorizationPolicy: "!blocked-ips"
```

**blocked-ips.txt**:
```txt
# Known scrapers
203.0.113.0/24

# Malicious network
198.51.100.0/25

# Individual threat actor
192.0.2.50/32
```

**Behavior**:
- IPs in the list: ❌ DENY (403 Forbidden)
- IPs not in the list: ✅ ALLOW

### Allowlist with Denylist Override

Allow specific IPs, but explicitly block some within that range:

**config.yaml**:
```yaml
server:
  address: ":9001"

metrics:
  address: ":9090"

matchControllers:
  - name: allowed-ips
    type: ip-match
    settings:
      cidrList: allowed-ips.txt
  
  - name: blocked-ips
    type: ip-match
    settings:
      cidrList: blocked-ips.txt

authorizationPolicy: "allowed-ips && !blocked-ips"
```

**allowed-ips.txt**:
```txt
# Allow entire corporate network
10.0.0.0/8
192.168.0.0/16
```

**blocked-ips.txt**:
```txt
# Block specific compromised hosts within corporate network
10.0.5.100/32
10.0.5.101/32
```

**Behavior**:
| Client IP | In Allowlist? | In Blocklist? | Result |
|-----------|--------------|---------------|---------|
| 10.0.0.5 | ✅ Yes | ❌ No | ✅ ALLOW |
| 10.0.5.100 | ✅ Yes | ✅ Yes | ❌ DENY |
| 8.8.8.8 | ❌ No | ❌ No | ❌ DENY |

### Multiple Allowlist Sources

Allow from corporate network OR partners:

**config.yaml**:
```yaml
server:
  address: ":9001"

metrics:
  address: ":9090"

matchControllers:
  - name: corporate-network
    type: ip-match
    settings:
      cidrList: corporate-ips.txt
  
  - name: partner-networks
    type: ip-match
    settings:
      cidrList: partner-ips.txt
  
  - name: blocked-threats
    type: ip-match
    settings:
      cidrList: threats.txt

authorizationPolicy: "(corporate-network || partner-networks) && !blocked-threats"
```

**Behavior**:
- Allow if in corporate OR partner networks
- Always block if in threats list

## Next Steps

- [ASN Match](/examples/asn-match)
- [IP Match - Redis](/examples/ip-match-redis)
- [Combined Policies](/examples/combined-policy)
- [Policy DSL Reference](/policy-dsl)