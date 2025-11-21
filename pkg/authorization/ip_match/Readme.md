# IP Match Authorization Controller `ip-match`

## Overview

The IP Match authorization controller makes allow/deny decisions based on the client's IP address by matching it against a configured list of CIDR ranges.

It supports both allowlist (permit only listed IPs) and denylist (block listed IPs) modes.

## Purpose

This controller enables fine-grained IP-based access control:
- **Allowlisting**: Restrict access to known IP ranges (e.g., corporate networks, VPNs)
- **Denylisting**: Block traffic from malicious IPs, bot networks, etc.

Common use cases:
- **Corporate access**: Allow only office IP ranges
- **Partner integration**: Whitelist partner network CIDRs
- **Threat mitigation**: Block known attack sources
- **Bot protection**: Deny known bot/scraper IP ranges

## Configuration

### Settings

| Setting | Type | Description |
|---|---|---|
| `cidrList` | string (required) | Path to a text file containing CIDR ranges (one per line) |
| `action` | string (required) | Either `allow` or `deny` - determines the matching behavior |

### Example

#### Allowlist Mode (Only allow specific IPs)

```yaml
authorizationControllers:
  - name: corporate-network
    type: ip-match
    settings:
      action: allow
      cidrList: config/corporate-network-cidrs.txt
```

#### Denylist Mode (Block specific IPs)

```yaml
authorizationControllers:
  - name: scraper
    type: ip-match
    settings:
      action: deny
      cidrList: config/scrapers-cidrs.txt
```

## CIDR List File Format

The CIDR list file is a plain text file supporting both single IPs and CIDR ranges. Lines starting with `#` are treated as comments and can be used to document entries.

### Format

```text
# Comment describing the ranges
192.0.2.0/24
198.51.100.50/32
203.0.113.0/25

# Another section
10.0.0.0/8
```

**Supported formats:**
- **CIDR notation**: `192.0.2.0/24` (most common)
- **Single IP**: `198.51.100.50` (auto-converted to `/32`)
- **Comments**: Lines starting with `#`

**Notes:**
- Only IPv4 is currently supported
- Empty lines are ignored
- Invalid lines are skipped silently

## Authorization Logic

### Allow Mode (`action: allow`)

- **Match found**: Request is **allowed** (HTTP 200)
- **No match**: Request is **denied** (HTTP 403)
- **Invalid source IP**: Request is **denied** (HTTP 403)

**Use case**: Implement a strict allowlist where only approved networks can access the service.

### Deny Mode (`action: deny`)

- **Match found**: Request is **denied** (HTTP 403)
- **No match**: Request is **allowed** (HTTP 200)
- **Invalid source IP**: Request is **allowed** (HTTP 200)

**Use case**: Block known threats while allowing all other traffic.

## Policy Integration

Combine multiple IP match controllers using boolean expressions:

```yaml
authorizationControllers:
  - name: whitelisted
    type: ip-match
    settings:
      action: allow
      cidrList: config/whitelisted-cidrs.txt
  
  - name: blacklisted
    type: ip-match
    settings:
      action: deny
      cidrList: config/blacklisted-cidrs.txt

# Deny blacklisted addresses unless they are whitelisted
authorizationPolicy: "whitelisted || !blacklisted"
```

## Managing CIDR Lists

### Synthesis and Deduplication

The application CLI provides a command to to optimize CIDR lists:

```bash
# Remove redundant CIDRs (those contained by others or duplicated)
envoy-authorization-service synthesize-cidr-list --file blocklist.txt > blocklist-optimized.txt
```

**Example:**
```text
# Before
10.0.0.0/24
10.0.0.0/25  # Redundant - contained by /24

# After
10.0.0.0/24
```

## See Also

- [ASN Match Authorization Controller](../asn_match/)
- [Authorization Policy DSL](../../policy/)
