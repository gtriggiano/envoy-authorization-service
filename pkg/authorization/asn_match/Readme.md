# ASN Match Authorization Controller `asn-match`

## Overview

The ASN Match authorization controller makes allow/deny decisions based on the Autonomous System Number (ASN) of the requesting client.

It reads from a configured list of ASNs and either allows or denies requests depending on whether the client's ASN matches an entry in the list.

## Purpose

This controller enables network-level access control by:
- Blocking traffic from specific ASNs (denial mode)
- Allowing only traffic from trusted ASNs (allowlist mode)

Common use cases:
- **Cloud provider restrictions**: Allow only traffic from major cloud providers
- **Enterprise networks**: Restrict access to corporate ASNs
- **Threat mitigation**: Block known malicious or spam-generating ASNs
- **Geographic proxy blocking**: Deny VPN/proxy service provider ASNs

## Configuration

### Settings

| Setting | Type | Description |
|---|---|---|
| `asList` | string (required) | Path to a text file containing the ASN list |
| `action` | string (required) | Either `allow` or `deny` - determines the matching behavior |

### Example

#### Allowlist Mode (Only allow specific ASNs)

```yaml
authorizationControllers:
  - name: trusted-cloud-provider
    type: asn-match
    settings:
      action: allow
      asList: config/trusted-cloud-providers-asns.txt
```

#### Denylist Mode (Block specific ASNs)

```yaml
authorizationControllers:
  - name: blacklisted-vpn-provider
    type: asn-match
    settings:
      action: deny
      asList: config/blacklisted-vpn-providers-asns.txt
```

## ASN List File Format

The ASN list file is a plain text file with one ASN per line. Lines starting with `#` are treated as comments.

### Format

```text
# Google
AS 15169

# Amazon AWS
AS 16509

# Microsoft Azure
AS 8075
```

**Notes:**
- The `AS` prefix is optional: both `AS 15169` and `15169` are valid
- Whitespace is ignored: both `AS 15169` and `AS15169` are valid
- Comments can appear on separate lines starting with `#`
- Empty lines are ignored
- Invalid lines are skipped silently

## Authorization Logic

### Allow Mode (`action: allow`)

- **Match found**: Request is **allowed** (HTTP 200)
- **No match**: Request is **denied** (HTTP 403)
- **No ASN data available**: Request is **denied** (HTTP 403)

**Use case**: Implement a strict allowlist where only approved networks can access the service.

### Deny Mode (`action: deny`)

- **Match found**: Request is **denied** (HTTP 403)
- **No match**: Request is **allowed** (HTTP 200)
- **No ASN data available**: Request is **allowed** (HTTP 200)

**Use case**: Block known bad actors while allowing all other traffic through.

## Dependencies

This controller **requires** an ASN analysis controller (typically [`maxmind-asn`](../../analysis/maxmind_asn/)) to be configured in the `analysisControllers` section. Without ASN data, authorization decisions default to the safe fallback:

- **Allow mode**: Denies requests (fail-closed)
- **Deny mode**: Allows requests (fail-open)

### Complete Configuration Example

```yaml
analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: config/GeoLite2-ASN.mmdb

authorizationControllers:
  - name: corporate-network
    type: asn-match
    settings:
      action: allow
      asList: config/corporate-network-asns.txt

authorizationPolicy: "corporate-network"
```

## Policy Integration

ASN match controllers can be combined with other authorization controllers using boolean policy expressions:

```yaml
authorizationControllers:
  - name: corporate-network
    type: asn-match
    settings:
      action: allow
      asList: config/corporate-network-asns.txt

  - name: trusted-address
    type: ip-match
    settings:
      action: allow
      cidrList: config/trusted-addresses-cidrs.txt

authorizationPolicy: "corporate-network || trusted-address"
```

## See Also

- [MaxMind ASN Analysis Controller](../../analysis/maxmind_asn/)
- [IP Match Authorization Controller](../ip_match/)
- [Authorization Policy DSL](../../policy/)
