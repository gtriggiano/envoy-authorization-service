# IP Match Controller `ip-match`

## Overview

The IP Match controller evaluates whether the client IP belongs to a configured set of CIDR ranges. It produces a `MatchVerdict` (`IsMatch` + description) that the policy engine uses to decide whether to allow or deny the request. The controller itself no longer encodes an allow/deny action.

## Configuration

### Settings

| Setting | Type | Description |
|---|---|---|
| `cidrList` | string (required) | Path to a text file containing CIDR ranges (one per line, `#` for comments). |

### Example

```yaml
matchControllers:
  - name: corporate-network
    type: ip-match
    settings:
      cidrList: config/corporate-network-cidrs.txt

# Only allow if the IP matches the allow-list
authorizationPolicy: "corporate-network"
```

To combine with a blocklist:

```yaml
matchControllers:
  - name: allowlist
    type: ip-match
    settings:
      cidrList: config/allow-cidrs.txt
  - name: blocklist
    type: ip-match
    settings:
      cidrList: config/block-cidrs.txt

# Allow when on the allowlist and not on the blocklist
authorizationPolicy: "allowlist && !blocklist"
```

## CIDR File Format

Plain text, one entry per line. Supports CIDR (`192.0.2.0/24`) and single IPs (`198.51.100.10` → treated as `/32`). Lines starting with `#` are comments; empty lines are ignored.

## See Also

- [ASN Match Controller](../asn_match/)
- [Policy DSL](../../policy/)
