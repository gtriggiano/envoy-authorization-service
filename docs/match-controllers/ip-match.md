# IP Match

The `ip-match` controller matches the request IP against a CIDR list.

## Configuration

```yaml
matchControllers:
  - name: corporate-network
    type: ip-match
    settings:
      cidrList: config/corporate-network-cidrs.txt
```

## Settings
- `cidrList` (required): Path to a text file with CIDR entries, one per line (`#` for comments).

## CIDR List Format
- Accepts CIDR ranges (`192.0.2.0/24`) and single IPs (treated as `/32`).
- Ignores blank lines and lines starting with `#`.

## Policy Patterns
- Allow-list only: `authorizationPolicy: "corporate-network"`.
- Combine allow + block lists: `authorizationPolicy: "allowlist && !blocklist"` where both are `ip-match` controllers with different lists.
