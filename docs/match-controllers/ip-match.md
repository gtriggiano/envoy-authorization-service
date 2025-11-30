# IP Match

The `ip-match` controller sets `IsMatch=true` when the client IP is contained in a CIDR list.

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
