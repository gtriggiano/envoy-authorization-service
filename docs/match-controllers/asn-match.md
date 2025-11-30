# ASN Match

The `asn-match` controller matches the client ASN against in a configured list.

## Configuration

```yaml
analysisControllers:
  - name: asn
    type: maxmind-asn
    settings:
      databasePath: GeoLite2-ASN.mmdb

matchControllers:
  - name: cloud-providers
    type: asn-match
    settings:
      asnList: config/cloud-providers-asns.txt
```

## Settings
- `asnList` (required): Path to a text file with ASN numbers (one per line; `AS` prefix optional).

## ASN List Format
- Supports lines like `15169` or `AS 15169`; `#` starts a comment; blank lines are ignored.

## Policy Patterns
- Allow only trusted ASNs: `authorizationPolicy: "trusted-asn"`.
- Combine allow + block lists: `authorizationPolicy: "trusted-asn && !blocked-asn"` using two `asn-match` controllers.
