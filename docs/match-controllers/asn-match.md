# ASN Match

The `asn-match` controller sets `IsMatch=true` when the client ASN appears in a configured list. It requires an analysis controller (e.g., `maxmind-asn`) to supply ASN data.

## Configuration

```yaml
analysisControllers:
  - name: asn-detect
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
