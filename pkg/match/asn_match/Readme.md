# ASN Match Controller `asn-match`

## Overview

The ASN Match controller reports whether the client's Autonomous System Number (ASN) appears in a configured list. It emits a `MatchVerdict` consumed by the policy engine; the controller itself does not decide to allow or deny.

## Configuration

### Settings

| Setting | Type | Description |
|---|---|---|
| `asnList` | string (required) | Path to a text file containing ASNs, one per line (`AS 15169` or `15169`). Lines starting with `#` are comments. |

### Example

```yaml
matchControllers:
  - name: trusted-asn
    type: asn-match
    settings:
      asnList: config/trusted-asns.txt

# Allow only if the ASN is trusted
authorizationPolicy: "trusted-asn"
```

Combine allow and block lists:

```yaml
authorizationPolicy: "trusted-asn && !blocked-asn"
```

## Use Cases

- Restrict access to corporate or partner networks
- Block traffic from known malicious ASNs
- Shape access for cloud or CDN networks

## See Also

- [IP Match Controller](../ip_match/)
- [Policy DSL](../../policy/)
