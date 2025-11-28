# MaxMind ASN Analysis Controller `maxmind-asn`

## Overview

The MaxMind ASN analysis controller enriches incoming requests with Autonomous System Number (ASN) information by querying the MaxMind ASN database.

This controller operates during the **analysis phase**, extracting metadata that can inform authorization decisions and/or be provided upstream.

## Purpose

This controller performs IP-to-ASN lookups to identify:
- The autonomous system number associated with the client's IP address
- The organization operating that autonomous system

This information is useful for:
- Blocking or allowing traffic from specific ASN ranges
- Tracking requests by network provider
- Security analysis and threat intelligence

## Configuration

| Setting | Type | Description |
|---|---|---|
| `databasePath` | string (required) | Absolute or relative path to the MaxMind ASN .mmdb database file |

### Example

```yaml
analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: config/GeoLite2-ASN.mmdb
```

## Output

### Upstream Headers

The controller injects the following headers into upstream requests (if the request is ultimately proxied):

| Header | Description | Example |
|--------|-------------|---------|
| `X-ASN-Number` | The autonomous system number | `15169` |
| `X-ASN-Organization` | The organization name for the ASN | `GOOGLE` |

## Caching

The controller implements an in-memory cache to minimize database lookups.

Cache hits are logged at debug level for observability.

## Error Handling

- If the IP address cannot be found in the database, the controller logs a warning and returns a report with `nil` lookup result
- Database read errors are logged and result in a `nil` lookup result

## Dependencies

A **[MaxMind ASN Database](https://dev.maxmind.com/geoip/docs/databases/asn/)**.

It's recommended to update it weekly.

## Integration with Authorization Controllers

The ASN information exposed by this controller can be consumed by authorization controllers like [`asn-match`](../../authorization/asn_match) to make allow/deny decisions based on the origin network.

### Example: ASN-based Authorization

```yaml
analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: config/GeoLite2-ASN.mmdb

authorizationControllers:
  - name: allowed-cloud-provider
    type: asn-match
    settings:
      action: allow
      asList: config/allowed-cloud-providers-asns.txt
```

## See Also

- [ASN Match Authorization Controller](../../authorization/asn_match)
- [MaxMind GeoIP Analysis Controller](../maxmind_geoip)
