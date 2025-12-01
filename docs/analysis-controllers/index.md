# Analysis Controllers

Analysis controllers run during the **first phase** of request processing to extract and enrich request metadata. They execute concurrently and never block or decide the request outcome; their reports are consumed by match controllers during authorization.

## Available Controllers

### [MaxMind ASN](/analysis-controllers/maxmind-asn)
Performs IP-to-ASN lookups using MaxMind GeoLite2 or GeoIP2 databases. Identifies the Autonomous System Number and organization name for the client IP. Essential for ASN-based match controllers.

### [MaxMind GeoIP](/analysis-controllers/maxmind-geoip)
Performs IP-to-location lookups using MaxMind GeoLite2 or GeoIP2 City databases. Extracts geographic data including country, city, coordinates, timezone, and more. Required for geofence-based authorization.

### [User-Agent Detect](/analysis-controllers/ua-detect)
Parses HTTP User-Agent headers to identify browser, operating system, device type, and bot detection. Useful for device-specific policies or bot filtering strategies.

## Complete Analysis Setup

```yaml
analysisControllers:
  # ASN detection
  - name: asn
    type: maxmind-asn
    settings:
      databasePath: /data/GeoLite2-ASN.mmdb
  
  # Geographic location
  - name: geoip
    type: maxmind-geoip
    settings:
      databasePath: /data/GeoLite2-City.mmdb
  
  # User agent parsing
  - name: user-agent
    type: ua-detect
```

## Next Steps

- Configure a controller above, then wire it into your [authorization policy](/policy-dsl).
- See [match controllers](/match-controllers/) to act on the analysis data.
