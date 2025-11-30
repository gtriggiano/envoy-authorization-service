# Analysis Controllers

Analysis controllers run during the **first phase** of request processing to extract and enrich request metadata.

They execute concurrently and cannot block requests directly.

## ASN

The `maxmind-asn` controller performs IP-to-ASN lookups to identify the Autonomous System Number and organization.

::: warning Note
You need [MaxMind databases](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) to run this example.
:::

**Configuration**:
```yaml
analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: config/GeoLite2-ASN.mmdb
```

**Upstream Headers Injected**:
- `X-ASN-Number` - The autonomous system number (e.g., `15169`)
- `X-ASN-Organization` - Organization name (e.g., `GOOGLE`)

**Use Cases**:
- Enable ASN-based authorization
- Track requests by network provider
- Security analysis and threat intelligence
- Provide network context to upstream services

**Requirements**:
- [MaxMind GeoLite2 ASN Database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
- Weekly database updates recommended

## GeoIP

The `maxmind-geoip` controller performs IP-to-location lookups to identify geographic information.

::: warning Note
You need [MaxMind databases](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) to run this example.
:::

**Configuration**:
```yaml
analysisControllers:
  - name: geoip-detect
    type: maxmind-geoip
    settings:
      databasePath: config/GeoLite2-City.mmdb
```

**Upstream Headers Injected**:
- `X-GeoIP-City` - City name
- `X-GeoIP-PostalCode` - Postal/ZIP code
- `X-GeoIP-Region` - State/province name
- `X-GeoIP-Country` - Country name
- `X-GeoIP-CountryISO` - ISO country code (e.g., `US`)
- `X-GeoIP-Continent` - Continent name
- `X-GeoIP-TimeZone` - IANA timezone
- `X-GeoIP-Latitude` - Decimal latitude
- `X-GeoIP-Longitude` - Decimal longitude

**Use Cases**:
- Geographic access restrictions
- Content localization
- Analytics and reporting
- Compliance requirements (GDPR, data residency)

**Requirements**:
- [MaxMind GeoLite2 City Database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
- Weekly database updates recommended

---

## User Agent

The `ua-detect` controller parses the HTTP `User-Agent` header to identify browser, OS, device type, and bots.

**Configuration**:
```yaml
analysisControllers:
  - name: user-agent
    type: ua-detect
```

**Upstream Headers Injected**:

**Browser Information**:
- `X-UA-Browser` - Browser name (e.g., `Chrome`)
- `X-UA-Browser-Version` - Full version string
- `X-UA-Browser-Major` - Major version
- `X-UA-Browser-Minor` - Minor version
- `X-UA-Browser-Patch` - Patch version

**Operating System**:
- `X-UA-OS-Name` - OS name (e.g., `Windows`, `macOS`, `Linux`)
- `X-UA-OS-Version` - Full OS version
- `X-UA-OS-Major` - Major version
- `X-UA-OS-Minor` - Minor version
- `X-UA-OS-Platform` - Platform architecture

**Device Information**:
- `X-UA-Device-Type` - One of: `desktop`, `mobile`, `tablet`, `bot`, `tv`, `unknown`
- `X-UA-Device-Mobile` - Boolean (`true`/`false`)
- `X-UA-Device-Tablet` - Boolean
- `X-UA-Device-Desktop` - Boolean
- `X-UA-Device-TV` - Boolean
- `X-UA-Device-Model` - Device model (when available)

**Bot Detection**:
- `X-UA-Bot-Name` - Bot name (when detected)
- `X-UA-Bot-URL` - Bot URL/homepage

**Use Cases**:
- Block or rate-limit bots
- Device-specific access policies
- Browser compatibility checks
- Analytics and user insights
- Mobile vs desktop routing

**Requirements**: None (no external dependencies)

## Complete Analysis Setup

```yaml
analysisControllers:
  # ASN detection
  - name: asn-lookup
    type: maxmind-asn
    settings:
      databasePath: /data/GeoLite2-ASN.mmdb
  
  # Geographic location
  - name: geoip-lookup
    type: maxmind-geoip
    settings:
      databasePath: /data/GeoLite2-City.mmdb
  
  # User agent parsing
  - name: user-agent-parse
    type: ua-detect
```

## Error Handling

Analysis controllers never block requests on errors:
- Database read errors logged as warnings
- Missing data returns empty reports
- Match controllers handle missing analysis data
- Metrics track error rates

## Get MaxMind Databases

**Quick Download**:
```bash
# Using the provided script
./scripts/fetch-maxmind.sh

# Will download databases to config/
```

**Manual Download**:
1. Sign up for [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
2. Generate license key
3. Download databases:
   - GeoLite2-ASN.mmdb
   - GeoLite2-City.mmdb

**Update Schedule**:
- MaxMind releases updates weekly (Tuesdays)
- Recommended: automated weekly updates

## Integration with Authorization

Analysis results flow to match controllers:

```yaml
# Analysis phase
analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: GeoLite2-ASN.mmdb

# Authorization phase (uses ASN from analysis)
matchControllers:
  - name: cloud-providers
    type: asn-match
    settings:
      action: allow
      asList: allowed-asns.txt

authorizationPolicy: "cloud-providers"
```

The `asn-match` controller accesses ASN data from the `asn-detect` analysis controller's report.

## Next Steps

- [Configure Match Controllers](/configuration/match-controllers)
- [Write Policy Expressions](/configuration/policy-dsl)
- [Configure Server & Metrics](/configuration/server-metrics)
- [View Configuration Examples](/examples/)
