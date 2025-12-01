# Regional Compliance with Geofences and ISP Guardrails

Control access to regulated services (payments, health data, adtech) so that only traffic from approved regions and residential ISPs is allowed, while keeping location and network telemetry for analytics.

## Scenario
- Product must serve only users inside approved countries/regions (e.g., EU + UK) for data residency.
- VPN/proxy egress from cloud providers should be rejected even if geolocated inside the region.
- Analytics needs city/country context to monitor adoption by market.

## Controllers Used
- `maxmind-geoip` — resolves client location for both auth and analytics.
- `maxmind-asn` — detects ISP/ASN to reject cloud or hosting exits.
- `geofence-match` (`eu-uk-geo`) — GeoJSON polygons for allowed regions.
- `asn-match` (`residential-isp`) — allowlist of consumer ISPs; block hosting ASNs by omission.

## Policy
Allow only when inside the geofence **and** coming from an allowed ASN:

```yaml
authorizationPolicy: "eu-uk-geo && residential-isp"
```

## Example Configuration
```yaml
analysisControllers:
  - name: geoip
    type: maxmind-geoip
    settings:
      databasePath: config/GeoLite2-City.mmdb

  - name: asn
    type: maxmind-asn
    settings:
      databasePath: config/GeoLite2-ASN.mmdb

matchControllers:
  - name: eu-uk-geo
    type: geofence-match
    settings:
      featuresFile: config/eu-uk.geojson

  - name: residential-isp
    type: asn-match
    settings:
      asnList: config/residential-isp-allowlist.txt
```

## Request Flow
1. `geoip` adds headers (`X-GeoIP-Country`, `X-GeoIP-City`, `X-GeoIP-Latitude`, `X-GeoIP-Longitude`).
2. `asn` adds `X-ASN-Number`/`X-ASN-Organization` so dashboards can separate consumer vs hosting traffic.
3. `geofence-match` validates the coordinates fall inside the approved polygons.
4. `asn-match` ensures traffic is from residential ISPs, not cloud/VPN exits.

## Value Delivered
- Satisfies data residency and licensing constraints.
- Reduces fraud by excluding cloud exit nodes even when geolocated correctly.
- Analytics can segment adoption by city/country while retaining privacy (no PII stored).

## Operations Tips
- Version GeoJSON in Git; validate with `envoy-authz validate-geojson` before deploys.
- Refresh MaxMind databases weekly.
