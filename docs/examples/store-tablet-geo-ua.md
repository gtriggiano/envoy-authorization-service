# Geofenced Store Tablets & Kiosks

Lock down store/kiosk tablets so they work only on-site and from approved device types, while feeding location and device analytics back to HQ.

## Scenario
- Retail/restaurant chain deploys in-store tablets for POS and inventory.
- Devices must function only when physically inside a store's geofence and using the managed Wi‑Fi.
- Analytics wants per-store traffic counts without exposing PII.

## Controllers Used
- `maxmind-geoip` — resolves coordinates for geofence checks.
- `ua-detect` — confirms device class is `tablet` and flags unexpected bots.
- `geofence-match` (`stores-geo`) — GeoJSON polygons per store.
- `ip-match` (`store-wifi`) — CIDR ranges for store Wi‑Fi gateways.

## Policy
Require the device to be inside a store geofence **and** on store Wi‑Fi. Tablet UA enforcement happens in the app using headers from `ua-detect`:

```yaml
authorizationPolicy: "stores-geo && store-wifi"
```

## Example Configuration
```yaml
analysisControllers:
  - name: geoip
    type: maxmind-geoip
    settings:
      databasePath: config/GeoLite2-City.mmdb

  - name: user-agent
    type: ua-detect

matchControllers:
  - name: stores-geo
    type: geofence-match
    settings:
      featuresFile: config/stores.geojson

  - name: store-wifi
    type: ip-match
    settings:
      cidrList: config/store-wifi-cidrs.txt
```

### UA Tablet Hint
The Policy DSL can’t directly consume UA headers. Enforce geofence/Wi‑Fi/stolen list at the gateway, then have the upstream application reject non-tablet UAs using the injected `X-UA-Device-Type` header.

## Request Flow
1. `geoip` enriches with coordinates; `ua-detect` adds device headers.
2. `geofence-match` asserts the IP geolocates inside a store polygon.
3. `store-wifi` double-checks the source IP is from managed Wi‑Fi ranges.
4. Application reads `X-UA-Device-Type=tablet` to enforce the final device check.

## Value Delivered
- Ensures store-only behavior without shipping GPS-aware code into the app.
- Delivers per-store traffic analytics from GeoIP headers without storing user IDs.

## Operations Tips
- Keep store polygons coarse (store footprint + parking) to avoid GPS jitter false denies.
