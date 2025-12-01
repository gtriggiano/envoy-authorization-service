# Geofence Match

The `geofence-match` controller matches the client location (latitude/longitude from GeoIP) against geographic polygons defined in a GeoJSON file.

## Prerequisites

This controller requires the `maxmind-geoip` analysis controller to provide location data:

```yaml
analysisControllers:
  - name: geoip
    type: maxmind-geoip
    settings:
      databasePath: GeoLite2-City.mmdb
```

## Configuration

```yaml
matchControllers:
  - name: allowed-regions
    type: geofence-match
    settings:
      polygonsFile: config/allowed-regions.geojson
```

## Settings

- `polygonsFile` (required): Path to a GeoJSON file containing polygon definitions.

## GeoJSON Format

The controller uses [GeoJSON](https://geojson.org/) (RFC 7946), the industry standard for geospatial data. Each feature must have:
- A `name` property (string) for identification
- A geometry of type `Polygon` or `MultiPolygon` with valid GPS coordinates

### Example GeoJSON File

```json
{
  "type": "FeatureCollection",
  "features": [
    {
      "type": "Feature",
      "properties": { "name": "europe-region" },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-10.0, 35.0],
          [40.0, 35.0],
          [40.0, 70.0],
          [-10.0, 70.0],
          [-10.0, 35.0]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": { "name": "us-east-coast" },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-85.0, 25.0],
          [-65.0, 25.0],
          [-65.0, 45.0],
          [-85.0, 45.0],
          [-85.0, 25.0]
        ]]
      }
    }
  ]
}
```

## Creating GeoJSON Files

You can create GeoJSON files using:
- **[geojson.io](https://geojson.io)** - Free online tool for drawing polygons on a map and exporting
- **Google Earth** - Export shapes as GeoJSON
- **QGIS** - Professional GIS software with GeoJSON export
- **Mapbox, Leaflet** - Web mapping libraries with GeoJSON support

## Validation Rules

The controller validates that:
- Polygons are closed (first and last coordinates match)
- Coordinates are within valid GPS bounds (latitude: -90 to 90, longitude: -180 to 180)
- Each polygon has at least 4 points (including closing point)
- Feature names are unique

## Upstream Headers

When a request is processed, the controller adds headers to upstream requests:
- `X-Geofence-{controller-name}`: `true` or `false` indicating if the location matched any polygon
- `X-Geofence-{controller-name}-Polygons`: Comma-separated list of matched polygon names (only when matched)

## Policy Patterns

- Allow only from specific regions: `authorizationPolicy: "allowed-regions"`
- Block specific regions: `authorizationPolicy: "!blocked-regions"`
- Combine with other controllers: `authorizationPolicy: "allowed-regions && !blocked-asn"`
- Require region AND IP allowlist: `authorizationPolicy: "allowed-regions && corporate-network"`

## Use Cases

- **Geographic restrictions**: Restrict access to users from specific countries or regions
- **Compliance**: Enforce data residency requirements
- **Fraud prevention**: Block or flag requests from unexpected locations
- **Regional routing**: Route requests based on geographic location
