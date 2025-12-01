# CLI Reference

Command-line interface reference for the Envoy Authorization Service.

## `start`

Start the authorization service.

### Usage

```bash
envoy-authorization-service start [flags]
```

### Flags

```
--config string   Path to configuration file (required)
```

### Example

```bash
envoy-authorization-service start --config /etc/auth-service/config.yaml
```

## `synthesize-cidr-list`

Optimize CIDR lists by removing redundant entries.

### Usage

```bash
envoy-authorization-service synthesize-cidr-list [flags]
```

### Flags

```
--file string      Path to CIDR list file (required)
--overwrite        Overwrite the original file with optimized version, otherwise prints on stdout
```

### Examples

**Create optimized copy**:
```bash
envoy-authorization-service synthesize-cidr-list \
  --file blocked-ips.txt > blocked-ips-optimized.txt
```

**Overwrite original**:
```bash
envoy-authorization-service synthesize-cidr-list \
  --file blocked-ips.txt \
  --overwrite
```

### Optimization Rules

- Removes duplicate entries
- Removes CIDRs contained within larger CIDRs
- Sorts output for consistency

**Example**:
```txt
# Before
10.0.0.0/24
10.0.0.0/25  # Removed (contained in /24)
10.0.0.50/32 # Removed (contained in /24)
192.168.1.0/24
192.168.1.0/24 # Removed (duplicate)

# After
10.0.0.0/24
192.168.1.0/24
```

## `synthesize-asn-list`

Remove duplicate ASN entries from lists.

### Usage

```bash
envoy-authorization-service synthesize-asn-list [flags]
```

### Flags

```
--file string      Path to ASN list file (required)
--overwrite        Overwrite the original file with deduplicated version, otherwise prints on stdout
```

### Examples

**Create deduplicated copy**:
```bash
envoy-authorization-service synthesize-asn-list \
  --file allowed-asns.txt > allowed-asns-clean.txt
```

**Overwrite original**:
```bash
envoy-authorization-service synthesize-asn-list \
  --file allowed-asns.txt \
  --overwrite
```

### Deduplication Rules

- Removes duplicate ASN entries
- Sorts output numerically
- Preserves comments

**Example**:
```txt
# Before
15169
16509
15169  # Removed (duplicate)
14618

# After
14618
15169
16509
```

## `validate-geojson`

Validate a GeoJSON file for use with the geofence-match controller.

### Usage

```bash
envoy-authorization-service validate-geojson [flags]
```

### Flags

```
--file string      Path to GeoJSON file to validate (required)
```

### Examples

**Validate a GeoJSON file**:
```bash
envoy-authorization-service validate-geojson --file europe.geojson
```

**Output on success**:
```
✓ GeoJSON file is valid
  Features found: 2
    - europe-region
    - us-east-coast
```

**Output on failure**:
```
Error: validation failed: polygon 'my-zone' ring 0 must be closed (first and last points must be identical)
```

### Validation Rules

The command validates that:

- The file is valid JSON and follows GeoJSON FeatureCollection format
- Each feature has a `name` property (string)
- Each feature has a `Polygon` or `MultiPolygon` geometry
- All polygons are closed (first and last points match)
- All coordinates are valid GPS coordinates:
  - Latitude: -90 to 90
  - Longitude: -180 to 180
- Feature names are unique
