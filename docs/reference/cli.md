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
--config string   Path to the configuration file (default "config.yaml", resolved from the current working directory)
```

### Example

```bash
envoy-authorization-service start --config /etc/auth-service/config.yaml
```

The process exits with status `1` when the configuration cannot be loaded or validated, or when a controller cannot be built.

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

- Removes duplicate entries (the first occurrence is kept)
- Removes CIDRs contained within larger CIDRs
- Preserves the original order of the surviving entries
- Preserves `#` comments: a comment line applies to the entries that follow it, up to the next blank line
- Drops lines that are not valid IPv4 addresses or IPv4 CIDRs (IPv6 is not supported)

**Example** (inline comments are not supported; the annotations below are explanatory only):

Input file:
```txt
192.168.1.0/24
# Office
10.0.0.0/24
10.0.0.0/25
10.0.0.50/32
192.168.1.0/24
2001:db8::/32
```

Output:
```txt
192.168.1.0/24

# Office
10.0.0.0/24
```

`10.0.0.0/25` and `10.0.0.50/32` are removed because `10.0.0.0/24` contains them, the second `192.168.1.0/24` is a duplicate, and `2001:db8::/32` is dropped because IPv6 is not supported.

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

- Removes duplicate ASN entries (the first occurrence is kept)
- Preserves the original order of the surviving entries
- Accepts `15169`, `AS15169` and `AS 15169`; output is normalised to `AS 15169`
- Preserves `#` comments: a comment line applies to the entries that follow it, up to the next blank line
- Drops lines that are not valid AS numbers

**Example**

Input file:
```txt
15169
AS16509
15169
AS 14618
```

Output:
```txt
AS 15169
AS 16509
AS 14618
```

The second `15169` is removed as a duplicate; the remaining entries keep their original order and are normalised to the `AS <number>` form.

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
