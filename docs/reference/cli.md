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

Relative paths **inside** the configuration file are resolved from the directory that contains the file, not from the working directory.

### Example

```bash
envoy-authorization-service start --config /etc/auth-service/config.yaml
```

The process exits with status `1` when the configuration cannot be loaded or validated, or when a controller cannot be built. A configuration with an empty `authorizationPolicy` or with `authorizationPolicyBypass: true` starts, and logs a `warn` line for each at startup.

## `validate`

Validate a configuration file exactly as `start` would load it, then exit.

### Usage

```bash
envoy-authorization-service validate [flags]
```

### Flags

```
--config string   Path to the configuration file (default "config.yaml")
--offline         Do not use the deployment environment: skip database connections and report missing credential and data files as warnings
```

### What is checked

- environment references (`${NAME}`) resolve, in both modes: give CI the variables or use `${NAME:-default}`
- strict YAML: unknown keys, duplicate keys, wrong types and invalid durations are errors
- every top-level field (listeners, TLS material, `clientIp`, `logging.level`, `shutdown.timeout`)
- the authorization policy: syntax and references to configured, enabled match controllers
- every enabled controller is built: unknown settings keys rejected, CIDR and ASN lists parsed, MaxMind databases opened, GeoJSON validated, database settings checked and, without `--offline`, databases connected to

With `--offline` the deployment environment is assumed to be unavailable. No connection is attempted, and credential files, certificate files and data files that cannot be found are reported as **warnings** rather than errors; files that exist are still parsed. This makes the flag suitable for validating a ConfigMap in CI, where `/config/...` and `/maxmind/...` only exist inside the pod.

The exit status is `0` when the configuration is valid and `1` otherwise.

### Examples

**Full validation on the target host**:
```bash
envoy-authorization-service validate --config /etc/auth-service/config.yaml
```

**Output on success**:
```
✓ configuration is valid: /etc/auth-service/config.yaml
  analysis controllers: asn-detect (maxmind-asn), geoip-detect (maxmind-geoip)
  match controllers: trusted (ip-match), scraper (ip-match)
  authorization policy: trusted || !scraper
  client IP sources: header:x-envoy-external-address, envoySource
```

**Offline validation in CI**:
```bash
envoy-authorization-service validate --offline --config kubernetes/examples/combined-policy/config.yaml
```

```
✓ configuration is valid: kubernetes/examples/combined-policy/config.yaml
  mode: offline (no database connections; missing credential and data files reported as warnings)
  analysis controllers: (none)
  match controllers: (none)
  controllers not fully built (offline): 5
  authorization policy: (trusted-partners && !blocked-networks) || (cloud-providers && !blocked-networks)
  client IP sources: envoySource
  warnings:
    - databasePath: file /maxmind/GeoLite2-ASN.mmdb not found, its content was not checked
    - cidrList: file /config/trusted-partners-ips.txt not found, its content was not checked
```

**Output on failure**:
```
✗ configuration is invalid: could not parse the configuration file: line 12: unknown key "cidrLst"
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
