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
