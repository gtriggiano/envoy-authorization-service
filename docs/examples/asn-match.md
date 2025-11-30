# ASN Match

Control access based on Autonomous System Numbers (ASN) to allow or block traffic from specific networks.

## Use Cases

- **Cloud Provider Allowlisting**: Allow only major cloud providers (AWS, GCP, Azure)
- **Hosting Network Blocking**: Block cheap hosting providers known for abuse
- **Geographic Network Control**: Restrict by network ownership
- **CDN Allowlisting**: Allow only known CDN networks

## Prerequisites

ASN-based authorization requires the `maxmind-asn` analysis controller:

```yaml
analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: GeoLite2-ASN.mmdb
```

Download the database: [MaxMind GeoLite2 ASN](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)

## Finding ASN Numbers Online

- [Hurricane Electric BGP Toolkit](https://bgp.he.net/)
- [IPInfo ASN Lookup](https://ipinfo.io/)

Example:
```
IP: 8.8.8.8
ASN: 15169
Organization: GOOGLE
```

## Deduplicate ASN Lists

Remove duplicate entries:

```bash
envoy-authorization-service synthesize-asn-list \
  --file cloud-asns.txt \
  --overwrite
```

**Before**:
```txt
15169
15169  # Duplicate
16509
```

**After**:
```txt
15169
16509
```

## Examples

### Allow Only Cloud Providers

Restrict access to major cloud providers:

**config.yaml**:
```yaml
authorizationPolicy: "cloud-providers"

analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: GeoLite2-ASN.mmdb

matchControllers:
  - name: cloud-providers
    type: asn-match
    settings:
      asList: cloud-asns.txt
```

**cloud-asns.txt**:
```txt
# AWS
16509
14618
8987

# Google Cloud
15169
396982

# Microsoft Azure
8075
8068

# Cloudflare
13335

# Akamai
16625
20940
```

**Behavior**:
- Traffic from cloud provider ASNs: ✅ ALLOW
- Traffic from other ASNs: ❌ DENY

### Block Abusive Hosting Networks

Block cheap hosting providers known for spam/abuse:

**config.yaml**:
```yaml
authorizationPolicy: "!blocked-hosting"

analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: GeoLite2-ASN.mmdb

matchControllers:
  - name: blocked-hosting
    type: asn-match
    settings:
      asList: blocked-asns.txt
```

**blocked-asns.txt**:
```txt
# Known spam/abuse hosting networks
# (Example ASNs - adjust based on your threat intelligence)
12345
67890
```

**Behavior**:
- Traffic from blocked ASNs: ❌ DENY
- Traffic from other ASNs: ✅ ALLOW

### Cloud Providers with IP Allowlist

Combine ASN filtering with IP allowlisting:

**config.yaml**:
```yaml
authorizationPolicy: "(corporate-ips || cloud-providers) && !blocked-asns"

analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: GeoLite2-ASN.mmdb

matchControllers:
  - name: corporate-ips
    type: ip-match
    settings:
      cidrList: corporate-ips.txt
  
  - name: cloud-providers
    type: asn-match
    settings:
      asList: cloud-asns.txt
  
  - name: blocked-asns
    type: asn-match
    settings:
      asList: blocked-asns.txt
```

**Behavior**:
- Allow if from corporate IPs OR cloud provider ASN
- Always block if from blocked ASN

### CDN and Cloud Allowlist

Allow only CDN and cloud traffic:

**config.yaml**:
```yaml
authorizationPolicy: "cdn-networks || cloud-providers"

analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: GeoLite2-ASN.mmdb

matchControllers:
  - name: cdn-networks
    type: asn-match
    settings:
      asList: cdn-asns.txt
  
  - name: cloud-providers
    type: asn-match
    settings:
      asList: cloud-asns.txt
```

**cdn-asns.txt**:
```txt
# Cloudflare
13335

# Fastly
54113

# Akamai
16625
20940
32787

# CloudFront (AWS)
16509
```

## Next Steps

- [IP Match](/examples/ip-match)
- [IP Match - Redis](/examples/ip-match-redis)
- [Combined Policies](/examples/combined-policy)
- [Policy DSL Reference](/policy-dsl)