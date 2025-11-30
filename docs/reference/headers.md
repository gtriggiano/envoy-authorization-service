# Headers Reference

HTTP headers injected by analysis controllers and available to upstream/downstream services.

## ASN

Injected by the `maxmind-asn` analysis controller.

| Header | Example | Description |
|--------|---------|-------------|
| `X-ASN-Number` | `15169` | Autonomous System Number associated with the client IP |
| `X-ASN-Organization` | `GOOGLE` | Organization name for the ASN |

### Configuration

```yaml
analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: GeoLite2-ASN.mmdb
```

## GeoIP

Injected by the `maxmind-geoip` analysis controller.

| Header | Example | Description |
|--------|---------|-------------|
| `X-GeoIP-City` | `Mountain View` | City name |
| `X-GeoIP-PostalCode` | `94043` | Postal/ZIP code |
| `X-GeoIP-Region` | `California` | State or province name |
| `X-GeoIP-Country` | `United States` | Country name |
| `X-GeoIP-CountryISO` | `US` | ISO 3166-1 alpha-2 country code |
| `X-GeoIP-Continent` | `North America` | Continent name |
| `X-GeoIP-TimeZone` | `America/Los_Angeles` | IANA time zone identifier |
| `X-GeoIP-Latitude` | `37.4192` | Decimal latitude |
| `X-GeoIP-Longitude` | `-122.0574` | Decimal longitude |

### Configuration

```yaml
analysisControllers:
  - name: geoip-detect
    type: maxmind-geoip
    settings:
      databasePath: GeoLite2-City.mmdb
```

## User Agent

Injected by the `ua-detect` analysis controller.

### Browser Information

| Header | Example | Description |
|--------|---------|-------------|
| `X-UA-Browser` | `Chrome` | Browser name |
| `X-UA-Browser-Version` | `120.0.6099.109` | Full browser version |
| `X-UA-Browser-Major` | `120` | Major version number |
| `X-UA-Browser-Minor` | `0` | Minor version number |
| `X-UA-Browser-Patch` | `6099` | Patch version number |

### Operating System

| Header | Example | Description |
|--------|---------|-------------|
| `X-UA-OS-Name` | `macOS` | Operating system name |
| `X-UA-OS-Version` | `10.15.7` | Full OS version |
| `X-UA-OS-Major` | `10` | Major version number |
| `X-UA-OS-Minor` | `15` | Minor version number |
| `X-UA-OS-Platform` | `x86_64` | Platform architecture |

### Device Information

| Header | Example | Description |
|--------|---------|-------------|
| `X-UA-Device-Type` | `desktop` | Device type: `desktop`, `mobile`, `tablet`, `bot`, `tv`, `unknown` |
| `X-UA-Device-Mobile` | `true` | Boolean indicating mobile device |
| `X-UA-Device-Tablet` | `false` | Boolean indicating tablet device |
| `X-UA-Device-Desktop` | `true` | Boolean indicating desktop device |
| `X-UA-Device-TV` | `false` | Boolean indicating TV device |
| `X-UA-Device-Model` | `iPhone` | Device model when available |

### Bot Detection

| Header | Example | Description |
|--------|---------|-------------|
| `X-UA-Bot-Name` | `Googlebot` | Bot name when detected |
| `X-UA-Bot-URL` | `https://www.google.com/bot.html` | Bot homepage URL when available |

### Configuration

```yaml
analysisControllers:
  - name: user-agent
    type: ua-detect
```

