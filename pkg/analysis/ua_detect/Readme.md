# User Agent Detection Analysis Controller `ua-detect`

## Overview

The User Agent Detection analysis controller extracts browser, operating system, and device
details from HTTP `User-Agent` headers and forwards them to upstream services as
structured headers and data.

Internally it uses `mileusna/useragent` as the fast primary parser, optionally falls
back to `ua-parser/uap-go` when the primary parser marks the UA as unknown, and caches
parsed results by UA string (cache enabled by default).

## Features

- Browser detection (name and version, including major/minor/patch components)
- Operating system detection (name and version)
- Device classification (desktop, mobile, tablet, bot)
- Bot detection with name and reference URL when available
- Zero external dependencies beyond the parser library

## Configuration

```yaml
analysisControllers:
  - name: ua-detect
    type: ua-detect
    enabled: true
    # settings:
    #   enableFallback: true  # optional: use regex-based ua-parser when primary parser reports unknown
    #   cacheEnabled: true    # optional: disable to skip UA result caching (defaults to true)
```

## Output

### Upstream Headers

| Header | Description | Example |
| --- | --- | --- |
| `X-UA-Browser` | Browser name | `Chrome` |
| `X-UA-Browser-Version` | Full browser version string | `118.0.0.0` |
| `X-UA-Browser-Major` | Browser major version | `118` |
| `X-UA-Browser-Minor` | Browser minor version | `0` |
| `X-UA-Browser-Patch` | Browser patch version (string to allow non-numeric) | `0` |
| `X-UA-OS-Name` | Operating system name | `Windows` |
| `X-UA-OS-Version` | Operating system version | `10.0` |
| `X-UA-OS-Major` | OS major version | `10` |
| `X-UA-OS-Minor` | OS minor version | `0` |
| `X-UA-OS-Platform` | OS platform identifier | `Windows` |
| `X-UA-Device-Type` | Normalized device type (`desktop`, `mobile`, `tablet`, `bot`, `tv`, `unknown`) | `desktop` |
| `X-UA-Device-Mobile` | `"true"` if detected as mobile | `false` |
| `X-UA-Device-Tablet` | `"true"` if detected as tablet | `false` |
| `X-UA-Device-Desktop` | `"true"` if detected as desktop | `true` |
| `X-UA-Device-TV` | `"true"` if detected as TV | `false` |
| `X-UA-Device-Model` | Device model when available | `iPhone` |
| `X-UA-Bot-Name` | Bot name when detected | `Googlebot` |
| `X-UA-Bot-URL` | Bot info URL when detected | `http://www.google.com/bot.html` |

## See Also

- [MaxMind ASN Analysis Controller](../maxmind_asn/)
- [MaxMind GeoIP Analysis Controller](../maxmind_geoip)
