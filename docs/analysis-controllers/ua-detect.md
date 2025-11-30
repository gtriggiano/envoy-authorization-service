# User-Agent Detection

The `ua-detect` analysis controller parses the HTTP `User-Agent` header to identify browser, OS, device type, and bots.

## Configuration

```yaml
analysisControllers:
  - name: user-agent
    type: ua-detect
```

## Upstream Headers Injected

**Browser information**
- `X-UA-Browser` — Browser name (e.g., `Chrome`)
- `X-UA-Browser-Version` — Full version string
- `X-UA-Browser-Major` — Major version
- `X-UA-Browser-Minor` — Minor version
- `X-UA-Browser-Patch` — Patch version

**Operating system**
- `X-UA-OS-Name` — OS name (e.g., `Windows`, `macOS`, `Linux`)
- `X-UA-OS-Version` — Full OS version
- `X-UA-OS-Major` — Major version
- `X-UA-OS-Minor` — Minor version
- `X-UA-OS-Platform` — Platform architecture

**Device information**
- `X-UA-Device-Type` — One of: `desktop`, `mobile`, `tablet`, `bot`, `tv`, `unknown`
- `X-UA-Device-Mobile` — Boolean (`true`/`false`)
- `X-UA-Device-Tablet` — Boolean
- `X-UA-Device-Desktop` — Boolean
- `X-UA-Device-TV` — Boolean
- `X-UA-Device-Model` — Device model (when available)

**Bot detection**
- `X-UA-Bot-Name` — Bot name (when detected)
- `X-UA-Bot-URL` — Bot URL/homepage

## Use Cases
- Block or rate-limit bots
- Device-specific access policies
- Browser compatibility checks
- Analytics and user insights
- Mobile vs desktop routing

## Requirements
- None (no external dependencies)
