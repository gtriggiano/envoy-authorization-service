---
layout: home

hero:
  name: Envoy Authorization Service
  tagline: Policy-driven, flexible and extensible access control with full observability built-in
  image:
    src: /logo.drawio.svg
    alt: Envoy Authorization Service
  actions:
    - theme: brand
      text: Get Started
      link: /get-started
    - theme: alt
      text: View on GitHub
      link: https://github.com/gtriggiano/envoy-authorization-service

features:
  - icon: 🚀
    title: Production-Ready
    details: Graceful shutdown, health endpoints, structured logging and sensible defaults.

  - icon: ⚡
    title: High Performance Pipeline
    details: Concurrent controller execution with smart caching to keep latency low under load.

  - icon: 📜
    title: Authz Policy DSL
    details: Compose precise authorization rules with validated boolean expressions over controller verdicts.

  - icon: 📊
    title: Full Observability
    details: Prometheus metrics, structured logs, and health checks with per-controller timings and error tracking.

  - icon: 🏷️
    title: Header Injection
    details: Inject analysis results into upstream and downstream headers to propagate trust signals safely.

  - icon: 🧩
    title: Configurable Controllers
    details: Drop-in analysis and match controller plugins so you can ship custom analysis/match logic.

  - icon: 🌐
    title: IP & User-Agent Intelligence
    details: Built-in MaxMind GeoIP/ASN enrichment and UA detection to add context before matching.

  - icon: 🧭
    title: Geofencing
    details: Enforce geographic policies with GeoJSON polygon matching and region-aware rules.

  - icon: 🗄️
    title: External Data Sources
    details: Redis and PostgreSQL integrations for dynamic IP/ASN lists and threat-intel driven decisions.

  
---

## How it works?

The Envoy Authorization Service implements the [Envoy gRPC External Authorization API](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) with a three-phase pipeline:

1. **Analysis Phase**: Extract and enrich request metadata (GeoIP, ASN, User Agent, etc...)
2. **Match Phase**: Execute multiple match controllers concurrently
3. **Policy Evaluation**: Combine match verdicts using boolean expressions (eg. `(corporate-network || partner-ip) && !evil-network`)

This architecture enables composable authorization patterns while maintaining high performance and observability.


## Quick Start

**Docker:**

```bash
docker pull ghcr.io/gtriggiano/envoy-authorization-service:{{VERSION}}
docker run -v $(pwd)/config.yaml:/config.yaml ghcr.io/gtriggiano/envoy-authorization-service:{{VERSION}} start --config /config.yaml
```

**Binary:**

Download the build for your arch:

::: code-group

```bash [Linux AMD64]
curl -LO https://github.com/gtriggiano/envoy-authorization-service/releases/v{{VERSION}}/download/envoy-authorization-service-linux-amd64
chmod +x envoy-authorization-service-linux-amd64
mv envoy-authorization-service-linux-amd64 /usr/local/bin/envoy-authorization-service
```

```bash [Linux ARM64]
curl -LO https://github.com/gtriggiano/envoy-authorization-service/releases/v{{VERSION}}/download/envoy-authorization-service-linux-arm64
chmod +x envoy-authorization-service-linux-arm64
mv envoy-authorization-service-linux-arm64 /usr/local/bin/envoy-authorization-service
```

```bash [macOS AMD64]
curl -LO https://github.com/gtriggiano/envoy-authorization-service/releases/v{{VERSION}}/download/envoy-authorization-service-darwin-amd64
chmod +x envoy-authorization-service-darwin-amd64
mv envoy-authorization-service-darwin-amd64 /usr/local/bin/envoy-authorization-service
```

```bash [macOS ARM64]
curl -LO https://github.com/gtriggiano/envoy-authorization-service/releases/v{{VERSION}}/download/envoy-authorization-service-darwin-arm64
chmod +x envoy-authorization-service-darwin-arm64
mv envoy-authorization-service-darwin-arm64 /usr/local/bin/envoy-authorization-service
```

:::

Then

```bash
envoy-authorization-service start --config config.yaml
```



## Example Configuration

::: warning Note
You need [MaxMind databases](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) to run this example.
:::

```yaml
analysisControllers:
  - name: asn-analysis
    type: maxmind-asn
    settings:
      databasePath: GeoLite2-ASN.mmdb
  - name: geoip-analysis
    type: maxmind-geoip
    settings:
      databasePath: GeoLite2-ASN.mmdb
```
