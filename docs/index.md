---
layout: home

hero:
  name: Envoy Authorization Service
  text: Policy-driven authorization for Envoy Proxy
  tagline: Flexible, extensible access control with full observability built-in
  image:
    src: /hero-image.svg
    alt: Envoy Authorization Service
  actions:
    - theme: brand
      text: Get Started
      link: /getting-started
    - theme: alt
      text: View on GitHub
      link: https://github.com/gtriggiano/envoy-authorization-service

features:
  - icon: 🚀
    title: Production-Ready
    details: Graceful shutdown, health endpoints, structured logging, and comprehensive Prometheus metrics out of the box.
  
  - icon: 🔌
    title: Extensible Architecture
    details: Plugin-based system for analysis and authorization controllers. Compose authorization logic with ease.
  
  - icon: 📜
    title: Policy DSL
    details: Express authorization requirements using validated boolean expressions that combine controller verdicts.
  
  - icon: 🏷️
    title: Header Injection
    details: Dynamically add headers to upstream and downstream requests based on analysis and authorization results.
  
  - icon: 📊
    title: Full Observability
    details: Comprehensive Prometheus metrics, structured logs, health checks, for complete visibility.
  
  - icon: ⚡
    title: High Performance
    details: Concurrent controller execution and intelligent caching for minimal latency.
  
  - icon: 🛠️
    title: Easy Configuration
    details: YAML-based configuration with validation, sensible defaults, and clear error messages.
  
  - icon: 🌍
    title: GeoIP & ASN Support
    details: Built-in MaxMind integration for IP geolocation and ASN lookups.
  
  - icon: 🗄️
    title: Database Integration
    details: Redis and PostgreSQL support for dynamic IP control based on behavioral analysis or threat intelligence.
---

## Quick Start

Install and run the authorization service:

::: code-group

```bash [Linux AMD64]
curl -LO https://github.com/gtriggiano/envoy-authorization-service/releases/latest/download/envoy-authorization-service-linux-amd64
chmod +x envoy-authorization-service-linux-amd64
mv envoy-authorization-service-linux-amd64 /usr/local/bin/envoy-authorization-service
```

```bash [Linux ARM64]
curl -LO https://github.com/gtriggiano/envoy-authorization-service/releases/latest/download/envoy-authorization-service-linux-arm64
chmod +x envoy-authorization-service-linux-arm64
mv envoy-authorization-service-linux-arm64 /usr/local/bin/envoy-authorization-service
```

```bash [macOS AMD64]
curl -LO https://github.com/gtriggiano/envoy-authorization-service/releases/latest/download/envoy-authorization-service-darwin-amd64
chmod +x envoy-authorization-service-darwin-amd64
mv envoy-authorization-service-darwin-amd64 /usr/local/bin/envoy-authorization-service
```

```bash [macOS ARM64]
curl -LO https://github.com/gtriggiano/envoy-authorization-service/releases/latest/download/envoy-authorization-service-darwin-arm64
chmod +x envoy-authorization-service-darwin-arm64
mv envoy-authorization-service-darwin-arm64 /usr/local/bin/envoy-authorization-service
```

:::

Then

```bash
envoy-authorization-service start --config config.yaml
```

Or use Docker:

```bash
docker pull ghcr.io/gtriggiano/envoy-authorization-service:latest
docker run -v $(pwd)/config.yaml:/config.yaml ghcr.io/gtriggiano/envoy-authorization-service:latest start --config /config.yaml
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

## How it works?

The Envoy Authorization Service implements the [Envoy gRPC External Authorization API](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) with a three-phase pipeline:

1. **Analysis Phase**: Extract and enrich request metadata (GeoIP, ASN, User Agent, etc...)
2. **Authorization Phase**: Execute multiple authorization controllers concurrently
3. **Policy Evaluation**: Combine verdicts using boolean expressions (eg. `(corporate-network || partner-ip) && !evil-network`)

This architecture enables composable authorization patterns while maintaining high performance and observability.
