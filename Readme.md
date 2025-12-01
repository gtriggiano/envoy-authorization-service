# Envoy Authorization Service

A production-ready authorization service implementing the [Envoy External Authorization API](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) with a flexible, policy-driven framework and full observability.

---

## 📖 Documentation

**[Read the full documentation →](https://gtriggiano.github.io/envoy-authorization-service/)**

---

## ✨ Features

- **🚀 Production-Ready** — Graceful shutdown, health endpoints, structured logging, comprehensive Prometheus metrics
- **🔌 Extensible** — Plugin-based analysis and match controller system
- **📜 Policy DSL** — Express complex authorization logic with validated boolean expressions
- **🌍 GeoIP & ASN** — Built-in MaxMind integration for IP geolocation and ASN lookups
- **📍 Geofencing** — Geographic access control with GeoJSON polygon matching
- **🗄️ External Data Sources** — Redis and PostgreSQL support for dynamic IP/ASN allow/deny lists
- **🏷️ Header Injection** — Enrich requests with analysis metadata
- **📊 Full Observability** — Detailed metrics, structured logs, health checks
- **⚡ High Performance** — Concurrent controller execution, intelligent caching

## 🎯 Quick Example

Compose authorization policies like:

```yaml
# Allow corporate network OR partners, but block known threats
authorizationPolicy: "(corporate-network || partner-ips) && !blocked-ips"
```

```yaml
# Allow only trusted ASNs from allowed regions
authorizationPolicy: "trusted-cloud-providers && europe-region"
```

## 🚀 Quick Start

**Using Docker:**

```bash
docker run -p 9001:9001 -p 9090:9090 \
  -v $(pwd)/config.yaml:/config.yaml \
  ghcr.io/gtriggiano/envoy-authorization-service:latest \
  start --config /config.yaml
```

**Using pre-built binaries:**

Download from [releases](https://github.com/gtriggiano/envoy-authorization-service/releases):

```bash
# Example for Linux AMD64
curl -LO https://github.com/gtriggiano/envoy-authorization-service/releases/latest/download/envoy-authorization-service-linux-amd64
chmod +x envoy-authorization-service-linux-amd64
./envoy-authorization-service-linux-amd64 start --config config.yaml
```

## 📝 Minimal Configuration

```yaml
# Simple IP allowlist example
matchControllers:
  - name: corporate-network
    type: ip-match
    settings:
      cidrList: corporate-ips.txt

authorizationPolicy: "corporate-network"
```

**[See more examples →](https://gtriggiano.github.io/envoy-authorization-service/examples/)**

## 🏗️ How It Works

The service processes authorization requests through a three-phase pipeline:

1. **Analysis Phase** — Extract and enrich request metadata (GeoIP, ASN, User-Agent, etc.)
2. **Match Phase** — Run match controllers concurrently to evaluate the request
3. **Policy Evaluation** — Combine match verdicts using boolean logic to allow or deny

All controllers run concurrently for maximum performance. Analysis results are available to match controllers and can be injected as headers to upstream services.

**[Learn more about the architecture →](https://gtriggiano.github.io/envoy-authorization-service/architecture)**

## 🎛️ Available Controllers

### Analysis Controllers

- **`maxmind-asn`** — IP-to-ASN lookups
- **`maxmind-geoip`** — IP-to-location (city, country, coordinates)
- **`ua-detect`** — User-Agent parsing (browser, OS, device, bots)

### Match Controllers

- **`ip-match`** — Match against CIDR lists
- **`ip-match-database`** — Dynamic IP matching via Redis/PostgreSQL
- **`asn-match`** — Match against ASN lists
- **`asn-match-database`** — Dynamic ASN matching via Redis/PostgreSQL
- **`geofence-match`** — Geographic polygon matching with GeoJSON

**[View all controllers →](https://gtriggiano.github.io/envoy-authorization-service/match-controllers/)**

## 📊 Observability

**Metrics endpoint:** `http://localhost:9090/metrics`

- Request rates and latencies by authority, verdict, and culprit controller
- Controller execution times and error rates
- Database query performance and cache hit rates
- In-flight request counts

**Health checks:**
- `GET /healthz` — Liveness probe
- `GET /readyz` — Readiness probe

**[Metrics reference →](https://gtriggiano.github.io/envoy-authorization-service/reference/metrics)**

## 🔧 Advanced Features

- **TLS/mTLS** — Secure gRPC connections with optional client certificate authentication
- **Policy Bypass** — Test mode to log denials without blocking requests
- **Custom Headers** — Inject dynamic headers to upstream and downstream requests
- **Graceful Shutdown** — Configurable timeout for clean termination
- **Cache Control** — TTL-based caching for database-backed controllers

**[Full configuration reference →](https://gtriggiano.github.io/envoy-authorization-service/configuration)**

## 🛠️ CLI Utilities

Optimize CIDR and ASN lists:

```bash
# Remove redundant CIDR entries
envoy-authorization-service synthesize-cidr-list --file ips.txt --overwrite

# Deduplicate ASN entries
envoy-authorization-service synthesize-asn-list --file asns.txt --overwrite

# Validate GeoJSON files
envoy-authorization-service validate-geojson --file regions.geojson
```

**[CLI reference →](https://gtriggiano.github.io/envoy-authorization-service/reference/cli)**

## 📚 Learn More

- **[Get Started](https://gtriggiano.github.io/envoy-authorization-service/get-started)** — Step-by-step setup guide
- **[Architecture](https://gtriggiano.github.io/envoy-authorization-service/architecture)** — Understand the request flow
- **[Policy DSL](https://gtriggiano.github.io/envoy-authorization-service/policy-dsl)** — Write authorization policies
- **[Examples](https://gtriggiano.github.io/envoy-authorization-service/examples/)** — Real-world configurations
- **[Deployment Guides](https://gtriggiano.github.io/envoy-authorization-service/guides/kubernetes)** — Docker, Kubernetes, observability

## 📦 Deployment

**Docker Compose:**

```yaml
services:
  auth-service:
    image: ghcr.io/gtriggiano/envoy-authorization-service:latest
    ports:
      - "9001:9001"  # gRPC
      - "9090:9090"  # Metrics
    volumes:
      - ./config.yaml:/config.yaml
    command: start --config /config.yaml
```

**[Kubernetes deployment guide →](https://gtriggiano.github.io/envoy-authorization-service/guides/kubernetes)**

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## 📄 License

[MIT](./LICENSE)
