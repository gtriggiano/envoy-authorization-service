# Getting Started

This guide will help you set up and run the Envoy Authorization Service in under 10 minutes.

## Prerequisites

- **Envoy Proxy** configured with the External Authorization filter
- **Go 1.25+** (if building from source)
- **MaxMind GeoIP databases** (optional, for GeoIP/ASN features)

## Installation

### Binary Installation

Download the pre-built binary for your platform:

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

### Docker

Pull the Docker image:

```bash
docker pull ghcr.io/gtriggiano/envoy-authorization-service:latest
```

### Build from Source

```bash
git clone https://github.com/gtriggiano/envoy-authorization-service.git
cd envoy-authorization-service
make build
```

## Basic Configuration

Create a `config.yaml` file:

```yaml
# Authorization controllers
authorizationControllers:
  - name: corporate-network
    type: ip-match
    settings:
      action: allow
      cidrList: corporate-network-cidrs.txt

# Policy expression
authorizationPolicy: "corporate-network"
```

Create an `corporate-network-cidrs.txt` file with your allowed IP ranges:

```txt
# Our corporate network
1.1.1.0/24
```

## Running the Service

### Using the Binary

```bash
envoy-authorization-service start --config config.yaml
```

### Using Docker

```bash
docker run -p 9001:9001 -p 9090:9090 \
  -v $(pwd)/config.yaml:/config.yaml \
  -v $(pwd)/corporate-network-cidrs.txt:/corporate-network-cidrs.txt \
  ghcr.io/gtriggiano/envoy-authorization-service:latest \
  start --config /config.yaml
```

### Using Docker Compose

```yaml
version: '3.8'

services:
  envoy_authz:
    image: ghcr.io/gtriggiano/envoy-authorization-service:latest
    ports:
      - "9001:9001"
      - "9090:9090"
    volumes:
      - ./config.yaml:/config.yaml
      - ./corporate-network-cidrs.txt:/corporate-network-cidrs.txt
    command: start --config /config.yaml
```

## Verify Installation

Check that the service is running:

```bash
# Health check
curl http://localhost:9090/healthz

# Readiness check
curl http://localhost:9090/readyz

# Metrics
curl http://localhost:9090/metrics
```

Expected response for health checks: `200 OK`

## Configure Envoy

Add the External Authorization filter to your Envoy configuration:

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      grpc_service:
        envoy_grpc:
          cluster_name: auth_service
        timeout: 1s
      transport_api_version: V3
      
clusters:
  - name: auth_service
    type: STRICT_DNS
    connect_timeout: 1s
    http2_protocol_options: {}
    load_assignment:
      cluster_name: auth_service
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: localhost
                    port_value: 9001
```

## Test Authorization

Send a test request through Envoy:

```bash
curl -v http://localhost:8080/test
```

The authorization service will:
1. Receive the request from Envoy
2. Check if the client IP is in `corporate-network-cidrs.txt`
3. Return OK or Denied to Envoy
4. Envoy forwards or rejects the request accordingly

## Next Steps

- [Learn about the architecture](/architecture)
- [Configure analysis controllers](/configuration/analysis-controllers)
- [Set up authorization controllers](/configuration/authorization-controllers)
- [Write policy expressions](/configuration/policy-dsl)
