# Getting Started

## Configuration

Create a `config.yaml` [configuration file](/configuration).

```yaml
# Match controllers
matchControllers:
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

### Docker

```bash
docker run -p 9001:9001 -p 9090:9090 \
  -v $(pwd)/config.yaml:/config.yaml \
  -v $(pwd)/corporate-network-cidrs.txt:/corporate-network-cidrs.txt \
  ghcr.io/gtriggiano/envoy-authorization-service:{{VERSION}} \
  start --config /config.yaml
```

### Docker Compose

```yaml
services:
  envoy_authz:
    image: ghcr.io/gtriggiano/envoy-authorization-service:{{VERSION}}
    ports:
      - "9001:9001"
      - "9090:9090"
    volumes:
      - ./config.yaml:/config.yaml
      - ./corporate-network-cidrs.txt:/corporate-network-cidrs.txt
    command: start --config /config.yaml
```

### Binary

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

```bash
envoy-authorization-service start --config config.yaml
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
- [Configure analysis controllers](/analysis-controllers/)
- [Set up match controllers](/match-controllers/)
- [Write policy expressions](/policy-dsl)
