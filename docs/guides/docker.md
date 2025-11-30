# Docker Deployment

Deploy the Envoy Authorization Service using Docker and Docker Compose.

## Quick Start

### Pull Image

```bash
docker pull ghcr.io/gtriggiano/envoy-authorization-service:{{VERSION}}
```

### Run Container

```bash
docker run -d \
  --name auth-service \
  -p 9001:9001 \
  -p 9090:9090 \
  -v $(pwd)/config.yaml:/config.yaml \
  ghcr.io/gtriggiano/envoy-authorization-service:{{VERSION}} \
  start --config /config.yaml
```

## Docker Compose

Create `docker-compose.yaml`:

```yaml
services:
  authz-service:
    image: ghcr.io/gtriggiano/envoy-authorization-service:{{VERSION}}
    container_name: envoy-authz-service
    ports:
      - "9001:9001"  # gRPC
      - "9090:9090"  # Metrics
    volumes:
      - ./config.yaml:/config.yaml:ro
    command: start --config /config.yaml
    restart: unless-stopped
    networks:
      - envoy-net

networks:
  envoy-net:
    driver: bridge
```

Start services:
```bash
docker-compose up -d
```

## With Envoy

Complete setup with Envoy Proxy:

```yaml
services:
  authz-service:
    image: ghcr.io/gtriggiano/envoy-authorization-service:{{VERSION}}
    container_name: envoy-authz-service
    volumes:
      - ./config.yaml:/config.yaml:ro
    command: start --config /config.yaml
    ports:
      - "9001:9001"  # gRPC
      - "9090:9090"  # Metrics
    networks:
      - envoy-net

  envoy:
    image: envoyproxy/envoy:v1.28-latest
    ports:
      - "8080:8080"
    volumes:
      - ./envoy.yaml:/etc/envoy/envoy.yaml:ro
    command: -c /etc/envoy/envoy.yaml
    depends_on:
      - authz-service
    networks:
      - envoy-net

  upstream:
    image: nginx:alpine
    networks:
      - envoy-net

networks:
  envoy-net:
    driver: bridge
```

**envoy.yaml**:
```yaml
static_resources:
  listeners:
    - name: main
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 8080
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                http_filters:
                  - name: envoy.filters.http.ext_authz
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
                      grpc_service:
                        envoy_grpc:
                          cluster_name: authz_service
                        timeout: 1s
                      transport_api_version: V3
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route: { cluster: upstream }

  clusters:
    - name: authz_service
      connect_timeout: 1s
      type: STRICT_DNS
      http2_protocol_options: {}
      load_assignment:
        cluster_name: authz_service
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: authz_service
                      port_value: 9001
    
    - name: upstream
      connect_timeout: 1s
      type: STRICT_DNS
      load_assignment:
        cluster_name: upstream
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: upstream
                      port_value: 80
```

## With Redis

Add Redis for dynamic IP control:

```yaml
services:
  authz-service:
    image: ghcr.io/gtriggiano/envoy-authorization-service:{{VERSION}}
    volumes:
      - ./config.yaml:/config.yaml:ro
    command: start --config /config.yaml
    ports:
      - "9001:9001"  # gRPC
      - "9090:9090"  # Metrics
    depends_on:
      - redis
    networks:
      - envoy-net

  redis:
    image: redis:7-alpine
    command: redis-server
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    networks:
      - envoy-net

  envoy:
    image: envoyproxy/envoy:v1.28-latest
    ports:
      - "8080:8080"
    volumes:
      - ./envoy.yaml:/etc/envoy/envoy.yaml:ro
    depends_on:
      - authz-service
    networks:
      - envoy-net

volumes:
  redis-data:

networks:
  envoy-net:
```

## Next Steps

- [Configure Match Controllers](/match-controllers/)
- [Write Policy Expressions](/policy-dsl)
- [Kubernetes Deployment](/guides/kubernetes)
- [Configuration Guide](/configuration)
- [View Configuration Examples](/examples/)
