# Get Started

The fastest way to try the authorization service is using the provided `docker-compose.yaml` and `config/envoy.yaml` files from the repository.

## Steps

### 1. Clone the Repository

```bash
git clone https://github.com/gtriggiano/envoy-authorization-service.git
cd envoy-authorization-service
```

### 2. Create a Configuration File

You can [start from an example](/examples/) or use the following, anyway put your [configuration file](/configuration) in `config/test.yaml`

```yaml
logging:
  level: debug

authorizationPolicy: "eu-or-us-east"

analysisControllers:
  - name: asn
    type: maxmind-asn
    settings:
      databasePath: config/GeoLite2-ASN.mmdb

  - name: geoip
    type: maxmind-geoip
    settings:
      databasePath: config/GeoLite2-City.mmdb

  - name: user-agent
    type: ua-detect

matchControllers:
  - name: eu-or-us-east
    type: geofence-match
    settings:
      featuresFile: config/Europe+US_East.geojson
```

::: warning For the config above you'll need MaxMind databases
```bash
make fetch-maxmind
# or directly:
./scripts/fetch-maxmind.sh

# then GeoLite2-ASN.mmdb and GeoLite2-City.mmdb will be in ./config
```

Relative paths in a configuration file are resolved from the directory that contains the file, so `databasePath: GeoLite2-ASN.mmdb` in `config/config.ip-match.yaml` finds `config/GeoLite2-ASN.mmdb` whatever the working directory is. Run `envoy-authorization-service validate --config config/config.ip-match.yaml` to check a file without starting the server.
:::

::: tip Redis and PostgreSQL Available
The `docker-compose.yaml` includes Redis and PostgreSQL services for testing database-backed controllers like `ip-match-database` and `asn-match-database`:

```bash
# Start all services including databases
docker compose up -d postgres redis
```

**The services have default ports mapped on host**, so you can reference them in controllers just setting `host: localhost`.

:::

### 3. Start the Authorization Service

```bash
go run main.go start --config config/test.yaml
```

### 4. Start Envoy and Upstream Services

```bash
docker compose up -d envoy upstream
```

This starts:
- **Envoy** on `localhost:8080` — configured with the ext_authz filter pointing to the authorization service at `host.docker.internal:9001`
- **Upstream** behind envoy or directly on `localhost:8082` — a simple echo server for testing

### 5. Test the Setup

```bash
curl -v http://localhost:8080
```

## Testing with Custom Source IPs

By default the service evaluates the address of the peer connected to Envoy (`AttributeContext.source.address`) and ignores every request header, so a client cannot pick the IP it is evaluated as. For local testing that is inconvenient: every request would come from the Docker bridge address.

The development setup therefore lets **Envoy** compute the client address and hands it to the service through a header only Envoy can write:

- `config/envoy.yaml` sets `use_remote_address: true` and `xff_num_trusted_hops: 1`, so Envoy trusts one `X-Forwarded-For` entry and writes the result to `x-envoy-external-address`, overwriting any value a client sent.
- The sample service configurations read that header first and fall back to the peer address:

```yaml
clientIp:
  sources:
    - header: x-envoy-external-address
    - envoySource
```

Use `X-Forwarded-For` to test how your policies behave with different client IPs:

```bash
curl -H "X-Forwarded-For: 1.1.1.100" http://localhost:8080

curl -H "X-Forwarded-For: 8.8.8.8" http://localhost:8080
```

Other headers (`X-Real-IP`, `X-Client-IP`, a client-supplied `X-Envoy-External-Address`, …) have no effect. You can do the same thing with the `host` (for `authority`) and `user-agent` headers.

::: warning Mind what you do in Production
`xff_num_trusted_hops: 1` is right only when exactly one trusted proxy sits in front of Envoy. If Envoy is the edge, remove the `clientIp` section (or keep `envoySource` alone) and set `xff_num_trusted_hops: 0`. The [Client IP Resolution](/guides/client-ip) guide covers the common topologies and the Envoy settings that go with each.
:::

## Next Steps

- [Learn about the architecture](/architecture)
- [Decide how the client IP is resolved](/guides/client-ip)
- [Configure analysis controllers](/analysis-controllers/)
- [Set up match controllers](/match-controllers/)
- [Write policy expressions](/policy-dsl)
