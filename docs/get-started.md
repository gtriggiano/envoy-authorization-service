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

**When referencing the databases in the configuration**, mind what will be `current working directory` when you'll launch the service and move from there.
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

The provided `config/envoy.yaml` is configured with `xff_num_trusted_hops: 1`, which makes Envoy trust the `X-Forwarded-For` header to determine the client IP. This allows you to simulate requests from different IP addresses for testing your authorization policies.

::: warning Mind what you do in Production
The `xff_num_trusted_hops: 1` setting is intended for development and testing. In production, set this value to match the actual number of trusted proxies in front of Envoy, or set it to `0` if Envoy is the edge proxy and should not trust `X-Forwarded-For` headers.
:::

Use the `X-Forwarded-For` header to test how your policies behave with different client IPs:

```bash
curl -H "X-Forwarded-For: 1.1.1.100" http://localhost:8080

curl -H "X-Forwarded-For: 8.8.8.8" http://localhost:8080
```

You can do the same thing with the `host` (for `authority`) and `user-agent` headers.

## Next Steps

- [Learn about the architecture](/architecture)
- [Configure analysis controllers](/analysis-controllers/)
- [Set up match controllers](/match-controllers/)
- [Write policy expressions](/policy-dsl)
