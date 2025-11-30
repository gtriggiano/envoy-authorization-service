# Architecture

The Envoy Authorization Service provides a flexible, extensible framework for implementing access control policies through a three-phase pipeline.

## Request Processing Flow

```mermaid
sequenceDiagram
    participant Client
    participant Envoy as Envoy Proxy
    participant AuthService as Authorization Service
    participant Analysis as Analysis Controllers
    participant AuthZ as Authorization Controllers
    participant Policy as Policy Engine
    participant Upstream as Upstream Service

    Client->>Envoy: HTTP Request
    Envoy->>AuthService: Check(request)
    
    Note over AuthService,Policy: Phase 1: Analysis (Concurrent)
    AuthService->>Analysis: Run configured analysis controllers
    par Analysis Controller 1
        Analysis->>Analysis: Process request
    and Analysis Controller 2
        Analysis->>Analysis: Process request
    and Analysis Controller N
        Analysis->>Analysis: Process request
    end
    Analysis-->>AuthService: Reports + Headers
    
    Note over AuthService,Policy: Phase 2: Authorization (Concurrent)
    AuthService->>AuthZ: Run configured match controllers
    par Authorization Controller 1
        AuthZ->>AuthZ: Evaluate request + analysis reports
    and Authorization Controller 2
        AuthZ->>AuthZ: Evaluate request + analysis reports
    and Authorization Controller N
        AuthZ->>AuthZ: Evaluate request + analysis reports
    end
    AuthZ-->>AuthService: Verdicts (OK/Deny)
    
    Note over AuthService,Policy: Phase 3: Policy Evaluation
    AuthService->>Policy: Evaluate authorization policy
    Policy->>Policy: Combine verdicts using DSL
    Policy-->>AuthService: Final decision (Allow/Deny)
    
    alt Request Allowed
        AuthService-->>Envoy: OK + Upstream/Downstream Headers
        Envoy->>Upstream: Forward request + Headers
        Upstream-->>Envoy: Response
        Envoy-->>Client: Response
    else Request Denied
        AuthService-->>Envoy: Denied Status + Downstream Headers
        Envoy-->>Client: Error Response (401/403/etc.) + Headers
    end
```

## Analysis Phase

Extract and enrich request metadata without blocking the request.

**Characteristics**:
- All analysis **controllers run concurrently**
- Controllers produce **reports** and, optionally, **headers** to inject into the upstream request in case of request being allowed
- Cannot directly deny requests
- The analysis reports will be available to match controllers

**Example Analysis Controllers**:
- `maxmind-asn`: Lookup ASN from IP address
- `maxmind-geoip`: Lookup geographic location from IP
- `ua-detect`: Parse User-Agent header

**Output**:
- Analysis reports for match controllers to consume
- HTTP headers to inject into upstream requests

## Match Phase

Identify matches based on analysis reports, request data, configuration and possibly I/O with external datasources.

**Characteristics**:
- All match **controllers run concurrently** and they are **provided with the reports** generated in the analysis phase
- Controllers return **match verdicts**
- Can inject headers for both allowed and denied requests

**Example Match Controllers**:
- `ip-match`: Checks request IP address against configured CIDRs
- `asn-match`: Checks request ASN against configured list
- `ip-match-database`: Looks up IP address in external data sources
- `asn-match-database`: Looks up the client ASN in external data sources

## Authorization Phase

Combine match controllers verdicts using boolean logic to reach the final authorization decision.

In Authorization Policy match controllers are referenced by name.

**Example Policies**:
```yaml
# Allow if is corporate network OR not in blocklist
authorizationPolicy: "corporate-network || !blocklist"

# Allow only if in allowlist AND from trusted ASN
authorizationPolicy: "ip-allowlist && trusted-asn"

# Allow only if in (allowlist OR partner) AND NOT in blocklist
authorizationPolicy: "(ip-allowlist || partner-ips) && !ip-blocklist"
```

## Header Injection

Controllers can inject both [upstream and downstream headers](/reference/headers).

### Upstream Headers
Added to requests forwarded to upstream services:
```go
X-ASN-Number: 15169
X-GeoIP-Country: US
X-UA-Device-Type: mobile
```

### Downstream Headers
Added to responses sent back to clients:
```go
X-Blocked-Reason: IP in denylist
```

**Use Cases**:
- Pass metadata to upstream services
- Provide feedback to clients

## Error Handling

### Analysis Controllers Errors
- Logged but don't block request
- Missing reports handled by match controllers
- Metrics updated for monitoring

### Match Controllers Errors
- Logged but don't block request
- A Match Controller is however required to return a match verdict

### Policy Errors
- Caught at startup (validation)
- Runtime errors deny request (fail-closed)
- Detailed error messages in logs
