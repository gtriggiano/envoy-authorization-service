# Authorization Policy DSL

The Authorization Policy DSL (Domain-Specific Language) is a boolean expression language that combines match controller verdicts to make final allow/deny decisions.

## Overview

Each match controller is conceivable as a boolean which tells if it matches or not the processing request.

The policy expression evaluates these booleans to decide whether to allow or deny the request.

::: warning
Not setting a policy or setting it as `""` means `no policy`, aka every request will be allowed.
:::

**Key Principles**:
- **Simple boolean logic**: Only `&&`, `||`, `!`, and parentheses
- **Controllers references**: Every identifier must reference a configured match controller
- **Deterministic evaluation**: Short-circuit evaluation with predictable behavior
- **Validated at startup**: Syntax and controller reference errors caught early

## Syntax

### Identifiers

Reference match controllers by name:
```yaml
authorizationPolicy: "corporate-network"
```

Names must match configured controllers exactly (case-sensitive).

### Logical AND (`&&`)

Both conditions must be true:
```yaml
authorizationPolicy: "ip-allowlist && trusted-asn"
```

**Short-circuit**: If the left side is false, the right side is not evaluated.

### Logical OR (`||`)

At least one condition must be true:
```yaml
authorizationPolicy: "corporate-network || partner-ips"
```

**Short-circuit**: If the left side is true, the right side is not evaluated.

### Logical NOT (`!`)

Inverts the boolean value:
```yaml
authorizationPolicy: "!blocked-ips"
```

### Grouping with Parentheses

Control evaluation order:
```yaml
authorizationPolicy: "(corporate-network || partner-ips) && !blocked-asns"
```

### Whitespace

Whitespace is ignored and can be used for readability:
```yaml
# These are equivalent
authorizationPolicy: "a&&b||c"
authorizationPolicy: "a && b || c"
authorizationPolicy: "a  &&  b  ||  c"
```

## Common Patterns

### Allowlist Only

Permit only specific IPs/ASNs:
```yaml
authorizationPolicy: "trusted-partners"

matchControllers:
  - name: trusted-partners
    type: ip-match
    settings:
      cidrList: trusted-partners-cidr.txt
```

### Denylist Only

Block specific IPs/ASNs:
```yaml
authorizationPolicy: "!rogue-subnets"

matchControllers:
  - name: rogue-subnets
    type: ip-match
    settings:
      cidrList: rogue-subnets-cidr.txt
```

### Allowlist with Exceptions

Allow specific IPs unless explicitly blocked:
```yaml
authorizationPolicy: "trusted-subnets && !blocked-ips"

matchControllers:
  - name: trusted-subnets
    type: ip-match
    settings:
      cidrList: trusted-subnets-cidrs.txt
  
  - name: blocked-ips
    type: ip-match
    settings:
      cidrList: blocked-ips-list.txt
```

### Multiple Allowlists

Allow from any of several sources:
```yaml
authorizationPolicy: "corporate-network || partner-ips || vpn-users"

matchControllers:
  - name: corporate-network
    type: ip-match
    settings:
      cidrList: corporate-network-cidrs.txt
  
  - name: partner-ips
    type: ip-match-database
    settings:
      database: # ...
  
  - name: vpn-users
    type: ip-match
    settings:
      cidrList: vpn-ips-cidrs.txt
```

### Layered Security

Combine multiple security controls:
```yaml
authorizationPolicy: "(allowed-ips || trusted-asns) && !blocked-ips"

matchControllers:
  - name: allowed-ips
    type: ip-match
    settings:
      cidrList: allowed-ips-cidrs.txt
  
  - name: trusted-asns
    type: asn-match
    settings:
      asnList: trusted-asns.txt
  
  - name: blocked-ips
    type: ip-match
    settings:
      cidrList: blocked-ips.txt
```

### Complex Policy

```yaml
authorizationPolicy: "(corporate-net || (partner-db && trusted-asn)) && !blocked-ips && !malicious-asns"
```

Allows if:
- In corporate network, OR
- In partner database AND from trusted ASN

AND NOT:
- In blocked IPs
- From malicious ASNs

## Evaluation Flow

Given policy: `"(allowlist || partners) && !blocklist"`

```mermaid
graph TD
    Start[Start Evaluation] --> AND["&& operator"]
    AND --> OR["|| operator"]
    AND --> NOT["! operator"]
    OR --> AL["allowlist controller"]
    OR --> PN["partners controller"]
    NOT --> BL["blocklist controller"]
    
    AL --> |IsMatch| OR_Result[Combine with ||]
    PN --> |IsMatch| OR_Result
    OR_Result --> AND_Left["Left side of &&"]
    
    BL --> |IsMatch| NOT_Result["Invert with !"]
    NOT_Result --> AND_Right["Right side of &&"]
    
    AND_Left --> Final["Combine with &&"]
    AND_Right --> Final
    Final --> Result{Allow or Deny?}
```

### Short-Circuit Evaluation

**AND (`&&`)**:
- If left side is `false`, right side is **not evaluated**
- Result is `false`

**OR (`||`)**:
- If left side is `true`, right side is **not evaluated**
- Result is `true`

**Example**:
```yaml
authorizationPolicy: "expensive-db-check || cached-allowlist"
```

If `expensive-db-check` returns `true`, `cached-allowlist` is never evaluated (performance optimization).

## Example Scenarios

### Scenario 1: Corporate or Partner Access

**Configuration**:
```yaml
matchControllers:
  - name: corporate
    type: ip-match
    settings:
      cidrList: corporate-ips.txt
  
  - name: partners
    type: ip-match-database
    settings:
      # database config...

authorizationPolicy: "corporate || partners"
```

**Evaluation**:

| IP | In Corporate? | In Partners DB? | `corporate` | `partners` | Policy | Result |
|----|--------------|----------------|-------------|-----------|--------|---------|
| 10.0.0.5 | Yes | No | `true` | `false` | `true \|\| false` | **ALLOW** |
| 203.0.113.5 | No | Yes | `false` | `true` | `false \|\| true` | **ALLOW** |
| 198.51.100.5 | No | No | `false` | `false` | `false \|\| false` | **DENY** |

### Scenario 2: Allowlist with Denylist Override

**Configuration**:
```yaml
matchControllers:
  - name: allowlist
    type: ip-match
    settings:
      cidrList: allowed-ips.txt
  
  - name: blocklist
    type: ip-match
    settings:
      cidrList: blocked-ips.txt

authorizationPolicy: "allowlist && !blocklist"
```

**Evaluation**:

| IP | In Allowlist? | In Blocklist? | `allowlist` | `blocklist` | `!blocklist` | Policy | Result |
|----|--------------|---------------|-------------|------------|-------------|--------|---------|
| 10.0.0.5 | Yes | No | `true` | `false` | `true` | `true && true` | **ALLOW** |
| 10.0.0.6 | Yes | Yes | `true` | `true` | `false` | `true && false` | **DENY** |
| 8.8.8.8 | No | No | `false` | `false` | `true` | `false && true` | **DENY** |

## Validation

### Startup Validation

The policy is validated when the service starts:

✅ **Valid**:
```yaml
authorizationPolicy: "corporate && (partners || vpn)"
```

❌ **Invalid** (syntax error):
```yaml
authorizationPolicy: "corporate && partners ||"  # Missing operand
authorizationPolicy: "corporate partners"         # Missing operator
authorizationPolicy: "corporate &&& partners"     # Invalid operator
```

❌ **Invalid** (unknown or disabled controller):
```yaml
authorizationPolicy: "corporate && undefined-controller"
```
Error: `authorization policy references an unknown controller: undefined-controller`

Only match controllers that are configured **and** enabled (`enabled` not set to `false`) can be referenced.

### Empty Policy

An empty or missing policy allows all requests:
```yaml
authorizationPolicy: ""  # or omit the field
```

The service logs `authorizationPolicy is empty: every request is allowed` at `warn` level on startup and sets the `envoy_authz_policy_configured` gauge to `0`. A non-empty policy requires at least one enabled match controller.

## Debugging Policies

### Logging

Every denied request produces a `warn` line (`msg=DENY`) with the request fields (authority, client IP and the source it was resolved from, GeoIP/ASN/UA fields when those analysis controllers are configured):
```
level=warn msg=DENY component=service-manager authority=api.example.com ip=1.1.1.1 ip_source=envoySource country_iso=- country_name=- continent=-
```

The controller that caused the denial is logged at **`debug`** level, one line per request (`msg="POLICY DENY"`), together with one `msg="match controller verdict"` line per match controller:
```
level=debug msg="POLICY DENY" component=service-manager authority=api.example.com ip=1.1.1.1 ip_source=envoySource country_iso=- country_name=- continent=- verdict=DENY culprit_controller_type=ip-match-database culprit_controller_name=partners culprit_description="IP 1.1.1.1 not found in 'POSTGRES'"
```

If `ip_source` is not what you expect (for example `envoySource` behind a load balancer, or `none`), the policy is evaluating the wrong address: see [Client IP Resolution](/guides/client-ip). So set `logging.level: debug` while debugging a policy. Allowed requests are logged at `debug` level (`msg=ALLOW`); with `authorizationPolicyBypass: true` requests that the policy would have denied are logged at `warn` level with `msg=BYPASS`. The culprit controller is always available in metrics through the `culprit_controller_*` labels regardless of log level.

### Bypass for Testing

Temporarily allow all requests while testing:
```yaml
authorizationPolicyBypass: true
```

The service logs `authorizationPolicyBypass is enabled` at `warn` level on startup and sets the `envoy_authz_policy_bypass_enabled` gauge to `1`.

::: warning
Be careful in production, using `authorizationPolicyBypass: true` will allow every request
:::



### Metrics

The policy outcome is the `policy_verdict` label of the request counter (`verdict` is what Envoy actually received, which differs only when bypass is enabled):
```prometheus
envoy_authz_requests_total{authority="api.example.com",verdict="ALLOW",policy_verdict="ALLOW",...} 15234
envoy_authz_requests_total{authority="api.example.com",verdict="DENY",policy_verdict="DENY",culprit_controller_name="partners",...} 47
```

See the [Metrics Reference](/reference/metrics) for the full label set.

## Best Practices

### 1. Keep Policies Simple

Prefer simple, readable policies:
```yaml
# Good
authorizationPolicy: "corporate || partners"

# Avoid (too complex)
authorizationPolicy: "((a || b) && (c || d)) || ((e && f) || (g && !h && i))"
```

### 2. Use Descriptive Controller Names

```yaml
# Good - policy is self-documenting
authorizationPolicy: "corporate-network || trusted-partners"

# Avoid - unclear intent
authorizationPolicy: "ctrl1 || ctrl2"
```

### 3. Document Complex Policies

Add comments in configuration:
```yaml
# Allow corporate or partners, but always block known threats
authorizationPolicy: "(corporate-network || partner-ips) && !threat-ips && !malicious-asns"
```

### 4. Test Policies Thoroughly

Use `authorizationPolicyBypass` in test environments to verify controller behavior before enabling policies.

## Next Steps

- [Configure Analysis Controllers](/analysis-controllers/)
- [Configure Match Controllers](/match-controllers/)
- [Configure Server & Metrics](/configuration)
- [View Configuration Examples](/examples/)
