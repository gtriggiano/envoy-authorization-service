# Client IP Resolution

Every IP-, ASN- and geo-based controller (`ip-match`, `ip-match-database`, `maxmind-asn`, `maxmind-geoip`, `asn-match`, `asn-match-database`, `geofence-match`) evaluates **one** address per request: the client IP the service resolved from the Envoy `CheckRequest`. If that address can be chosen by the client, every one of those controls can be bypassed. This page explains where the address comes from, how to configure it for your topology, and which Envoy settings must match.

## How the address is resolved

The `clientIp.sources` list is walked **in order**; the first source that yields a valid address wins. Only the sources you list are consulted.

```yaml
clientIp:
  sources:                              # Default: [envoySource]
    - header: x-envoy-external-address  # a single address written by a proxy you control
    - xff:                              # X-Forwarded-For, parsed right-to-left
        trustedHops: 1
    - envoySource                       # AttributeContext.source.address
  requireValid: false                   # Default: false. true => deny when no source yields an address
```

| Source | Reads | Use it when |
|--------|-------|-------------|
| `envoySource` | `AttributeContext.source.address`: the address of the TCP peer that opened the connection to Envoy, or the client address from the PROXY protocol header when Envoy's `proxy_protocol` listener filter is enabled | Envoy is the edge, or an L4 load balancer in front of it speaks PROXY protocol. **Never spoofable by request headers.** |
| `header: <name>` | The named request header, which must contain exactly one address | A proxy you control writes the header on every request and **overwrites** anything the client sent. The canonical case is `x-envoy-external-address`, see below. |
| `xff: {trustedHops: N}` | `X-Forwarded-For`, taking the entry `N` positions from the **right** end (`0` = right-most) | You need to read `X-Forwarded-For` yourself because Envoy is not configured to determine the client address. |

Address values are normalised before use: `ip:port`, `[ipv6]` and `[ipv6]:port` forms are accepted, IPv6 zones are dropped, IPv4-mapped IPv6 addresses (`::ffff:203.0.113.10`) are unmapped, and unspecified addresses (`0.0.0.0`, `::`) are rejected. Anything that does not parse (`unknown`, RFC 7239 `for=…` syntax, obfuscated identifiers, comma lists in a `header` source) makes that source fall through to the next one.

When no source yields an address the controllers run with an unset IP: IP list controllers report "no match", ASN/GeoIP analysis emits nothing. Set `requireValid: true` to deny such requests instead (HTTP 403, body `client IP address could not be resolved`); the denial is counted in the request metrics with `culprit_controller_name="client-ip"`, `culprit_controller_kind="client-ip"` and `culprit_controller_result="ERROR"`. `authorizationPolicyBypass: true` also bypasses this check (the request is logged with `msg=BYPASS` and processed normally).

Every request log line carries the resolved address and its origin:

```
level=debug msg="POLICY DENY" … ip=211.0.27.5 ip_source=header:x-envoy-external-address …
```

`ip_source` is one of `envoySource`, `header:<name>`, `xff`, or `none`. At startup the service logs the configured chain (`msg="client IP resolution configured" sources=[…]`).

## What Envoy sends

The relevant behaviour of Envoy's HTTP connection manager, checked against Envoy v1.36 with the `ext_authz` gRPC filter:

- **`AttributeContext.source.address` is always the direct TCP peer.** It does not change with `xff_num_trusted_hops`, `use_remote_address` or the contents of `X-Forwarded-For`. When a load balancer or another proxy terminates the client connection, `source.address` is that proxy's address.
- **The `proxy_protocol` listener filter rewrites the connection address.** When an L4 balancer sends a PROXY protocol header, `source.address` is the client address from that header, not the balancer's, and the same address is used for `X-Forwarded-For` and `x-envoy-external-address` handling.
- **`x-envoy-external-address` is written only when `use_remote_address: true`.** Envoy then sets it to the *trusted client address* it computed from `xff_num_trusted_hops` and overwrites any value the client sent. With `use_remote_address: false` (the default) Envoy neither sets nor sanitises the header, and a client-supplied value is forwarded untouched, so in that mode the header must not be trusted.
- **With `use_remote_address: true` Envoy appends the peer address to `X-Forwarded-For`** before the request reaches the authorization service; with `false` the header is forwarded as received.

| Envoy HTTP connection manager | Incoming `X-Forwarded-For` | `source.address` | `x-envoy-external-address` | `X-Forwarded-For` seen by the service |
|-------------------------------|----------------------------|------------------|----------------------------|--------------------------------------|
| `use_remote_address` unset/`false`, any `xff_num_trusted_hops` | anything | peer | not set (client value passes through!) | unchanged |
| `use_remote_address: true`, `xff_num_trusted_hops: 0` | anything | peer | peer | `…, peer` |
| `use_remote_address: true`, `xff_num_trusted_hops: 1` | `A` | peer | `A` | `A, peer` |
| `use_remote_address: true`, `xff_num_trusted_hops: 1` | `A, B` | peer | `B` | `A, B, peer` |
| `use_remote_address: true`, `xff_num_trusted_hops: 2` | `A` | peer | peer (too few entries) | `A, peer` |
| `use_remote_address: true`, `xff_num_trusted_hops: 2` | `A, B` | peer | `A` | `A, B, peer` |

Envoy's own rules are documented under [`use_remote_address`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto#envoy-v3-api-field-extensions-filters-network-http-connection-manager-v3-httpconnectionmanager-use-remote-address), [`xff_num_trusted_hops`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto#envoy-v3-api-field-extensions-filters-network-http-connection-manager-v3-httpconnectionmanager-xff-num-trusted-hops) and [X-Forwarded-For](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-for).

## Recipes by topology

### Envoy is the edge

Clients connect straight to Envoy (or through an L4 balancer that preserves the client address).

```yaml
# authorization service: nothing to configure, this is the default
clientIp:
  sources:
    - envoySource
```

Nothing in the request can influence the result. Leave `use_remote_address` and `xff_num_trusted_hops` at their defaults or set `use_remote_address: true` for correct access logs; the service does not depend on them.

### L4 load balancer with PROXY protocol

A TCP/TLS-passthrough balancer (cloud NLB, HAProxy in TCP mode, …) hides the client address behind its own, unless it prepends a [PROXY protocol](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt) header. Enable the header on the balancer and let Envoy consume it with the `proxy_protocol` listener filter:

```yaml
# envoy.yaml (listener)
listener_filters:
  - name: envoy.filters.listener.proxy_protocol
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.listener.proxy_protocol.v3.ProxyProtocol
```

```yaml
# authorization service: the default is correct
clientIp:
  sources:
    - envoySource
  requireValid: true            # optional: fail closed
```

Envoy replaces the connection's remote address with the one from the PROXY header before any HTTP processing, so `source.address` is the real client and request headers play no role. Keep `xff_num_trusted_hops: 0` because the balancer does not touch HTTP. Two things must hold: only the balancer may reach the listener (a connection without a PROXY header is rejected by the filter by default, but a direct client could send its own header and claim any address), and the balancer must be the one writing the header for every connection.

### Trusted proxies in front of Envoy (recommended)

Clients reach Envoy through a CDN, a cloud L7 load balancer or another proxy tier that appends to `X-Forwarded-For`. `source.address` is now the proxy, so let **Envoy** compute the client address and read it back from the header Envoy controls:

```yaml
# envoy.yaml (http_connection_manager)
use_remote_address: true
xff_num_trusted_hops: 1   # number of trusted proxies in front of Envoy
```

```yaml
# authorization service
clientIp:
  sources:
    - header: x-envoy-external-address
    - envoySource               # fallback for connections that bypass the proxy tier
  requireValid: true            # optional: fail closed
```

Because `use_remote_address` is `true`, Envoy overwrites `x-envoy-external-address` on every request; a client cannot inject it. Envoy also falls back to the peer address when `X-Forwarded-For` has fewer entries than `xff_num_trusted_hops`, so a client that sends no header cannot pick a different address either.

::: warning The proxy tier must be trusted end to end
`xff_num_trusted_hops: N` means "the right-most N `X-Forwarded-For` entries were written by proxies I trust". If clients can reach Envoy directly (for example the Envoy Service is exposed on a public IP next to the load balancer), a client can prepend fake entries and be treated as coming from any address. Restrict Envoy's ingress to the proxy tier, or keep `envoySource` first and accept that the proxy address is what gets evaluated.
:::

### Reading `X-Forwarded-For` directly

Use this when Envoy cannot be configured with `use_remote_address: true`, for example because a service mesh owns the Envoy configuration. The `xff` source parses the header **right to left** so client-prepended entries never matter:

```yaml
clientIp:
  sources:
    - xff:
        trustedHops: 1
    - envoySource
```

`trustedHops` is the number of right-most entries written by proxies you trust; the entry immediately to their left is the client. It is the same number you would give Envoy's `xff_num_trusted_hops` in the same deployment:

| Deployment | `X-Forwarded-For` seen by the service | `trustedHops` |
|------------|---------------------------------------|---------------|
| One proxy in front of Envoy, Envoy `use_remote_address: false` (Envoy does not append) | `client` | `0` |
| One proxy in front of Envoy, Envoy `use_remote_address: true` (Envoy appends the proxy) | `client, proxy` | `1` |
| CDN → load balancer → Envoy, `use_remote_address: false` | `client, cdn` | `1` |
| CDN → load balancer → Envoy, `use_remote_address: true` | `client, cdn, lb` | `2` |

If the header has fewer than `trustedHops + 1` entries the source yields nothing and the next source is tried; that is why `envoySource` belongs at the end of the list.

### A non-Envoy edge sets its own header

CDNs and WAFs often publish the client address in a dedicated header (`CF-Connecting-IP`, `True-Client-IP`, `Fastly-Client-IP`, …). You can read it with a `header` source, but **only** if that edge overwrites the header on every request and clients cannot bypass the edge:

```yaml
clientIp:
  sources:
    - header: cf-connecting-ip
    - envoySource
```

Header names are matched case-insensitively. A `header` source must contain exactly one address; `X-Forwarded-For` is rejected here on purpose, use `xff` for it.

### Envoy `original_ip_detection_extensions`

Envoy can also compute the trusted client address with an [original IP detection extension](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto#envoy-v3-api-field-extensions-filters-network-http-connection-manager-v3-httpconnectionmanager-original-ip-detection-extensions) (`custom_header`, `xff` with CIDR ranges, …). Per the Envoy documentation these extensions apply when `use_remote_address` is `false`, so Envoy does not write `x-envoy-external-address` in that setup. Read the header the extension trusts with a `header` source, and make sure the edge strips or overwrites client-supplied copies of it.

## Local development

The repository's `config/envoy.yaml` uses `use_remote_address: true` with `xff_num_trusted_hops: 1`, and the sample service configurations read `x-envoy-external-address` first. This is what lets you simulate client addresses on your machine:

```bash
curl -H "X-Forwarded-For: 211.0.27.5" http://localhost:8080   # evaluated as 211.0.27.5
curl -H "X-Envoy-External-Address: 211.0.27.5" http://localhost:8080   # ignored: Envoy overwrites the header
curl -H "X-Real-IP: 211.0.27.5" http://localhost:8080          # ignored: not a configured source
```

Trusting one `X-Forwarded-For` hop is only appropriate when the machine in front of Envoy is yours. Do not carry this Envoy setting into production unless a trusted proxy really sits in front of Envoy.

## Checking your setup

1. **Identify what sits between your clients and Envoy.** If nothing does, the default (`envoySource`) is correct and needs no configuration.
2. **If proxies sit in front of Envoy**, `source.address` is the proxy, so follow [Trusted proxies in front of Envoy](#trusted-proxies-in-front-of-envoy-recommended). Without it, allow-list policies deny everyone and deny-list policies block nobody.
3. **Watch `ip_source` in the logs**: it should read `header:x-envoy-external-address` (or `xff`) for client traffic, and `envoySource` only for connections that legitimately bypass the proxy tier.
4. **Enable `requireValid: true`** once the chain is stable, so a misconfigured proxy fails closed instead of evaluating an empty address.
