# Bot-Resistant Signup & Trial Forms

Protect public signup forms from automated abuse (credential stuffing, fake trials, spam) while still collecting device/network analytics for growth teams.

## Scenario
- Public endpoints attract headless browsers and data-center bots.
- Real customers may come from home networks or mobile devices.
- Security wants an instant kill-switch for abusive IPs pushed from detection systems.
- Product analytics needs UA and GeoIP context for funnel dashboards.

## Controllers Used
- `ua-detect` — parse browser/device to spot headless patterns; enrich analytics.
- `maxmind-asn` — identify hosting/cloud ASNs commonly used by bots.
- `maxmind-geoip` — provide geo headers for funnel breakdowns and anomaly detection.
- `asn-match` (`hosting-blocklist`) — deny traffic from cloud/hosting providers.
- `ip-match-database` (`abuse-feed`) — Redis-fed dynamic blocklist from fraud pipelines.
- `ip-match` (`vip-allowlist`) — static list for trusted QA/partners to bypass blocks.

## Policy
Allow if the request is **not** from hosting ASNs and **not** in the abuse feed, or is explicitly allowlisted:

```yaml
authorizationPolicy: "(vip-allowlist || (!hosting-blocklist && !abuse-feed))"
```

## Example Configuration
```yaml
analysisControllers:
  - name: user-agent
    type: ua-detect

  - name: asn
    type: maxmind-asn
    settings:
      databasePath: config/GeoLite2-ASN.mmdb

  - name: geoip
    type: maxmind-geoip
    settings:
      databasePath: config/GeoLite2-City.mmdb

matchControllers:
  - name: hosting-blocklist
    type: asn-match
    settings:
      asnList: config/hosting-providers.txt

  - name: abuse-feed
    type: ip-match-database
    settings:
      matchesOnFailure: false
      cache:
        ttl: 5m
      database:
        type: redis
        redis:
          keyPrefix: "abuse:signup:"
          host: redis.fraud.svc.cluster.local
          port: 6379

  - name: vip-allowlist
    type: ip-match
    settings:
      cidrList: config/vip-allowlist.txt
```

## Request Flow
1. Analysis controllers enrich every request; downstream logging keeps UA/ASN/Geo for behavioral insights.
2. `hosting-blocklist` rejects data-center ranges (AWS/GCP/Azure/etc.).
3. `abuse-feed` reads Redis keys inserted by rate-limiters or ML models; cached for 5 minutes to reduce load.
4. `vip-allowlist` ensures QA teams and key partners can always test forms.

## Value Delivered
- Reduces fake account creation and promo abuse with minimal friction to real users.
- Aligns growth analytics (device/geo breakdowns) with security posture.
- Operates with instant block/unblock through Redis without redeploys.

## Metrics to Watch
- `envoy_authz_match_database_requests_total` for abuse-feed load.

