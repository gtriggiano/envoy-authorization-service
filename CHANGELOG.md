# Changelog


## [v1.4.1](https://github.com/gtriggiano/envoy-authorization-service/compare/v1.4.0...v1.4.1) - 2026-02-24

### Chores
- bump github.com/envoyproxy/go-control-plane/envoy ([#37](https://github.com/gtriggiano/envoy-authorization-service/issues/37))
- bump github.com/redis/go-redis/v9 from 9.17.3 to 9.18.0 ([#36](https://github.com/gtriggiano/envoy-authorization-service/issues/36))
- bump google.golang.org/grpc from 1.78.0 to 1.79.1 ([#32](https://github.com/gtriggiano/envoy-authorization-service/issues/32))
- bump github.com/redis/go-redis/v9 from 9.17.2 to 9.17.3 ([#30](https://github.com/gtriggiano/envoy-authorization-service/issues/30))
- bump [@types](https://github.com/types)/node from 25.2.2 to 25.3.0 in /docs ([#38](https://github.com/gtriggiano/envoy-authorization-service/issues/38))
- bump mermaid from 11.12.2 to 11.12.3 in /docs ([#35](https://github.com/gtriggiano/envoy-authorization-service/issues/35))
- bump vue from 3.5.27 to 3.5.28 in /docs ([#33](https://github.com/gtriggiano/envoy-authorization-service/issues/33))
- bump [@types](https://github.com/types)/node from 25.2.1 to 25.2.2 in /docs ([#31](https://github.com/gtriggiano/envoy-authorization-service/issues/31))


### Refactoring
- normalize `authority` value to lowercase



## [v1.4.0](https://github.com/gtriggiano/envoy-authorization-service/compare/v1.3.1...v1.4.0) - 2026-02-10

### Chores
- bump actions/github-script from 7 to 8 ([#9](https://github.com/gtriggiano/envoy-authorization-service/issues/9))
- remove redundant build constraint comments from e2e test files
- update copyright year to 2026 in LICENSE and site footer
- bump google.golang.org/grpc from 1.77.0 to 1.78.0 ([#18](https://github.com/gtriggiano/envoy-authorization-service/issues/18))
- bump [@types](https://github.com/types)/node from 24.10.1 to 25.2.0 in /docs ([#23](https://github.com/gtriggiano/envoy-authorization-service/issues/23))
- bump actions/upload-artifact from 4 to 5 ([#10](https://github.com/gtriggiano/envoy-authorization-service/issues/10))
- bump github.com/spf13/cobra from 1.10.1 to 1.10.2 ([#7](https://github.com/gtriggiano/envoy-authorization-service/issues/7))
- bump vue from 3.5.25 to 3.5.27 in /docs ([#20](https://github.com/gtriggiano/envoy-authorization-service/issues/20))
- bump github.com/oschwald/geoip2-golang/v2 ([#17](https://github.com/gtriggiano/envoy-authorization-service/issues/17))
- bump golang.org/x/sync from 0.18.0 to 0.19.0 ([#12](https://github.com/gtriggiano/envoy-authorization-service/issues/12))
- bump github.com/jackc/pgx/v5 from 5.7.6 to 5.8.0 ([#16](https://github.com/gtriggiano/envoy-authorization-service/issues/16))
- bump mermaid from 11.12.1 to 11.12.2 in /docs ([#8](https://github.com/gtriggiano/envoy-authorization-service/issues/8))
- v1.4.0


### Features
- add country_name label to authorization metrics ([#24](https://github.com/gtriggiano/envoy-authorization-service/issues/24))



## [v1.3.1](https://github.com/gtriggiano/envoy-authorization-service/compare/v1.3.0...v1.3.1) - 2025-12-03

### Chores
- v1.3.1


### Documentation
- reorganize navigation and update examples section for clarity



## [v1.3.0](https://github.com/gtriggiano/envoy-authorization-service/compare/v1.2.0...v1.3.0) - 2025-12-03

### Chores
- bump actions/upload-pages-artifact from 3 to 4 ([#4](https://github.com/gtriggiano/envoy-authorization-service/issues/4))
- bump actions/checkout from 4 to 6 ([#6](https://github.com/gtriggiano/envoy-authorization-service/issues/6))
- bump actions/setup-go from 5 to 6 ([#5](https://github.com/gtriggiano/envoy-authorization-service/issues/5))
- v1.3.0


### Documentation
- improve metrics documentation and provide better prometheus rules


### Features
- add options for country and geofence metrics tracking



## [v1.2.0](https://github.com/gtriggiano/envoy-authorization-service/compare/v1.1.3...v1.2.0) - 2025-12-03

### Chores
- standardize commit message prefix for dependency updates
- add dependabot configuration for automated dependency updates
- bump github.com/redis/go-redis/v9 ([#3](https://github.com/gtriggiano/envoy-authorization-service/issues/3))
- v1.2.0


### Documentation
- improve trial DEX and get started documentation
- add Geofence section to headers reference


### Features
- enhance client IP extraction taking into account Envoy behind a reverse proxy


### Refactoring
- remove unused strings import and deny reason check in TestManagerCheckDeniesViaPolicy
- standardize cache logging messages across analysis and match controllers
- rename ControllerKind to ControllerType and update related fields



## [v1.1.3](https://github.com/gtriggiano/envoy-authorization-service/compare/v1.1.2...v1.1.3) - 2025-12-01

### Chores
- v1.1.3


### Documentation
- update feature descriptions
- remove "verdict.IsMatch semantics" section from policy DSL documentation



## [v1.1.2](https://github.com/gtriggiano/envoy-authorization-service/compare/v1.1.1...v1.1.2) - 2025-12-01

### Chores
- v1.1.2


### Documentation
- update examples
- update controller names for consistency in analysis documentation
- enhance footer with licensing information and add custom layout
- enhance documentation for analysis and match controllers



## [v1.1.1](https://github.com/gtriggiano/envoy-authorization-service/compare/v1.1.0...v1.1.1) - 2025-12-01

### Chores
- fix typos in code and documentation ([#2](https://github.com/gtriggiano/envoy-authorization-service/issues/2))
- v1.1.1


### Documentation
- add comprehensive README for Envoy Authorization Service
- add documentation for `envoy_authz_geofence_match_totals` metric



## [v1.1.0](https://github.com/gtriggiano/envoy-authorization-service/compare/v1.0.1...v1.1.0) - 2025-12-01

### Chores
- v1.1.0


### Features
- add `geofence-match` controller ([#1](https://github.com/gtriggiano/envoy-authorization-service/issues/1))



## [v1.0.1](https://github.com/gtriggiano/envoy-authorization-service/compare/v1.0.0...v1.0.1) - 2025-12-01

### Chores
- add image source label to Dockerfile
- v1.0.1



## v1.0.0 - 2025-12-01

### Chores
- deps
- add initial changelog and version file
- first implementation
- v1.0.0


