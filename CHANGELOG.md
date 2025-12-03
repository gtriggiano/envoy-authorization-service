# Changelog


## [v1.3.1](https://github.com/gtriggiano/envoy-authorization-service/compare/v1.3.0...v1.3.1) - 2025-12-03

### Documentation
- reorganize navigation and update examples section for clarity



## [v1.3.0](https://github.com/gtriggiano/envoy-authorization-service/compare/v1.2.0...v1.3.0) - 2025-12-03

### Chores
- bump actions/upload-pages-artifact from 3 to 4 ([#4](https://github.com/gtriggiano/envoy-authorization-service/issues/4))
- bump actions/checkout from 4 to 6 ([#6](https://github.com/gtriggiano/envoy-authorization-service/issues/6))
- bump actions/setup-go from 5 to 6 ([#5](https://github.com/gtriggiano/envoy-authorization-service/issues/5))


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


