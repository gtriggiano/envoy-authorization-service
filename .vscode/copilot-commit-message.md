# Commit Message Guidelines

## Conventional Commits Specification

All commit messages in this repository MUST follow the [Conventional Commits](https://www.conventionalcommits.org/) specification.

### Format

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types

- **feat**: A new feature (correlates with MINOR in semantic versioning)
- **fix**: A bug fix (correlates with PATCH in semantic versioning)
- **docs**: Documentation only changes
- **style**: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc)
- **refactor**: A code change that neither fixes a bug nor adds a feature
- **perf**: A code change that improves performance
- **test**: Adding missing tests or correcting existing tests
- **build**: Changes that affect the build system or external dependencies (example scopes: go.mod, Dockerfile, Makefile)
- **ci**: Changes to CI configuration files and scripts (example scopes: github-actions, kubernetes)
- **chore**: Other changes that don't modify src or test files
- **revert**: Reverts a previous commit

### Scope (Optional)

The scope should be the name of the package or component affected:
- `analysis`
- `asnlist`
- `auth`
- `authorization`
- `cidrlist`
- `config`
- `controller`
- `grpc`
- `logging`
- `metrics`
- `policy`
- `runtime`
- ...etc

### Description

- Use the imperative, present tense: "change" not "changed" nor "changes"
- Don't capitalize the first letter
- No period (.) at the end
- Keep it concise (50 characters or less)

### Body (Optional)

- Use the imperative, present tense
- Include motivation for the change and contrast with previous behavior
- Wrap at 72 characters

### Breaking Changes

**IMPORTANT**: When a commit introduces breaking changes, you MUST:

1. Add an exclamation mark (!) after the type/scope: `feat!:` or `feat(auth)!:`
2. Add a `BREAKING CHANGE:` footer in the commit body explaining:
   - What changed
   - Why it changed
   - Migration path for users

Breaking changes can be part of commits of any type.

#### Examples of Breaking Changes

```
feat(auth)!: change authorization header format

The authorization service now expects JWT tokens in Bearer format
instead of custom X-Auth-Token header.

BREAKING CHANGE: The X-Auth-Token header is no longer supported.
Update all clients to use "Authorization: Bearer <token>" header instead.
Migration: Replace X-Auth-Token headers with standard Authorization headers.
```

```
refactor(policy)!: redesign policy evaluation engine

Complete rewrite of the policy evaluation logic to improve performance
and maintainability.

BREAKING CHANGE: Policy configuration format has changed.
- Old format used 'rules' array, new format uses 'conditions' object
- IP matching syntax changed from CIDR notation to range notation
See migration guide in docs/migration-v2.md for detailed instructions.
```

### Examples

#### Feature without breaking change
```
feat(authorization): add ASN-based access control

Implement ASN (Autonomous System Number) matching for advanced
IP-based authorization policies using MaxMind GeoIP database.
```

#### Bug fix
```
fix(cidrlist): handle IPv6 addresses correctly

Fix parsing error when processing IPv6 CIDR ranges in whitelist.
```

#### Documentation
```
docs(readme): add deployment instructions for Kubernetes
```

#### Breaking change
```
feat(config)!: change configuration file format to YAML

Switch from JSON to YAML for better readability and support for comments.

BREAKING CHANGE: Configuration files must now use YAML format instead of JSON.
Rename config.json to config.yaml and convert the format.
See config/config.example.yaml for the new structure.
```

#### Multiple changes with breaking change
```
feat(grpc)!: upgrade to gRPC v1.50 and change service interface

Update gRPC dependencies and refactor service definition for better
streaming support and error handling.

BREAKING CHANGE: The AuthorizationService RPC interface has changed.
- CheckAuthorization now returns a stream instead of unary response
- Error codes have been standardized to use Google's error model
Update all gRPC clients to handle streaming responses.
```

### Detection of Breaking Changes

When generating commit messages, analyze the changes for:

1. **API/Interface Changes**:
   - Modified function signatures (parameters, return types)
   - Removed or renamed public functions, methods, or types
   - Changed gRPC service definitions

2. **Configuration Changes**:
   - Modified configuration file structure or format
   - Removed or renamed configuration options
   - Changed default values that affect behavior

3. **Behavior Changes**:
   - Modified algorithm or logic that changes output
   - Changed error handling or error types
   - Modified data structures or formats

4. **Dependency Changes**:
   - Major version upgrades of dependencies
   - Changed minimum version requirements

5. **Deployment Changes**:
   - Modified Kubernetes manifests in incompatible ways
   - Changed environment variables or command-line flags
   - Modified Docker image structure or entrypoint

If ANY of these conditions are met, mark the commit as breaking and provide clear migration instructions.
