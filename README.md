# sonar-jwt-auth

Let CI jobs submit SonarQube scanner reports with a short-lived **OIDC JWT** (e.g. a Kubernetes ServiceAccount token)
instead of a stored SonarQube token. SonarQube Server has no built-in support for external-issuer tokens.

```
pod ──(projected SA token, aud=sonarqube)──▶ SonarQube ──▶ JwtServiceAuthentication
                                                 │            verify signature against the issuer's JWKS,
        issuer's /.well-known + JWKS  ◀──────────┘            check exp/aud, match a rule → act as a SonarQube user
```

Anything that is not a JWT of a configured issuer (normal user tokens, UI login, anonymous) is handled exactly as before.

## How it hooks in
SonarQube plugins cannot see server classes, and plugin filters never see `/api/*`. This project uses the same mechanism as
[sonarqube-community-branch-plugin](https://github.com/mc1arke/sonarqube-community-branch-plugin): the jar is a **javaagent**
(which puts it on the system classpath) carrying a `CoreExtension` that registers a `ServiceAuthentication` bean — the server's own
hook that `RequestAuthenticator` consults on every request. It is **not** installed in `extensions/plugins/`.

Because it relies on server internals, **rebuild and retest on every SonarQube upgrade** (built against 26.10.0 Community Build).
It runs fine alongside the branch plugin (tested: main + branch analyses).

## Configuration
Set `SONAR_JWT_AUTH_CONFIG` to a JSON file (default `/opt/sonarqube/conf/jwt-auth.json`). It is re-read when it changes (mount a ConfigMap).
Without the file the feature is off. See [`deploy/jwt-auth-config.json`](deploy/jwt-auth-config.json).

| Field (per source) | |
|---|---|
| `name` | unique label, shown in logs |
| `issuer` | expected `iss` |
| `discoveryUrl` | base URL serving `/.well-known/openid-configuration` (default: the issuer) |
| `audiences` | required; one must be in the token's `aud` |
| `rules[]` | first match wins (see below) |
| `allowedPathPrefixes` | default = what sonar-scanner needs (`/api/ce/submit`, `/api/v2/analysis/`, `/batch/`, …); `["*"]` = all |
| `allowInsecureHttp` | permit http discovery/JWKS (test clusters only) |

**Multiple sources** (e.g. Jenkins and Tekton clusters) are independent entries. Kubernetes clusters share the default issuer
`https://kubernetes.default.svc.cluster.local`, so entries with the same `issuer` are told apart by which cluster's keys verify the signature.
Giving each cluster a distinct `--service-account-issuer` is still recommended.

### Rules
| Field | |
|---|---|
| `subject` | regex that must match the whole `sub` (e.g. `system:serviceaccount:(?<ns>[a-z0-9-]+):(?<sa>[a-z0-9-]+)`) |
| `login` | template: `${ns}`-style regex named groups plus `${source}` (the source's name, keeps identical subjects of different clusters apart) |
| `projectKeyPattern` | optional regex; every project key in a request must match entirely |
| `autoProvision` | create the user on first use as an external user (provider `jwt-auth`); without it the user named by `login` must already exist |
| `name` | display-name template for provisioned users |
| `groups` | groups provisioned users are kept in (re-synced every 5 min). Must already exist; `sonar-administrators` is refused |

Provisioned users: SonarQube generates the internal login itself (from the display name plus a numeric suffix, e.g. `tekton-default-scanner74333`) and keeps `login` as the external identity, which is what this plugin looks users up by.
A user an administrator deactivates stays deactivated. An existing user of another origin (e.g. a local account) with the same login is used as-is and never modified.

Permissions: the mapped user's groups decide what is allowed. Create a service user in a group that only has *Create Projects* and *Execute Analysis*.

Security properties: only RS256/ES256; `kid`, `exp` and `aud` are mandatory; the discovery document's `issuer` must equal the configured one;
https is required unless `allowInsecureHttp`; invalid config keeps the previous config; a rejected JWT never falls back to anything weaker.

## Publishing a cluster's keys
A cluster's API server serves discovery/JWKS only to authenticated clients. [`oidc-helper`](https://github.com/obegron/secret-sync)
(proxy mode) republishes them; see `deploy/oidc-helper.yaml`.

## Build & try it (k3d)
```bash
scripts/fetch-server-jar.sh                     # compile-time only server jar
mvn package                                     # runs the unit tests
# put the branch plugin jar (optional) and the built jar into docker/, then:
cp target/sonar-jwt-auth-*.jar docker/sonar-jwt-auth.jar
docker build -t sonar-oidc-test:dev docker
k3d cluster create sonar-oidc -p "9000:30900@server:0"
# import images, apply deploy/*.yaml, run scripts/bootstrap-sonar.sh, then deploy/scanner-job.yaml
```
The JVM options that load it (see `deploy/sonarqube.yaml`):
`SONAR_WEB_JAVAADDITIONALOPTS=-javaagent:/opt/sonarqube/extensions/sonar-jwt-auth.jar=web`.

`scripts/bootstrap-sonar.sh` and `deploy/` contain throwaway credentials for a local test cluster only.

## Multi-tenant test
`deploy/oidc-helper-b.yaml` + a second k3d cluster (`k3d cluster create sonar-oidc-b -p "19092:30902@server:0"`) stand in for a second CI cluster.
Both clusters have the same issuer and a `default/scanner` ServiceAccount; they end up as separate users (`tekton-…`, `jenkins-…`) in separate groups,
each limited to its own project-key prefix.

## Not done yet
- Metrics/audit beyond log lines.
