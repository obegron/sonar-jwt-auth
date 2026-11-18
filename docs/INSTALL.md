# Installing sonar-jwt-auth

## 1. Check compatibility
The extension uses SonarQube internals, so it only supports specific Community Build versions ([matrix](OPERATIONS.md#compatibility)).
On an unsupported version it **switches itself off with an ERROR in the log** (SonarQube still starts and works normally).

## 2. Get the jar
Download `sonar-jwt-auth-<version>.jar` from the GitHub release, or build it: `scripts/build.sh` (needs docker, Java 21, Maven).
The release also publishes `ghcr.io/obegron/sonar-jwt-auth-init:<version>`, a tiny image that only carries the jar (for init containers).

## 3. Make the issuer's public keys reachable
SonarQube fetches `<discoveryUrl>/.well-known/openid-configuration` and the `jwks_uri` it names. Any OIDC issuer works.
A Kubernetes API server only serves these to authenticated clients, so republish them with
[`oidc-helper`](https://github.com/obegron/secret-sync) (`deploy/oidc-helper.yaml`), or enable anonymous discovery
(`system:service-account-issuer-discovery` for `system:unauthenticated`) if your network allows it.
Use `https`. Private CA: with the Helm chart set `caCerts.enabled`; otherwise add `-Djavax.net.ssl.trustStore=...` to the web JVM options.
(`allowInsecureHttp` exists for test clusters only.)

## 4. Write the config
`jwt-auth.json` (a ConfigMap in Kubernetes). One entry per issuer/cluster; clusters may share the same `issuer` string.

```json
{ "sources": [
  { "name": "tekton",
    "issuer": "https://kubernetes.default.svc.cluster.local",
    "discoveryUrl": "https://oidc.tekton.example.org",
    "audiences": ["sonarqube"],
    "rules": [ {
      "subject": "system:serviceaccount:(?<ns>[a-z0-9-]+):(?<sa>[a-z0-9-]+)",
      "login": "tekton_${ns}_${sa}",
      "name": "Tekton ${ns}/${sa}",
      "autoProvision": true,
      "groups": ["ci-scanners"],
      "projectKeyPattern": "tekton-.*" } ] },
  { "name": "jenkins", "issuer": "https://kubernetes.default.svc.cluster.local", "discoveryUrl": "https://oidc.jenkins.example.org",
    "audiences": ["sonarqube"],
    "rules": [ { "subject": "system:serviceaccount:jenkins:agent", "login": "jenkins_agent", "autoProvision": true, "groups": ["ci-scanners"], "projectKeyPattern": "jenkins-.*" } ] }
] }
```

| Source field | |
|---|---|
| `name` | unique label used in logs and `${source}` |
| `issuer` | expected `iss` |
| `discoveryUrl` | base URL of `/.well-known/openid-configuration` (default: the issuer) |
| `audiences` | **required**; one must be in the token's `aud` |
| `rules[]` | first match wins |
| `allowedPathPrefixes` | what a JWT session may call; default is exactly what `sonar-scanner` needs. Exact paths, or a prefix ending in `/`; `["*"]` = everything |
| `maxTokenLifetimeSeconds` | default 86400: tokens valid longer than this (exp − iat) are refused. 0 disables |
| `clockSkewSeconds` | default 60 |
| `allowInsecureHttp` | permit http discovery/JWKS (tests only) |

| Rule field | |
|---|---|
| `subject` | regex matching the whole `sub`; named groups are available as `${name}` |
| `login` | identity template; must start with literal text; `${source}` is the source name. Values captured from the token may not contain the literal separators between placeholders (so `a-b`+`c` can never equal `a`+`b-c`) — use `_` as separator for Kubernetes names |
| `autoProvision` | create the user on first use (external user, provider `jwt-auth`). Otherwise `login` must name an existing user. A user of another origin with the same login is **never** adopted |
| `name`, `groups` | display name / groups of provisioned users (groups must exist; `sonar-administrators` is refused) |
| `projectKeyPattern` | regex; every project the request touches must match, and requests that cannot be tied to a project are refused |

The file is re-read within ~10 s of a change (mount the ConfigMap as a **directory**, not `subPath`). An invalid file is logged and the previous config stays active.

## 5. Install the agent
The jar is a **javaagent**, not a plugin: do **not** put it in `extensions/plugins/`. Add to the web process JVM options:
`-javaagent:/path/to/sonar-jwt-auth.jar=web` and mount the config at `/opt/sonarqube/jwt-auth/jwt-auth.json` (or set `SONAR_JWT_AUTH_CONFIG`).

### a) Docker
```bash
cp sonar-jwt-auth-*.jar docker/sonar-jwt-auth.jar && docker build -t sonarqube-jwt docker
docker run -d -p 9000:9000 -v $PWD/jwt-auth:/opt/sonarqube/jwt-auth:ro sonarqube-jwt     # jwt-auth/jwt-auth.json
```
### b) Official Helm chart
`kubectl create configmap sonar-jwt-auth-config --from-file=jwt-auth.json` then
`helm upgrade --install sonarqube sonarqube/sonarqube -f deploy/helm/values-sonar-jwt-auth.yaml` — see the comments in that file.
### c) Together with sonarqube-community-branch-plugin
Both are javaagents: list both in the same option, e.g.
`-javaagent:.../sonarqube-community-branch-plugin-26.10.0.jar=web -javaagent:.../sonar-jwt-auth.jar=web` (see `docker/Dockerfile.branch-plugin`).

## 6. Give the identity the least privilege it needs
Provisioned users get **only** the permissions of the groups you list. Create a group once:
```bash
A='-u admin:<password>'; S=https://sonar.example.org
curl $A -X POST $S/api/user_groups/create -d name=ci-scanners
curl $A -X POST $S/api/permissions/add_group -d groupName=ci-scanners -d permission=provisioning   # Create Projects
curl $A -X POST $S/api/permissions/add_group -d groupName=ci-scanners -d permission=scan           # Execute Analysis
```
Never grant a provisioned group *Administer System*; the plugin cannot detect that for you.
Because `scan` is a global permission, `projectKeyPattern` is the per-team boundary — set it.

## 7. Use it from CI
The scanner just needs the JWT in `SONAR_TOKEN`. Kubernetes (Tekton, Argo, plain pods) — a projected token with the right audience:
```yaml
volumes:
  - name: sonar-token
    projected: {sources: [{serviceAccountToken: {audience: sonarqube, expirationSeconds: 600, path: token}}]}
# step:
#   export SONAR_TOKEN="$(cat /var/run/secrets/sonar/token)"
#   sonar-scanner -Dsonar.host.url=https://sonar.example.org -Dsonar.projectKey=tekton-myapp
```
Jenkins: use the OIDC token your Jenkins issues (e.g. the *OpenID Connect Provider* plugin's ID-token credential, audience `sonarqube`) as `SONAR_TOKEN`.
Branch analysis needs `sonar.branch.name` and the branch plugin, as before.

## 8. Verify
Boot log should show, in order:
```
jwt-auth: extension registered (SonarQube API ...)
jwt-auth: loaded 2 source(s) from /opt/sonarqube/jwt-auth/jwt-auth.json: [tekton(...), jenkins(...)]
jwt-auth source 'tekton': loaded 1 signing key(s)
```
Then run a scan. `scripts/integration/run.sh` runs the whole acceptance test against a throw-away SonarQube if you want proof first.
