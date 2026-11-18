# Installing sonar-jwt-auth

## 1. Check compatibility
The extension uses SonarQube internals, so it only supports specific Community Build versions (**26.x, 26.10 primary**) ([matrix](OPERATIONS.md#compatibility)).
On a version where an internal API it uses is missing it **switches itself off with an ERROR in the log**. That check covers the classes and methods it calls, not every possible behaviour change, so always try an upgrade on a staging instance first (`scripts/integration/run.sh`).

## 2. Get the jar (and the init image, for Kubernetes)
**Download a release** — <https://github.com/obegron/sonar-jwt-auth/releases> — and verify it. The Docker and Helm routes below use files from this repository, so work inside a clone:
```bash
git clone https://github.com/obegron/sonar-jwt-auth && cd sonar-jwt-auth
gh release download v0.1.3 -R obegron/sonar-jwt-auth            # or download sonar-jwt-auth-0.1.3.jar and SHA256SUMS from the release page
gh attestation verify sonar-jwt-auth-*.jar -R obegron/sonar-jwt-auth     # optional: proves it was built by this repo's CI (docs/OPERATIONS.md#verifying-a-release)
sha256sum -c SHA256SUMS && mkdir -p docker && cp sonar-jwt-auth-0.1.3.jar docker/sonar-jwt-auth.jar     # run from a checkout of this repo, for the Docker route
```
Each release also publishes the init-container image `ghcr.io/obegron/sonar-jwt-auth-init:<version>` (public), which the Helm values use as is.

**Or build from source** (needs docker, Java 21, Maven):
```bash
scripts/build.sh                                   # fetches the compile-time server jar, runs the tests -> target/sonar-jwt-auth-<version>.jar
cp target/sonar-jwt-auth-*.jar docker/sonar-jwt-auth.jar
docker build -t <your-registry>/sonar-jwt-auth-init:<version> -f docker/Dockerfile.init docker && docker push <your-registry>/sonar-jwt-auth-init:<version>   # Kubernetes / Helm only, if you host your own image
```

## 3. Tell SonarQube where the issuer's public keys are
Pick one `source` style per issuer. Nothing to install on the issuer side in any of them.

**A. Same Kubernetes cluster as SonarQube — read the API server directly.** (The official Helm chart does not mount a ServiceAccount token by default: set `serviceAccount.automountToken: true`, as `deploy/helm/values-sonar-jwt-auth.yaml` does. Without it the pod has no `ca.crt`/`token` and the log says `cannot load caFile ... NoSuchFileException`.) The pod's own ServiceAccount may read the discovery endpoints
(`system:service-account-issuer-discovery` is bound to every ServiceAccount by default):
```json
{ "name": "tekton", "issuer": "https://kubernetes.default.svc.cluster.local",
  "discoveryUrl": "https://kubernetes.default.svc", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks",
  "caFile": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", "bearerTokenFile": "/var/run/secrets/kubernetes.io/serviceaccount/token", ... }
```
(`issuer` must equal what `kubectl get --raw /.well-known/openid-configuration` reports. This is the default for k3s/kubeadm; **managed clouds use their own issuer**,
e.g. EKS `https://oidc.eks.<region>.amazonaws.com/id/<id>` and GKE `https://container.googleapis.com/v1/projects/<p>/locations/<l>/clusters/<c>` — those are
public https endpoints, so use style C there, without bearer token.)
This style is exercised end to end by the `k8s-e2e` CI job (`scripts/e2e-k8s.sh`: official Helm chart, this config, a scanner pod).

**B. Another cluster, or SonarQube outside Kubernetes — a key file, no network.** Export the keys once and mount them next to the config:
```bash
scripts/export-jwks.sh <kube-context> > jenkins-jwks.json       # = kubectl get --raw /openid/v1/jwks
kubectl create namespace sonarqube        # if it does not exist yet (same namespace as step 5b)
kubectl -n sonarqube create configmap sonar-jwt-auth-config --from-file=jwt-auth.json=my-jwt-auth.json --from-file=jenkins-jwks.json
```
```json
{ "name": "jenkins", "issuer": "https://kubernetes.default.svc.cluster.local", "jwksFile": "/opt/sonarqube/jwt-auth/jenkins-jwks.json", ... }
```
The file is re-read within ~10 seconds of a change (a removed key stops working then). Kubernetes only changes its signing keys when an operator rotates them: re-export then (a CronJob can do it).

**C. Any OIDC issuer reachable over https** (Jenkins OIDC provider, a cloud IdP, a Kubernetes cluster exposed through an Ingress with TLS):
`"discoveryUrl": "https://oidc.example.org"`. The `jwks_uri` it announces must be https and on the same host (`allowForeignJwksHost` to relax).
For a private CA set `"caFile"` to a PEM file (the JVM trust store is then not used for this source). `jwksUri` skips discovery.
`allowInsecureHttp` permits plain http and exists for throw-away test clusters only.

## 4. Write the config
`jwt-auth.json` (a ConfigMap in Kubernetes). **Replace the example hostnames (`*.example.org`) with your own.** One entry per issuer/cluster; clusters may share the same `issuer` string.

```json
{ "sources": [
  { "name": "tekton",
    "issuer": "https://kubernetes.default.svc.cluster.local",
    "discoveryUrl": "https://oidc.tekton.example.org",
    "audiences": ["sonarqube"],
    "maxTokenLifetimeSeconds": 900,
    "rules": [ {
      "subject": "system:serviceaccount:(?<ns>[a-z0-9-]+):(?<sa>[a-z0-9-]+)",
      "login": "tekton_${ns}_${sa}",
      "name": "Tekton ${ns}/${sa}",
      "autoProvision": true,
      "groups": ["ci-scanners"],
      "projectKeyPattern": "${ns}_.*" } ] },
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
| `jwksFile` / `jwksUri` / `caFile` / `bearerTokenFile` / `allowForeignJwksHost` | how the keys are obtained, see step 3 |
| `allowQualityGateWait` | default false. Set true if your pipelines use `sonar.qualitygate.wait=true`: the scanner then polls `/api/ce/task` and `/api/qualitygates/project_status` by task/analysis id, which cannot be tied to a project key. Trade-off: a scoped identity could read the status of another project's task/analysis *if it knew its random id* |
| `allowedPathPrefixes` | what a JWT session may call; default is exactly what `sonar-scanner` needs. Exact paths, or a prefix ending in `/`. **Widening it weakens `projectKeyPattern`**: only the built-in endpoints are scoped precisely, other paths are only checked for `projectKey`/`project`/`component`/`key`. `["*"]` is refused when any rule has a `projectKeyPattern` |
| `maxTokenLifetimeSeconds` | default 86400 (a safe upper bound, but revocation is by expiry only): **set it just above your tokens' lifetime**, e.g. 900 for `expirationSeconds: 600` as in the example. Tokens valid longer (exp − iat) are refused; 0 disables |
| `clockSkewSeconds` | default 60 |
| `allowInsecureHttp` | permit http discovery/JWKS (tests only) |

| Rule field | |
|---|---|
| `subject` | regex matching the whole `sub`; named groups are available as `${name}` |
| `login` | identity template; must start with literal text; `${source}` is the source name. Values captured from the token may not contain the literal separators between placeholders (so `a-b`+`c` can never equal `a`+`b-c`) — use `_` as separator for Kubernetes names |
| `autoProvision` | create the user on first use (external user, provider `jwt-auth`). Otherwise `login` must name an existing user. A user of another origin with the same login is **never** adopted |
| `name`, `groups` | display name / groups of provisioned users (groups must exist; `sonar-administrators` is refused). **Groups are re-synced every 5 minutes and replace the user's group memberships**, so manual additions are lost and a rule change takes up to 5 minutes to apply. Every user is also in SonarQube's default group (`sonar-users`) and gets the permissions granted to *Anyone* |
| `projectKeyPattern` | regex; every project the request touches must match, and requests that cannot be tied to a project are refused. May use the rule's placeholders: `"${ns}_.*"` gives **each namespace its own project-key prefix with one rule** (the captured value is regex-quoted). **Use `_` (or `:`) after the placeholder, never `-`**: Kubernetes names contain `-`, so `${ns}-.*` would let namespace `team` touch the projects of `team-dev` (config load warns about it). `_` is safe only because Kubernetes namespace/ServiceAccount names cannot contain it: for subjects whose values can (e.g. Jenkins job names) pick a separator the values cannot contain, or write one rule per team with a fixed pattern. A rule with `autoProvision` and no `projectKeyPattern` lets every matching identity overwrite any project (config load warns). A fixed pattern such as `tekton-.*` is shared by every identity the rule matches: use one rule per team, or `${ns}`, when teams must not touch each other's projects |

The file is re-read within ~10 s of a change (mount the ConfigMap as a **directory**, not `subPath`). An invalid file is logged and the previous config stays active.

## 5. Install the agent
The ConfigMap must be mounted as a **directory** at `/opt/sonarqube/jwt-auth` (not with `subPath`, which Kubernetes never updates).
The jar is a **javaagent**, not a plugin: do **not** put it in `extensions/plugins/`. Add to the web process JVM options:
`-javaagent:/path/to/sonar-jwt-auth.jar=web` and mount the config at `/opt/sonarqube/jwt-auth/jwt-auth.json` (or set `SONAR_JWT_AUTH_CONFIG`).

**Before the first scan, create the groups your rules name** (step 6) — provisioned users only get the permissions of groups that exist.

### a) Docker
The jar from step 2 is already at `docker/sonar-jwt-auth.jar`.
```bash
docker build -t sonarqube-jwt docker
mkdir -p jwt-auth && cp my-jwt-auth.json jwt-auth/jwt-auth.json                              # your config from step 4
docker run -d -p 9000:9000 -v $PWD/jwt-auth:/opt/sonarqube/jwt-auth:ro sonarqube-jwt
```
This starts SonarQube as in its own quick start: the Linux host needs `vm.max_map_count>=524288` (Elasticsearch; or add `-e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true` for evaluation), and it uses the embedded H2 database, which is for evaluation only —
for production add an external PostgreSQL (`-e SONAR_JDBC_URL=... -e SONAR_JDBC_USERNAME=... -e SONAR_JDBC_PASSWORD=...`) and a volume for `/opt/sonarqube/data`.

### b) Official Helm chart
```bash
helm repo add sonarqube https://SonarSource.github.io/helm-chart-sonarqube && helm repo update
kubectl create namespace sonarqube
kubectl -n sonarqube create configmap sonar-jwt-auth-config --from-file=jwt-auth.json=my-jwt-auth.json     # your config from step 4
helm upgrade --install sonarqube sonarqube/sonarqube -n sonarqube -f deploy/helm/values-sonar-jwt-auth.yaml --set monitoringPasscode=<secret>
```
The values use the published init image `ghcr.io/obegron/sonar-jwt-auth-init:0.1.3` (the tag must match the SonarQube version you tested against, see [OPERATIONS.md](OPERATIONS.md#compatibility)). If you build and host your own, replace the registry **and the tag** in the values file.
**Database:** recent chart versions no longer bundle PostgreSQL — without `jdbcOverwrite` SonarQube uses its embedded H2, which is for evaluation only. For production configure an external database as usual.
This install path is run for real, with the official chart, by the `k8s-e2e` CI job.
### c) Together with sonarqube-community-branch-plugin
Both are javaagents: list both in the same option, e.g.
`-javaagent:.../sonarqube-community-branch-plugin-26.10.0.jar=web -javaagent:.../sonar-jwt-auth.jar=web` (see `docker/Dockerfile.branch-plugin`).

## 6. Give the identity the least privilege it needs
(The `deploy/` demo configs use the groups `tekton-scanners` / `jenkins-scanners`, which `scripts/bootstrap-sonar.sh` creates; use your own names in your config.)
Provisioned users get the permissions of the groups you list, plus the default group and *Anyone*. Create a group once.
You need the URL of the new instance and an admin login: Docker → `http://localhost:9000`; Helm → `kubectl -n sonarqube port-forward svc/sonarqube-sonarqube 9000:9000` then `http://localhost:9000`.
A fresh SonarQube has the login `admin` / password `admin`; change it first (`curl -u admin:admin -X POST $S/api/users/change_password -d login=admin -d previousPassword=admin -d password=<new>`).
```bash
A='-u admin:<new-password>'; S=http://localhost:9000    # or your public URL
curl $A -X POST $S/api/user_groups/create -d name=ci-scanners
curl $A -X POST $S/api/permissions/add_group -d groupName=ci-scanners -d permission=provisioning   # Create Projects
curl $A -X POST $S/api/permissions/add_group -d groupName=ci-scanners -d permission=scan           # Execute Analysis
```
Never grant a provisioned group *Administer System*; the plugin cannot detect that for you.
Because `scan` is a global permission, `projectKeyPattern` is the per-team boundary — set it. Note that any identity with *Execute Analysis*
can read the instance's global settings including secured ones (that is how SonarQube lets scanners read e.g. credentials for ALM integrations);
`projectKeyPattern` does not and cannot hide those.

## 7. Use it from CI
The scanner just needs the JWT in `SONAR_TOKEN`. Kubernetes (Tekton, Argo, plain pods) — a projected token with the right audience:
```yaml
volumes:
  - name: sonar-token
    projected: {sources: [{serviceAccountToken: {audience: sonarqube, expirationSeconds: 600, path: token}}]}
# step:
#   (mount it: volumeMounts: [{name: sonar-token, mountPath: /var/run/secrets/sonar, readOnly: true}]; NAMESPACE = the pod's namespace, e.g. from the downward API metadata.namespace)
#   export SONAR_TOKEN="$(cat /var/run/secrets/sonar/token)"
#   sonar-scanner -Dsonar.host.url=https://sonar.example.org -Dsonar.projectKey=${NAMESPACE}_myapp   # must start with the pod's namespace + "_" because the rule above says "${ns}_.*"
```
Jenkins: each Jenkins is its own `source` (its own issuer/keys), so you decide per source whether projects need a prefix. A Jenkins that should be free to use any project key:
```json
{ "name": "jenkins", "issuer": "https://jenkins.example.org", "discoveryUrl": "https://jenkins.example.org", "audiences": ["sonarqube"], "maxTokenLifetimeSeconds": 900,
  "rules": [ { "subject": ".*", "login": "jenkins_ci", "name": "Jenkins CI", "autoProvision": true, "groups": ["ci-scanners"], "projectKeyPattern": ".*" } ] }
```
`"projectKeyPattern": ".*"` states "any project" on purpose (no config warning; an *absent* pattern also means unscoped but logs a warning). Paths are still limited to what the scanner needs. Tekton sources keep their own `${ns}_.*` prefixes next to it.
Use the OIDC token your Jenkins issues (e.g. the *OpenID Connect Provider* plugin's ID-token credential, audience `sonarqube`) as `SONAR_TOKEN`.
`sonar.qualitygate.wait=true` needs `"allowQualityGateWait": true` on the source (see the table in step 4). Branch analysis needs `sonar.branch.name` and the branch plugin, as before.

## 8. Verify
Boot log should show, in order:
```
jwt-auth: extension registered (SonarQube API ...)
jwt-auth: loaded 2 source(s) from /opt/sonarqube/jwt-auth/jwt-auth.json: [tekton(...), jenkins(...)]
jwt-auth source 'tekton': loaded 1 signing key(s)
```
Then run a scan. `scripts/integration/run.sh` runs the whole acceptance test against a throw-away SonarQube if you want proof first.
