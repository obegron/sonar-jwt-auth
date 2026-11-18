# sonar-jwt-auth

Let CI jobs submit SonarQube scanner reports with a short-lived **OIDC JWT** — for example a Kubernetes ServiceAccount token — instead of a
stored SonarQube token. SonarQube Server has no built-in support for external-issuer tokens; this adds it for the **Community Build**.

```
pod ──(projected SA token, aud=sonarqube)──▶ SonarQube ──▶ sonar-jwt-auth
                                                 │          verify signature against the issuer's JWKS, check exp/aud/lifetime,
         issuer's /.well-known + JWKS  ◀─────────┘          match a rule → act as a (auto-provisioned) SonarQube user, scoped to its projects
```

- **Nothing stored in pipelines**; tokens expire in minutes. (Revocation is by expiry only — keep tokens short-lived.)
- **No extra components**: read keys straight from a Kubernetes API server, from a static key file, or from any https OIDC issuer.
- **Several issuers at once** (e.g. a Jenkins cluster and a Tekton cluster), even when they share the default Kubernetes issuer string.
- **Least privilege**: users are auto-provisioned into groups you choose; a JWT session can only call the scanner's endpoints and, with
  `projectKeyPattern`, only its own team's projects. Anything that is not a configured JWT (user tokens, UI login) is untouched.
- **Defensive**: if an internal API it needs is missing it disables itself with an ERROR instead of breaking startup (always test upgrades on staging); unexpected errors never affect other credentials.
- Works alongside [sonarqube-community-branch-plugin](https://github.com/mc1arke/sonarqube-community-branch-plugin).

## Quick start
1. `scripts/build.sh` (builds and tests the jar; release jars once published) → [docs/INSTALL.md](docs/INSTALL.md): config file, Docker / Helm install, permissions, CI usage.
2. Prove it works on your machine in ~3 minutes: `scripts/integration/run.sh` (needs docker + `pip install cryptography`).
3. Operate it: [docs/OPERATIONS.md](docs/OPERATIONS.md) — compatibility matrix, upgrade/rollback, security model, log reference.

## How it hooks in (for the curious)
SonarQube plugins cannot see server classes, and plugin filters never see `/api/*`. So the jar is a no-op **javaagent** (it lands on the system
classpath) carrying a `CoreExtension` — the mechanism the branch plugin uses — that registers SonarQube's own `ServiceAuthentication` hook, which the
server consults on every request. Because that is an internal API, releases are version-matched and checked at startup ([OPERATIONS.md](docs/OPERATIONS.md#compatibility)).

## Repository layout
`src/` plugin · `scripts/integration/` acceptance test · `deploy/` example manifests (k3d test setup, Helm values) · `docker/` image recipes · `docs/`.
`scripts/bootstrap-sonar.sh` and `deploy/` contain throwaway credentials for local test clusters only.

Apache-2.0 — see [LICENSE](LICENSE) and the licence note in [docs/OPERATIONS.md](docs/OPERATIONS.md#licence).
