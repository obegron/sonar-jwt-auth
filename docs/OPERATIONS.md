# Operating sonar-jwt-auth

## Compatibility
**Supported: SonarQube Community Build 26.x. 26.10 is the primary target** — it is the release that removed unauthenticated analysis submission, which is what this project replaces.
Older lines are out of scope: the `ServiceAuthentication` hook this relies on does not exist in 25.1 (checked against the 25.1.0 server jar), and the extension would disable itself there.

The same jar (built against 26.10) runs the full integration test in a real SonarQube of each of these versions in CI:

| SonarQube Community Build | Evidence |
|---|---|
| **26.10.x** (primary) | integration test (CI) + compile/unit (CI) + Kubernetes/Helm end-to-end (CI) + manual k3d run with sonarqube-community-branch-plugin 26.10.0 |
| 26.9.x, 26.11.x | integration test (CI) + compile/unit (CI) |
| other 26.x | expected to work, **not tested**: add the version to the CI matrix before relying on it |
| 25.x and older | unsupported; the extension disables itself with an ERROR if an internal API it needs is missing. That guard checks the classes and methods it calls, **not** every behaviour change or the container wiring, so test upgrades on staging |

The Helm values (`deploy/helm/values-sonar-jwt-auth.yaml`) and the "Kubernetes API server" key source are installed and exercised for real, with the official chart (2026.5.x) in k3d, by the `k8s-e2e` CI job. The integration test also runs against an external PostgreSQL (`DB=postgres`, CI job `integration-postgres`). What has **not** been done: managed-cloud issuers (EKS/GKE). Releases carry SHA-256 checksums and GitHub build-provenance attestations (see "Verifying a release").
Other editions and multi-node (DCE) SonarQube are untested.
**Upgrade procedure:** (the weekly `compat-latest` run tells you in advance whether the newest SonarQube breaks it) (1) read the release notes for a jar built for the new version, (2) upgrade the jar and SonarQube together,
(3) check the boot log for `extension registered`, (4) run `scripts/integration/run.sh` against a staging instance.
**Rollback:** remove the `-javaagent` option for this jar (SonarQube then behaves as if it was never installed; provisioned users and projects stay).

## Verifying a release
Each release is built by this repository's workflow, which signs a provenance attestation for the jar and for the init image (Sigstore, keyless: the signer is the workflow itself, no key of the maintainer is involved).
```bash
gh attestation verify sonar-jwt-auth-<version>.jar -R obegron/sonar-jwt-auth                     # the jar was built by obegron/sonar-jwt-auth CI from a tagged commit
gh attestation verify oci://ghcr.io/obegron/sonar-jwt-auth-init:<version> -R obegron/sonar-jwt-auth   # same for the init image
sha256sum -c SHA256SUMS                                                                              # integrity of the downloaded file
```
This proves *where and how* an artifact was built (this repo, this workflow, this commit), not that the code is free of bugs — review the commit if that matters to you.

## Supported and unsupported
- **Supported (tested in CI):** single-node SonarQube Community Build 26.9–26.11 (26.10 primary), embedded H2 and external PostgreSQL 17, Docker and the official Helm chart on Kubernetes, key sources "Kubernetes API server", "jwksFile" and "https discovery".
- **Unverified / unsupported:** SonarQube Data Center Edition and other multi-node setups (provisioning/group re-sync state is per node), other editions, 25.x and older, managed-cloud issuers (EKS/GKE; use https discovery, untested), databases other than PostgreSQL.
- A scheduled CI run (`compat-latest`, weekly) tests the shipped jar against the newest Community Build tag so an incompatible upstream release shows up as a red run before you upgrade.

## Security model, and what it does not do
- **Revocation is by expiry only** (there is no per-token revocation). A leaked token works until it expires: use short-lived tokens (Kubernetes `expirationSeconds: 600`) and a matching `maxTokenLifetimeSeconds` (900).
- A token is accepted only if: RS256/ES256 signature verifies with a key from the issuer's JWKS; `iss` matches a source; `aud` contains an accepted audience;
  `exp` valid and `exp − iat` ≤ `maxTokenLifetimeSeconds`; `sub` matches a rule. Anything claiming a configured issuer but failing is **rejected**, never downgraded.
- A JWT session can only call the scanner endpoints in `allowedPathPrefixes`, and with `projectKeyPattern` only the projects it names. Requests whose path
  looks like routing tricks (`..`, `;`, `%`, `//`) are refused.
- **Denials surface as HTTP 401** with the reason in the SonarQube log (SonarQube's authentication layer cannot return 403 from this hook).
  JWKS stop working after the next refresh (every ≤10 min; a cached key set is trusted for at most 6 h if the issuer is unreachable).
- The extension cannot see which permissions a group holds: do not put a group with *Administer* in `groups`.
- Any identity with *Execute Analysis* can read global settings including secured ones (SonarQube lets scanners do that); `projectKeyPattern` cannot hide them.
- Widening `allowedPathPrefixes` weakens project scoping (only the built-in scanner endpoints are scoped precisely).
- Provisioned groups are re-synced every 5 minutes and overwrite manual membership changes.
- No metrics endpoint yet; use the log lines below. Repeated rejections are logged at most once a minute per category.

## Observability and alerting
There is no metrics endpoint; the extension logs (logger `io.github.obegron.sonarjwt.*`, same file/stdout as SonarQube):
- once per start: `extension registered`, `loaded N source(s)`, `source 'x': loaded N signing key(s)`, and `config warning:` lines for risky config;
- every 5 minutes, only if something happened: `jwt-auth: since last report: authenticated=… provisioned=… denied(scope/path/user)=… rejected=… [reason: n]`.

Alert on (log-based, e.g. Loki/ELK/CloudWatch filters): any `ERROR` from `io.github.obegron.sonarjwt`; the *absence* of `extension registered` after a SonarQube start;
`DISABLED` (extension off); `key refresh failed` repeating (issuer unreachable); a sudden jump in `rejected=` (expired tokens, clock skew, rotated keys) or `denied=` (a pipeline reaching outside its scope).

## "Not authorized" from sonar-scanner: which kind is it?
SonarQube's authentication hook can only answer 401, so the scanner prints the same "Not authorized" whether the **token is bad** or the **identity is valid but refused**. The server log tells them apart:
- `rejected token … token expired / audience not accepted / signature mismatch / no key / subject … matches no rule / lifetime exceeds` → the token itself is the problem (clock, audience, rules, key rotation).
- `… may not call <path>` or `… denied on <path>: … outside the allowed scope / names no project` → the token is fine, the identity is out of its allowed paths or project prefix.
- `maps to unknown/inactive SonarQube user`, `refusing to provision`, `deactivated by an administrator` → user-mapping problem.
The 5-minute summary line counts them separately (`rejected=` vs `denied(scope/path/user)=`), so a rise in `denied` points at a pipeline reaching outside its scope.
(A real 403 is not possible from this hook: SonarQube's authentication layer only turns an authentication failure into 401, and a low-privilege session would let a refused identity read other teams' project lists.)

## Log reference (logger `io.github.obegron.sonarjwt.*`)
| Message (start) | Meaning / action |
|---|---|
| `extension registered` | loaded (boot) |
| `this SonarQube version is not compatible ... DISABLED` | upgrade the jar or remove the agent |
| `no config file ... DISABLED` | set `SONAR_JWT_AUTH_CONFIG` / mount the file |
| `INVALID config ...` | fix the JSON; previous config (if any) stays active |
| `source 'x': loaded N signing key(s)` | issuer reachable |
| `cannot load caFile ... NoSuchFileException` | the pod has no ServiceAccount token/CA: Helm chart default `serviceAccount.automountToken: false` (set it true for key source A) |
| `key refresh failed, keeping previous keys` | issuer/jwks unreachable, wrong `issuer`, untrusted certificate (`caFile`), jwks_uri not https or on another host, or unreadable `jwksFile`/token file |
| `rejected token ...: token expired / audience not accepted / signature mismatch / no key / subject ... matches no rule / token lifetime exceeds` | self-explanatory; check clock, audience, rules |
| `... may not call <path>` | add the path to `allowedPathPrefixes` if intended |
| `... denied on <path>: ...outside the allowed scope / names no project` | project key vs `projectKeyPattern` |
| `maps to unknown/inactive SonarQube user` | rule without `autoProvision`: create the user or enable it |
| `refusing to provision '...': a SonarQube user with that login already exists` | login collides with a local user: change the template prefix |
| `provisioned user ...` | first use of a new identity |
| `unexpected error, request left to normal authentication` | a bug: please report with the stack trace at DEBUG |

Repeated warnings are throttled to one per minute per message.

## Hardening checklist
- `https` discovery, short-lived tokens, `audiences` specific to SonarQube, `projectKeyPattern` on every rule.
- Distinct `--service-account-issuer` per Kubernetes cluster (clusters sharing an issuer string are told apart by their keys, but distinct issuers are clearer and avoid ambiguity if a key is ever reused).
- Restrict who can create ServiceAccounts in namespaces your rules match. Every new matching identity that scans becomes a SonarQube user and users are never
  removed automatically: review/deactivate stale `jwt-auth` users from time to time (Administration → Security → Users, filter by provider).
- Prefer `${ns}`-scoped `projectKeyPattern`s (or one rule per team) over one shared pattern, so teams cannot touch each other's projects.

## Licence
Apache-2.0 (see `LICENSE`). The build compiles against SonarQube's server jar (LGPL-3.0) as a `system`-scoped, never-packaged dependency; the released jar
contains none of SonarQube's code. sonarqube-community-branch-plugin is a separate LGPL project and is not redistributed here.
