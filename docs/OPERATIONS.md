# Operating sonar-jwt-auth

## Compatibility
| SonarQube Community Build | Status |
|---|---|
| 26.10.x | **Supported**: unit + integration tests, and a manual k3d run with sonarqube-community-branch-plugin 26.10.0 |
| 26.9.x, 26.11.x | Compiled and unit-tested in CI against those server jars; **not** integration-tested |
| anything else | Self-disables with an ERROR if an internal API it needs is missing (checked at startup) |

Helm values (`deploy/helm/values-sonar-jwt-auth.yaml`) were rendered against chart 2026.5.1005 and accepted by a server-side dry run; the init-container jar copy was run for real; a full chart install was **not** performed.
Server editions other than Community, and SonarQube DCE/multi-node, are untested.
**Upgrade procedure:** (1) read the release notes for a jar built for the new version, (2) upgrade the jar and SonarQube together,
(3) check the boot log for `extension registered`, (4) run `scripts/integration/run.sh` against a staging instance.
**Rollback:** remove the `-javaagent` option for this jar (SonarQube then behaves as if it was never installed; provisioned users and projects stay).

## Security model, and what it does not do
- A token is accepted only if: RS256/ES256 signature verifies with a key from the issuer's JWKS; `iss` matches a source; `aud` contains an accepted audience;
  `exp` valid and `exp − iat` ≤ `maxTokenLifetimeSeconds`; `sub` matches a rule. Anything claiming a configured issuer but failing is **rejected**, never downgraded.
- A JWT session can only call the scanner endpoints in `allowedPathPrefixes`, and with `projectKeyPattern` only the projects it names. Requests whose path
  looks like routing tricks (`..`, `;`, `%`, `//`) are refused.
- **Denials surface as HTTP 401** with the reason in the SonarQube log (SonarQube's authentication layer cannot return 403 from this hook).
- **Revocation is by expiry**: there is no per-token revocation. Keep `expirationSeconds` short (Kubernetes: 600) and the lifetime cap on. Keys removed from the
  JWKS stop working after the next refresh (every ≤10 min; a cached key set is trusted for at most 6 h if the issuer is unreachable).
- The plugin cannot see which permissions a group holds: do not put a group with *Administer* in `groups`.
- No metrics endpoint yet; use the log lines below.

## Log reference (logger `io.github.obegron.sonarjwt.*`)
| Message (start) | Meaning / action |
|---|---|
| `extension registered` | loaded (boot) |
| `this SonarQube version is not compatible ... DISABLED` | upgrade the jar or remove the agent |
| `no config file ... DISABLED` | set `SONAR_JWT_AUTH_CONFIG` / mount the file |
| `INVALID config ...` | fix the JSON; previous config (if any) stays active |
| `source 'x': loaded N signing key(s)` | issuer reachable |
| `key refresh failed, keeping previous keys` | issuer/jwks unreachable, wrong `issuer`, or jwks_uri not https |
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
- Distinct `--service-account-issuer` per Kubernetes cluster (the plugin tells same-issuer clusters apart by key, but distinct issuers are clearer).
- Restrict who can create ServiceAccounts in namespaces your rules match.

## Licence
Apache-2.0 (see `LICENSE`). The build compiles against SonarQube's server jar (LGPL-3.0) as a `system`-scoped, never-packaged dependency; the released jar
contains none of SonarQube's code. sonarqube-community-branch-plugin is a separate LGPL project and is not redistributed here.
