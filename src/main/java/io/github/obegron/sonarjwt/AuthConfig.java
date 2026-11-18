package io.github.obegron.sonarjwt;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Plugin configuration (JSON). Several independent token sources (e.g. a Jenkins cluster and a Tekton cluster) can be trusted at once.
 * <pre>
 * { "sources": [ {
 *     "name": "tekton",
 *     "issuer": "https://kubernetes.default.svc.cluster.local",
 *     "discoveryUrl": "https://oidc.tekton.example",
 *     "audiences": ["sonarqube"],
 *     "rules": [ { "subject": "system:serviceaccount:ci:pipeline", "login": "tekton-scanner" } ]
 * } ] }
 * </pre>
 */
public final class AuthConfig {
  /** Paths a JWT-authenticated session may call unless a source overrides it: what sonar-scanner needs. */
  public static final List<String> DEFAULT_ALLOWED_PATHS = List.of(
      "/api/ce/submit", "/api/v2/analysis/", "/api/settings/values", "/api/plugins/installed", "/api/plugins/download",
      "/api/server/version", "/api/qualityprofiles/search", "/api/languages/list", "/api/features/list", "/api/metrics/search",
      "/api/analysis_cache/get", "/api/projects/create", "/api/project_branches/list", "/api/project_pull_requests/list", "/api/new_code_periods/show", "/batch/project");

  public List<Source> sources = List.of();

  /** Non-fatal findings from {@link #validate()}; logged when the config is loaded. */
  public transient List<String> warnings = new ArrayList<>();

  @JsonIgnoreProperties(ignoreUnknown = false)
  public static final class Source {
    public String name;
    /** Value of the token's {@code iss} claim. */
    public String issuer;
    /** Base URL serving {@code /.well-known/openid-configuration}; defaults to the issuer. */
    public String discoveryUrl;
    /** Needed when discovery or the JWKS is served over plain http (e.g. in a test cluster). Off by default. */
    public boolean allowInsecureHttp;
    /** Skip discovery and fetch the keys from this URL (https). Needed e.g. for the Kubernetes API server, whose advertised jwks_uri may not be reachable. */
    public String jwksUri;
    /** Skip the network entirely: read the JWKS from this file (e.g. a mounted ConfigMap holding `kubectl get --raw /openid/v1/jwks`). Re-read when it changes. */
    public String jwksFile;
    /** PEM file with the CA(s) to trust for https discovery/JWKS (private CA, or the in-cluster /var/run/secrets/kubernetes.io/serviceaccount/ca.crt). */
    public String caFile;
    /** File holding a bearer token sent to the discovery URL (e.g. the pod's ServiceAccount token to read a Kubernetes API server). Re-read on every fetch. */
    public String bearerTokenFile;
    /** By default the jwks_uri announced by discovery must be on the same host as discoveryUrl. */
    public boolean allowForeignJwksHost;
    /** At least one must appear in the token's {@code aud}. */
    public List<String> audiences = List.of();
    /** First matching rule wins. */
    public List<Rule> rules = List.of();
    /** Paths this source may call: exact paths, or a prefix ending in '/'; empty = {@link #DEFAULT_ALLOWED_PATHS}; ["*"] = everything. */
    public List<String> allowedPathPrefixes = List.of();
    public long clockSkewSeconds = 60;
    /**
     * Allow sonar.qualitygate.wait (default true): the scanner then polls /api/ce/task and /api/qualitygates/project_status by task/analysis id, which
     * cannot be tied to a project key. The trade-off: a scoped identity could read the status of another project's task/analysis, but only if it knew its
     * random, unguessable id. Set false to forbid. Ignored when allowedPathPrefixes is set explicitly (list the two paths yourself then).
     */
    public boolean allowQualityGateWait = true;
    /** Tokens valid for longer than this (exp - iat) are refused, so a leaked long-lived token is not accepted. 0 disables the check. */
    public long maxTokenLifetimeSeconds = 86400;

    /** Sources with the same identity share cached keys across config reloads. */
    String keyIdentity() {
      return String.join("|", String.valueOf(issuer), effectiveDiscoveryUrl(), String.valueOf(jwksUri), String.valueOf(jwksFile),
          String.valueOf(caFile), String.valueOf(bearerTokenFile), String.valueOf(allowInsecureHttp), String.valueOf(allowForeignJwksHost));
    }

    String effectiveDiscoveryUrl() { return discoveryUrl == null || discoveryUrl.isBlank() ? issuer : discoveryUrl; }
    List<String> effectiveAllowedPaths() {
      if (!allowedPathPrefixes.isEmpty()) return allowedPathPrefixes;
      if (!allowQualityGateWait) return DEFAULT_ALLOWED_PATHS;
      List<String> p = new ArrayList<>(DEFAULT_ALLOWED_PATHS);
      p.add("/api/ce/task"); p.add("/api/qualitygates/project_status");
      return p;
    }
  }

  @JsonIgnoreProperties(ignoreUnknown = false)
  public static final class Rule {
    /** Regex, must match the whole {@code sub}. Named groups can be used in {@link #login} as ${name}. */
    public String subject;
    /**
     * Template for the identity. Without autoProvision: an existing SonarQube user. With it: the provisioned user's external id.
     * Must start with literal text (e.g. "tekton_${ns}_${sa}"); values captured from the token may not contain the literal separators
     * between placeholders, so two different subjects can never produce the same login.
     */
    public String login;
    /**
     * Optional regex: project keys in the request must match entirely. May use the same ${name} placeholders as {@link #login}
     * (replaced by the quoted captured value), e.g. "${ns}_.*" gives every namespace its own project-key prefix with a single rule (use a separator that cannot occur in the value: "-" would let namespace "team" match the projects of "team-dev").
     */
    public String projectKeyPattern;
    /** Create the user on first use (external user, provider "jwt-auth"). Existing users, including local ones, are never modified. */
    public boolean autoProvision;
    /** Display name template for provisioned users (${group} placeholders allowed); defaults to the token's sub. */
    public String name;
    /** SonarQube groups provisioned users are kept in (re-synced periodically). "sonar-administrators" is refused. */
    public List<String> groups = List.of();

    transient Pattern subjectPattern;
    transient Pattern projectPattern;
  }

  public static AuthConfig load(Path file) throws IOException {
    AuthConfig c = new ObjectMapper().readValue(file.toFile(), AuthConfig.class);
    c.validate();
    return c;
  }

  public static AuthConfig parse(String json) throws IOException {
    AuthConfig c = new ObjectMapper().readValue(json, AuthConfig.class);
    c.validate();
    return c;
  }

  void validate() {
    Set<String> names = new HashSet<>();
    List<String> problems = new ArrayList<>();
    for (Source s : sources) {
      String n = s.name == null ? "?" : s.name;
      if (s.name == null || s.name.isBlank() || !names.add(s.name)) problems.add("source name missing or duplicated: " + n);
      if (s.issuer == null || s.issuer.isBlank()) problems.add(n + ": issuer is required");
      if (s.audiences == null || s.audiences.isEmpty()) problems.add(n + ": at least one audience is required");
      if (s.rules == null || s.rules.isEmpty()) problems.add(n + ": at least one rule is required");
      if (s.maxTokenLifetimeSeconds < 0) problems.add(n + ": maxTokenLifetimeSeconds must be >= 0");
      if (s.allowedPathPrefixes != null) for (String ap : s.allowedPathPrefixes)
        if (!ap.equals("*") && (!ap.startsWith("/") || ap.contains("..") || ap.contains("%") || ap.contains(";"))) problems.add(n + ": bad allowedPathPrefixes entry: " + ap);
      if (s.clockSkewSeconds < 0 || s.clockSkewSeconds > 600) problems.add(n + ": clockSkewSeconds must be 0..600");
      if (s.issuer != null && s.jwksFile == null) {
        String url = s.jwksUri != null ? s.jwksUri : s.effectiveDiscoveryUrl();
        if (!(url.startsWith("https://") || (url.startsWith("http://") && s.allowInsecureHttp)))
          problems.add(n + ": " + (s.jwksUri != null ? "jwksUri" : "discoveryUrl") + " must be https (or http with allowInsecureHttp=true): " + url);
      }
      if (s.jwksFile != null && (s.jwksUri != null || s.discoveryUrl != null)) problems.add(n + ": jwksFile cannot be combined with jwksUri/discoveryUrl");
      boolean scoped = s.rules != null && s.rules.stream().anyMatch(r -> r.projectKeyPattern != null);
      if (scoped && s.allowedPathPrefixes != null && s.allowedPathPrefixes.contains("*"))
        problems.add(n + ": allowedPathPrefixes [\"*\"] cannot be combined with projectKeyPattern (scoping could not be guaranteed)");
      if (s.rules != null) for (Rule r : s.rules) {
        if (r.subject == null || r.login == null || r.login.isBlank()) { problems.add(n + ": rule needs subject and login"); continue; }
        if (r.login.matches(".*\\$\\{\\w+}\\$\\{.*")) problems.add(n + ": adjacent placeholders in login template are ambiguous: " + r.login);
        if (r.login.contains("${") && !r.login.matches("^[A-Za-z0-9_.@-]{2,}.*")) problems.add(n + ": login template must start with literal text: " + r.login);
        if (!r.autoProvision && (!r.groups.isEmpty() || r.name != null)) problems.add(n + ": groups/name require autoProvision=true");
        for (String g : r.groups) if (g == null || g.isBlank() || g.equals("sonar-administrators")) problems.add(n + ": group not allowed: " + g);
        // NOTE: a group that holds the Administer permission is NOT detected here; keep provisioned groups to Create Projects / Execute Analysis.
        try {
          r.subjectPattern = Pattern.compile(r.subject);
          java.util.Set<String> known = new java.util.HashSet<>(java.util.List.of("source"));
          java.util.regex.Matcher g = Pattern.compile("\\(\\?<([A-Za-z][A-Za-z0-9]*)>").matcher(r.subject);
          while (g.find()) known.add(g.group(1));
          for (String tpl : java.util.Arrays.asList(r.login, r.name, r.projectKeyPattern)) {
            if (tpl == null) continue;
            for (String ph : JwtVerifier.placeholderNames(tpl)) if (!known.contains(ph))
              problems.add(n + ": unknown placeholder ${" + ph + "} in '" + tpl + "' (available: " + known + ")");
          }
          if (!r.autoProvision)
            warnings.add(n + ": rule '" + r.subject + "' maps onto the EXISTING SonarQube user '" + r.login + "': make sure it is a dedicated service account, never a human or an administrator");
          if (r.autoProvision && r.projectKeyPattern == null)
            warnings.add(n + ": rule '" + r.subject + "' has autoProvision but no projectKeyPattern: every matching identity can create and overwrite ANY project (Execute Analysis and Create Projects are global permissions)");
          if (r.projectKeyPattern != null && r.projectKeyPattern.matches(".*\\$\\{\\w+}-.*"))
            warnings.add(n + ": projectKeyPattern '" + r.projectKeyPattern + "' puts '-' right after a placeholder: Kubernetes names contain '-', so namespace 'team' would also match the projects of 'team-dev'. Use a separator that cannot occur in the value, e.g. '${ns}_.*'");
          if (r.projectKeyPattern != null) {
            if (r.projectKeyPattern.contains("${")) Pattern.compile(r.projectKeyPattern.replaceAll("\\$\\{\\w+}", "x")); // syntax check only
            else r.projectPattern = Pattern.compile(r.projectKeyPattern);
          }
          if (s.name != null) for (char ch : JwtVerifier.innerSeparators(r.login)) if (s.name.indexOf(ch) >= 0)
            problems.add(n + ": source name contains '" + ch + "', which separates placeholders in login template '" + r.login + "' (every token would be refused as ambiguous)");
        } catch (PatternSyntaxException e) { problems.add(n + ": bad regex: " + e.getMessage()); }
      }
    }
    if (!problems.isEmpty()) throw new IllegalArgumentException("invalid jwt-auth config: " + String.join("; ", problems));
  }
}
