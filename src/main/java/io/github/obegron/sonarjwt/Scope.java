package io.github.obegron.sonarjwt;

import java.util.List;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Fail-closed project scoping. For every endpoint a JWT session may call we know which request parameter names the project,
 * and whether it is mandatory. A source/rule with a projectKeyPattern may only touch matching projects; an endpoint we cannot
 * scope (unknown path, or the project is missing) is refused rather than allowed.
 */
final class Scope {
  private Scope() { }

  enum Mode { NONE, REQUIRED, OPTIONAL }
  private record Entry(String path, Mode mode, List<String> params, List<String> forbidden) {}

  private static Entry e(String path, Mode mode, String... params) { return new Entry(path, mode, List.of(params), List.of()); }

  /** Paths are compared after removing a ".protobuf" suffix. */
  private static final List<Entry> TABLE = List.of(
      e("/api/ce/submit", Mode.REQUIRED, "projectKey"),
      e("/api/projects/create", Mode.REQUIRED, "project"),
      e("/api/v2/analysis/active_rules", Mode.REQUIRED, "projectKey"),
      e("/api/v2/analysis/version", Mode.NONE), e("/api/v2/analysis/jres", Mode.NONE), e("/api/v2/analysis/jres/", Mode.NONE), e("/api/v2/analysis/engine", Mode.NONE),
      e("/api/settings/values", Mode.OPTIONAL, "component"),
      e("/api/qualityprofiles/search", Mode.OPTIONAL, "project"),
      e("/api/analysis_cache/get", Mode.REQUIRED, "project"),
      e("/batch/project", Mode.REQUIRED, "key"),
      e("/api/project_branches/list", Mode.REQUIRED, "project"),
      e("/api/project_pull_requests/list", Mode.REQUIRED, "project"),
      new Entry("/api/qualitygates/project_status", Mode.REQUIRED, List.of("projectKey"), List.of("analysisId", "projectId")),
      e("/api/plugins/installed", Mode.NONE), e("/api/plugins/download", Mode.NONE), e("/api/server/version", Mode.NONE),
      e("/api/languages/list", Mode.NONE), e("/api/features/list", Mode.NONE), e("/api/metrics/search", Mode.NONE));

  private static final List<String> GENERIC = List.of("projectKey", "project", "component", "key");

  /**
   * @return the path to match against, or null if it looks like an attempt to confuse routing
   * ({@code ..}, {@code ;} path parameters, percent-encoding, doubled or backslash separators, control characters)
   */
  static String canonicalPath(String path) {
    if (path == null || path.isEmpty() || path.charAt(0) != '/') return null;
    if (path.contains("..") || path.contains(";") || path.contains("%") || path.contains("//") || path.contains("\\")) return null;
    for (int i = 0; i < path.length(); i++) if (path.charAt(i) < 0x21 || path.charAt(i) > 0x7e) return null;
    return path.endsWith(".protobuf") ? path.substring(0, path.length() - ".protobuf".length()) : path;
  }

  /** Is the (canonical) path covered by one of the allowed prefixes? A prefix ending in '/' is a subtree, anything else is exact. */
  static boolean pathAllowed(String canonical, List<String> allowedPrefixes) {
    for (String p : allowedPrefixes) {
      if (p.equals("*")) return true;
      if (p.endsWith("/") ? canonical.startsWith(p) : canonical.equals(p)) return true;
    }
    return false;
  }

  /** @return null if the request is inside the scope, otherwise the reason it is refused */
  static String violation(String canonicalPath, Function<String, String[]> params, Pattern scope) {
    if (scope == null) return null;
    Entry entry = null;
    for (Entry t : TABLE) if (canonicalPath.equals(t.path()) || (t.path().endsWith("/") && canonicalPath.startsWith(t.path()))) { entry = t; break; }
    if (entry == null) entry = new Entry(canonicalPath, Mode.REQUIRED, GENERIC, List.of());
    if (entry.mode() == Mode.NONE) return null;
    for (String f : entry.forbidden()) if (params.apply(f) != null) return "parameter '" + f + "' is not allowed for a scoped identity";
    boolean seen = false;
    for (String name : entry.params()) {
      String[] values = params.apply(name);
      if (values == null) continue;
      seen = true;
      for (String v : values) if (!scope.matcher(v).matches()) return "project '" + Log.clean(v) + "' is outside the allowed scope";
    }
    if (!seen && entry.mode() == Mode.REQUIRED) return "request names no project (" + String.join("/", entry.params()) + ") so it cannot be scoped";
    return null;
  }
}
