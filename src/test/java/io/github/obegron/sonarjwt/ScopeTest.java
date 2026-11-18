package io.github.obegron.sonarjwt;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class ScopeTest {
  static final Pattern TEKTON = Pattern.compile("tekton-.*");
  static Function<String, String[]> params(Object... kv) {
    java.util.Map<String, String[]> m = new java.util.HashMap<>();
    for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1] instanceof String[] a ? a : new String[] {(String) kv[i + 1]});
    return m::get;
  }

  @Test void routingTricksAreRefused() {
    for (String bad : new String[] {"/api/ce/submit/../../api/users/search", "/api/ce/submit;x=1", "/api/ce/%2e%2e/users", "/api//ce/submit", "/api\\ce", "api/ce/submit", "", "/api/ce/submit\n"})
      assertNull(Scope.canonicalPath(bad), bad);
    assertEquals("/api/settings/values", Scope.canonicalPath("/api/settings/values.protobuf"));
    assertEquals("/api/ce/submit", Scope.canonicalPath("/api/ce/submit"));
  }

  @Test void pathAllowlistIsExactUnlessSubtree() {
    List<String> d = AuthConfig.DEFAULT_ALLOWED_PATHS;
    assertTrue(Scope.pathAllowed("/api/ce/submit", d));
    assertTrue(Scope.pathAllowed("/api/v2/analysis/engine", d));
    assertFalse(Scope.pathAllowed("/api/ce/submit/x", d));
    assertFalse(Scope.pathAllowed("/api/ce/submitx", d));
    assertFalse(Scope.pathAllowed("/api/ce/task", d));          // cannot be scoped by project: not allowed by default
    assertFalse(Scope.pathAllowed("/api/users/search", d));
    assertFalse(Scope.pathAllowed("/api/user_tokens/generate", d));
    assertTrue(Scope.pathAllowed("/anything", List.of("*")));
  }

  @Test void scopedIdentityMayOnlyTouchMatchingProjects() {
    assertNull(Scope.violation("/api/ce/submit", params("projectKey", "tekton-a"), TEKTON));
    assertNotNull(Scope.violation("/api/ce/submit", params("projectKey", "jenkins-a"), TEKTON));
    assertNotNull(Scope.violation("/api/ce/submit", params("projectKey", new String[] {"tekton-a", "jenkins-a"}), TEKTON)); // duplicated param
    assertNotNull(Scope.violation("/api/ce/submit", params(), TEKTON));                                                     // project missing: fail closed
    assertNotNull(Scope.violation("/api/projects/create", params("name", "x"), TEKTON));
    assertNull(Scope.violation("/api/projects/create", params("project", "tekton-x"), TEKTON));
  }

  @Test void optionalAndUnscopedEndpoints() {
    assertNull(Scope.violation("/api/settings/values", params(), TEKTON));                       // global settings
    assertNotNull(Scope.violation("/api/settings/values", params("component", "jenkins-a"), TEKTON));
    assertNull(Scope.violation("/api/v2/analysis/engine", params(), TEKTON));
    assertNull(Scope.violation("/api/v2/analysis/jres/59f0d0ff-c68e-46ab-85da-31cfc0f5cbde", params(), TEKTON)); // JRE download carries an id, not a project
    assertNull(Scope.violation("/api/plugins/installed", params(), TEKTON));
    assertNull(Scope.violation("/api/ce/submit", params(), null));                               // no scope configured
  }

  @Test void unknownEndpointsAndCrossProjectIdsAreFailClosed() {
    assertNotNull(Scope.violation("/api/custom/thing", params(), TEKTON));
    assertNull(Scope.violation("/api/custom/thing", params("project", "tekton-q"), TEKTON));
    assertNotNull(Scope.violation("/api/qualitygates/project_status", params("projectKey", "tekton-a", "analysisId", "AX1"), TEKTON));
    assertNotNull(Scope.violation("/api/qualitygates/project_status", params("analysisId", "AX1"), TEKTON));
    assertNull(Scope.violation("/api/qualitygates/project_status", params("projectKey", "tekton-a"), TEKTON));
  }
}
