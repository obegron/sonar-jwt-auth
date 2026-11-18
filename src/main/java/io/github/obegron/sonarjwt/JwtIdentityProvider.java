package io.github.obegron.sonarjwt;

import org.sonar.api.server.authentication.Display;
import org.sonar.api.server.authentication.IdentityProvider;

/** Identity provider under which JWT users are provisioned. Not registered for interactive login, so it never shows on the login page. */
final class JwtIdentityProvider implements IdentityProvider {
  static final String KEY = "jwt-auth";
  @Override public String getKey() { return KEY; }
  @Override public String getName() { return "JWT (workload identity)"; }
  @Override public Display getDisplay() { return Display.builder().setIconPath("/images/sonarcloud-square-logo.svg").setBackgroundColor("#236a97").build(); }
  @Override public boolean isEnabled() { return true; }
  @Override public boolean allowsUsersToSignUp() { return true; }
}
