package io.github.obegron.sonarjwt;

import org.sonar.api.SonarQubeSide;
import org.sonar.core.extension.CoreExtension;

/** Registered through META-INF/services, loaded from the system classpath (the jar is also a javaagent) so server classes are visible. */
public class JwtAuthCoreExtension implements CoreExtension {
  @Override public String getName() { return "jwt-auth"; }

  @Override public void load(Context context) {
    if (context.getRuntime().getSonarQubeSide() == SonarQubeSide.SERVER) context.addExtension(JwtServiceAuthentication.class);
  }
}
