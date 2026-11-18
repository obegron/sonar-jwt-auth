package io.github.obegron.sonarjwt;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.SonarQubeSide;
import org.sonar.core.extension.CoreExtension;

/** Registered through META-INF/services, loaded from the system classpath (the jar is also a javaagent) so server classes are visible. */
public class JwtAuthCoreExtension implements CoreExtension {
  private static final Logger LOG = LoggerFactory.getLogger(JwtAuthCoreExtension.class);

  @Override public String getName() { return "jwt-auth"; }

  @Override public void load(Context context) {
    if (context.getRuntime().getSonarQubeSide() != SonarQubeSide.SERVER) return;
    try {
      List<String> problems = Compat.problems(JwtAuthCoreExtension.class.getClassLoader());
      if (!problems.isEmpty()) {
        LOG.error("jwt-auth: this SonarQube version is not compatible; JWT authentication is DISABLED (SonarQube itself is unaffected). "
            + "Remove the -javaagent option or install a matching sonar-jwt-auth release. Missing: {}", problems);
        return;
      }
      context.addExtension(JwtServiceAuthentication.class);
      LOG.info("jwt-auth: extension registered (SonarQube API {})", context.getRuntime().getApiVersion());
    } catch (Throwable t) { // never let this extension prevent SonarQube from starting
      LOG.error("jwt-auth: failed to register, JWT authentication is DISABLED: {}", t.toString());
    }
  }
}
