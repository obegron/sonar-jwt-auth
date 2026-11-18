package io.github.obegron.sonarjwt;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Loads the config file and rebuilds the verifier when the file changes (ConfigMap updates are picked up without a restart). */
final class ConfigHolder {
  private static final Logger LOG = LoggerFactory.getLogger(ConfigHolder.class);
  static final String ENV = "SONAR_JWT_AUTH_CONFIG";
  static final String DEFAULT_PATH = "/opt/sonarqube/conf/jwt-auth.json";

  private final Path file;
  private final Clock clock;
  private volatile JwtVerifier verifier;
  private volatile long lastModified = -1;
  private volatile long lastCheck;

  ConfigHolder(Clock clock) {
    this.clock = clock;
    String p = System.getenv(ENV);
    this.file = Path.of(p == null || p.isBlank() ? DEFAULT_PATH : p);
  }

  /** @return the current verifier, or null when no (valid) config exists */
  JwtVerifier verifier() {
    long now = System.currentTimeMillis();
    if (now - lastCheck > 10_000) { lastCheck = now; reloadIfChanged(); }
    return verifier;
  }

  private synchronized void reloadIfChanged() {
    try {
      if (!Files.isRegularFile(file)) {
        if (lastModified != -2) LOG.info("jwt-auth: no config at {}, JWT authentication disabled", file);
        lastModified = -2; verifier = null; return;
      }
      long m = Files.getLastModifiedTime(file).toMillis();
      if (m == lastModified) return;
      AuthConfig cfg = AuthConfig.load(file);
      verifier = new JwtVerifier(cfg, clock);
      lastModified = m;
      LOG.info("jwt-auth: loaded {} source(s) from {}", cfg.sources.size(), file);
    } catch (Exception e) {
      lastModified = file.toFile().lastModified(); // do not retry the same broken file every time
      LOG.error("jwt-auth: invalid config {} ({}); keeping previous configuration", file, e.toString());
    }
  }
}
