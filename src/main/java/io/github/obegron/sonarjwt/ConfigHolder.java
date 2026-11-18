package io.github.obegron.sonarjwt;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Loads the config file at startup (problems show in the boot log) and watches it every 10 s on a background thread, so edits are
 * applied, and a broken edit is reported, even when no authenticated request arrives.
 */
final class ConfigHolder {
  private static final Logger LOG = LoggerFactory.getLogger(ConfigHolder.class);
  static final String ENV = "SONAR_JWT_AUTH_CONFIG";
  static final String DEFAULT_PATH = "/opt/sonarqube/jwt-auth/jwt-auth.json";

  private final Path file;
  private final Clock clock;
  private volatile JwtVerifier verifier;
  private volatile long lastModified = -1;

  ConfigHolder(Clock clock) {
    this.clock = clock;
    String p = System.getenv(ENV);
    this.file = Path.of(p == null || p.isBlank() ? DEFAULT_PATH : p);
    reloadIfChanged();
    Executors.newSingleThreadScheduledExecutor(r -> { Thread t = new Thread(r, "jwt-auth-config"); t.setDaemon(true); return t; })
        .scheduleWithFixedDelay(this::reloadIfChanged, 10, 10, TimeUnit.SECONDS);
  }

  /** @return the current verifier, or null when no (valid) config exists */
  JwtVerifier verifier() { return verifier; }

  private synchronized void reloadIfChanged() {
    try {
      if (!Files.isRegularFile(file)) {
        if (lastModified != -2) LOG.warn("jwt-auth: no config file at {} (set {}); JWT authentication is DISABLED", file, ENV);
        lastModified = -2; verifier = null; return;
      }
      long m = Files.getLastModifiedTime(file).toMillis();
      if (m == lastModified) return;
      AuthConfig cfg = AuthConfig.load(file);
      JwtVerifier v = new JwtVerifier(cfg, clock);
      v.warmUp();
      verifier = v;
      lastModified = m;
      LOG.info("jwt-auth: loaded {} source(s) from {}: {}", cfg.sources.size(), file, cfg.sources.stream().map(s -> s.name + "(" + s.issuer + ")").toList());
    } catch (Exception e) {
      lastModified = file.toFile().lastModified(); // do not retry the same broken file on every request
      LOG.error("jwt-auth: INVALID config {} ({}); {}", file, e.toString(), verifier == null ? "JWT authentication is DISABLED" : "keeping the previous configuration");
    }
  }
}
