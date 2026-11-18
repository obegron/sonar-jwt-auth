package io.github.obegron.sonarjwt;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Base64;
import java.util.HashSet;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.server.authentication.UserIdentity;
import org.sonar.api.server.http.HttpRequest;
import org.sonar.db.DbClient;
import org.sonar.db.DbSession;
import org.sonar.db.user.UserDto;
import org.sonar.server.authentication.ServiceAuthentication;
import org.sonar.server.authentication.UserRegistrar;
import org.sonar.server.authentication.UserRegistration;
import org.sonar.server.authentication.event.AuthenticationEvent;
import org.sonar.server.exceptions.ForbiddenException;
import org.sonar.server.user.UserSession;
import org.sonar.server.user.UserSessionFactory;

/**
 * Called by SonarQube's RequestAuthenticator for every request. Turns a valid OIDC JWT (Bearer, or the Basic form sonar-scanner uses)
 * into a session of the SonarQube user selected by the matching rule. Anything else falls through to the normal authentication.
 */
public class JwtServiceAuthentication implements ServiceAuthentication {
  private static final Logger LOG = LoggerFactory.getLogger(JwtServiceAuthentication.class);
  private static final String[] PROJECT_PARAMS = {"projectKey", "project", "component", "key"};

  private final DbClient db;
  private final UserSessionFactory sessions;
  private final UserRegistrar registrar;
  private final ConfigHolder config = new ConfigHolder(Clock.systemUTC());
  private final JwtIdentityProvider provider = new JwtIdentityProvider();
  /** login -> last time we synced name/groups, so the scanner's many requests do not each hit the registrar. */
  private final ConcurrentHashMap<String, Long> lastSync = new ConcurrentHashMap<>();
  private static final long RESYNC_MS = 5 * 60_000L;

  public JwtServiceAuthentication(DbClient db, UserSessionFactory sessions, UserRegistrar registrar) {
    this.db = db; this.sessions = sessions; this.registrar = registrar;
  }

  @Override
  public Optional<UserSession> authenticate(HttpRequest req) {
    String token = extractToken(req.getHeader("Authorization"));
    if (token == null) return Optional.empty();
    JwtVerifier verifier = config.verifier();
    if (verifier == null) return Optional.empty();

    JwtVerifier.Result result = verifier.verify(token);
    if (result instanceof JwtVerifier.Rejected r) {
      LOG.warn("jwt-auth: rejected {} {}: {}", req.getMethod(), req.getRequestURI(), r.reason());
      return Optional.empty();
    }
    if (!(result instanceof JwtVerifier.Accepted ok)) return Optional.empty();

    String path = req.getRequestURI().substring(req.getContextPath().length());
    if (!pathAllowed(path, ok)) {
      LOG.warn("jwt-auth: {} ({}) may not call {}", ok.subject(), ok.source(), path);
      return Optional.empty();
    }
    checkProjectScope(req, ok);

    UserDto user = findOrProvision(ok);
    if (user == null) {
      LOG.warn("jwt-auth: {} ({}) maps to unknown/inactive SonarQube user '{}' (autoProvision is off)", ok.subject(), ok.source(), ok.login());
      return Optional.empty();
    }
    LOG.debug("jwt-auth: {} ({}) -> user {} for {} {}", ok.subject(), ok.source(), ok.login(), req.getMethod(), path);
    return Optional.of(sessions.create(user, false));
  }

  /**
   * Provisioned users are found by external identity: SonarQube's registrar generates its own internal login
   * (derived from the display name) and keeps ours as the external id. A user an admin deactivated stays deactivated.
   */
  private UserDto findOrProvision(JwtVerifier.Accepted ok) {
    JwtVerifier.Provisioning prov = ok.provisioning();
    UserDto byLogin, ours = null;
    try (DbSession s = db.openSession(false)) {
      byLogin = db.userDao().selectActiveUserByLogin(s, ok.login());
      if (prov != null) ours = db.userDao().selectByExternalIdAndIdentityProvider(s, ok.login(), JwtIdentityProvider.KEY);
    }
    if (prov == null) return byLogin;
    if (ours != null && !ours.isActive()) { LOG.warn("jwt-auth: user for '{}' was deactivated by an administrator", ok.login()); return null; }
    if (ours == null && byLogin != null) return byLogin; // an existing user of another origin owns this login: use it, never modify it
    long now = System.currentTimeMillis();
    if (ours != null && now - lastSync.getOrDefault(ok.login(), 0L) < RESYNC_MS) return ours;
    try {
      UserDto registered = registrar.register(UserRegistration.builder()
          .setUserIdentity(UserIdentity.builder().setProviderId(ok.login()).setProviderLogin(ok.login()).setLogin(ok.login())
              .setName(prov.name()).setGroups(new HashSet<>(prov.groups())).build())
          .setProvider(provider).setSource(AuthenticationEvent.Source.external(provider)).build());
      lastSync.put(ok.login(), now);
      if (ours == null) LOG.info("jwt-auth: provisioned user '{}' (login {}) for {} ({}) in groups {}", ok.login(), registered.getLogin(), ok.subject(), ok.source(), prov.groups());
      return registered;
    } catch (RuntimeException e) {
      LOG.error("jwt-auth: provisioning '{}' failed: {}", ok.login(), e.toString());
      return ours;
    }
  }

  static boolean pathAllowed(String path, JwtVerifier.Accepted ok) {
    for (String p : ok.allowedPathPrefixes()) if (p.equals("*") || path.equals(p) || (p.endsWith("/") ? path.startsWith(p) : path.startsWith(p + "/") || path.startsWith(p + "."))) return true;
    return false;
  }

  private static void checkProjectScope(HttpRequest req, JwtVerifier.Accepted ok) {
    Pattern scope = ok.projectKeyPattern();
    if (scope == null) return;
    for (String name : PROJECT_PARAMS) {
      String[] values = req.getParameterValues(name);
      if (values == null) continue;
      for (String v : values) {
        if (!scope.matcher(v).matches()) {
          LOG.warn("jwt-auth: {} ({}) may not touch project '{}'", ok.subject(), ok.source(), v);
          throw new ForbiddenException("Project key '" + v + "' is outside what this identity may access");
        }
      }
    }
  }

  /** Bearer <jwt>, or Basic base64("<jwt>:") as sent by sonar-scanner's second stage. */
  static String extractToken(String header) {
    if (header == null) return null;
    String h = header.trim();
    try {
      if (h.regionMatches(true, 0, "Bearer ", 0, 7)) return h.substring(7).trim();
      if (h.regionMatches(true, 0, "Basic ", 0, 6)) {
        String d = new String(Base64.getDecoder().decode(h.substring(6).trim()), StandardCharsets.UTF_8);
        int i = d.indexOf(':');
        return i < 0 ? d : d.substring(0, i);
      }
    } catch (IllegalArgumentException ignored) { }
    return null;
  }
}
