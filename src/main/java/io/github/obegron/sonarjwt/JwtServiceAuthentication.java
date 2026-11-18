package io.github.obegron.sonarjwt;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Base64;
import java.util.HashSet;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
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
import org.sonar.server.user.UserSession;
import org.sonar.server.user.UserSessionFactory;

/**
 * Called by SonarQube's RequestAuthenticator for every request. Turns a valid OIDC JWT (Bearer, or the Basic form sonar-scanner uses)
 * into a session of the SonarQube user selected by the matching rule. Anything else falls through to the normal authentication.
 * It must never make authentication worse for other credentials: unexpected errors are logged and treated as "not ours".
 */
public class JwtServiceAuthentication implements ServiceAuthentication {
  private static final Logger LOG = LoggerFactory.getLogger(JwtServiceAuthentication.class);
  private static final long RESYNC_MS = 5 * 60_000L;

  private final DbClient db;
  private final UserSessionFactory sessions;
  private final UserRegistrar registrar;
  private final ConfigHolder config;
  private final JwtIdentityProvider provider = new JwtIdentityProvider();
  /** login -> last time name/groups were synced, so the scanner's many requests do not each hit the registrar. */
  private final ConcurrentHashMap<String, Long> lastSync = new ConcurrentHashMap<>();
  /** one lock per login: the scanner issues parallel requests, and only one may create a brand-new user. */
  private final ConcurrentHashMap<String, Object> locks = new ConcurrentHashMap<>();

  public JwtServiceAuthentication(DbClient db, UserSessionFactory sessions, UserRegistrar registrar) {
    this(db, sessions, registrar, new ConfigHolder(Clock.systemUTC()));
  }

  JwtServiceAuthentication(DbClient db, UserSessionFactory sessions, UserRegistrar registrar, ConfigHolder config) {
    this.db = db; this.sessions = sessions; this.registrar = registrar; this.config = config;
  }

  @Override
  public Optional<UserSession> authenticate(HttpRequest req) {
    try {
      return doAuthenticate(req);
    } catch (RuntimeException | LinkageError e) {
      Log.throttledWarn(LOG, "error", "jwt-auth: unexpected error, request left to normal authentication: " + e);
      return Optional.empty();
    }
  }

  private Optional<UserSession> doAuthenticate(HttpRequest req) {
    String token = extractToken(req.getHeader("Authorization"));
    if (token == null) return Optional.empty();
    JwtVerifier verifier = config.verifier();
    if (verifier == null) return Optional.empty();

    JwtVerifier.Result result = verifier.verify(token);
    if (result instanceof JwtVerifier.Rejected r) {
      Log.throttledWarn(LOG, "rejected:" + Log.category(r.reason()), "jwt-auth: rejected token for " + Log.clean(req.getMethod()) + " " + Log.clean(req.getRequestURI()) + ": " + r.reason());
      return Optional.empty();
    }
    if (!(result instanceof JwtVerifier.Accepted ok)) return Optional.empty();

    String uri = req.getRequestURI(), ctx = req.getContextPath();
    String path = Scope.canonicalPath(uri.startsWith(ctx) ? uri.substring(ctx.length()) : uri);
    if (path == null) { Log.throttledWarn(LOG, "path:" + ok.subject(), "jwt-auth: refused suspicious request path from " + Log.clean(ok.subject()) + ": " + Log.clean(uri)); return Optional.empty(); }
    if (!Scope.pathAllowed(path, ok.allowedPathPrefixes())) {
      Log.throttledWarn(LOG, "denied-path:" + ok.subject(), "jwt-auth: " + Log.clean(ok.subject()) + " (" + ok.source() + ") may not call " + path + " (add it to allowedPathPrefixes if intended)");
      return Optional.empty();
    }
    String violation = Scope.violation(path, req::getParameterValues, ok.projectKeyPattern());
    if (violation != null) {
      Log.throttledWarn(LOG, "scope:" + ok.subject(), "jwt-auth: " + Log.clean(ok.subject()) + " (" + ok.source() + ") denied on " + path + ": " + violation);
      // Not an exception: a ForbiddenException thrown here is not handled by SonarQube's authentication layer (HTTP 500). Declining leaves
      // the JWT unrecognised, so the request ends in the normal 401 and the reason is in the log.
      return Optional.empty();
    }

    UserDto user = findOrProvision(ok);
    if (user == null) return Optional.empty();
    LOG.debug("jwt-auth: {} ({}) -> user {} for {} {}", ok.subject(), ok.source(), user.getLogin(), req.getMethod(), path);
    return Optional.of(sessions.create(user, false));
  }

  /**
   * Provisioned users are found by external identity: SonarQube's registrar generates its own internal login
   * (derived from the display name) and keeps ours as the external id. A user an admin deactivated stays deactivated,
   * and a user of another origin (e.g. a local account) is never adopted by an autoProvision rule.
   */
  private UserDto findOrProvision(JwtVerifier.Accepted ok) {
    JwtVerifier.Provisioning prov = ok.provisioning();
    if (prov == null) {
      try (DbSession s = db.openSession(false)) {
        UserDto u = db.userDao().selectActiveUserByLogin(s, ok.login());
        if (u == null) Log.throttledWarn(LOG, "nouser:" + ok.login(), "jwt-auth: " + Log.clean(ok.subject()) + " (" + ok.source() + ") maps to unknown/inactive SonarQube user '" + ok.login() + "'");
        return u;
      }
    }
    UserDto ours = selectOurs(ok.login());
    if (ours != null && !ours.isActive()) { Log.throttledWarn(LOG, "deact:" + ok.login(), "jwt-auth: user for '" + ok.login() + "' was deactivated by an administrator"); return null; }
    long now = System.currentTimeMillis();
    if (ours != null && now - lastSync.getOrDefault(ok.login(), 0L) < RESYNC_MS) return ours;

    synchronized (locks.computeIfAbsent(ok.login(), k -> new Object())) {
      ours = selectOurs(ok.login()); // another thread may have created it while we waited
      if (ours != null && !ours.isActive()) return null;
      if (ours != null && System.currentTimeMillis() - lastSync.getOrDefault(ok.login(), 0L) < RESYNC_MS) return ours;
      if (ours == null) {
        UserDto clash;
        try (DbSession s = db.openSession(false)) { clash = db.userDao().selectActiveUserByLogin(s, ok.login()); }
        if (clash != null) {
          Log.throttledWarn(LOG, "clash:" + ok.login(), "jwt-auth: refusing to provision '" + ok.login() + "': a SonarQube user with that login already exists and is not managed by jwt-auth");
          return null;
        }
      }
      try {
        UserDto registered = registrar.register(UserRegistration.builder()
            .setUserIdentity(UserIdentity.builder().setProviderId(ok.login()).setProviderLogin(ok.login()).setLogin(ok.login())
                .setName(prov.name()).setGroups(new HashSet<>(prov.groups())).build())
            .setProvider(provider).setSource(AuthenticationEvent.Source.external(provider)).build());
        lastSync.put(ok.login(), System.currentTimeMillis());
        if (ours == null) LOG.info("jwt-auth: provisioned user '{}' (login {}) for {} ({}) in groups {}", ok.login(), registered.getLogin(), Log.clean(ok.subject()), ok.source(), prov.groups());
        return registered;
      } catch (RuntimeException e) {
        UserDto again = selectOurs(ok.login()); // lost a race against another node/process: the user exists now
        if (again != null && again.isActive()) return again;
        Log.throttledWarn(LOG, "provfail:" + ok.login(), "jwt-auth: provisioning '" + ok.login() + "' failed: " + e);
        return ours != null && ours.isActive() ? ours : null;
      }
    }
  }

  private UserDto selectOurs(String externalId) {
    try (DbSession s = db.openSession(false)) { return db.userDao().selectByExternalIdAndIdentityProvider(s, externalId, JwtIdentityProvider.KEY); }
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
