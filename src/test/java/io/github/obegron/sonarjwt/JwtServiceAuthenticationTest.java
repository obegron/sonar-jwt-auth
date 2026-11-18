package io.github.obegron.sonarjwt;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sonar.api.server.http.HttpRequest;
import org.sonar.db.DbClient;
import org.sonar.db.DbSession;
import org.sonar.db.user.UserDao;
import org.sonar.db.user.UserDto;
import org.sonar.server.authentication.UserRegistrar;
import org.sonar.server.user.UserSession;
import org.sonar.server.user.UserSessionFactory;

/** The glue between a verified JWT and SonarQube's user model, with SonarQube's services mocked. */
class JwtServiceAuthenticationTest {
  static final String ISS = "https://issuer.test";
  DbClient db = mock(DbClient.class); UserDao users = mock(UserDao.class); DbSession dbSession = mock(DbSession.class);
  UserSessionFactory sessions = mock(UserSessionFactory.class); UserRegistrar registrar = mock(UserRegistrar.class);
  UserSession session = mock(UserSession.class);
  JwtVerifierTest.Cluster cluster; Path cfg; JwtVerifierTest.MutableClock clock;

  @BeforeEach void setUp() throws Exception {
    when(db.openSession(false)).thenReturn(dbSession); when(db.userDao()).thenReturn(users);
    when(sessions.create(any(UserDto.class), eq(false))).thenReturn(session);
    clock = new JwtVerifierTest.MutableClock(java.time.Instant.parse("2026-11-18T12:00:00Z"));
    cluster = new JwtVerifierTest.Cluster("http://unused", "k1");
    Path jwks = Files.createTempFile("jwks", ".json"); Files.writeString(jwks, cluster.jwks());
    cfg = Files.createTempFile("cfg", ".json");
    write("""
      {"sources":[{"name":"it","issuer":"%s","jwksFile":"%s","audiences":["sonarqube"],"rules":[
        {"subject":"system:serviceaccount:team:fixed","login":"existing-user"},
        {"subject":"system:serviceaccount:(?<ns>[a-z0-9]+):(?<sa>[a-z0-9]+)","login":"ci_${ns}_${sa}","name":"CI ${ns}/${sa}","autoProvision":true,"groups":["scanners"],"projectKeyPattern":"team-.*"}]}]}
      """.formatted(ISS, jwks));
  }

  void write(String json) throws Exception { Files.writeString(cfg, json); }
  JwtServiceAuthentication auth() { return new JwtServiceAuthentication(db, sessions, registrar, new ConfigHolder(cfg, Clock.systemUTC(), false)); }

  String jwt(String sub) throws Exception {
    long now = java.time.Instant.now().getEpochSecond();
    return JwtVerifierTest.sign(cluster.rsa.getPrivate(), Map.of("alg", "RS256", "kid", "k1"),
        Map.of("iss", ISS, "sub", sub, "aud", List.of("sonarqube"), "iat", now, "exp", now + 300));
  }

  HttpRequest request(String token, String path, String... params) {
    HttpRequest r = mock(HttpRequest.class);
    when(r.getHeader("Authorization")).thenReturn(token == null ? null : "Bearer " + token);
    when(r.getRequestURI()).thenReturn(path); when(r.getContextPath()).thenReturn(""); when(r.getMethod()).thenReturn("POST");
    for (int i = 0; i < params.length; i += 2) when(r.getParameterValues(params[i])).thenReturn(new String[] {params[i + 1]});
    return r;
  }

  UserDto user(String login, boolean active, String provider) {
    UserDto u = new UserDto(); u.setLogin(login); u.setActive(active); u.setExternalIdentityProvider(provider); return u;
  }

  @Test void requestsWithoutAJwtAreLeftAlone() throws Exception {
    JwtServiceAuthentication a = auth();
    assertTrue(a.authenticate(request(null, "/api/ce/submit")).isEmpty());
    assertTrue(a.authenticate(request("squ_abcdef0123456789", "/api/ce/submit")).isEmpty());
    verifyNoInteractions(users, registrar);
  }

  @Test void existingUserRuleMapsToThatUser() throws Exception {
    when(users.selectActiveUserByLogin(dbSession, "existing-user")).thenReturn(user("existing-user", true, "sonarqube"));
    assertTrue(auth().authenticate(request(jwt("system:serviceaccount:team:fixed"), "/api/server/version")).isPresent());
    verify(registrar, never()).register(any());
  }

  @Test void unknownUserWithoutAutoProvisionIsRefused() throws Exception {
    when(users.selectActiveUserByLogin(dbSession, "existing-user")).thenReturn(null);
    assertTrue(auth().authenticate(request(jwt("system:serviceaccount:team:fixed"), "/api/server/version")).isEmpty());
  }

  @Test void newIdentityIsProvisionedOnceWithGroups() throws Exception {
    UserDto created = user("ci-team-bot123", true, "jwt-auth");
    when(users.selectByExternalIdAndIdentityProvider(dbSession, "ci_team_bot", "jwt-auth")).thenReturn(null);
    when(users.selectActiveUserByLogin(dbSession, "ci_team_bot")).thenReturn(null);
    when(registrar.register(any())).thenReturn(created);
    JwtServiceAuthentication a = auth(); String t = jwt("system:serviceaccount:team:bot");
    assertTrue(a.authenticate(request(t, "/api/projects/create", "project", "team-x")).isPresent());
    when(users.selectByExternalIdAndIdentityProvider(dbSession, "ci_team_bot", "jwt-auth")).thenReturn(created); // now exists
    assertTrue(a.authenticate(request(t, "/api/projects/create", "project", "team-y")).isPresent());
    verify(registrar, times(1)).register(any());   // second call reuses the user, within the 5 minute resync window
  }

  @Test void provisioningNeverAdoptsAUserOfAnotherOrigin() throws Exception {
    when(users.selectByExternalIdAndIdentityProvider(any(), eq("ci_team_bot"), eq("jwt-auth"))).thenReturn(null);
    when(users.selectActiveUserByLogin(dbSession, "ci_team_bot")).thenReturn(user("ci_team_bot", true, "sonarqube")); // a local account with that login
    assertTrue(auth().authenticate(request(jwt("system:serviceaccount:team:bot"), "/api/projects/create", "project", "team-x")).isEmpty());
    verify(registrar, never()).register(any());
  }

  @Test void aUserDeactivatedByAnAdministratorStaysDeactivated() throws Exception {
    when(users.selectByExternalIdAndIdentityProvider(dbSession, "ci_team_bot", "jwt-auth")).thenReturn(user("ci-team-bot1", false, "jwt-auth"));
    assertTrue(auth().authenticate(request(jwt("system:serviceaccount:team:bot"), "/api/projects/create", "project", "team-x")).isEmpty());
    verify(registrar, never()).register(any());
  }

  @Test void scopePathAndRoutingRulesAreEnforcedBeforeAnyUserLookup() throws Exception {
    String t = jwt("system:serviceaccount:team:bot");
    JwtServiceAuthentication a = auth();
    assertTrue(a.authenticate(request(t, "/api/projects/create", "project", "other-x")).isEmpty());   // outside projectKeyPattern
    assertTrue(a.authenticate(request(t, "/api/ce/submit")).isEmpty());                                // names no project
    assertTrue(a.authenticate(request(t, "/api/users/search")).isEmpty());                             // not allowed
    assertTrue(a.authenticate(request(t, "/api/ce/submit/../../api/users/search", "projectKey", "team-x")).isEmpty()); // routing trick
    verifyNoInteractions(users, registrar);
  }

  @Test void aFailureInsideTheExtensionNeverBreaksTheRequest() throws Exception {
    when(db.openSession(false)).thenThrow(new IllegalStateException("db down"));
    assertTrue(auth().authenticate(request(jwt("system:serviceaccount:team:fixed"), "/api/server/version")).isEmpty());
    // and a malformed config means "feature off", not an error
    write("{ not json"); 
    assertEquals(Optional.empty(), auth().authenticate(request(jwt("system:serviceaccount:team:fixed"), "/api/server/version")));
  }

  @Test void aLoserOfAProvisioningRaceStillGetsTheUser() throws Exception {
    UserDto created = user("ci-team-bot9", true, "jwt-auth");
    when(users.selectByExternalIdAndIdentityProvider(dbSession, "ci_team_bot", "jwt-auth")).thenReturn(null, null, created); // appears after the failed insert
    when(users.selectActiveUserByLogin(dbSession, "ci_team_bot")).thenReturn(null);
    when(registrar.register(any())).thenThrow(new IllegalStateException("duplicate key"));
    assertTrue(auth().authenticate(request(jwt("system:serviceaccount:team:bot"), "/api/projects/create", "project", "team-x")).isPresent());
  }
}
