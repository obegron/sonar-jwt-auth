package io.github.obegron.sonarjwt;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JwtVerifierTest {
  static final String ISS = "https://kubernetes.default.svc.cluster.local";
  static final ObjectMapper JSON = new ObjectMapper();

  MutableClock clock;
  Map<String, String> web; // url -> body
  int fetches;

  /** One JWKS "cluster": signing key pair plus the discovery documents that publish it. */
  static final class Cluster {
    final String base; final KeyPair rsa; final String kid;
    Cluster(String base, String kid) throws Exception {
      this.base = base; this.kid = kid;
      KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); g.initialize(2048); rsa = g.generateKeyPair();
    }
    String jwks() throws Exception {
      RSAPublicKey k = (RSAPublicKey) rsa.getPublic();
      return JSON.writeValueAsString(Map.of("keys", List.of(Map.of("kty", "RSA", "kid", kid, "alg", "RS256", "use", "sig",
          "n", b64(unsigned(k.getModulus().toByteArray())), "e", b64(unsigned(k.getPublicExponent().toByteArray()))))));
    }
    void publish(Map<String, String> web, String issuer) throws Exception {
      web.put(base + "/.well-known/openid-configuration", JSON.writeValueAsString(Map.of("issuer", issuer, "jwks_uri", base + "/jwks")));
      web.put(base + "/jwks", jwks());
    }
  }

  @BeforeEach void setUp() { clock = new MutableClock(Instant.parse("2026-11-18T12:00:00Z")); web = new HashMap<>(); fetches = 0; }

  JwtVerifier verifier(String json) throws Exception {
    return new JwtVerifier(AuthConfig.parse(json), (url, auth) -> { fetches++; String b = web.get(url); if (b == null) throw new IllegalStateException("404 " + url); return b; }, clock);
  }

  static String config(String... sources) { return "{\"sources\":[" + String.join(",", sources) + "]}"; }
  static String source(String name, String base, String subjectRegex, String login) {
    return "{\"name\":\"" + name + "\",\"issuer\":\"" + ISS + "\",\"discoveryUrl\":\"" + base + "\",\"allowInsecureHttp\":true,"
        + "\"audiences\":[\"sonarqube\"],\"rules\":[{\"subject\":\"" + subjectRegex + "\",\"login\":\"" + login + "\"}]}";
  }

  String token(Cluster c, Map<String, Object> claimOverrides) throws Exception {
    Map<String, Object> claims = new LinkedHashMap<>(Map.of("iss", ISS, "sub", "system:serviceaccount:ci:pipeline", "aud", List.of("sonarqube"),
        "exp", clock.instant().plusSeconds(600).getEpochSecond(), "iat", clock.instant().getEpochSecond()));
    claims.putAll(claimOverrides);
    claims.values().removeIf(Objects::isNull);
    return sign(c.rsa.getPrivate(), Map.of("alg", "RS256", "kid", c.kid, "typ", "JWT"), claims);
  }

  static String sign(PrivateKey key, Map<String, Object> header, Map<String, Object> claims) throws Exception {
    String signing = b64(JSON.writeValueAsBytes(header)) + "." + b64(JSON.writeValueAsBytes(claims));
    Signature s = Signature.getInstance("SHA256withRSA"); s.initSign(key); s.update(signing.getBytes(StandardCharsets.US_ASCII));
    return signing + "." + b64(s.sign());
  }

  @Test void acceptsValidTokenAndMapsLogin() throws Exception {
    Cluster c = new Cluster("http://t", "k1"); c.publish(web, ISS);
    var r = verifier(config(source("tekton", "http://t", "system:serviceaccount:ci:pipeline", "tekton-scanner"))).verify(token(c, Map.of()));
    var ok = assertInstanceOf(JwtVerifier.Accepted.class, r);
    assertEquals("tekton-scanner", ok.login()); assertEquals("tekton", ok.source());
  }

  @Test void loginTemplateUsesNamedGroups() throws Exception {
    Cluster c = new Cluster("http://t", "k1"); c.publish(web, ISS);
    var r = verifier(config(source("t", "http://t", "system:serviceaccount:(?<ns>[a-z-]+):pipeline", "ci-${ns}"))).verify(token(c, Map.of()));
    assertEquals("ci-ci", assertInstanceOf(JwtVerifier.Accepted.class, r).login());
  }

  @Test void rejectsExpiredButToleratesSkew() throws Exception {
    Cluster c = new Cluster("http://t", "k1"); c.publish(web, ISS);
    JwtVerifier v = verifier(config(source("t", "http://t", ".*", "uu")));
    long now = clock.instant().getEpochSecond();
    assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(c, Map.of("exp", now - 30))));
    assertInstanceOf(JwtVerifier.Rejected.class, v.verify(token(c, Map.of("exp", now - 120))));
  }

  @Test void rejectsMissingExpNotYetValidWrongAudienceMissingSub() throws Exception {
    Cluster c = new Cluster("http://t", "k1"); c.publish(web, ISS);
    JwtVerifier v = verifier(config(source("t", "http://t", ".*", "uu")));
    Map<String, Object> noExp = new HashMap<>(); noExp.put("exp", null);
    assertInstanceOf(JwtVerifier.Rejected.class, v.verify(token(c, noExp)));
    assertInstanceOf(JwtVerifier.Rejected.class, v.verify(token(c, Map.of("nbf", clock.instant().getEpochSecond() + 3600))));
    assertInstanceOf(JwtVerifier.Rejected.class, v.verify(token(c, Map.of("aud", List.of("other")))));
    assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(c, Map.of("aud", "sonarqube"))));
    assertInstanceOf(JwtVerifier.Rejected.class, v.verify(token(c, Map.of("sub", ""))));
  }

  @Test void autoProvisionRuleCarriesNameAndGroupsAndInvalidLoginsAreRejected() throws Exception {
    Cluster c = new Cluster("http://t", "k1"); c.publish(web, ISS);
    String cfg = config("{\"name\":\"t\",\"issuer\":\"" + ISS + "\",\"discoveryUrl\":\"http://t\",\"allowInsecureHttp\":true,\"audiences\":[\"sonarqube\"],\"rules\":["
        + "{\"subject\":\"system:serviceaccount:(?<ns>[^:]+):(?<sa>[^:]+)\",\"login\":\"k8s-${ns}-${sa}\",\"name\":\"SA ${ns}/${sa}\",\"autoProvision\":true,\"groups\":[\"scanners\"]}]}");
    var ok = assertInstanceOf(JwtVerifier.Accepted.class, verifier(cfg).verify(token(c, Map.of())));
    assertEquals("k8s-ci-pipeline", ok.login());
    assertEquals("SA ci/pipeline", ok.provisioning().name());
    assertEquals(List.of("scanners"), ok.provisioning().groups());
    // a sub that would produce a login with illegal characters is refused
    assertInstanceOf(JwtVerifier.Rejected.class, verifier(cfg).verify(token(c, Map.of("sub", "system:serviceaccount:ci:we ird/sa"))));
    // rules without autoProvision carry no provisioning info
    assertNull(assertInstanceOf(JwtVerifier.Accepted.class, verifier(config(source("t", "http://t", ".*", "fixed-user"))).verify(token(c, Map.of()))).provisioning());
  }

  @Test void provisioningConfigIsValidated() {
    String head = "{\"name\":\"a\",\"issuer\":\"https://i\",\"audiences\":[\"x\"],\"rules\":[";
    assertThrows(IllegalArgumentException.class, () -> AuthConfig.parse(config(head + "{\"subject\":\".*\",\"login\":\"uu\",\"groups\":[\"g\"]}]}")));  // groups need autoProvision
    assertThrows(IllegalArgumentException.class, () -> AuthConfig.parse(config(head + "{\"subject\":\".*\",\"login\":\"uu\",\"autoProvision\":true,\"groups\":[\"sonar-administrators\"]}]}")));
    assertDoesNotThrow(() -> AuthConfig.parse(config(head + "{\"subject\":\".*\",\"login\":\"uu\",\"autoProvision\":true,\"groups\":[\"scanners\"]}]}")));
  }

  @Test void sourcePlaceholderKeepsSameSubjectOfDifferentClustersApart() throws Exception {
    Cluster a = new Cluster("http://a", "k1"), b = new Cluster("http://b", "k1"); a.publish(web, ISS); b.publish(web, ISS);
    JwtVerifier v = verifier(config(source("jenkins", "http://a", ".*", "gw-${source}"), source("tekton", "http://b", ".*", "gw-${source}")));
    assertEquals("gw-jenkins", assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(a, Map.of()))).login());
    assertEquals("gw-tekton", assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(b, Map.of()))).login());
  }

  // ---------------- key sources: jwksFile, jwksUri, host pinning, reload, https + CA + bearer

  @Test void jwksFileNeedsNoNetworkAndIsReReadOnRotation() throws Exception {
    Cluster c = new Cluster("http://unused", "k1");
    java.nio.file.Path f = java.nio.file.Files.createTempFile("jwks", ".json"); java.nio.file.Files.writeString(f, c.jwks());
    JwtVerifier v = verifier(config("{\"name\":\"f\",\"issuer\":\"" + ISS + "\",\"jwksFile\":\"" + f + "\",\"audiences\":[\"sonarqube\"],\"rules\":[{\"subject\":\".*\",\"login\":\"file-user\"}]}"));
    assertEquals("file-user", assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(c, Map.of()))).login());
    assertEquals(0, fetches);
    Cluster rotated = new Cluster("http://unused", "k2");
    java.nio.file.Files.writeString(f, rotated.jwks());
    clock.advance(Duration.ofSeconds(11));
    assertEquals("file-user", assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(rotated, Map.of()))).login());
  }

  @Test void jwksUriSkipsDiscoveryAndJwksFileExcludesUrls() throws Exception {
    Cluster c = new Cluster("http://t", "k1"); web.put("http://t/keys", c.jwks()); // no discovery document at all
    JwtVerifier v = verifier(config("{\"name\":\"u\",\"issuer\":\"" + ISS + "\",\"jwksUri\":\"http://t/keys\",\"allowInsecureHttp\":true,\"audiences\":[\"sonarqube\"],\"rules\":[{\"subject\":\".*\",\"login\":\"uri-user\"}]}"));
    assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(c, Map.of())));
    assertThrows(IllegalArgumentException.class, () -> AuthConfig.parse(config("{\"name\":\"u\",\"issuer\":\"" + ISS + "\",\"jwksFile\":\"/x\",\"jwksUri\":\"https://h/k\",\"audiences\":[\"a\"],\"rules\":[{\"subject\":\".*\",\"login\":\"uu\"}]}")));
  }

  @Test void jwksUriFromDiscoveryMustStayOnTheDiscoveryHost() throws Exception {
    Cluster c = new Cluster("http://t", "k1");
    web.put("http://t/.well-known/openid-configuration", JSON.writeValueAsString(Map.of("issuer", ISS, "jwks_uri", "http://elsewhere/jwks")));
    web.put("http://elsewhere/jwks", c.jwks());
    String strict = config(source("t", "http://t", ".*", "uu"));
    assertInstanceOf(JwtVerifier.Rejected.class, verifier(strict).verify(token(c, Map.of())));
    String relaxed = strict.replace("\"allowInsecureHttp\":true", "\"allowInsecureHttp\":true,\"allowForeignJwksHost\":true");
    assertInstanceOf(JwtVerifier.Accepted.class, verifier(relaxed).verify(token(c, Map.of())));
  }

  @Test void reloadingConfigKeepsCachedKeysOfUnchangedSources() throws Exception {
    Cluster c = new Cluster("http://t", "k1"); c.publish(web, ISS);
    String json = config(source("t", "http://t", ".*", "uu"));
    KeySet.Fetcher f = (url, auth) -> { fetches++; return web.get(url); };
    JwtVerifier first = new JwtVerifier(AuthConfig.parse(json), f, clock);
    assertInstanceOf(JwtVerifier.Accepted.class, first.verify(token(c, Map.of())));
    int afterFirst = fetches;
    web.clear(); // issuer now unreachable
    JwtVerifier reloaded = new JwtVerifier(AuthConfig.parse(json.replace("\"uu\"", "\"vv\"")), clock, first); // only a rule changed
    assertEquals("vv", assertInstanceOf(JwtVerifier.Accepted.class, reloaded.verify(token(c, Map.of()))).login());
    assertEquals(afterFirst, fetches);
  }

  @Test void configRejectsAdjacentPlaceholdersAndWildcardWithScope() {
    String head = "{\"name\":\"a\",\"issuer\":\"https://i\",\"audiences\":[\"x\"],";
    assertThrows(IllegalArgumentException.class, () -> AuthConfig.parse(config(head + "\"rules\":[{\"subject\":\".*\",\"login\":\"ci_${a}${b}\"}]}")));
    assertThrows(IllegalArgumentException.class, () -> AuthConfig.parse(config(head + "\"allowedPathPrefixes\":[\"*\"],\"rules\":[{\"subject\":\".*\",\"login\":\"fixed-user\",\"projectKeyPattern\":\"a-.*\"}]}")));
    assertDoesNotThrow(() -> AuthConfig.parse(config(head + "\"allowedPathPrefixes\":[\"*\"],\"rules\":[{\"subject\":\".*\",\"login\":\"fixed-user\"}]}")));
  }

  @Test void httpsWithPrivateCaAndBearerTokenWorksAndAnUntrustedCaFails() throws Exception {
    java.nio.file.Path dir = java.nio.file.Files.createTempDirectory("tls");
    String keytool = System.getProperty("java.home") + "/bin/keytool";
    run(keytool, "-genkeypair", "-alias", "s", "-keyalg", "RSA", "-keysize", "2048", "-validity", "2", "-dname", "CN=localhost", "-ext", "san=dns:localhost",
        "-keystore", dir + "/ks.p12", "-storetype", "PKCS12", "-storepass", "changeit", "-keypass", "changeit");
    run(keytool, "-exportcert", "-rfc", "-alias", "s", "-keystore", dir + "/ks.p12", "-storepass", "changeit", "-file", dir + "/ca.pem");
    java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
    try (var in = java.nio.file.Files.newInputStream(dir.resolve("ks.p12"))) { ks.load(in, "changeit".toCharArray()); }
    javax.net.ssl.KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory.getInstance("SunX509"); kmf.init(ks, "changeit".toCharArray());
    javax.net.ssl.SSLContext ssl = javax.net.ssl.SSLContext.getInstance("TLS"); ssl.init(kmf.getKeyManagers(), null, null);
    com.sun.net.httpserver.HttpsServer srv = com.sun.net.httpserver.HttpsServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
    srv.setHttpsConfigurator(new com.sun.net.httpserver.HttpsConfigurator(ssl));
    Cluster c = new Cluster("https://localhost:" + srv.getAddress().getPort(), "k1");
    List<String> sawAuth = java.util.Collections.synchronizedList(new ArrayList<>());
    String discoveryBody = JSON.writeValueAsString(Map.of("issuer", ISS, "jwks_uri", c.base + "/jwks")), jwksBody = c.jwks();
    srv.createContext("/", ex -> {
      sawAuth.add(ex.getRequestURI().getPath() + "=" + ex.getRequestHeaders().getFirst("Authorization"));
      String body = ex.getRequestURI().getPath().endsWith("openid-configuration") ? discoveryBody : jwksBody;
      byte[] b = body.getBytes(StandardCharsets.UTF_8); ex.sendResponseHeaders(200, b.length); ex.getResponseBody().write(b); ex.close();
    });
    srv.start();
    try {
      java.nio.file.Path tok = dir.resolve("token"); java.nio.file.Files.writeString(tok, "sa-token-123\n");
      String src = "{\"name\":\"k8s\",\"issuer\":\"" + ISS + "\",\"discoveryUrl\":\"" + c.base + "\",\"caFile\":\"" + dir + "/ca.pem\",\"bearerTokenFile\":\"" + tok
          + "\",\"audiences\":[\"sonarqube\"],\"rules\":[{\"subject\":\".*\",\"login\":\"tls-user\"}]}";
      JwtVerifier trusted = new JwtVerifier(AuthConfig.parse(config(src)), clock, null);
      assertEquals("tls-user", assertInstanceOf(JwtVerifier.Accepted.class, trusted.verify(token(c, Map.of()))).login());
      assertTrue(sawAuth.contains("/.well-known/openid-configuration=Bearer sa-token-123"), sawAuth.toString());
      // no caFile -> the self-signed certificate is not trusted -> keys never load
      JwtVerifier untrusted = new JwtVerifier(AuthConfig.parse(config(src.replace("\"caFile\":\"" + dir + "/ca.pem\",", ""))), clock, null);
      assertInstanceOf(JwtVerifier.Rejected.class, untrusted.verify(token(c, Map.of())));
    } finally { srv.stop(0); }
  }

  private static void run(String... cmd) throws Exception {
    Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
    String out = new String(p.getInputStream().readAllBytes());
    assertEquals(0, p.waitFor(), out);
  }

  // ---------------- per-identity project scope, placeholder validation, hardening of the fetcher

  @Test void projectKeyPatternCanUseCapturedValuesQuoted() throws Exception {
    Cluster c = new Cluster("http://t", "k1"); c.publish(web, ISS);
    String cfg = config("{\"name\":\"t\",\"issuer\":\"" + ISS + "\",\"discoveryUrl\":\"http://t\",\"allowInsecureHttp\":true,\"audiences\":[\"sonarqube\"],\"rules\":["
        + "{\"subject\":\"system:serviceaccount:(?<ns>[^:]+):(?<sa>[^:]+)\",\"login\":\"ci_${ns}_${sa}\",\"autoProvision\":true,\"projectKeyPattern\":\"${ns}_.*\"}]}");
    JwtVerifier v = verifier(cfg);
    var a = assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(c, Map.of("sub", "system:serviceaccount:team-a:bot"))));
    assertTrue(a.projectKeyPattern().matcher("team-a_service").matches());
    assertFalse(a.projectKeyPattern().matcher("team-b_service").matches());
    // the overlap a hyphen separator would cause: namespace "team" vs project of "team-dev"
    var team = assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(c, Map.of("sub", "system:serviceaccount:team:bot"))));
    assertFalse(team.projectKeyPattern().matcher("team-dev_x").matches());
    // a captured value containing regex syntax ('.') matches only itself; values the login check refuses (a '*') never get this far
    var dotted = assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(c, Map.of("sub", "system:serviceaccount:a.b:bot"))));
    assertFalse(dotted.projectKeyPattern().matcher("axb_x").matches());
    assertTrue(dotted.projectKeyPattern().matcher("a.b_x").matches());
    assertInstanceOf(JwtVerifier.Rejected.class, v.verify(token(c, Map.of("sub", "system:serviceaccount:a.*:bot"))));
  }

  @Test void unknownPlaceholdersAndBadSourceNamesAreCaughtAtConfigLoad() {
    String head = "\"issuer\":\"https://i\",\"audiences\":[\"x\"],";
    String sub = "\"subject\":\"system:serviceaccount:(?<ns>[^:]+):(?<sa>[^:]+)\"";
    assertThrows(IllegalArgumentException.class, () -> AuthConfig.parse(config("{\"name\":\"a\"," + head + "\"rules\":[{" + sub + ",\"login\":\"ci_${nss}_${sa}\"}]}")));
    assertThrows(IllegalArgumentException.class, () -> AuthConfig.parse(config("{\"name\":\"a\"," + head + "\"rules\":[{" + sub + ",\"login\":\"ci_${ns}\",\"projectKeyPattern\":\"${team}-.*\"}]}")));
    // a source name containing the separator makes every token "ambiguous": refuse the config instead of failing at request time
    assertThrows(IllegalArgumentException.class, () -> AuthConfig.parse(config("{\"name\":\"tekton_prod\"," + head + "\"rules\":[{" + sub + ",\"login\":\"ci_${source}_${ns}\"}]}")));
    assertDoesNotThrow(() -> AuthConfig.parse(config("{\"name\":\"tekton-prod\"," + head + "\"rules\":[{" + sub + ",\"login\":\"ci_${source}_${ns}\",\"projectKeyPattern\":\"${ns}_.*\"}]}")));
  }

  @Test void anUnusableCaFileFailsClosedInsteadOfFallingBackToTheJvmTrustStore() throws Exception {
    Cluster c = new Cluster("https://localhost:1", "k1");
    String src = "{\"name\":\"k\",\"issuer\":\"" + ISS + "\",\"discoveryUrl\":\"https://localhost:1\",\"caFile\":\"/nonexistent/ca.pem\","
        + "\"audiences\":[\"sonarqube\"],\"rules\":[{\"subject\":\".*\",\"login\":\"tls-user\"}]}";
    assertInstanceOf(JwtVerifier.Rejected.class, new JwtVerifier(AuthConfig.parse(config(src)), clock, null).verify(token(c, Map.of())));
  }

  @Test void aSlowDripResponseCannotHoldARefreshThreadForever() throws Exception {
    com.sun.net.httpserver.HttpServer srv = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
    srv.createContext("/", ex -> { ex.sendResponseHeaders(200, 100_000); ex.getResponseBody().write(new byte[10]); ex.getResponseBody().flush();
      try { Thread.sleep(6000); } catch (InterruptedException ignored) { } ex.close(); });
    srv.start();
    long old = KeySet.readDeadlineSeconds; KeySet.readDeadlineSeconds = 1;
    try {
      Cluster c = new Cluster("http://127.0.0.1:" + srv.getAddress().getPort(), "k1");
      String src = "{\"name\":\"slow\",\"issuer\":\"" + ISS + "\",\"jwksUri\":\"" + c.base + "/jwks\",\"allowInsecureHttp\":true,"
          + "\"audiences\":[\"sonarqube\"],\"rules\":[{\"subject\":\".*\",\"login\":\"slow-user\"}]}";
      long t0 = System.nanoTime();
      assertInstanceOf(JwtVerifier.Rejected.class, new JwtVerifier(AuthConfig.parse(config(src)), clock, null).verify(token(c, Map.of())));
      assertTrue((System.nanoTime() - t0) / 1_000_000_000 < 5, "caller waited at most WAIT_SECONDS");
    } finally { KeySet.readDeadlineSeconds = old; srv.stop(0); }
  }

  @Test void qualityGateWaitIsOffByDefaultAndAddsExactlyTwoPathsWhenEnabled() throws Exception {
    String head = "{\"name\":\"a\",\"issuer\":\"https://i\",\"audiences\":[\"x\"],";
    String rules = "\"rules\":[{\"subject\":\".*\",\"login\":\"fixed-user\"}]}";
    var off = AuthConfig.parse(config(head + rules)).sources.get(0).effectiveAllowedPaths();
    assertFalse(off.contains("/api/ce/task")); assertFalse(off.contains("/api/qualitygates/project_status"));
    var on = AuthConfig.parse(config(head + "\"allowQualityGateWait\":true," + rules)).sources.get(0).effectiveAllowedPaths();
    assertTrue(on.contains("/api/ce/task") && on.contains("/api/qualitygates/project_status"));
    assertEquals(off.size() + 2, on.size());
    assertTrue(on.contains("/api/new_code_periods/show"));
  }

  @Test void riskyConfigIsAcceptedButWarnedAbout() throws Exception {
    String head = "{\"name\":\"a\",\"issuer\":\"https://i\",\"audiences\":[\"x\"],";
    String sub = "\"subject\":\"system:serviceaccount:(?<ns>[^:]+):(?<sa>[^:]+)\"";
    AuthConfig noScope = AuthConfig.parse(config(head + "\"rules\":[{" + sub + ",\"login\":\"ci_${ns}\",\"autoProvision\":true}]}"));
    assertTrue(noScope.warnings.stream().anyMatch(w -> w.contains("no projectKeyPattern")), noScope.warnings.toString());
    AuthConfig hyphen = AuthConfig.parse(config(head + "\"rules\":[{" + sub + ",\"login\":\"ci_${ns}\",\"autoProvision\":true,\"projectKeyPattern\":\"${ns}-.*\"}]}"));
    assertTrue(hyphen.warnings.stream().anyMatch(w -> w.contains("team-dev")), hyphen.warnings.toString());
    AuthConfig good = AuthConfig.parse(config(head + "\"rules\":[{" + sub + ",\"login\":\"ci_${ns}\",\"autoProvision\":true,\"projectKeyPattern\":\"${ns}_.*\"}]}"));
    assertEquals(List.of(), good.warnings);
  }

  @Test void anUnscopedRuleIsDeclaredWithDotStarAndRaisesNoWarning() throws Exception {
    String head = "{\"name\":\"jenkins\",\"issuer\":\"https://i\",\"audiences\":[\"x\"],";
    AuthConfig c = AuthConfig.parse(config(head + "\"rules\":[{\"subject\":\".*\",\"login\":\"jenkins_ci\",\"autoProvision\":true,\"projectKeyPattern\":\".*\"}]}"));
    assertEquals(List.of(), c.warnings);                                         // an explicit ".*" is a deliberate choice: no warning
    var pattern = c.sources.get(0).rules.get(0).projectPattern;
    assertTrue(pattern.matcher("payments-api").matches() && pattern.matcher("Some.Other:key_1").matches());
  }

  @Test void aRefreshReturningNoKeysKeepsTheWorkingOnes() throws Exception {
    Cluster c = new Cluster("http://t", "k1"); c.publish(web, ISS);
    JwtVerifier v = verifier(config(source("t", "http://t", ".*", "uu")));
    assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(c, Map.of())));
    web.put("http://t/jwks", "{\"keys\":[]}");                    // issuer now publishes nothing usable
    clock.advance(Duration.ofMinutes(11));                           // past the cache TTL: refresh happens
    assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(c, Map.of())));
    assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(c, Map.of())));
  }

  @Test void logCategoriesGroupSimilarProblemsButNotDifferentOnes() {
    assertEquals(Log.category("subject 'a' matches no rule of source x"), Log.category("subject 'b' matches no rule of source x"));
    assertNotEquals(Log.category("token expired"), Log.category("audience not accepted by source x"));
  }

  @Test void statsSummarizeActivityOnceAndResetAndAreBounded() {
    Stats st = new Stats();
    assertNull(st.drain());
    st.accepted(); st.accepted(); st.provisioned(); st.denied(); st.rejected("token expired"); st.rejected("token expired"); st.rejected("audience not accepted");
    String line = st.drain();
    assertTrue(line.contains("authenticated=2") && line.contains("provisioned=1") && line.contains("denied(scope/path/user)=1") && line.contains("rejected=3"), line);
    assertTrue(line.contains("[token expired: 2]"), line);
    assertNull(st.drain());                                              // reset
    for (int i = 0; i < 500; i++) st.rejected("category " + i);          // an attacker cannot grow it without bound
    assertTrue(st.drain().length() < 600);
  }

  @Test void ruleMappingOntoAnExistingUserIsWarnedAbout() throws Exception {
    AuthConfig c = AuthConfig.parse(config(source("t", "http://t", ".*", "svc-user")));
    assertTrue(c.warnings.stream().anyMatch(w -> w.contains("EXISTING SonarQube user")), c.warnings.toString());
  }

  @Test void rejectsSubjectWithoutRule() throws Exception {
    Cluster c = new Cluster("http://t", "k1"); c.publish(web, ISS);
    var r = verifier(config(source("t", "http://t", "system:serviceaccount:ci:other", "u"))).verify(token(c, Map.of()));
    assertInstanceOf(JwtVerifier.Rejected.class, r);
  }

  @Test void rejectsTamperedPayloadAndForeignKey() throws Exception {
    Cluster c = new Cluster("http://t", "k1"); c.publish(web, ISS);
    Cluster attacker = new Cluster("http://evil", "k1"); // same kid, different key
    JwtVerifier v = verifier(config(source("t", "http://t", ".*", "uu")));
    assertInstanceOf(JwtVerifier.Rejected.class, v.verify(token(attacker, Map.of())));
    String[] p = token(c, Map.of()).split("\\.");
    String forged = p[0] + "." + b64(JSON.writeValueAsBytes(Map.of("iss", ISS, "sub", "admin", "aud", "sonarqube", "exp", clock.instant().plusSeconds(60).getEpochSecond()))) + "." + p[2];
    assertInstanceOf(JwtVerifier.Rejected.class, v.verify(forged));
  }

  @Test void rejectsAlgNoneAndHmacConfusion() throws Exception {
    Cluster c = new Cluster("http://t", "k1"); c.publish(web, ISS);
    JwtVerifier v = verifier(config(source("t", "http://t", ".*", "uu")));
    String none = b64(JSON.writeValueAsBytes(Map.of("alg", "none", "kid", "k1"))) + "." + b64(JSON.writeValueAsBytes(Map.of("iss", ISS, "sub", "x", "aud", "sonarqube", "exp", clock.instant().plusSeconds(60).getEpochSecond()))) + ".";
    assertInstanceOf(JwtVerifier.Rejected.class, v.verify(none));
    String hs = b64(JSON.writeValueAsBytes(Map.of("alg", "HS256", "kid", "k1"))) + "." + b64(JSON.writeValueAsBytes(Map.of("iss", ISS, "sub", "x", "aud", "sonarqube", "exp", clock.instant().plusSeconds(60).getEpochSecond()))) + "." + b64(new byte[32]);
    assertInstanceOf(JwtVerifier.Rejected.class, v.verify(hs));
  }

  @Test void notApplicableForOrdinarySonarTokensAndUnknownIssuers() throws Exception {
    Cluster c = new Cluster("http://t", "k1"); c.publish(web, ISS);
    JwtVerifier v = verifier(config(source("t", "http://t", ".*", "uu")));
    assertInstanceOf(JwtVerifier.NotApplicable.class, v.verify("squ_0123456789abcdef"));
    assertInstanceOf(JwtVerifier.NotApplicable.class, v.verify("a.b.c"));
    String other = sign(c.rsa.getPrivate(), Map.of("alg", "RS256", "kid", "k1"), Map.of("iss", "https://elsewhere", "sub", "x", "exp", clock.instant().plusSeconds(60).getEpochSecond()));
    assertInstanceOf(JwtVerifier.NotApplicable.class, v.verify(other));
  }

  @Test void keyRotationRefreshesOnUnknownKidButIsRateLimited() throws Exception {
    Cluster old = new Cluster("http://t", "k1"); old.publish(web, ISS);
    JwtVerifier v = verifier(config(source("t", "http://t", ".*", "uu")));
    assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(old, Map.of())));
    Cluster rotated = new Cluster("http://t", "k2"); rotated.publish(web, ISS);
    String t2 = token(rotated, Map.of());
    assertInstanceOf(JwtVerifier.Rejected.class, v.verify(t2)); // within the 10s retry window: no refetch yet
    clock.advance(Duration.ofSeconds(11));
    assertInstanceOf(JwtVerifier.Accepted.class, v.verify(t2));
  }

  @Test void twoClustersWithTheSameIssuerAreToldApartByTheirKeys() throws Exception {
    Cluster jenkins = new Cluster("http://jenkins", "k1"), tekton = new Cluster("http://tekton", "k1");
    jenkins.publish(web, ISS); tekton.publish(web, ISS);
    JwtVerifier v = verifier(config(
        source("jenkins", "http://jenkins", "system:serviceaccount:ci:pipeline", "gw-jenkins"),
        source("tekton", "http://tekton", "system:serviceaccount:ci:pipeline", "tekton-scanner")));
    assertEquals("gw-jenkins", assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(jenkins, Map.of()))).login());
    assertEquals("tekton-scanner", assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(tekton, Map.of()))).login());
  }

  @Test void unreachableSourceDoesNotBreakTheOthers() throws Exception {
    Cluster tekton = new Cluster("http://tekton", "k1"); tekton.publish(web, ISS);
    JwtVerifier v = verifier(config(source("down", "http://down", ".*", "aa"), source("tekton", "http://tekton", ".*", "tekton-scanner")));
    assertEquals("tekton-scanner", assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(tekton, Map.of()))).login());
  }

  @Test void ecdsaEs256Works() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC"); g.initialize(new ECGenParameterSpec("secp256r1")); KeyPair kp = g.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) kp.getPublic();
    web.put("http://e/.well-known/openid-configuration", JSON.writeValueAsString(Map.of("issuer", ISS, "jwks_uri", "http://e/jwks")));
    web.put("http://e/jwks", JSON.writeValueAsString(Map.of("keys", List.of(Map.of("kty", "EC", "crv", "P-256", "kid", "e1",
        "x", b64(pad32(pub.getW().getAffineX().toByteArray())), "y", b64(pad32(pub.getW().getAffineY().toByteArray())))))));
    String signing = b64(JSON.writeValueAsBytes(Map.of("alg", "ES256", "kid", "e1"))) + "." + b64(JSON.writeValueAsBytes(Map.of("iss", ISS, "sub", "s", "aud", "sonarqube", "iat", clock.instant().getEpochSecond(), "exp", clock.instant().plusSeconds(60).getEpochSecond())));
    Signature s = Signature.getInstance("SHA256withECDSAinP1363Format"); s.initSign(kp.getPrivate()); s.update(signing.getBytes(StandardCharsets.US_ASCII));
    var r = verifier(config(source("e", "http://e", ".*", "uu"))).verify(signing + "." + b64(s.sign()));
    assertInstanceOf(JwtVerifier.Accepted.class, r);
  }

  @Test void configValidationFailsClosed() {
    assertThrows(IllegalArgumentException.class, () -> AuthConfig.parse(config("{\"name\":\"a\",\"issuer\":\"https://i\",\"rules\":[{\"subject\":\".*\",\"login\":\"uu\"}]}"))); // no audience
    assertThrows(IllegalArgumentException.class, () -> AuthConfig.parse(config("{\"name\":\"a\",\"issuer\":\"http://i\",\"audiences\":[\"x\"],\"rules\":[{\"subject\":\".*\",\"login\":\"uu\"}]}"))); // http w/o opt-in
    assertThrows(IllegalArgumentException.class, () -> AuthConfig.parse(config("{\"name\":\"a\",\"issuer\":\"https://i\",\"audiences\":[\"x\"],\"rules\":[{\"subject\":\"(\",\"login\":\"uu\"}]}"))); // bad regex
    assertThrows(Exception.class, () -> AuthConfig.parse(config("{\"name\":\"a\",\"issuer\":\"https://i\",\"audience\":[\"x\"],\"rules\":[]}"))); // typo'd key
  }

  @Test void discoveryIssuerMismatchIsRejected() throws Exception {
    Cluster c = new Cluster("http://t", "k1"); c.publish(web, "https://someone-else");
    assertInstanceOf(JwtVerifier.Rejected.class, verifier(config(source("t", "http://t", ".*", "uu"))).verify(token(c, Map.of())));
  }

  @Test void tokenExtraction() {
    assertEquals("a.b.c", JwtServiceAuthentication.extractToken("Bearer a.b.c"));
    assertEquals("a.b.c", JwtServiceAuthentication.extractToken("Basic " + Base64.getEncoder().encodeToString("a.b.c:".getBytes())));
    assertNull(JwtServiceAuthentication.extractToken(null));
  }

  @Test void loginTemplatesCannotCollideAcrossSubjects() throws Exception {
    Cluster c = new Cluster("http://t", "k1"); c.publish(web, ISS);
    String sub = "system:serviceaccount:(?<ns>[^:]+):(?<sa>[^:]+)";
    // '-' between placeholders: ns "a-b" could collide with sa "b-c" of ns "a" -> refused
    JwtVerifier dash = verifier(config(source("t", "http://t", sub, "ci-${ns}-${sa}")));
    assertInstanceOf(JwtVerifier.Rejected.class, dash.verify(token(c, Map.of("sub", "system:serviceaccount:team-a:builder"))));
    assertInstanceOf(JwtVerifier.Accepted.class, dash.verify(token(c, Map.of("sub", "system:serviceaccount:team:builder"))));
    // '_' cannot occur in Kubernetes names: dashes in values are fine
    JwtVerifier under = verifier(config(source("t", "http://t", sub, "ci_${ns}_${sa}")));
    assertEquals("ci_team-a_builder", assertInstanceOf(JwtVerifier.Accepted.class, under.verify(token(c, Map.of("sub", "system:serviceaccount:team-a:builder")))).login());
  }

  @Test void configRequiresLiteralLoginPrefixAndSaneAllowedPaths() {
    String head = "{\"name\":\"a\",\"issuer\":\"https://i\",\"audiences\":[\"x\"],";
    assertThrows(IllegalArgumentException.class, () -> AuthConfig.parse(config(head + "\"rules\":[{\"subject\":\".*\",\"login\":\"${sa}\"}]}")));
    assertThrows(IllegalArgumentException.class, () -> AuthConfig.parse(config(head + "\"allowedPathPrefixes\":[\"/api/../x\"],\"rules\":[{\"subject\":\".*\",\"login\":\"fixed-user\"}]}")));
  }

  @Test void longLivedTokensAreRefusedByDefault() throws Exception {
    Cluster c = new Cluster("http://t", "k1"); c.publish(web, ISS);
    JwtVerifier v = verifier(config(source("t", "http://t", ".*", "uu")));
    long now = clock.instant().getEpochSecond();
    assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(c, Map.of("iat", now, "exp", now + 3600))));
    assertInstanceOf(JwtVerifier.Rejected.class, v.verify(token(c, Map.of("iat", now, "exp", now + 10 * 86400))));
    Map<String, Object> noIat = new HashMap<>(); noIat.put("iat", null);
    assertInstanceOf(JwtVerifier.Rejected.class, v.verify(token(c, noIat)));
  }

  @Test void oversizedAndMalformedTokensAreIgnoredCheaply() throws Exception {
    Cluster c = new Cluster("http://t", "k1"); c.publish(web, ISS);
    JwtVerifier v = verifier(config(source("t", "http://t", ".*", "uu")));
    assertInstanceOf(JwtVerifier.NotApplicable.class, v.verify("a".repeat(9000) + ".b.c"));
    assertEquals("a?b", Log.clean("a\nb"));
    assertTrue(Log.clean("x".repeat(500)).length() < 90);
  }

  @Test void compatGuardPassesOnTheRealServerClassesAndFailsSoftWithout() {
    assertEquals(List.of(), Compat.problems(JwtVerifierTest.class.getClassLoader()));
    assertFalse(Compat.problems(new java.net.URLClassLoader(new java.net.URL[0], null)).isEmpty());
  }

  static byte[] pad32(byte[] b) { byte[] u = unsigned(b); byte[] o = new byte[32]; System.arraycopy(u, 0, o, 32 - u.length, u.length); return o; }
  static byte[] unsigned(byte[] b) { return b.length > 1 && b[0] == 0 ? Arrays.copyOfRange(b, 1, b.length) : b; }
  static String b64(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

  static final class MutableClock extends Clock {
    Instant now; MutableClock(Instant i) { now = i; }
    void advance(Duration d) { now = now.plus(d); }
    @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
    @Override public Clock withZone(java.time.ZoneId z) { return this; }
    @Override public Instant instant() { return now; }
  }
}
