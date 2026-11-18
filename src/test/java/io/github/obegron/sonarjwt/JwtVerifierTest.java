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
    return new JwtVerifier(AuthConfig.parse(json), url -> { fetches++; String b = web.get(url); if (b == null) throw new IllegalStateException("404 " + url); return b; }, clock);
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
    JwtVerifier v = verifier(config(source("jenkins", "http://a", ".*", "${source}-scanner"), source("tekton", "http://b", ".*", "${source}-scanner")));
    assertEquals("jenkins-scanner", assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(a, Map.of()))).login());
    assertEquals("tekton-scanner", assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(b, Map.of()))).login());
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
    assertInstanceOf(JwtVerifier.Rejected.class, v.verify(t2)); // within 30s retry window: no refetch yet
    clock.advance(Duration.ofSeconds(31));
    assertInstanceOf(JwtVerifier.Accepted.class, v.verify(t2));
  }

  @Test void twoClustersWithTheSameIssuerAreToldApartByTheirKeys() throws Exception {
    Cluster jenkins = new Cluster("http://jenkins", "k1"), tekton = new Cluster("http://tekton", "k1");
    jenkins.publish(web, ISS); tekton.publish(web, ISS);
    JwtVerifier v = verifier(config(
        source("jenkins", "http://jenkins", "system:serviceaccount:ci:pipeline", "jenkins-scanner"),
        source("tekton", "http://tekton", "system:serviceaccount:ci:pipeline", "tekton-scanner")));
    assertEquals("jenkins-scanner", assertInstanceOf(JwtVerifier.Accepted.class, v.verify(token(jenkins, Map.of()))).login());
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
    String signing = b64(JSON.writeValueAsBytes(Map.of("alg", "ES256", "kid", "e1"))) + "." + b64(JSON.writeValueAsBytes(Map.of("iss", ISS, "sub", "s", "aud", "sonarqube", "exp", clock.instant().plusSeconds(60).getEpochSecond())));
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

  @Test void tokenExtractionAndPathRules() {
    assertEquals("a.b.c", JwtServiceAuthentication.extractToken("Bearer a.b.c"));
    assertEquals("a.b.c", JwtServiceAuthentication.extractToken("Basic " + Base64.getEncoder().encodeToString("a.b.c:".getBytes())));
    assertNull(JwtServiceAuthentication.extractToken(null));
    var ok = new JwtVerifier.Accepted("s", "sub", "u", null, AuthConfig.DEFAULT_ALLOWED_PATHS);
    assertTrue(JwtServiceAuthentication.pathAllowed("/api/ce/submit", ok));
    assertTrue(JwtServiceAuthentication.pathAllowed("/api/settings/values.protobuf", ok));
    assertTrue(JwtServiceAuthentication.pathAllowed("/api/v2/analysis/engine", ok));
    assertTrue(JwtServiceAuthentication.pathAllowed("/batch/project.protobuf", ok));
    assertTrue(JwtServiceAuthentication.pathAllowed("/api/project_branches/list", ok));
    assertFalse(JwtServiceAuthentication.pathAllowed("/api/project_branches/delete", ok));
    assertFalse(JwtServiceAuthentication.pathAllowed("/api/users/search", ok));
    assertFalse(JwtServiceAuthentication.pathAllowed("/api/ce/submitx", ok));
    assertFalse(JwtServiceAuthentication.pathAllowed("/api/user_tokens/generate", ok));
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
