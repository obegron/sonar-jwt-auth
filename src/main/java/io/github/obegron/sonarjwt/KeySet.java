package io.github.obegron.sonarjwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** The signing keys of one source, fetched through OIDC discovery and cached. */
final class KeySet {
  private static final Logger LOG = LoggerFactory.getLogger(KeySet.class);
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final Duration TTL = Duration.ofMinutes(10);
  private static final Duration MIN_RETRY = Duration.ofSeconds(30);
  private static final Duration MAX_STALE = Duration.ofHours(24);
  private static final int MAX_BODY = 1 << 20;

  /** Fetches a URL body; swappable in tests. */
  interface Fetcher { String get(String url) throws Exception; }

  static Fetcher httpFetcher() {
    HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build();
    return url -> {
      HttpResponse<String> r = client.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10)).GET().build(),
          HttpResponse.BodyHandlers.ofString());
      if (r.statusCode() != 200) throw new IllegalStateException("HTTP " + r.statusCode() + " from " + url);
      if (r.body().length() > MAX_BODY) throw new IllegalStateException("response too large from " + url);
      return r.body();
    };
  }

  private final AuthConfig.Source source;
  private final Fetcher fetcher;
  private final Clock clock;
  private volatile Map<String, PublicKey> keys = Map.of();
  private volatile Instant fetchedAt = Instant.EPOCH;
  private Instant lastAttempt = Instant.EPOCH;

  KeySet(AuthConfig.Source source, Fetcher fetcher, Clock clock) { this.source = source; this.fetcher = fetcher; this.clock = clock; }

  /** The key for {@code kid}, refreshing (rate limited) when it is unknown or the cache is old. */
  PublicKey find(String kid) {
    Instant now = clock.instant();
    PublicKey k = keys.get(kid);
    boolean fresh = Duration.between(fetchedAt, now).compareTo(TTL) < 0;
    if (k == null || !fresh) refresh(now);
    if (Duration.between(fetchedAt, clock.instant()).compareTo(MAX_STALE) > 0) return null;
    return keys.get(kid);
  }

  private synchronized void refresh(Instant now) {
    if (Duration.between(lastAttempt, now).compareTo(MIN_RETRY) < 0) return;
    lastAttempt = now;
    try {
      String base = source.effectiveDiscoveryUrl();
      JsonNode cfg = JSON.readTree(fetcher.get(base.replaceAll("/+$", "") + "/.well-known/openid-configuration"));
      if (!source.issuer.equals(cfg.path("issuer").asText())) {
        throw new IllegalStateException("discovery issuer '" + cfg.path("issuer").asText() + "' != configured '" + source.issuer + "'");
      }
      String jwksUri = cfg.path("jwks_uri").asText("");
      if (!(jwksUri.startsWith("https://") || (jwksUri.startsWith("http://") && source.allowInsecureHttp)))
        throw new IllegalStateException("jwks_uri not allowed (https required unless allowInsecureHttp): " + jwksUri);
      Map<String, PublicKey> next = parseJwks(fetcher.get(jwksUri));
      keys = next;
      fetchedAt = clock.instant();
      LOG.info("jwt-auth source '{}': loaded {} signing key(s)", source.name, next.size());
    } catch (Exception e) {
      LOG.warn("jwt-auth source '{}': key refresh failed, keeping previous keys: {}", source.name, e.toString());
    }
  }

  static Map<String, PublicKey> parseJwks(String json) throws Exception {
    Map<String, PublicKey> out = new HashMap<>();
    for (JsonNode k : JSON.readTree(json).path("keys")) {
      String kid = k.path("kid").asText("");
      if (kid.isEmpty() || "enc".equals(k.path("use").asText())) continue;
      try {
        switch (k.path("kty").asText()) {
          case "RSA" -> out.put(kid, KeyFactory.getInstance("RSA").generatePublic(
              new RSAPublicKeySpec(big(k.path("n").asText()), big(k.path("e").asText()))));
          case "EC" -> {
            if (!"P-256".equals(k.path("crv").asText())) continue;
            AlgorithmParameters p = AlgorithmParameters.getInstance("EC");
            p.init(new ECGenParameterSpec("secp256r1"));
            out.put(kid, KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(
                new ECPoint(big(k.path("x").asText()), big(k.path("y").asText())), p.getParameterSpec(ECParameterSpec.class))));
          }
          default -> { }
        }
      } catch (Exception e) { LOG.warn("jwt-auth: skipping unusable JWK kid={}: {}", kid, e.toString()); }
    }
    return out;
  }

  private static BigInteger big(String b64) { return new BigInteger(1, Base64.getUrlDecoder().decode(b64)); }
}
